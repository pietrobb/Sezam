"""Automatic encrypted vault snapshots before risky operations.

A snapshot is a page-level copy of sezam.db made with the SQLite backup
API. It holds only what sezam.db already holds: ciphertext and wrapped
keys, opened by the master password that was valid when it was taken.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from ..securefile import private_temp_path, publish
from . import ai_access
from .db import VaultDB, VaultSchemaTooNew, check_vault_schema
from .inuse import InUseLock, VaultInUse

SNAPSHOT_DIR = "snapshots"
KEEP_SNAPSHOTS = 20
PRE_RESTORE = "pre-restore"
KEEP_PRE_RESTORE = 3
# MCP servers told to lock close the vault within a moment.
IN_USE_WAIT_SECONDS = 5.0

_REASON_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_NAME_RE = re.compile(r"^(\d{8}T\d{6}_\d{6}Z)-([a-z0-9][a-z0-9-]{0,31})\.db$")


class SnapshotError(RuntimeError):
    """A snapshot could not be taken; the risky operation must not run."""


@dataclass(frozen=True)
class SnapshotInfo:
    name: str
    path: Path
    created: str
    reason: str
    size: int


def snapshot_dir(vault_dir: str | Path) -> Path:
    return Path(vault_dir) / SNAPSHOT_DIR


def take_snapshot(db: VaultDB, reason: str, keep: int = KEEP_SNAPSHOTS) -> Path:
    """Copy the open vault database into ``<vault>/snapshots``.

    Raises SnapshotError on any failure so the caller aborts instead of
    running the risky operation without a way back.
    """
    if not _REASON_RE.match(reason):
        raise SnapshotError(f"Invalid snapshot reason: {reason!r}")
    directory = snapshot_dir(db.path.parent)
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        if os.name != "nt":
            os.chmod(directory, 0o700)
        dest = _unique_path(directory, reason)
        _backup(db, dest)
    except Exception as exc:
        raise SnapshotError(f"Vault snapshot failed ({type(exc).__name__}); operation aborted") from exc
    # Review 7c10379 (R7-H): a password change in another process committing
    # while this copy was made swept the snapshots before it was published;
    # it opened with the old password. Read on a fresh connection: the
    # caller's own may still see the old state.
    copied, live = _snapshot_salt(dest), _snapshot_salt(db.path)
    if copied is not None and live is not None and copied != live:
        with suppress(OSError):
            dest.unlink()
        raise SnapshotError(
            "The master password was changed in another Sezam program during the "
            "snapshot; operation aborted. Lock the vault and unlock it again."
        )
    prune_snapshots(db.path.parent, keep)
    return dest


def _backup(db: VaultDB, dest: Path) -> None:
    """SQLite online backup into an owner-only file, published atomically.

    The copy is switched from WAL to a rollback journal, so it is a single
    self-contained file and reading it later leaves no -wal/-shm behind.
    """
    tmp = private_temp_path(dest)
    try:
        conn = sqlite3.connect(str(tmp))
        try:
            with db._guard:
                db.conn.backup(conn)
            ai_access.off_in_copy(conn)
            conn.execute("PRAGMA journal_mode=DELETE")
        finally:
            conn.close()
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        publish(tmp, dest)
    except BaseException:
        with suppress(OSError):
            tmp.unlink()
        raise


def _unique_path(directory: Path, reason: str) -> Path:
    now = time.time()
    while True:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now))
        micros = int((now % 1) * 1_000_000)
        dest = directory / f"{stamp}_{micros:06d}Z-{reason}.db"
        if not dest.exists():
            return dest
        now += 0.000001


def list_snapshots(vault_dir: str | Path) -> list[SnapshotInfo]:
    """Snapshots in ``<vault>/snapshots``, oldest first. Foreign files are ignored."""
    directory = snapshot_dir(vault_dir)
    if not directory.is_dir():
        return []
    result = []
    for path in directory.iterdir():
        match = _NAME_RE.match(path.name)
        if not match or path.is_symlink() or not path.is_file():
            continue
        stamp = match.group(1)
        created = (
            f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]} "
            f"{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]} UTC"
        )
        result.append(
            SnapshotInfo(path.name, path, created, match.group(2), path.stat().st_size)
        )
    result.sort(key=lambda s: s.name)
    return result


def prune_snapshots(vault_dir: str | Path, keep: int = KEEP_SNAPSHOTS) -> None:
    """Keep the newest ``keep`` snapshots and the newest KEEP_PRE_RESTORE 'pre-restore' ones.

    Review 8595ec1: the 'pre-restore' snapshot of every restore attempt counted
    against the others, so a few attempts pushed out the oldest snapshots,
    those from before the incident being looked for. The two kinds now have
    their own limits.
    """
    snapshots = list_snapshots(vault_dir)
    pre = [s for s in snapshots if s.reason == PRE_RESTORE]
    others = [s for s in snapshots if s.reason != PRE_RESTORE]
    doomed = pre[: max(0, len(pre) - KEEP_PRE_RESTORE)] + others[: max(0, len(others) - keep)]
    for old in doomed:
        try:
            old.path.unlink()
        except OSError:
            pass


def _snapshot_salt(path: Path) -> str | None:
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT value FROM vault_meta WHERE key = 'argon2_salt'"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def vault_salt(vault_dir: str | Path) -> str | None:
    """The salt of the live vault's current master password (public meta)."""
    return _snapshot_salt(Path(vault_dir) / "sezam.db")


def snapshots_of_other_passwords(
    vault_dir: str | Path, current_salt: str, spare: str | None = None
) -> list[SnapshotInfo]:
    """The snapshots a password other than the current one opens (not ``spare``).

    Unreadable files are not among them: nothing tells which password they
    belong to.
    """
    return [
        info for info in list_snapshots(vault_dir)
        if info.name != spare and _snapshot_salt(info.path) not in (None, current_salt)
    ]


def drop_snapshots_of_other_passwords(
    vault_dir: str | Path, current_salt: str, spare: str | None = None
) -> int:
    """Delete the snapshots a password other than the current one opens.

    Review d615826: a password change leaves the DEKs as they are, so a
    snapshot taken before it opened with the old (perhaps leaked) password
    and its keys still decrypted today's data; up to 20 of them were kept.
    ``spare`` (the snapshot the change itself took) stays until the new
    password has opened the vault once. Unreadable files stay.
    """
    removed = 0
    for info in snapshots_of_other_passwords(vault_dir, current_salt, spare):
        with suppress(OSError):
            info.path.unlink()
            removed += 1
    return removed


def drop_snapshot_of_other_password(vault_dir: str | Path, name: str, current_salt: str) -> None:
    """Delete snapshot ``name`` if a password other than the current one opens it."""
    for info in list_snapshots(vault_dir):
        if info.name == name and _snapshot_salt(info.path) not in (None, current_salt):
            with suppress(OSError):
                info.path.unlink()


# ── Restore ──

_REQUIRED_META = ("user_id", "encrypted_keypair", "argon2_salt", "argon2_params", "root_node_id")


def find_snapshot(vault_dir: str | Path, name: str) -> SnapshotInfo:
    """Only an exact name listed by list_snapshots; never a path."""
    for info in list_snapshots(vault_dir):
        if info.name == name:
            return info
    raise SnapshotError(f"No snapshot named {name!r}; see 'sezam snapshot list'")


def stage_snapshot(vault_dir: str | Path, name: str) -> Path:
    """Copy a snapshot into a private staging dir and check it is a vault.

    Returns the staging directory, which holds ``sezam.db`` and can be
    opened as a Vault. Nothing in the live vault is touched.
    """
    info = find_snapshot(vault_dir, name)
    return stage_file(vault_dir, info.path, f"Snapshot {name}")


def stage_file(vault_dir: str | Path, source: str | Path, label: str) -> Path:
    """Like stage_snapshot, for any vault file, e.g. from 'sezam export --format
    backup' (review 526419e N3). A file of a newer schema is refused."""
    staging = Path(tempfile.mkdtemp(dir=vault_dir, prefix=".restore-"))
    staged = staging / "sezam.db"
    name = label
    try:
        src = sqlite3.connect(f"{Path(source).resolve().as_uri()}?mode=ro", uri=True)
        try:
            dst = sqlite3.connect(str(staged))
            try:
                src.backup(dst)
                dst.execute("PRAGMA journal_mode=DELETE")
                ok = dst.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                try:
                    meta = dict(dst.execute(
                        "SELECT key, value FROM vault_meta WHERE value IS NOT NULL AND value != ''"
                    ).fetchall())
                except sqlite3.DatabaseError:
                    meta = {}
            finally:
                dst.close()
        finally:
            src.close()
        if not ok or not set(_REQUIRED_META) <= set(meta):
            raise SnapshotError(f"{name} is not an intact Sezam vault")
        check_schema_version(meta.get("schema_version"), name)
        if os.name != "nt":
            os.chmod(staged, 0o600)
    except SnapshotError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise SnapshotError(f"{name} cannot be read ({type(exc).__name__})") from exc
    return staging


def check_schema_version(value: str | None, label: str) -> None:
    try:
        check_vault_schema(value)
    except VaultSchemaTooNew as exc:
        raise SnapshotError(f"{label}: {exc} Nothing restored.") from exc


def discard_staged(staging: Path) -> None:
    shutil.rmtree(staging, ignore_errors=True)


def install_staged(vault_dir: str | Path, staging: Path) -> Path | None:
    """Replace the live sezam.db with a staged snapshot.

    The current vault is snapshotted first ('pre-restore'), so a restore can
    itself be undone; if that fails, nothing is replaced. Returns the
    pre-restore snapshot path (None when there was no vault).

    Refused while any other process (desktop app, MCP server, another
    command) holds the vault open: it would go on using, and writing into,
    the replaced file (lockout review M7). The exclusive hold also keeps
    them from opening it until the new file is in place.
    """
    vault_dir = Path(vault_dir)
    in_use = InUseLock(vault_dir / "sezam.db")
    try:
        in_use.acquire(exclusive=True, timeout=IN_USE_WAIT_SECONDS)
    except VaultInUse as exc:
        raise SnapshotError(f"{exc} Nothing restored.") from exc
    try:
        return _install_staged(vault_dir, staging)
    finally:
        in_use.release()


def _team_anchors(db: VaultDB) -> dict:
    """What this device trusts about the team log (review 1141a20, R9-E)."""
    from .sync_common import CONFIRMED_MEMBER_KEYS_META
    from .team_log_local import CONFIRMED_GENESIS_META, GENESIS_META

    return {
        "rows": [tuple(r) for r in db.fetchall("SELECT seq, body, sig, hash FROM team_log ORDER BY seq")],
        "meta": {key: db.get_meta(key) for key in (GENESIS_META, CONFIRMED_GENESIS_META)},
        "members": db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {},
    }


def _keep_team_anchors(staged: VaultDB, anchors: dict) -> None:
    """An older snapshot never takes back the log, pin or confirmations.

    Restoring one used to bring back a shorter team log and no pinned or
    confirmed genesis: the device then followed a server log it had refused
    before (an automatic downgrade). What the live vault holds wins; what it
    lacks the snapshot keeps (forgetting a pin is its own explicit command).
    """
    from .sync_common import CONFIRMED_MEMBER_KEYS_META

    with staged.transaction(immediate=True):
        if anchors["rows"]:
            staged.execute("DELETE FROM team_log")
            for row in anchors["rows"]:
                staged.execute("INSERT INTO team_log (seq, body, sig, hash) VALUES (?, ?, ?, ?)", row)
        for key, value in anchors["meta"].items():
            if value is not None:
                staged.set_meta(key, value)
        if anchors["members"]:
            members = staged.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {}
            staged.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {**members, **anchors["members"]})


def _install_staged(vault_dir: Path, staging: Path) -> Path | None:
    from . import ai_access

    live = vault_dir / "sezam.db"
    pre_restore = None
    live_epoch = 0
    anchors = None
    if live.exists():
        db = VaultDB(live, hold_in_use=False)
        try:
            db.open()
            # Prunes only older 'pre-restore' snapshots (prune_snapshots).
            pre_restore = take_snapshot(db, PRE_RESTORE)
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            with suppress(TypeError, ValueError):
                live_epoch = max(int(db.get_meta(ai_access.EPOCH_KEY) or 0), 0)
            anchors = _team_anchors(db)
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotError(
                f"Current vault could not be snapshotted ({type(exc).__name__}); nothing restored"
            ) from exc
        finally:
            db.close()
    staged = VaultDB(staging / "sezam.db", hold_in_use=False)
    try:
        staged.open()
        ai_access.off_for_restore(staged, live_epoch)
        if anchors is not None:
            _keep_team_anchors(staged, anchors)
    except Exception as exc:
        raise SnapshotError(
            f"AI access or the team log trust could not be carried into the restored copy "
            f"({type(exc).__name__}); nothing restored"
        ) from exc
    finally:
        staged.close()
    # A WAL left from the old database would be replayed into the new one.
    for suffix in ("-wal", "-shm"):
        side = vault_dir / f"sezam.db{suffix}"
        if side.exists():
            side.unlink()
    os.replace(staging / "sezam.db", live)
    return pre_restore
