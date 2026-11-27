"""AI kill switch: persistent ``ai_access_enabled`` / ``ai_access_epoch``.

The state lives in ``vault_meta`` so it survives restarts of ``mcp-serve``.
Turning AI access off needs no password and works on a locked vault (it is
the emergency brake); turning it on needs an unlocked vault, which callers
open with a freshly typed master password. Any value that cannot be read
or parsed counts as off, and so does 'on' without a valid MAC under the KEK.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import logging
import os
import socket
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

from . import oplock
from .db import VaultDB

if TYPE_CHECKING:
    from .crud import Vault

logger = logging.getLogger(__name__)

ENABLED_KEY = "ai_access_enabled"
EPOCH_KEY = "ai_access_epoch"
PENDING_AUDIT_KEY = "ai_access_audit_pending"
# Review d615826: vault_meta is plain SQLite, so an agent with a shell could
# turn AI access on (DELETE the row: unset meant on) or blind the phone's
# brake (raise the applied remote epoch). 'On' and the applied remote epoch
# now count only with an HMAC under a key derived from the KEK; turning off
# needs no key and an unverifiable value counts as off / as nothing applied.
STATE_MAC_KEY = "ai_access_mac"
REMOTE_APPLIED_KEY = "ai_remote_policy_epoch"
REMOTE_APPLIED_MAC_KEY = "ai_remote_policy_mac"
_MAC_CONTEXT = b"sezam/ai-access-state/v1"


@dataclass(frozen=True)
class AIAccessState:
    enabled: bool
    epoch: int


@contextmanager
def _meta_db(vault: "Vault") -> Iterator[VaultDB]:
    """The vault's open connection, or a short-lived one while locked."""
    # Held throughout, so a lock() from another thread cannot close the
    # shared connection between this check and the reads.
    with vault.db._guard:
        if vault.db._conn is not None:
            yield vault.db
            return
    if not vault.db.exists():
        raise FileNotFoundError("Vault not found.")
    db = VaultDB(vault.db.path)
    db.open()
    try:
        yield db
    finally:
        db.close()


def _parse(enabled: str | None, epoch: str | None) -> AIAccessState:
    # Unset is off: a vault from before the kill switch needs 'sezam ai on'.
    try:
        epoch_value = 0 if epoch is None else int(epoch)
    except ValueError:
        return AIAccessState(False, 0)
    if epoch_value < 0:
        return AIAccessState(False, 0)
    return AIAccessState(enabled == "1", epoch_value)


def _vault_kek(vault: "Vault") -> bytes | None:
    """A copy of the KEK while the vault is unlocked, else None."""
    manager = getattr(vault, "_dek_mgr", None)
    kek = getattr(manager, "_kek", None) if vault.is_unlocked else None
    return bytes(kek) if kek else None


def _mac(kek: bytes, *fields: str | None) -> str:
    key = hmac.new(kek, _MAC_CONTEXT, hashlib.sha256).digest()
    message = json.dumps(list(fields), separators=(",", ":")).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _state_mac(kek: bytes, db: VaultDB) -> str:
    # Review 18c300f R16-H3: an 'on' names the anchor home it was sealed
    # next to, so deleting the home rows (and server_url) no longer turns a
    # vault that expects its anchor into one that expects none: the 'on'
    # stops verifying.
    return _mac(kek, STATE_MAC_KEY, db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY),
                db.get_meta(ANCHOR_HOME_KEY))


def _state_verified(kek: bytes, db: VaultDB) -> bool:
    if _verified(db, STATE_MAC_KEY, _state_mac(kek, db)):
        return True
    # An 'on' sealed before R16-H3 names no home: it counts only next to a
    # home that verifies (deleting that home turns it off). A vault on no
    # server that had one needs 'sezam ai on' once.
    legacy = _mac(kek, STATE_MAC_KEY, db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
    home = db.get_meta(ANCHOR_HOME_KEY)
    return (
        home is not None
        and '"released"' not in home  # a home let go (R16-L6) checks nothing
        and _verified(db, ANCHOR_HOME_MAC_KEY, _home_mac(kek, db))
        and _verified(db, STATE_MAC_KEY, legacy)
    )


def _remote_mac(kek: bytes, db: VaultDB) -> str:
    return _mac(kek, REMOTE_APPLIED_MAC_KEY, db.get_meta(REMOTE_APPLIED_KEY))


def _verified(db: VaultDB, mac_key: str, expected: str) -> bool:
    stored = db.get_meta(mac_key)
    return isinstance(stored, str) and hmac.compare_digest(stored, expected)


def seal_new_vault(db: VaultDB, kek: bytes | bytearray) -> None:
    """A newly created vault starts with AI access on, sealed under its KEK."""
    db.set_meta(ENABLED_KEY, "1")
    db.set_meta(EPOCH_KEY, "0")
    db.set_meta(STATE_MAC_KEY, _state_mac(bytes(kek), db))


def rewrap_macs(db: VaultDB, old_kek: bytes | bytearray, new_kek: bytes | bytearray) -> None:
    """KEK change (password change, adopted rotation): what verified under
    the old KEK is sealed under the new one; anything else stays unverified."""
    old, new = bytes(old_kek), bytes(new_kek)
    if _state_verified(old, db):
        db.set_meta(STATE_MAC_KEY, _state_mac(new, db))
    if _verified(db, REMOTE_APPLIED_MAC_KEY, _remote_mac(old, db)):
        db.set_meta(REMOTE_APPLIED_MAC_KEY, _remote_mac(new, db))
    if _verified(db, ANCHOR_HOME_MAC_KEY, _home_mac(old, db)):
        db.set_meta(ANCHOR_HOME_MAC_KEY, _home_mac(new, db))


def read_state(vault: "Vault") -> AIAccessState:
    """Current kill switch state; any failure to read it means off.

    On an unlocked vault 'on' also needs a valid MAC. A locked vault cannot
    check it, so there it is only what the vault claims (for display and the
    start of mcp-serve); every tool call needs the vault unlocked anyway.
    """
    try:
        kek = _vault_kek(vault)
        with _meta_db(vault) as db:
            state = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
            if state.enabled and kek is not None and not _state_verified(kek, db):
                logger.warning("AI access state does not verify; treating it as off")
                return AIAccessState(False, state.epoch)
            return state
    except Exception:
        logger.warning("AI access state is unreadable; treating it as off", exc_info=True)
        return AIAccessState(False, 0)


def verified_on_epoch(vault: "Vault") -> int | None:
    """The epoch of a verified 'on' (unlocked vault, valid MAC), else None.
    What a broker's in-memory brake may be released by (review 7c10379 H6):
    a locked vault's claim of 'on' is not checked and must not count."""
    kek = _vault_kek(vault)
    if kek is None:
        return None
    try:
        with _meta_db(vault) as db:
            state = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
            if state.enabled and _state_verified(kek, db):
                return state.epoch
    except Exception:
        logger.warning("AI access state is unreadable; treating it as off", exc_info=True)
    return None


def remote_applied_epoch(vault: "Vault") -> int:
    """Epoch of the last remote policy applied here. Only a value sealed
    under the KEK counts; anything else is 0, so any valid policy brakes again."""
    kek = _vault_kek(vault)
    if kek is None:
        return 0
    db = vault.db
    if not _verified(db, REMOTE_APPLIED_MAC_KEY, _remote_mac(kek, db)):
        return 0
    try:
        return max(int(db.get_meta(REMOTE_APPLIED_KEY) or 0), 0)
    except (TypeError, ValueError):
        return 0


def record_remote_applied(vault: "Vault", epoch: int) -> None:
    """Seal the epoch of a remote policy just applied (vault unlocked)."""
    kek = _vault_kek(vault)
    if kek is None:
        raise PermissionError("Recording a remote AI policy needs the unlocked vault.")
    db = vault.db
    with db.transaction():
        db.set_meta(REMOTE_APPLIED_KEY, str(epoch))
        db.set_meta(REMOTE_APPLIED_MAC_KEY, _remote_mac(kek, db))


# Review c78fd19 R13-11: an agent under the owner's OS user (L1) saved the
# rows of a sealed 'on' and wrote them back after 'sezam ai off'. A running
# broker refused them (its off floor), a restarted one took them. The broker
# now anchors the highest 'off' it saw on the sync server, per vault file on
# this machine, and an 'on' below the anchor counts as off.
FLOOR_KEY = "ai_access_floor"


def legacy_anchor_id(vault: "Vault") -> str | None:
    """The anchor id before R14-M3 (hostname + path, keyed by the KEK); only
    read once, to carry its epoch over to the sealed anchor home."""
    kek = _vault_kek(vault)
    if kek is None:
        return None
    where = f"{socket.gethostname()}\0{os.path.realpath(vault.db.path)}"
    return _mac(kek, "ai_anchor_id", where)


# Review 8bc70f7 R14-M3: the anchor was looked up on whatever server
# vault_meta named (an agent could drop or redirect server_url, and the
# broker then checked nothing or an empty server) under an id made of the
# hostname and path. The anchor's home is now sealed under the KEK: a random
# id, the server and the account. A vault that has one, or names a server,
# expects its anchor; one that cannot be checked keeps AI access off.
ANCHOR_HOME_KEY = "ai_anchor_home"
ANCHOR_HOME_MAC_KEY = "ai_anchor_home_mac"


@dataclass(frozen=True)
class AnchorHome:
    anchor: str
    server_url: str
    user_id: str


class AnchorUnverifiable(RuntimeError):
    """The vault expects an anchor this process cannot check."""


# Review c02cc47 R17-L: a home was made on, and 'sezam ai on' moved it to,
# whatever server_url vault_meta named; an agent under the owner's OS user
# wrote its own server there first. name_server seals the server and account
# it names under the KEK; a home is made or moved only to a sealed one, or to
# one the owner confirms at 'sezam ai on'.
SERVER_SEAL_KEY = "ai_server_seal"


class UnsealedServer(RuntimeError):
    """'sezam ai on' would anchor on a server no master password confirmed."""

    def __init__(self, server_url: str):
        super().__init__(
            f"AI access stays off: this vault names the sync server {server_url}, which no "
            "master password confirmed (a vault from an earlier version, or a program changed "
            "it). Confirm it with 'sezam ai on' in a terminal or by connecting to it again, or "
            "run 'sezam ai on --server-gone'."
        )
        self.server_url = server_url


def _server_mac(kek: bytes, server_url: str, user_id: str) -> str:
    return _mac(kek, SERVER_SEAL_KEY, server_url, user_id)


def _server_sealed(kek: bytes, db: VaultDB, server_url: str, user_id: str) -> bool:
    return _verified(db, SERVER_SEAL_KEY, _server_mac(kek, server_url, user_id))


def _home_mac(kek: bytes, db: VaultDB) -> str:
    return _mac(kek, ANCHOR_HOME_MAC_KEY, db.get_meta(ANCHOR_HOME_KEY))


def _sealed_home_rows(db: VaultDB, kek: bytes) -> dict | None:
    """The home rows (a home or a released server); None without any.
    Raises AnchorUnverifiable when their seal does not verify."""
    if db.get_meta(ANCHOR_HOME_KEY) is None and db.get_meta(ANCHOR_HOME_MAC_KEY) is None:
        return None
    if not _verified(db, ANCHOR_HOME_MAC_KEY, _home_mac(kek, db)):
        raise AnchorUnverifiable("the sealed AI anchor home does not verify")
    return db.get_meta_json(ANCHOR_HOME_KEY)


def anchor_expected(vault: "Vault") -> bool:
    """Whether AI access waits for a check of the server-held anchor (also
    readable on a locked vault, for the brake)."""
    with _meta_db(vault) as db:
        return bool(
            db.get_meta(ANCHOR_HOME_KEY) or db.get_meta(ANCHOR_HOME_MAC_KEY) or db.get_meta("server_url")
        )


def _seal_home(db: VaultDB, kek: bytes, home: AnchorHome | None, released: str | None = None) -> None:
    """Seal ``home`` (None: the vault expects no anchor any more), or with
    ``released`` the owner's word that this server is gone. A verified 'on'
    is sealed again next to it (R16-H3: it names its home)."""
    was_on = _state_verified(kek, db)
    if released is not None:
        db.set_meta_json(ANCHOR_HOME_KEY, {"released": released})
        db.set_meta(ANCHOR_HOME_MAC_KEY, _home_mac(kek, db))
    elif home is None:
        db.execute("DELETE FROM vault_meta WHERE key IN (?, ?)", (ANCHOR_HOME_KEY, ANCHOR_HOME_MAC_KEY))
    else:
        db.set_meta_json(ANCHOR_HOME_KEY, {
            "anchor": home.anchor, "server_url": home.server_url, "user_id": home.user_id,
        })
        db.set_meta(ANCHOR_HOME_MAC_KEY, _home_mac(kek, db))
    if was_on:
        db.set_meta(STATE_MAC_KEY, _state_mac(kek, db))


def anchor_home(vault: "Vault") -> AnchorHome | None:
    """The sealed anchor home; a new one for a vault on a server that has
    none yet. None for a vault on no server. Raises AnchorUnverifiable for a
    locked vault, or a home whose seal does not verify."""
    kek = _vault_kek(vault)
    if kek is None:
        raise AnchorUnverifiable("the vault is locked")
    db = vault.db
    with oplock.exclusive(db.path), db.transaction(immediate=True):
        server_url, user_id = db.get_meta("server_url"), db.get_meta("user_id")
        raw = _sealed_home_rows(db, kek)
        if raw is not None:
            if "released" not in raw:
                return AnchorHome(str(raw["anchor"]), str(raw["server_url"]), str(raw["user_id"]))
            # R16-L6: the owner let this server go ('sezam ai on
            # --server-gone'); a vault connected to another one anchors there.
            if raw["released"] == server_url:
                return None
        if not server_url or not user_id:
            return None
        if not _server_sealed(kek, db, server_url, user_id):
            raise AnchorUnverifiable(
                f"no master password confirmed the sync server {server_url}; "
                "'sezam ai on' anchors the AI switch there"
            )
        home = AnchorHome(os.urandom(32).hex(), server_url, user_id)
        _seal_home(db, kek, home)
        return home


def name_server(vault: "Vault", server_url: str) -> None:
    """The vault now syncs with ``server_url``; its anchor home is sealed in
    the same step. Capability review 501: made lazily by the first broker,
    the home left the 'on' sealed without one valid until then, and a copy
    of those rows taken meanwhile came back once the home rows were deleted.
    An 'on' sealed before the vault ever named a server (creation, 'ai on'
    with no server) still names no home: rows copied then roll the switch
    back to that time (stated limit, test_r16_ai_anchor_marker)."""
    db = vault.db
    with oplock.exclusive(db.path):
        kek = _vault_kek(vault)
        with db.transaction(immediate=True):
            db.set_meta("server_url", server_url)
            if kek is not None:  # R17-L: named with the password, so sealed
                db.set_meta(SERVER_SEAL_KEY, _server_mac(kek, server_url, db.get_meta("user_id")))
        if kek is not None:
            anchor_home(vault)


def rehome_anchor(vault: "Vault", server_gone: bool = False, confirmed: str | None = None) -> None:
    """'sezam ai on' (fresh password): the anchor moves to the server the
    vault now syncs with. On a vault that syncs with no server any more the
    owner drops it.

    Review 18c300f R16-L6: a sync server that is gone kept AI access off for
    good (nothing removes server_url). With ``server_gone`` the owner says
    so: the vault stops expecting an anchor on that server until it connects
    to another one (or 'sezam ai on' without it anchors there again).

    Review c02cc47 R17-L: the home moved only to a sealed server (or the one
    the owner ``confirmed``; UnsealedServer otherwise), under a new id: kept,
    the old server's anchor records still verified for the new home."""
    kek = _vault_kek(vault)
    if kek is None:
        return
    db = vault.db
    with oplock.exclusive(db.path), db.transaction(immediate=True):
        server_url, user_id = db.get_meta("server_url"), db.get_meta("user_id")
        if not server_url or not user_id:
            _seal_home(db, kek, None)
            return
        if server_gone:
            _seal_home(db, kek, None, released=server_url)
            return
        try:
            raw = _sealed_home_rows(db, kek)
        except AnchorUnverifiable:
            raw = None
        home = None
        if raw is not None and "released" not in raw:
            home = AnchorHome(str(raw["anchor"]), str(raw["server_url"]), str(raw["user_id"]))
        stays = home is not None and (home.server_url, home.user_id) == (server_url, user_id)
        if not stays and not _server_sealed(kek, db, server_url, user_id) and confirmed != server_url:
            raise UnsealedServer(server_url)
        db.set_meta(SERVER_SEAL_KEY, _server_mac(kek, server_url, user_id))
        _seal_home(db, kek, home if stays else AnchorHome(os.urandom(32).hex(), server_url, user_id))


def anchor_mac(vault: "Vault", anchor: str, epoch: int) -> str | None:
    """What a server-held anchor must carry: the server cannot raise it."""
    kek = _vault_kek(vault)
    return None if kek is None else _mac(kek, "ai_anchor_epoch", anchor, str(epoch))


def _floor(db: VaultDB) -> int:
    try:
        return max(int(db.get_meta(FLOOR_KEY) or 0), 0)
    except (TypeError, ValueError):
        return 0


def raise_floor(vault: "Vault", epoch: int) -> None:
    """Keep the anchored floor in the vault, so 'sezam ai on' turns access on
    at an epoch the broker takes. Deleting it only keeps 'on' too low (off)."""
    # INV-6: the vault lock before _meta_db's statement guard.
    with oplock.exclusive(vault.db.path), _meta_db(vault) as db:
        with db.transaction(immediate=True):
            if epoch > _floor(db):
                db.set_meta(FLOOR_KEY, str(epoch))


def _origin(source: str) -> dict:
    try:
        user = getpass.getuser()
    except Exception:
        user = None
    return {
        "source": source,
        "host": socket.gethostname(),
        "os_user": user,
        "pid": os.getpid(),
        "at": int(time.time()),
    }


def disable(vault: "Vault", source: str, extra: dict | None = None) -> AIAccessState:
    """Turn AI access off and bump the epoch. Never needs a password.

    The audit record is written now when the vault is unlocked; otherwise
    (or if writing it fails) it is queued and written at the next unlock,
    so the brake itself never depends on the audit log. ``extra`` goes
    into the audit detail (e.g. the epoch of a remote policy).

    Review 7c10379 H6: the MAC of the 'on' state stayed, so writing back
    ('1', old epoch) turned AI on at the next unlock. It is deleted with the
    switch; only 'sezam ai on' seals a new one.
    """
    # INV-6: the switch does not wait for a sync holding the vault lock
    # (db.brake); its audit record does, outside _meta_db's statement guard.
    with _meta_db(vault) as db, db.brake():
        # Write lock before the read: another broker's 'off' committed in
        # between failed this one with 'database is locked' (review 7c10379).
        with db.transaction(immediate=True):
            current = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
            state = AIAccessState(False, current.epoch + 1)
            db.set_meta(ENABLED_KEY, "0")
            db.set_meta(EPOCH_KEY, str(state.epoch))
            db.execute("DELETE FROM vault_meta WHERE key = ?", (STATE_MAC_KEY,))
    detail = {**(extra or {}), "epoch": state.epoch, **_origin(source)}
    if not _write_audit(vault, "ai_off", detail):
        with _meta_db(vault) as db, db.brake():
            with db.transaction(immediate=True):  # another broker may queue one too
                pending = _pending(db)
                pending.append({"action": "ai_off", "detail": detail})
                db.set_meta_json(PENDING_AUDIT_KEY, pending)
    return state


def off_in_copy(conn) -> None:
    """Review 1141a20 M-AI4: a copy of sezam.db (snapshot, encrypted backup)
    never carries 'on'. Its rows with a valid MAC were a ready 'on' for an
    agent under the owner's OS user (L1) to write back after 'sezam ai off'.
    A restore turns access off anyway (off_for_restore). ``conn`` is a
    sqlite3 connection to the copy, not the live vault."""
    with conn:
        conn.execute("DELETE FROM vault_meta WHERE key = ?", (STATE_MAC_KEY,))
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, '0')", (ENABLED_KEY,)
        )


def off_for_restore(db: VaultDB, live_epoch: int) -> AIAccessState:
    """Turn AI access off in a snapshot or backup about to replace the vault.

    Review a159e97: the copy held 'on' with a MAC under the same KEK, so a
    restore turned AI access back on after it had been switched off. The
    restored vault starts off, at an epoch past both the copy's and the live
    vault's; the audit record is written at the next unlock.
    """
    with db.transaction(immediate=True):
        current = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
        state = AIAccessState(False, max(current.epoch, live_epoch) + 1)
        db.set_meta(ENABLED_KEY, "0")
        db.set_meta(EPOCH_KEY, str(state.epoch))
        db.execute("DELETE FROM vault_meta WHERE key = ?", (STATE_MAC_KEY,))
        pending = _pending(db)
        pending.append({"action": "ai_off", "detail": {"epoch": state.epoch, **_origin("restore")}})
        db.set_meta_json(PENDING_AUDIT_KEY, pending)
    return state


def enable(
    vault: "Vault", source: str, server_gone: bool = False, confirmed_server: str | None = None,
) -> AIAccessState:
    """Turn AI access on; the vault must be unlocked (fresh password).
    ``server_gone`` / ``confirmed_server``: see rehome_anchor."""
    if not vault.is_unlocked:
        raise PermissionError("Turning AI access on requires the master password.")
    db = vault.db
    # R17-L: the home first; a server no password confirmed leaves access off.
    rehome_anchor(vault, server_gone, confirmed_server)
    current = read_state(vault)
    # Not below the anchored floor (R13-11): an 'on' written back from a
    # saved copy left the epoch there, and the broker would not take it.
    state = AIAccessState(True, max(current.epoch, _floor(db)))
    # Audit first: if it cannot be recorded, access stays off.
    vault._audit_log(
        "ai_on",
        json.dumps({
            "epoch": state.epoch, **_origin(source), **({"server_gone": True} if server_gone else {}),
        }, sort_keys=True).encode(),
        strict=True,
    )
    kek = _vault_kek(vault)
    if kek is None:
        raise PermissionError("Turning AI access on requires the master password.")
    # Review 8595ec1: an 'ai off' from another process committed after the
    # read above was overwritten. Read again under the write lock; a brake
    # applied meanwhile wins.
    with db.transaction(immediate=True):
        now = _parse(db.get_meta(ENABLED_KEY), db.get_meta(EPOCH_KEY))
        if now.epoch != current.epoch:
            raise RuntimeError(
                f"AI access was switched off meanwhile (epoch {current.epoch} -> {now.epoch}); "
                "it stays off. Run 'sezam ai on' again to turn it on."
            )
        db.set_meta(ENABLED_KEY, "1")
        db.set_meta(EPOCH_KEY, str(state.epoch))
        db.set_meta(STATE_MAC_KEY, _state_mac(kek, db))
    return state


def _write_audit(vault: "Vault", action: str, detail: dict) -> bool:
    if not vault.is_unlocked:
        return False
    try:
        vault._audit_log(
            action, json.dumps(detail, sort_keys=True).encode(), strict=True
        )
    except Exception:
        logger.warning("Audit record %r queued for the next unlock", action, exc_info=True)
        return False
    return True


def _pending(db: VaultDB) -> list:
    try:
        value = db.get_meta_json(PENDING_AUDIT_KEY)
    except ValueError:
        value = None
    return value if isinstance(value, list) else []


def flush_pending_audit(vault: "Vault") -> None:
    """Write kill switch audit records queued while the vault was locked."""
    db = vault.db
    pending = _pending(db)
    if not pending:
        return
    written = []
    for record in pending:
        detail = dict(record.get("detail") or {}, recorded_at_unlock=True)
        if _write_audit(vault, str(record.get("action")), detail):
            written.append(record)
    # Capability review run 470: the brake appends to this queue without the
    # vault lock (db.brake), so an 'ai off' from another process may have
    # landed since the read above. Remove only what was written, under the
    # write lock the brake's append also takes.
    with db.transaction(immediate=True):
        remaining = _pending(db)
        for record in written:
            if record in remaining:
                remaining.remove(record)
        if remaining:
            db.set_meta_json(PENDING_AUDIT_KEY, remaining)
        else:
            db.execute("DELETE FROM vault_meta WHERE key = ?", (PENDING_AUDIT_KEY,))
