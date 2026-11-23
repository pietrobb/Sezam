"""SQLite database management for local vault.

WAL mode, atomic writes (write to tmp → rename for backups).
"""

from __future__ import annotations

import itertools
import json
import os
import sqlite3
import threading
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, Iterator, Optional

from . import oplock
from .inuse import InUseLock
from .schema import (
    BASE_VERSION_TRIGGERS_SQL,
    SCHEMA_SQL,
    SCHEMA_VERSION,
    SYNC_CONFLICTS_SQL,
    row_payload_hash,
)


class VaultSchemaTooNew(RuntimeError):
    """The vault was written by a newer Sezam (review 526419e N3)."""


class VaultChangedElsewhere(RuntimeError):
    """Another process changed the vault's keys or account after this one opened it."""


class IdentityChangedElsewhere(VaultChangedElsewhere):
    """Another process bound the vault to another account id or keypair."""


# What a process loads at unlock and keeps in memory: the KEK, the keypair and
# its wrap, the account id, the key epoch and the server. A change of any of
# them gives the vault a new generation (docs/DESIGN_TEAM_LOG.md §8, H10).
GENERATION_META = "vault_generation"
GENERATION_KEYS = frozenset({
    "kek_dek_id", "argon2_salt", "argon2_params", "encrypted_keypair",
    "signing_pk", "encryption_pk", "user_id", "key_epoch", "server_url",
})

# INV-6 (docs/ROOT_CAUSE_PLAN.md, R15-P5): a push in one process read the
# outbox, sent it and cleared what it sent while another process queued rows
# and rewrote vault_meta keys (only four outbox kinds checked the lock). Every
# write to these tables is now made by a thread holding the vault lock:
# VaultDB takes it for each write statement and transaction, and TEMP
# triggers refuse one made around VaultDB (its raw connection).
_ORDERED_TABLES = ("outbox", "vault_meta")
# The AI kill switch (ai_access.disable) writes these without waiting for a
# sync: stopping an agent must not wait for the network (VaultDB.brake).
BRAKE_KEYS = frozenset({
    "ai_access_enabled", "ai_access_epoch", "ai_access_mac", "ai_access_audit_pending",
})


def _order_triggers_sql() -> str:
    triggers = []
    for table in _ORDERED_TABLES:
        for op, keys in (("INSERT", ("NEW",)), ("UPDATE", ("OLD", "NEW")), ("DELETE", ("OLD",))):
            allowed = " AND ".join(
                f"sezam_write_ordered({row + '.key' if table == 'vault_meta' else 'NULL'})"
                for row in keys
            )
            triggers.append(
                f"CREATE TEMP TRIGGER IF NOT EXISTS inv6_{table}_{op.lower()} "
                f"BEFORE {op} ON main.{table} WHEN NOT ({allowed}) BEGIN "
                f"SELECT RAISE(ABORT, 'INV-6: {table} written without the vault lock'); END;"
            )
    return "\n".join(triggers)


def check_vault_schema(value: Optional[str]) -> None:
    """Refuse a vault of a schema this version does not know.

    Opening it anyway would read tables it misunderstands and write rows a
    newer Sezam then misreads. A vault without the key predates it (1).
    """
    try:
        version = int(value) if value else 1
    except ValueError:
        version = None
    if version is None or version > SCHEMA_VERSION:
        raise VaultSchemaTooNew(
            f"This vault has schema version {value}, this Sezam knows up to "
            f"{SCHEMA_VERSION}. Update Sezam to open it; nothing was changed."
        )


# vault_meta keys that held operations waiting for the server before they
# became outbox rows (docs/SYNC_SINGLE_SOURCE.md 3.4).
_PENDING_META_KEYS = (
    "pending_key_rotation", "pending_rekey_batch", "queued_revocations",
    "org_recovery_server_pending", "org_recovery_rewrap_pending", "pending_server_reseed",
    "pending_bootstrap_keypair_upload", "team_log_pending", "team_log_set_aside",
    "team_log_grants", "lost_envelope_withdrawals", "revived_folders",
)

# Triggers older versions kept on nodes and entries (d14d368: the object_base_*
# side tables; the first outbox: the base capture on is_dirty).
_LEGACY_ROW_TRIGGERS = (
    "nodes_base_insert", "nodes_base_clean", "nodes_base_delete", "nodes_base_capture",
    "entries_base_insert", "entries_base_clean", "entries_base_delete", "entries_base_capture",
    "base_hash_reset", "outbox_base_capture",
)


def _has_pending_meta(conn: sqlite3.Connection) -> bool:
    marks = ",".join("?" * len(_PENDING_META_KEYS))
    return conn.execute(
        f"SELECT 1 FROM vault_meta WHERE key IN ({marks})", _PENDING_META_KEYS
    ).fetchone() is not None


def _move_pending_meta(conn: sqlite3.Connection) -> None:
    """Queue the pending operations of a vault from before as outbox rows."""
    meta = {
        key: value for key, value in conn.execute(
            f"SELECT key, value FROM vault_meta WHERE key IN ({','.join('?' * len(_PENDING_META_KEYS))})",
            _PENDING_META_KEYS,
        )
    }

    def loads(key: str) -> Any:
        return json.loads(meta[key]) if meta.get(key) else None

    def dumps(value: Any) -> Optional[str]:
        return None if value is None else json.dumps(value, separators=(",", ":"))

    rows: list[tuple[str, Optional[str], Optional[str], str]] = []
    for key, kind in (("pending_key_rotation", "key_change"), ("pending_rekey_batch", "rekey")):
        if loads(key):
            rows.append((kind, "", dumps(loads(key)), "queued"))
    rows += [("revoke", user_id, None, "queued") for user_id in loads("queued_revocations") or []]
    for key, name in (("org_recovery_server_pending", "registration"),
                      ("org_recovery_rewrap_pending", "rewrap")):
        if loads(key) is not None:
            rows.append(("org_recovery", name, dumps(loads(key)), "queued"))
    if meta.get("pending_server_reseed"):
        rows.append(("reseed", "", dumps(meta["pending_server_reseed"]), "queued"))
    if meta.get("pending_bootstrap_keypair_upload"):
        rows.append(("bootstrap", "", None, "queued"))
    rows += [("team_change", None, dumps(c), "queued") for c in loads("team_log_pending") or []]
    rows += [("team_change", None, dumps(i), "refused") for i in loads("team_log_set_aside") or []]
    rows += [("team_grant", e, dumps(c), "queued") for e, c in (loads("team_log_grants") or {}).items()]
    rows += [("withdrawal", e, dumps(r), "held")
             for e, r in (loads("lost_envelope_withdrawals") or {}).items()]
    conn.executemany(
        "INSERT OR IGNORE INTO outbox (kind, object_id, body, state) VALUES (?, ?, ?, ?)", rows
    )
    conn.executemany("DELETE FROM vault_meta WHERE key = ?", [(k,) for k in _PENDING_META_KEYS])


class VaultDB:
    """SQLite database wrapper for sezam.db."""

    def __init__(self, path: str | Path, *, hold_in_use: bool = True):
        self.path = Path(path)
        self._conn: Optional[sqlite3.Connection] = None
        # Shared "in use" lock while open, so a snapshot restore cannot
        # replace the file under this process (lockout review M7).
        self._in_use = InUseLock(self.path) if hold_in_use else None
        self._savepoints = itertools.count(1)
        # The connection is shared across threads (check_same_thread=False).
        # Closing it while another thread is inside a statement crashes the
        # process (access violation), and lock() may come from any thread
        # (idle lock, 'sezam lock', ai_off) while e.g. the remote policy
        # poller writes. Statements and close() therefore take turns.
        self._guard = threading.RLock()
        self._txn_held = False  # the guard is held once more for an open transaction
        # Generations this connection may see: the one it pinned and the ones
        # it wrote itself (a rolled-back write leaves the pinned one stored).
        self._generations: set[Optional[str]] = set()
        self._txn_lock = None  # the vault lock held for the open transaction
        self._txn_owner: Optional[int] = None  # the thread whose transaction holds it
        self._local = threading.local()  # .brake: depth of brake() in this thread

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not open")
        return self._conn

    def open(self) -> None:
        """Open database connection with WAL mode."""
        if self._in_use is not None:
            self._in_use.acquire(exclusive=False, timeout=10.0)
        try:
            self._restrict_permissions()
            self._conn = sqlite3.connect(
                str(self.path),
                # Autocommit: every statement commits on its own. Multi-statement
                # writes must use begin()/commit() or transaction().
                isolation_level=None,
                check_same_thread=False,  # Vault unlocked in worker thread, used in main
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.create_function(
                "sezam_payload_hash", 2, row_payload_hash, deterministic=True
            )
            self._conn.create_function("sezam_write_ordered", 1, self._write_ordered)
            self._check_schema()
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._restrict_permissions()
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SYNC_CONFLICTS_SQL)
            if self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'entries'"
            ).fetchone():
                self._upgrade_sync_columns()
                self._conn.executescript(BASE_VERSION_TRIGGERS_SQL)
            self._guard_writes()
            self.pin_generation()
        except BaseException:
            self.close()
            raise

    def _upgrade_sync_columns(self, locked: bool = False) -> None:
        """A vault from before docs/SYNC_SINGLE_SOURCE.md points 1 and 3.

        Its rows lack the base pair and mark unsent changes with ``is_dirty``;
        unsent envelopes and audit records are kept in side tables, pending
        account-level operations in vault_meta (_move_pending_meta). Flagged
        rows get a queued write before the outbox trigger exists, so the base
        already on the row stays (the trigger would take the edited row as its
        own base); then the flag column and the side tables go.
        """
        conn = self._conn

        def columns(table: str) -> set[str]:
            return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

        def has_table(name: str) -> bool:
            return conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
            ).fetchone() is not None

        def meta(key: str):
            row = conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
            return None if row is None else row[0]

        tables = {table: columns(table) for table in ("nodes", "entries")}
        outbox_columns = columns("outbox")
        legacy_base = has_table("object_base_version")
        if (
            all("base_hash" in c and "is_dirty" not in c for c in tables.values())
            and {"state", "body"} <= outbox_columns
            and not legacy_base
            and not has_table("object_base_hash")
            and not has_table("envelope_sync_state")
            and not has_table("audit_sync_state")
            and not _has_pending_meta(conn)
            and meta("schema_version") == str(SCHEMA_VERSION)
        ):
            return
        if not locked:  # INV-6: it rewrites the outbox and vault_meta; looked at again once held
            with oplock.exclusive(self.path):
                return self._upgrade_sync_columns(locked=True)
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Every trigger an older version made on these rows (d14d368, the
            # public release, kept the base in object_base_* by triggers that
            # read is_dirty: review 782dde8 R12 #1). The current ones are
            # created again after the upgrade.
            for trigger in _LEGACY_ROW_TRIGGERS:
                conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            if "state" not in outbox_columns:
                conn.execute("ALTER TABLE outbox ADD COLUMN state TEXT NOT NULL DEFAULT 'queued'")
            if "body" not in outbox_columns:
                conn.execute("ALTER TABLE outbox ADD COLUMN body TEXT")
            revived_meta = meta("revived_folders")
            _move_pending_meta(conn)
            for table, have in tables.items():
                for column, kind in (("base_version", "INTEGER"), ("base_hash", "TEXT")):
                    if column not in have:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
                if "is_dirty" in have:
                    if legacy_base:
                        # The server copy an unsent row was made on: its
                        # version, and its payload hash where it was recorded
                        # for that version.
                        base = (
                            "(SELECT version FROM object_base_version "
                            f"WHERE object_id = {table}.id)"
                        )
                        digest = (
                            "(SELECT payload_hash FROM object_base_hash "
                            f"WHERE object_id = {table}.id AND version = {base})"
                            if has_table("object_base_hash") else "NULL"
                        )
                        conn.execute(
                            f"UPDATE {table} SET base_version = {base}, base_hash = {digest} "
                            "WHERE is_dirty = 1"
                        )
                    conn.execute(
                        "INSERT OR IGNORE INTO outbox (kind, object_id) "
                        f"SELECT 'write', id FROM {table} WHERE is_dirty = 1 ORDER BY id"
                    )
                    conn.execute(f"ALTER TABLE {table} DROP COLUMN is_dirty")
            conn.execute("DROP TABLE IF EXISTS object_base_version")
            conn.execute("DROP TABLE IF EXISTS object_base_hash")
            if has_table("envelope_sync_state"):
                if not meta("envelope_sync_state_seeded"):
                    # Older still: what another account made came from the server.
                    conn.execute(
                        "INSERT OR IGNORE INTO envelope_sync_state (envelope_id) "
                        "SELECT id FROM access_envelopes WHERE created_by <> ?",
                        (meta("user_id") or "",),
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO outbox (kind, object_id) "
                    "SELECT 'envelope', id FROM access_envelopes WHERE id NOT IN "
                    "(SELECT envelope_id FROM envelope_sync_state) ORDER BY id"
                )
                conn.execute("DROP TABLE envelope_sync_state")
                conn.execute("DELETE FROM vault_meta WHERE key = 'envelope_sync_state_seeded'")
            if has_table("audit_sync_state"):
                # sync_status: none or 0 unsent, 2 another account's record to
                # send again, 1 sent, -1 quarantined.
                conn.execute(
                    "INSERT OR IGNORE INTO outbox (kind, object_id, state) "
                    "SELECT 'audit', a.id, CASE WHEN s.sync_status = -1 "
                    "THEN 'refused' ELSE 'queued' END FROM audit_log a "
                    "LEFT JOIN audit_sync_state s ON s.audit_id = a.id "
                    "WHERE COALESCE(s.sync_status, 0) <> 1 ORDER BY a.timestamp, a.id"
                )
                conn.execute("DROP TABLE audit_sync_state")
            revived = json.loads(revived_meta or "[]")
            conn.executemany(
                "UPDATE outbox SET body = '{\"revived\":true}' WHERE kind = 'write' AND object_id = ?",
                [(folder,) for folder in revived],
            )
            # R16-L7: an older version that knows only 1 now refuses the
            # vault instead of failing on the is_dirty it expects.
            conn.execute(
                "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def _restrict_permissions(self) -> None:
        """Owner-only vault directory and database files (POSIX).

        Review d615826: the vault directory and sezam.db were created with the
        umask (usually world-readable), so any local user could copy the
        wrapped keys for offline password guessing. A new sezam.db is created
        0600 before SQLite opens it (its -wal/-shm take the same mode), and an
        existing vault of this user is tightened on open.
        """
        if os.name == "nt":
            return  # the user profile's ACL applies
        directory = self.path.parent
        if directory.stat().st_uid == os.getuid():
            directory.chmod(0o700)
        if not self.path.exists():
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        for path in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            try:
                info = path.stat()
            except FileNotFoundError:
                continue
            if info.st_uid == os.getuid() and info.st_mode & 0o077:
                path.chmod(0o600)

    def _check_schema(self) -> None:
        """Before anything is written (review 526419e N3); a new file has no table."""
        try:
            row = self._conn.execute(
                "SELECT value FROM vault_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.OperationalError:
            return
        check_vault_schema(row[0] if row else None)

    def close(self) -> None:
        """Close database connection."""
        with self._guard:
            if self._conn:
                self._conn.close()
                self._conn = None
            self._settle_transaction()
            if self._in_use is not None:
                self._in_use.release()

    def create_schema(self) -> None:
        """Create all tables and indexes."""
        self.conn.executescript(SCHEMA_SQL)
        self._guard_writes()
        self.set_meta("schema_version", str(SCHEMA_VERSION))

    def _guard_writes(self) -> None:
        """INV-6: the outbox and vault_meta refuse a write without the vault
        lock (this connection only; TEMP)."""
        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if set(_ORDERED_TABLES) <= tables:
            self._conn.executescript(_order_triggers_sql())

    def _write_ordered(self, key: Optional[str]) -> bool:
        return oplock.held_here(self.path) or (key in BRAKE_KEYS and self._braking())

    def _braking(self) -> bool:
        return getattr(self._local, "brake", 0) > 0

    @contextmanager
    def brake(self) -> Iterator[None]:
        """The AI kill switch writes BRAKE_KEYS in this thread without the
        vault lock, so 'sezam ai off' never waits for a sync; nothing else."""
        depth = getattr(self._local, "brake", 0)
        self._local.brake = depth + 1
        try:
            yield
        finally:
            self._local.brake = depth

    def in_own_transaction(self) -> bool:
        """This thread has a transaction open (it keeps the write lock to its end)."""
        return self._txn_owner == threading.get_ident()

    def _ordered(self, sql: str):
        """INV-6: the vault lock for a statement that writes, taken before
        the statement guard (the order every holder takes them in)."""
        if self._txn_owner == threading.get_ident() or self._braking():
            return nullcontext()  # this thread's transaction holds it (or the brake)
        if sql.lstrip()[:6].upper() in ("SELECT", "PRAGMA"):
            return nullcontext()
        return oplock.exclusive(self.path, implicit=True)

    def exists(self) -> bool:
        """Check if database file exists."""
        return self.path.exists()

    # -- vault_meta helpers --

    def get_meta(self, key: str) -> Optional[str]:
        row = self.fetchone("SELECT value FROM vault_meta WHERE key = ?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        if key not in GENERATION_KEYS:
            self._write_meta(key, value)
            return
        with self.transaction():
            if self.get_meta(key) == value:
                return
            self.require_generation()
            self._write_meta(key, value)
            from ..models import new_ulid

            generation = new_ulid()
            self._write_meta(GENERATION_META, generation)
            self._generations.add(generation)

    def _write_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )

    def _stored_generation(self) -> Optional[str]:
        try:
            return self.get_meta(GENERATION_META)
        except sqlite3.OperationalError:  # a new file before create_schema
            return None

    def pin_generation(self) -> None:
        """Take the vault's current generation as the one this process loaded."""
        self._generations = {self._stored_generation()}

    def require_generation(self) -> None:
        """Review a159e97 H10: the GUI or 'mcp-serve' stayed unlocked while
        another process changed the password, the keypair, the account id, the
        key epoch or the server. What it then wrote or synced used the state
        it had loaded: DEKs under a dead KEK, audit under a dead id, pushes to
        the old server. A process whose generation is no longer the vault's
        writes none of that."""
        if self._stored_generation() not in self._generations:
            raise VaultChangedElsewhere(
                "Another Sezam program changed this vault's password, keys, account "
                "or server; lock the vault and unlock it again."
            )

    def get_meta_json(self, key: str) -> Any:
        raw = self.get_meta(key)
        return json.loads(raw) if raw else None

    def set_meta_json(self, key: str, value: Any) -> None:
        self.set_meta(key, json.dumps(value, separators=(",", ":")))

    # -- Generic query helpers --

    def _check_held(self) -> None:
        # A marker cleared while this process slept: stop writing (review 526419e S1).
        if self._in_use is not None:
            self._in_use.ensure_held()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._ordered(sql), self._guard:
            self._check_held()
            try:
                return self.conn.execute(sql, params)
            finally:
                self._settle_transaction()

    def executemany(self, sql: str, params_list: list[tuple]) -> sqlite3.Cursor:
        with self._ordered(sql), self._guard:
            self._check_held()
            try:
                return self.conn.executemany(sql, params_list)
            finally:
                self._settle_transaction()

    def _settle_transaction(self) -> None:
        """Review 1141a20 M-AI3: an open transaction (BEGIN, begin(), a
        savepoint) belongs to the thread that opened it. It keeps the guard
        until COMMIT/ROLLBACK, so no other thread's statement runs inside it
        and is committed or undone with it. Called with the guard held.

        INV-6: it keeps the vault lock too (the statement that opened it
        holds it already, unless it is the kill switch's)."""
        open_now = self._conn is not None and self._conn.in_transaction
        if open_now and not self._txn_held:
            self._guard.acquire()
            self._txn_held = True
            if not self._braking():
                lock = oplock.exclusive(self.path, implicit=True)
                lock.__enter__()
                self._txn_lock, self._txn_owner = lock, threading.get_ident()
        elif not open_now and self._txn_held:
            self._txn_held = False
            lock, self._txn_lock, self._txn_owner = self._txn_lock, None, None
            try:
                if lock is not None:
                    lock.__exit__(None, None, None)
            finally:
                self._guard.release()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        with self._guard:
            return self.conn.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._guard:
            return self.conn.execute(sql, params).fetchall()

    def begin(self) -> None:
        self.execute("BEGIN")

    def commit(self) -> None:
        self.execute("COMMIT")

    def rollback(self) -> None:
        self.execute("ROLLBACK")

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[None]:
        """All-or-nothing block; nests inside an outer BEGIN via SAVEPOINT.

        ``immediate``: a block that reads and then writes takes the write
        lock first (BEGIN IMMEDIATE, waiting up to busy_timeout). Otherwise
        a commit of another connection between its read and its write
        fails the write at once, which busy_timeout does not retry.

        Review 1141a20 M-AI3: the block holds the statement guard to its end.
        The connection is shared, so another thread's statements ran inside
        this transaction (or nested a savepoint into it) and were undone with
        it."""
        with self._ordered("SAVEPOINT"), self._guard:
            with self._transaction(immediate):
                yield

    @contextmanager
    def _transaction(self, immediate: bool) -> Iterator[None]:
        if immediate and not self.conn.in_transaction:
            self.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self.execute("ROLLBACK")
                raise
            self.execute("COMMIT")
            return
        name = f"sp_{next(self._savepoints)}"
        self.execute(f"SAVEPOINT {name}")
        try:
            yield
        except BaseException:
            self.execute(f"ROLLBACK TO {name}")
            self.execute(f"RELEASE {name}")
            raise
        self.execute(f"RELEASE {name}")

    # -- Backup (atomic write: copy to tmp → rename) --

    def backup(self, dest_path: str | Path) -> None:
        """Create an atomic backup of the database."""
        from ..securefile import private_temp_path, publish
        from .ai_access import off_in_copy

        dest = Path(dest_path)
        tmp = private_temp_path(dest)
        try:
            backup_conn = sqlite3.connect(str(tmp))
            try:
                with self._guard:
                    self.conn.backup(backup_conn)
                off_in_copy(backup_conn)
            finally:
                backup_conn.close()
            publish(tmp, dest)
        except Exception:
            if tmp.exists():
                tmp.unlink()
            raise

    def integrity_check(self) -> bool:
        """Run SQLite integrity check."""
        result = self.fetchone("PRAGMA integrity_check")
        return result[0] == "ok"
