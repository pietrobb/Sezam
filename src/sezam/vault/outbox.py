"""The outbox: what waits for the server (docs/SYNC_SINGLE_SOURCE.md point 3).

A folder or entry has an unsent change exactly when it has a ``write`` row
here; the data row carries no flag. Queue a write *before* changing the row:
the outbox trigger takes the row as it is then as the base the edit is made
on (a row that does not exist yet keeps base NULL, never on the server).

An access envelope or audit record is queued (``envelope``/``audit``) by a
trigger when its row is made and leaves the outbox when the server is known
to hold it: a push it went in was accepted, or a pull brought it. An audit
record this device must never send stays as state ``refused``.

Account-level operations carry what is sent in ``body`` (JSON) and are read
and written through pending_states.py and team_log_local.py: one at most of
``key_change``, ``rekey``, ``reseed``, ``bootstrap`` (object_id ``''``), an
``org_recovery`` per ``registration``/``rewrap``, a ``revoke`` per member in
re-key order, a ``team_change`` per queued team-log change (state
``refused``: set aside) and a ``team_grant`` per envelope whose push carries
its team changes.

A ``withdrawal`` (object_id: the envelope, body: its row) is a tombstone of
this account a restored server lost; it stays ``held`` until its member is
revoked, then goes back in for the re-key, which withdraws it again. The
``write`` of a folder kept because it holds unsent work after another
device deleted it carries body ``{"revived": true}`` until it is sent.
"""

import json
from typing import Any, Iterable, Optional

from . import sync_core

WRITE = "write"
ENVELOPE = "envelope"
AUDIT = "audit"
KEY_CHANGE = "key_change"
REKEY = "rekey"
REVOKE = "revoke"
ORG_RECOVERY = "org_recovery"
RESEED = "reseed"
BOOTSTRAP = "bootstrap"
TEAM_CHANGE = "team_change"
TEAM_GRANT = "team_grant"
WITHDRAWAL = "withdrawal"
QUEUED = "queued"
REFUSED = "refused"
HELD = "held"
ONE = ""  # object_id of an operation this vault has at most one of
REVIVED_BODY = '{"revived":true}'  # body of a write that brings a folder back


def _dump(value: Any) -> Optional[str]:
    return None if value is None else json.dumps(value, separators=(",", ":"))


def body(db: Any, kind: str, object_id: str = ONE) -> Any:
    """The body of the ``kind`` operation, None when none is queued."""
    row = db.fetchone(
        "SELECT body FROM outbox WHERE kind = ? AND object_id = ?", (kind, object_id)
    )
    return None if row is None or row["body"] is None else json.loads(row["body"])


def has(db: Any, kind: str, object_id: str = ONE) -> bool:
    return db.fetchone(
        "SELECT 1 FROM outbox WHERE kind = ? AND object_id = ?", (kind, object_id)
    ) is not None


def put(db: Any, kind: str, value: Any = None, object_id: str = ONE, state: str = QUEUED) -> None:
    """Queue the operation; one already queued keeps its place, with this body."""
    db.execute(
        "INSERT INTO outbox (kind, object_id, body, state) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (kind, object_id) DO UPDATE SET body = excluded.body, state = excluded.state",
        (kind, object_id, _dump(value), state),
    )


def items(db: Any, kind: str, state: str = QUEUED) -> list[tuple[Optional[str], Any]]:
    """(object_id, body) of every ``kind`` row in ``state``, in queue order."""
    return [
        (r["object_id"], None if r["body"] is None else json.loads(r["body"]))
        for r in db.fetchall(
            "SELECT object_id, body FROM outbox WHERE kind = ? AND state = ? ORDER BY seq",
            (kind, state),
        )
    ]


def replace_items(
    db: Any, kind: str, new: Iterable[tuple[Optional[str], Any]], state: str = QUEUED
) -> None:
    """The ``kind`` rows in ``state`` are ``new``, queued in that order."""
    rows = [(kind, object_id, _dump(value), state) for object_id, value in new]
    with db.transaction():
        db.execute("DELETE FROM outbox WHERE kind = ? AND state = ?", (kind, state))
        db.executemany(
            "INSERT OR IGNORE INTO outbox (kind, object_id, body, state) VALUES (?, ?, ?, ?)", rows
        )


def pending(kind: str, column: str) -> str:
    """SQL: ``column`` names an object with a queued ``kind`` row."""
    return (
        f"EXISTS (SELECT 1 FROM outbox o WHERE o.kind = '{kind}' "
        f"AND o.object_id = {column} AND o.state = 'queued')"
    )


def parents_first(rows: list) -> list:
    """Audit rows in queue order, but never a record before a queued parent.

    A clock jump or a record the server lost and that was queued again can
    put a child ahead of its parent; sent split over requests, a pull between
    them would see the child without its parent (CI 44293105454).
    """
    refs = [{"id": r["id"], "parent_ids": json.loads(r["parent_ids"])} for r in rows]
    return [rows[i] for i in sync_core.call("parents_first", rows=refs)]


def queue(db: Any, kind: str, object_id: str) -> None:
    db.execute("INSERT OR IGNORE INTO outbox (kind, object_id) VALUES (?, ?)", (kind, object_id))


def requeue(db: Any, kind: str, object_id: str) -> None:
    """Queued again whatever its state was (the server lost it)."""
    db.execute(
        "INSERT INTO outbox (kind, object_id) VALUES (?, ?) "
        "ON CONFLICT (kind, object_id) DO UPDATE SET state = 'queued'",
        (kind, object_id),
    )


def refuse(db: Any, kind: str, object_id: str) -> None:
    db.execute(
        "INSERT INTO outbox (kind, object_id, state) VALUES (?, ?, 'refused') "
        "ON CONFLICT (kind, object_id) DO UPDATE SET state = 'refused'",
        (kind, object_id),
    )


def sent(db: Any, kind: str, object_id: str) -> None:
    """The server holds it: nothing of it waits any more."""
    db.execute("DELETE FROM outbox WHERE kind = ? AND object_id = ?", (kind, object_id))


def restore_envelope(db: Any, item: dict, created_by: Optional[str]) -> None:
    """Put back an envelope a batch that never landed withdrew.

    The batch item says whether it was still unsent then (``unsent``); one the
    server held is not sent again. Batches from before the flag name none.
    """
    if db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (item["id"],)):
        return
    db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            item["id"], item["dek_id"], item["user_id"], created_by,
            item["access_level"], bytes.fromhex(item["encrypted_dek"]),
        ),
    )
    if not item.get("unsent"):
        sent(db, ENVELOPE, item["id"])


def is_pending(db: Any, kind: str, object_id: str) -> bool:
    return db.fetchone(
        "SELECT 1 FROM outbox WHERE kind = ? AND object_id = ? AND state = 'queued'",
        (kind, object_id),
    ) is not None


def queued(alias: str) -> str:
    """SQL: the row ``alias`` has a queued write."""
    return f"EXISTS (SELECT 1 FROM outbox o WHERE o.kind = 'write' AND o.object_id = {alias}.id)"


def not_queued(alias: str) -> str:
    return f"NOT {queued(alias)}"


def queue_write(db: Any, object_id: str) -> None:
    db.execute("INSERT OR IGNORE INTO outbox (kind, object_id) VALUES ('write', ?)", (object_id,))


def queue_writes(db: Any, table: str, where: str, params: tuple = ()) -> None:
    """Queue a write for every row of ``table`` matching ``where``."""
    db.execute(
        f"INSERT OR IGNORE INTO outbox (kind, object_id) SELECT 'write', id FROM {table} "
        f"WHERE {where} ORDER BY id",
        params,
    )


def mark_revived(db: Any, object_id: str) -> None:
    """The queued write brings back a folder deleted elsewhere (SM73)."""
    db.execute(
        "UPDATE outbox SET body = ? WHERE kind = 'write' AND object_id = ?",
        (REVIVED_BODY, object_id),
    )


def revived_folders(db: Any) -> set[str]:
    """Live folders whose queued write brings them back."""
    return {
        r["id"] for r in db.fetchall(
            "SELECT n.id FROM nodes n JOIN outbox o ON o.kind = 'write' AND o.object_id = n.id "
            "WHERE o.body = ? AND n.is_deleted = 0",
            (REVIVED_BODY,),
        )
    }


def drop_write(db: Any, object_id: str) -> None:
    db.execute("DELETE FROM outbox WHERE kind = 'write' AND object_id = ?", (object_id,))


def drop_all_writes(db: Any) -> None:
    db.execute("DELETE FROM outbox WHERE kind = 'write'")


def has_write(db: Any, object_id: str) -> bool:
    return db.fetchone(
        "SELECT 1 FROM outbox WHERE kind = 'write' AND object_id = ?", (object_id,)
    ) is not None


def queued_ids(db: Any, table: str) -> set[str]:
    return {
        r["id"] for r in db.fetchall(f"SELECT t.id FROM {table} t WHERE {queued('t')}")
    }
