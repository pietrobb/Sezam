"""Sync redesign S3 (docs/SYNC_SINGLE_SOURCE.md point 3): the outbox.

What waits for the server is a row in ``outbox`` with a send order, not a flag
on the data row. The data row carries no ``is_dirty``; a local change queues a
write (once per object, keeping its place), the push sends writes in outbox
order and an accepted write leaves the outbox in the same transaction that
moves the row's base.
"""

from __future__ import annotations

import sqlite3

from sezam import cli
from sezam.vault import oplock, outbox, pending_states
from sezam.vault.db import VaultDB
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)


def _queue(db) -> list[str]:
    return [
        r["object_id"]
        for r in db.fetchall("SELECT object_id FROM outbox WHERE kind = 'write' ORDER BY seq")
    ]


def test_rows_carry_no_dirty_flag(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    for table in ("nodes", "entries"):
        columns = {r["name"] for r in vault.db.fetchall(f"PRAGMA table_info({table})")}
        assert "is_dirty" not in columns
    vault.lock()


def test_a_change_queues_one_write_that_keeps_its_place(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    root = vault.db.get_meta("root_node_id")
    first = vault.create_node("First")
    second = vault.create_node("Second")
    entry = vault.create_entry(first, "db01", [{"key": "password", "value": "v1"}])
    assert _queue(vault.db) == [root, first, second, entry]

    # Edited again before it was sent: still one write, at its first place.
    vault.rename_node(first, "First again")
    vault.update_entry(entry, fields=[{"key": "password", "value": "v2"}])
    assert _queue(vault.db) == [root, first, second, entry]
    vault.lock()


def test_push_sends_in_outbox_order_and_empties_it(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    assert _queue(laptop.db) == []

    folder = laptop.create_node("Servers")
    entry = laptop.create_entry(folder, "db01", [{"key": "password", "value": "v1"}])
    laptop.rename_node(folder, "Servers 2")  # stays before the entry
    client = _client(laptop, url)
    sent: list[list[str]] = []
    real_request = client._request

    def request(method, path, body=None, *args, **kwargs):
        if method == "POST" and path == "/api/sync":
            sent.append([o["id"] for o in body["objects"] if o["id"] in {folder, entry}])
        return real_request(method, path, body, *args, **kwargs)

    client._request = request
    client.push()
    assert [ids for ids in sent if ids] == [[folder, entry]]
    assert _queue(laptop.db) == []
    # Accepted: the pushed copy is the base now.
    row = laptop.db.fetchone("SELECT version FROM nodes WHERE id = ?", (folder,))
    assert client._base(folder)[0] == row["version"]
    laptop.lock()


def test_a_vault_with_dirty_flags_moves_them_into_the_outbox(server, tmp_path):  # noqa: F811
    """A vault from before the outbox: its unsent rows are sent, on their own base."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    folder = laptop.create_node("Servers")
    other = laptop.create_node("Other")
    _client(laptop, url).push()
    laptop.rename_node(folder, "Servers, unsent")
    base = _client(laptop, url)._base(folder)
    path = laptop.db.path
    laptop.lock()

    # Back to the old format: a flag on the row, the old capture trigger.
    conn = sqlite3.connect(path)
    conn.executescript(
        "DROP TRIGGER outbox_base_capture;"
        "ALTER TABLE nodes ADD COLUMN is_dirty INTEGER NOT NULL DEFAULT 1;"
        "ALTER TABLE entries ADD COLUMN is_dirty INTEGER NOT NULL DEFAULT 1;"
        "UPDATE nodes SET is_dirty = id IN (SELECT object_id FROM outbox WHERE kind = 'write');"
        "UPDATE entries SET is_dirty = id IN (SELECT object_id FROM outbox WHERE kind = 'write');"
        "DELETE FROM outbox WHERE kind = 'write';"
        "CREATE TRIGGER nodes_base_capture AFTER UPDATE OF is_dirty ON nodes "
        "WHEN OLD.is_dirty = 0 AND NEW.is_dirty = 1 BEGIN "
        "UPDATE nodes SET base_version = OLD.version WHERE id = NEW.id; END;"
    )
    conn.commit()
    conn.close()

    db = VaultDB(path)
    db.open()
    try:
        assert _queue(db) == [folder]
        for table in ("nodes", "entries"):
            columns = {r["name"] for r in db.fetchall(f"PRAGMA table_info({table})")}
            assert "is_dirty" not in columns
        row = db.fetchone("SELECT base_version, base_hash FROM nodes WHERE id = ?", (folder,))
        assert (row["base_version"], row["base_hash"]) == base
        assert not outbox.has_write(db, other)
    finally:
        db.close()


def test_envelope_and_audit_push_state_moves_into_the_outbox(server, tmp_path):  # noqa: F811
    """S3 part 2: unsent envelopes and audit records are outbox rows too."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    _client(laptop, url).push()
    assert laptop.db.fetchall("SELECT kind FROM outbox") == []
    path = laptop.db.path
    laptop.lock()

    # The old side tables: audit 0 = unsent, 1 = sent, 2 = another account's
    # to send again, -1 = quarantined; an envelope not listed is unsent.
    audit = ["A1", "A2", "A3", "A4"]
    envelopes = ["E1", "E2"]
    conn = sqlite3.connect(path)
    conn.executescript(
        "DROP TRIGGER audit_queue; DROP TRIGGER envelope_queue;"
        "CREATE TABLE audit_sync_state (audit_id TEXT PRIMARY KEY, sync_status INTEGER);"
        "CREATE TABLE envelope_sync_state (envelope_id TEXT PRIMARY KEY);"
        "INSERT INTO vault_meta (key, value) VALUES ('envelope_sync_state_seeded', '1');"
    )
    conn.executemany(
        "INSERT INTO audit_log (id, parent_ids, actor_id, action, encrypted_details, "
        "timestamp, signature) VALUES (?, '[]', 'u', 'x', NULL, ?, X'00')",
        [(a, i) for i, a in enumerate(audit)],
    )
    conn.executemany(
        "INSERT INTO access_envelopes (id, dek_id, user_id, created_by, access_level, "
        "encrypted_dek) VALUES (?, 'D', 'u', 'u', 'read', X'00')",
        [(e,) for e in envelopes],
    )
    conn.executemany(
        "INSERT INTO audit_sync_state VALUES (?, ?)",
        [(audit[0], 1), (audit[1], 0), (audit[2], 2), (audit[3], -1)],
    )
    conn.executemany(
        "INSERT INTO envelope_sync_state VALUES (?)", [(e,) for e in envelopes[1:]]
    )
    conn.commit()
    conn.close()

    db = VaultDB(path)
    db.open()
    try:
        rows = {
            (r["kind"], r["object_id"]): r["state"]
            for r in db.fetchall("SELECT kind, object_id, state FROM outbox")
        }
        expected = {("audit", a): "queued" for a in audit[1:]}
        expected[("audit", audit[3])] = "refused"
        expected[("envelope", envelopes[0])] = "queued"
        assert rows == expected
        assert not db.fetchone(
            "SELECT 1 FROM sqlite_master WHERE name IN ('audit_sync_state', 'envelope_sync_state')"
        )
        assert db.get_meta("envelope_sync_state_seeded") is None
    finally:
        db.close()


def test_a_new_envelope_waits_in_the_outbox_until_the_server_takes_it(server, tmp_path):  # noqa: F811
    """Made locally it is queued; a local copy that goes takes its row along."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    folder = laptop.create_node("Ops")
    _client(laptop, url).push()
    laptop.db.execute(
        "INSERT INTO access_envelopes (id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "SELECT 'E1', dek_id, ?, ?, 'read', X'00' FROM nodes WHERE id = ?",
        (laptop.db.get_meta("user_id"), laptop.db.get_meta("user_id"), folder),
    )
    assert outbox.is_pending(laptop.db, outbox.ENVELOPE, "E1")
    laptop.db.execute("DELETE FROM access_envelopes WHERE id = 'E1'")
    assert not laptop.db.fetchone("SELECT 1 FROM outbox WHERE object_id = 'E1'")
    laptop.lock()


def test_a_pulled_server_copy_drops_nothing_it_did_not_replace(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    folder = laptop.create_node("Mine")
    other = laptop.create_node("Other")
    _client(laptop, url).push()

    laptop.rename_node(folder, "Mine, unsent")
    _client(laptop, url).pull()
    assert outbox.has_write(laptop.db, folder)
    assert not outbox.has_write(laptop.db, other)
    laptop.lock()


def test_pending_operations_move_from_vault_meta_into_the_outbox(server, tmp_path):  # noqa: F811
    """S3 part 2b: account-level operations were JSON in vault_meta (3.4)."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    _client(laptop, url).push()
    path = laptop.db.path
    laptop.lock()

    old = {
        "pending_key_rotation": '{"epoch":2,"proof":"p"}',
        "pending_rekey_batch": '{"object_ids":["o1"],"revoked_user_id":"bob"}',
        "queued_revocations": '["carol","dave"]',
        "org_recovery_server_pending": '{"wrapped_kek":"w"}',
        "org_recovery_rewrap_pending": '{"wrapped_kek":"r"}',
        "pending_server_reseed": f"push {url}",
        "pending_bootstrap_keypair_upload": "1",
        "team_log_pending": '[["member.add",{"user_id":"eve"}],["member.remove",{"user_id":"bob"}]]',
        "team_log_set_aside": '[{"change":["access.set",{"folder":"f"}],"reason":"refused"}]',
        "team_log_grants": '{"E1":[["access.set",{"folder":"g"}]]}',
        "lost_envelope_withdrawals": '{"V1":{"dek_id":"D","user_id":"bob"}}',
    }
    conn = sqlite3.connect(path)
    conn.execute("ALTER TABLE outbox DROP COLUMN body")
    conn.executemany("INSERT INTO vault_meta (key, value) VALUES (?, ?)", old.items())
    folder = conn.execute("SELECT id FROM nodes WHERE is_deleted = 0").fetchone()[0]
    conn.create_function("sezam_payload_hash", 2, lambda *_: None)  # the base trigger's
    conn.execute("INSERT INTO outbox (kind, object_id) VALUES ('write', ?)", (folder,))
    conn.execute("INSERT INTO vault_meta (key, value) VALUES ('revived_folders', ?)", (f'["{folder}"]',))
    conn.commit()
    conn.close()

    from sezam.vault.team_log_local import queued_changes, set_aside_changes

    db = VaultDB(path)
    db.open()
    try:
        assert pending_states.key_change_journal(db) == {"epoch": 2, "proof": "p"}
        assert pending_states.rekey_batch(db) == {"object_ids": ["o1"], "revoked_user_id": "bob"}
        assert pending_states.revocation_queue(db) == ["carol", "dave"]
        assert pending_states.org_recovery_registration(db) == {"wrapped_kek": "w"}
        assert pending_states.org_recovery_rewrap(db) == {"wrapped_kek": "r"}
        assert pending_states.reseed_state(db) == f"push {url}"
        assert pending_states.bootstrap_upload_flag(db)
        assert queued_changes(db) == [["member.add", {"user_id": "eve"}], ["member.remove", {"user_id": "bob"}]]
        assert set_aside_changes(db) == [{"change": ["access.set", {"folder": "f"}], "reason": "refused"}]
        assert dict(outbox.items(db, outbox.TEAM_GRANT)) == {"E1": [["access.set", {"folder": "g"}]]}
        assert outbox.items(db, outbox.WITHDRAWAL, outbox.HELD) == [("V1", {"dek_id": "D", "user_id": "bob"})]
        assert outbox.revived_folders(db) == {folder}
        assert db.get_meta("revived_folders") is None
        marks = ",".join("?" * len(old))
        assert db.fetchall(f"SELECT key FROM vault_meta WHERE key IN ({marks})", tuple(old)) == []
    finally:
        db.close()


def test_a_key_change_waits_as_an_outbox_row_until_its_push(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    _client(laptop, url).push()

    laptop.change_password(PASSWORD, "another-password!")
    assert outbox.has(laptop.db, outbox.KEY_CHANGE)
    assert pending_states.key_change_pending(laptop.db)
    assert laptop.db.get_meta("pending_key_rotation") is None
    _client(laptop, url).push()
    assert not outbox.has(laptop.db, outbox.KEY_CHANGE)
    assert laptop.db.fetchall("SELECT kind FROM outbox") == []
    laptop.lock()


def test_revocations_and_team_changes_keep_queue_order(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    with oplock.exclusive(vault.db.path):  # INV-6
        pending_states.set_revocation_queue(vault.db, ["carol", "bob", "dave"])
    assert pending_states.revocation_queue(vault.db) == ["carol", "bob", "dave"]
    with oplock.exclusive(vault.db.path):  # INV-6
        pending_states.set_revocation_queue(vault.db, ["bob", "dave"])
    assert pending_states.revocation_queue(vault.db) == ["bob", "dave"]

    from sezam.vault.team_log_local import (
        _set_aside, _set_queued_changes, queued_changes, retry_set_aside,
    )
    _set_queued_changes(vault.db, [["a", {}], ["b", {}]])
    _set_aside(vault.db, [{"change": ["c", {}], "reason": "r"}])
    assert queued_changes(vault.db) == [["a", {}], ["b", {}]]
    assert retry_set_aside(vault.db) == 1
    assert queued_changes(vault.db) == [["a", {}], ["b", {}], ["c", {}]]
    vault.lock()


def test_audit_records_go_parents_first_in_queue_order():
    from sezam.vault import outbox
    rows = [
        {"id": "c", "parent_ids": '["p"]'},  # queued before its parent (lost parent queued again)
        {"id": "x", "parent_ids": "[]"},
        {"id": "p", "parent_ids": '["gone"]'},  # parent the server already holds
    ]
    assert [r["id"] for r in outbox.parents_first(rows)] == ["x", "p", "c"]
