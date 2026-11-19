"""Review 526419e #1: a push was never split, so one large push blocked sync for good.

The server takes at most 1000 objects / 16 MiB per request and 1 MiB per
object (server/app/models/schemas.py). The desktop sent every dirty object
in one request: an import of 600 entries (1200+ objects), a long offline
stretch of audit records or a single note over 1 MiB got a 422 on every
sync, nothing was marked pushed, and connect still said the data was synced.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault import crud, sync_limits
from sezam.vault.sync_limits import SyncUnitTooLarge
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)


def _server_ids(db, object_type: str) -> set[str]:
    return {
        o["id"] for o in db._storage.get("vault_objects", [])
        if o["object_type"] == object_type
    }


def test_connect_pushes_an_import_of_600_entries(server, tmp_path, capsys):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Import")
    entry_ids = {
        laptop.create_entry(folder, f"e{i}", [{"key": "password", "value": f"pw{i}"}])
        for i in range(600)
    }
    cli._server_connect_flow(url, laptop, PASSWORD)
    out = capsys.readouterr()
    assert entry_ids <= _server_ids(db, "entry")
    assert len(_server_ids(db, "audit")) >= 600
    assert "Data boli synchronizovane" in out.out
    assert not laptop.db.fetchone("SELECT id FROM entries WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")
    laptop.lock()


def test_offline_audit_records_do_not_block_an_edit(server, tmp_path):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    entry_id = laptop.create_entry(folder, "db01", [{"key": "password", "value": "old"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    for _ in range(1022):  # every offline read writes an audit record
        laptop.read_entry(entry_id)
    laptop.update_entry(entry_id, fields=[{"key": "password", "value": "new"}])

    result = _client(laptop, url).push()
    assert not result["conflicts"]
    stored = next(o for o in db._storage["vault_objects"] if o["id"] == entry_id)
    assert stored["version"] == 2
    laptop.lock()


def test_pushes_over_16_mib_are_split_by_bytes(server, tmp_path):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Notes")
    note = "x" * (900 * 1024)
    entry_ids = {
        laptop.create_entry(folder, f"n{i}", [{"key": "note", "value": note}])
        for i in range(20)  # ~18 MiB of payload
    }
    cli._server_connect_flow(url, laptop, PASSWORD)
    assert entry_ids <= _server_ids(db, "entry")
    laptop.lock()


def test_an_entry_over_1_mib_is_refused_when_saved(tmp_path):
    vault = _vault(tmp_path / "v", "admin")
    folder = vault.create_node("Notes")
    big = [{"key": "note", "value": "x" * (1100 * 1024)}]
    with pytest.raises(SyncUnitTooLarge, match="at most"):
        vault.create_entry(folder, "big", big)
    assert not vault.db.fetchone("SELECT id FROM entries")
    entry_id = vault.create_entry(folder, "small", [{"key": "note", "value": "ok"}])
    with pytest.raises(SyncUnitTooLarge):
        vault.update_entry(entry_id, fields=big)
    assert vault.get_field_value(entry_id, "note") == "ok"
    vault.lock()


def test_a_stored_oversized_entry_does_not_block_the_rest(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    folder = laptop.create_node("Notes")
    # An entry saved before the check existed.
    monkeypatch.setattr(crud, "require_syncable_entry", lambda *_: None)
    big_id = laptop.create_entry(folder, "big", [{"key": "note", "value": "x" * (1100 * 1024)}])
    monkeypatch.undo()
    small_id = laptop.create_entry(folder, "small", [{"key": "note", "value": "ok"}])

    result = _client(laptop, url).push()
    assert small_id in _server_ids(db, "entry")
    assert big_id not in _server_ids(db, "entry")
    assert [c["id"] for c in result["conflicts"]] == [big_id]
    assert "1 MiB" in result["conflicts"][0]["error"]
    laptop.lock()


def test_an_atomic_unit_over_the_limit_is_refused_before_the_change(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    for name in ("A", "B", "C"):
        laptop.create_node(name)
    cli._server_connect_flow(url, laptop, PASSWORD)
    epoch = laptop.db.get_meta("key_epoch")
    monkeypatch.setattr(sync_limits, "MAX_STAGED_OBJECTS", 2)
    with pytest.raises(SyncUnitTooLarge, match="one unit"):
        laptop.change_password(PASSWORD, "another-password-1!")
    assert laptop.db.get_meta("key_epoch") == epoch
    laptop.lock()
