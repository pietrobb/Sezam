"""Lockout review 2026-11-08, medium finding M2: no trash, no undo.

A delete kept tombstones, but nothing could bring them back: deleting a
folder threw away its whole subtree for good, entry_history was written but
never read, and a bulk delete left no copy of the database. Deleted entries
and folders can now be listed and restored (CLI ``sezam trash``, GUI
"Restore Deleted…"), earlier entry versions listed, shown and restored
(``sezam history``), and a folder delete takes a vault snapshot first.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault import outbox
from sezam.vault.snapshots import list_snapshots
from sezam.vault.trash import (
    TrashError,
    list_history,
    list_trash,
    read_history,
    restore_entry,
    restore_history,
    restore_node,
)
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


def _value(vault, path: str, key: str):
    entry = vault.find_entry_by_path(path)
    if entry is None:
        return None
    return next(f["value"] for f in entry["fields"] if f["key"] == key)


@pytest.fixture
def vault(tmp_path):
    v = _vault(tmp_path / "v", "admin")
    yield v
    v.lock()


def _tree(vault):
    ops = vault.create_node("Ops")
    sub = vault.create_node("Sub", ops)
    vault.create_entry(ops, "vpn", [{"key": "password", "value": "v1", "sensitive": True}])
    vault.create_entry(sub, "db", [{"key": "password", "value": "d1"}])
    return ops, sub


def test_deleted_entry_is_listed_and_restored(vault):
    ops, _sub = _tree(vault)
    entry = vault.find_entry_by_path("Ops/vpn")["id"]
    vault.delete_entry(entry)
    assert vault.find_entry_by_path("Ops/vpn") is None

    listed = list_trash(vault)
    assert [(i["id"], i["type"], i["name"], i["path"]) for i in listed] == [
        (entry, "entry", "vpn", "Ops")
    ]
    restore_entry(vault, entry)
    assert _value(vault, "Ops/vpn", "password") == "v1"
    assert list_trash(vault) == []
    # Searchable again, and the restore is a new version to sync.
    assert any(r["entry_id"] == entry for r in vault.search("vpn"))
    assert outbox.has_write(vault.db, entry)


def test_deleted_folder_subtree_is_restored_whole(vault):
    ops, sub = _tree(vault)
    vault.delete_node(ops)
    assert vault.find_entry_by_path("Ops/Sub/db") is None

    listed = list_trash(vault)
    assert [(i["id"], i["type"], i["entries"]) for i in listed] == [(ops, "folder", 2)]
    assert restore_node(vault, ops) == 2
    assert _value(vault, "Ops/vpn", "password") == "v1"
    assert _value(vault, "Ops/Sub/db", "password") == "d1"
    assert list_trash(vault) == []


def test_folder_delete_takes_a_vault_snapshot_first(vault):
    ops, _sub = _tree(vault)
    before = {s.name for s in list_snapshots(vault.db.path.parent)}
    vault.delete_node(ops)
    taken = [s for s in list_snapshots(vault.db.path.parent) if s.name not in before]
    assert [s.reason for s in taken] == ["delete-folder"]


def test_entry_in_a_deleted_folder_is_restored_with_the_folder(vault):
    _ops, sub = _tree(vault)
    entry = vault.find_entry_by_path("Ops/Sub/db")["id"]
    vault.delete_node(sub)
    with pytest.raises(TrashError):
        restore_entry(vault, entry)
    with pytest.raises(KeyError):
        restore_entry(vault, "01HZZZZZZZZZZZZZZZZZZZZZZZ")


def test_history_versions_are_readable_and_restorable(vault):
    _tree(vault)
    entry = vault.find_entry_by_path("Ops/vpn")["id"]
    vault.update_entry(entry, fields=[{"key": "password", "value": "v2"}])
    vault.update_entry(entry, fields=[{"key": "password", "value": "v3"}])

    versions = list_history(vault, entry)
    assert len(versions) == 2
    oldest = versions[-1]["id"]
    assert read_history(vault, entry, oldest)[0]["value"] == "v1"

    restore_history(vault, entry, oldest)
    assert _value(vault, "Ops/vpn", "password") == "v1"
    # The replaced version is not lost either.
    newest = list_history(vault, entry)[0]["id"]
    assert read_history(vault, entry, newest)[0]["value"] == "v3"


def test_cli_trash_and_history(vault, monkeypatch):
    ops, _sub = _tree(vault)
    entry = vault.find_entry_by_path("Ops/vpn")["id"]
    vault.update_entry(entry, fields=[{"key": "password", "value": "v2", "sensitive": True}])
    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_unlock_vault", lambda v, *a, **k: None)
    monkeypatch.setattr(vault, "lock", lambda: None)
    runner = CliRunner()

    listed = runner.invoke(cli.main, ["history", "Ops/vpn"])
    assert listed.exit_code == 0, listed.output
    version_id = list_history(vault, entry)[0]["id"]
    assert version_id in listed.output
    shown = runner.invoke(cli.main, ["history", "Ops/vpn", "--show", version_id])
    assert shown.exit_code == 0 and "password: ****" in shown.output
    restored = runner.invoke(cli.main, ["history", "Ops/vpn", "--restore", version_id])
    assert restored.exit_code == 0, restored.output
    assert _value(vault, "Ops/vpn", "password") == "v1"

    vault.delete_node(ops)
    trash = runner.invoke(cli.main, ["trash"])
    assert trash.exit_code == 0 and ops in trash.output and "Ops" in trash.output
    back = runner.invoke(cli.main, ["trash", "restore", ops])
    assert back.exit_code == 0, back.output
    assert _value(vault, "Ops/Sub/db", "password") == "d1"
    missing = runner.invoke(cli.main, ["trash", "restore", ops])
    assert missing.exit_code != 0


def test_restore_syncs_and_works_on_a_device_that_only_pulled_the_delete(
    server, tmp_path  # noqa: F811
):
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    ops, _sub = _tree(laptop)
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    try:
        cli._server_connect_flow(url, phone, PASSWORD)
        assert _value(phone, "Ops/Sub/db", "password") == "d1"

        laptop.delete_node(ops)
        assert _client(laptop, url).push()["conflicts"] == []
        _client(phone, url).pull()
        assert phone.find_entry_by_path("Ops/Sub/db") is None

        # The phone never deleted anything itself, it only has the tombstones.
        assert restore_node(phone, ops) == 2
        assert _client(phone, url).push()["conflicts"] == []
        _client(laptop, url).pull()
        assert _value(laptop, "Ops/Sub/db", "password") == "d1"
        assert _value(laptop, "Ops/vpn", "password") == "v1"
        assert list_trash(laptop) == []
    finally:
        phone.lock()
        laptop.lock()
