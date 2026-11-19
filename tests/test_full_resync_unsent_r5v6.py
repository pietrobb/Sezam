"""Review d150605 #6: a full resync after a 410 dropped what was never sent.

The laptop worked offline (a new entry, a new folder, an edit) while tombstone
GC moved the server's floor past its checkpoint. The next pull said 410 and
the full resync replaced everything with the server's snapshot: the offline
work was gone (the server had never seen it, so nothing marked it "ahead").
The CLI did not offer a push, and --export-dirty wrote ciphertext objects
without their keys that nothing could read or load back.
"""

from __future__ import annotations

import sqlite3

from click.testing import CliRunner

from sezam import cli
from sezam.vault.crud import Vault
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _gc_tombstones,
    _vault,
    server,
)


def _offline_work_then_gc(url, db, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    db01 = laptop.create_entry(
        folder, "db01", [{"key": "password", "value": "old", "sensitive": True}]
    )
    gone = laptop.create_entry(folder, "gone", [{"key": "k", "value": "v"}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    # Another device deletes something; 90 days later GC collects it.
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone.delete_entry(gone)
    assert _client(phone, url).push()["conflicts"] == []
    phone.lock()
    _gc_tombstones(db)

    # Meanwhile the laptop worked offline.
    laptop.create_entry(folder, "db02", [{"key": "password", "value": "new", "sensitive": True}])
    other = laptop.create_node("Offline")
    laptop.create_entry(other, "vpn", [{"key": "password", "value": "vpn", "sensitive": True}])
    laptop.update_entry(db01, fields=[{"key": "password", "value": "edited", "sensitive": True}])
    return laptop


def _assert_all_there(vault) -> None:
    assert _entry_value(vault, "Servers", "db02", "password") == "new"
    assert _entry_value(vault, "Offline", "vpn", "password") == "vpn"
    assert _entry_value(vault, "Servers", "db01", "password") == "edited"


def test_full_resync_after_410_keeps_and_sends_offline_work(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _offline_work_then_gc(url, db, tmp_path)
    client = _client(laptop, url)

    result = client.full_resync(confirmed=True)
    assert result["kept_local"] == 4  # db02, Offline, vpn, edited db01
    _assert_all_there(laptop)
    assert client.push()["conflicts"] == []
    laptop.lock()

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    _assert_all_there(tablet)
    assert _entry_value(tablet, "Servers", "gone", "k") is None
    tablet.lock()


def test_offline_entry_in_a_folder_deleted_elsewhere_reaches_the_server(server, tmp_path):  # noqa: F811
    """Capability review run 100: the folder's tombstone is still on the server.

    The full resync kept the offline entry but overwrote its folder as deleted,
    and the server's parent check refused the entry on every push.
    """
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Shared")
    laptop.create_entry(folder, "x", [{"key": "k", "value": "v"}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    other = phone.create_node("Other")
    gone = phone.create_entry(other, "gone", [{"key": "k", "value": "v"}])
    assert _client(phone, url).push()["conflicts"] == []
    phone.delete_entry(gone)
    assert _client(phone, url).push()["conflicts"] == []
    _gc_tombstones(db)
    phone.delete_node(folder)  # above the floor: its tombstone stays
    assert _client(phone, url).push()["conflicts"] == []
    phone.lock()

    laptop.create_entry(folder, "offline", [{"key": "password", "value": "kept", "sensitive": True}])
    client = _client(laptop, url)
    client.full_resync(confirmed=True)
    assert client.push()["conflicts"] == []
    assert client.push()["conflicts"] == []
    assert _entry_value(laptop, "Shared", "offline", "password") == "kept"
    laptop.lock()

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert _entry_value(tablet, "Shared", "offline", "password") == "kept"
    tablet.lock()


def test_an_ordinary_pull_of_the_folder_tombstone_keeps_the_offline_entry(server, tmp_path):  # noqa: F811
    """The same without a 410: the pulled tombstone buried the unsent entry."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Shared")
    sub = laptop.create_node("Sub", parent_id=folder)
    laptop.create_entry(sub, "x", [{"key": "k", "value": "v"}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone.delete_node(folder)
    assert _client(phone, url).push()["conflicts"] == []
    phone.lock()

    laptop.create_entry(sub, "offline", [{"key": "password", "value": "kept", "sensitive": True}])
    client = _client(laptop, url)
    client.pull()
    assert client.push()["conflicts"] == []
    assert client.push()["conflicts"] == []
    laptop.lock()

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    shared = next(n for n in tablet.list_nodes() if n["name"] == "Shared")
    [restored] = tablet.list_nodes(shared["id"])
    assert restored["name"] == "Sub"
    assert [e["name"] for e in tablet.list_entries(restored["id"])] == ["offline"]
    tablet.lock()


def test_export_dirty_is_an_encrypted_vault_copy_that_opens(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _offline_work_then_gc(url, db, tmp_path)
    export = tmp_path / "before-resync" / "sezam.db"
    export.parent.mkdir()

    result = _client(laptop, url).full_resync(confirmed=True, dirty_export_path=export)
    assert result["dirty_exported"] >= 4
    laptop.lock()

    conn = sqlite3.connect(export)
    assert conn.execute("SELECT count(*) FROM entries").fetchone()[0] >= 3
    conn.close()
    copy = Vault(export.parent)
    copy.unlock(PASSWORD)
    _assert_all_there(copy)
    copy.lock()


def test_cli_full_resync_offers_to_push_what_it_kept(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _offline_work_then_gc(url, db, tmp_path)
    monkeypatch.setattr(cli, "_open_vault", lambda: laptop)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault: None)
    monkeypatch.setattr(laptop, "lock", lambda: None)

    # Confirm the resync, accept the push.
    result = CliRunner().invoke(cli.main, ["pull", "--full-resync"], input="y\ny\n")
    assert result.exit_code == 0, result.output
    assert "are kept and sent with the next push" in result.output
    assert "Push them to the server now?" in result.output
    assert "accepted, 0 conflict(s)" in result.output  # with the new folder's DEK

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    _assert_all_there(tablet)
    tablet.lock()
