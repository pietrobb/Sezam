"""Review d150605 #1: tombstone GC must not leave an item without its folder.

Device A deleted folder F; device B of the same admin, not yet pulled, added
an entry to F and pushed. The server took the live entry below the deleted
folder (no parent check for an admin), and 90 days later GC collected F's
tombstone while the entry lived on. Every new device and every full resync
then died on 'FOREIGN KEY constraint failed', and nobody could see the
orphan to delete it.
"""

from __future__ import annotations

import asyncio

from sezam import cli
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


def _node_id(vault, name: str) -> str:
    return next(n["id"] for n in vault.list_nodes() if n["name"] == name)


def _root_entries(vault) -> dict[str, str]:
    root = vault.db.get_meta("root_node_id")
    return {e["name"]: e["id"] for e in vault.list_entries(root)}


def _gc(db, days: int = 0) -> None:
    from server.app.main import _cleanup_tombstones

    for obj in db._storage["vault_objects"]:
        if obj.get("is_deleted"):
            obj["modified_at"] = 0
    asyncio.run(_cleanup_tombstones(db, days))


def test_server_refuses_a_live_entry_below_a_deleted_folder(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    laptop.create_entry(folder, "old", [{"key": "password", "value": "x", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    laptop.delete_node(folder)
    assert _client(laptop, url).push()["accepted"]

    late = phone.create_entry(
        _node_id(phone, "F"), "late", [{"key": "password", "value": "y", "sensitive": True}]
    )
    result = _client(phone, url).push()
    assert [c["id"] for c in result["conflicts"]] == [late]
    assert "parent folder" in result["conflicts"][0]["error"]
    assert not [o for o in db._storage["vault_objects"] if o["id"] == late]
    laptop.lock()
    phone.lock()


def test_gc_keeps_a_deleted_folder_something_still_hangs_below(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    sub = laptop.create_node("Sub", parent_id=folder)
    laptop.create_entry(sub, "alive", [{"key": "password", "value": "x", "sensitive": True}])
    gone = laptop.create_node("Gone")
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.lock()

    # What an older server let in: F and Sub tombstoned, the entry still live.
    for obj in db._storage["vault_objects"]:
        if obj["id"] in (folder, sub, gone):
            obj["is_deleted"] = 1
    _gc(db)

    ids = {o["id"] for o in db._storage["vault_objects"]}
    assert folder in ids and sub in ids
    assert gone not in ids


def test_new_device_and_full_resync_reattach_an_orphan(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    laptop.create_entry(folder, "orphan", [{"key": "password", "value": "kept", "sensitive": True}])
    keep = laptop.create_node("Keep")
    laptop.create_entry(keep, "web", [{"key": "password", "value": "w", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    # What an older server's GC left: the folder's tombstone collected (the
    # floor raised past it), its entry still live.
    db._storage["vault_objects"] = [
        o for o in db._storage["vault_objects"] if o["id"] != folder
    ]
    counter = db._storage["commit_counter"][0]
    counter["gc_floor_seq"] = counter["next_seq"]
    counter["next_seq"] += 1

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    orphan = _root_entries(phone)["orphan"]
    assert phone.get_field_value(orphan, "password") == "kept"

    assert _client(laptop, url).full_resync(confirmed=True)["full_resync"]
    orphan = _root_entries(laptop)["orphan"]
    assert laptop.get_field_value(orphan, "password") == "kept"
    assert [n["name"] for n in laptop.list_nodes()] == ["Keep"]
    laptop.lock()
    phone.lock()
