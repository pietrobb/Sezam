"""Stateful test finding SM8: an edit sent again after tombstone GC never reached the deleter.

The laptop deleted an entry (tombstone at version 2) and GC collected the
tombstone. The phone had edited the same entry offline (also version 2,
on top of version 1) and sent it: the server, no longer holding the
tombstone, took it. The laptop still held its own tombstone at version 2,
took the different version 2 for equivocation and kept the entry deleted
while every other device showed it. A server that still held the tombstone
would have refused the edit; serving it proves the tombstone was collected,
so it is a revival.
"""

from __future__ import annotations

from sezam import cli
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _root_entries(vault) -> dict[str, dict]:
    root = vault.db.get_meta("root_node_id")
    return {e["id"]: e for e in vault.list_entries(root)}


def test_an_edit_sent_after_gc_reaches_the_device_that_deleted(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    entry = laptop.create_entry(
        laptop.db.get_meta("root_node_id"), "E", [{"key": "password", "value": "1", "sensitive": True}]
    )
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    laptop_client = _client(laptop, url)
    phone_client = _client(phone, url)

    laptop.delete_entry(entry)
    assert laptop_client.push()["accepted"]
    laptop_client.pull()
    _gc(db)
    assert not [o for o in db._storage["vault_objects"] if o["id"] == entry]

    phone.update_entry(entry, name="edited")
    result = phone_client.push()
    assert entry in [a["id"] for a in result["accepted"]], result

    pulled = laptop_client.pull()
    assert not pulled.get("equivocations"), pulled
    assert _root_entries(laptop)[entry]["name"] == "edited"
    laptop.lock()
    phone.lock()
