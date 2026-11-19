"""Stateful test finding SM5: a full resync emptied what went to the trash offline.

A full resync keeps what this device never sent (review d150605 #6), except
a delete of something the server no longer has. An entry created offline in
a folder that was then deleted (still offline) counted as such a delete,
although the server never had it: the resync dropped it and it was gone from
the trash on every device. Now only a delete of something the server had
and lost (GC'd) is dropped; the rest goes out as a tombstone and stays in
the trash.
"""

from __future__ import annotations

from sezam.vault.trash import list_trash
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_lost_update_base_version_sm1 import _two_devices, _vault_reader


def _trashed_entries(vault) -> int:
    return sum(item.get("entries", 0) for item in list_trash(vault) if item["type"] == "folder")


def test_an_entry_created_and_deleted_offline_stays_in_the_trash(server, tmp_path):
    url, _db = server
    laptop, phone, _entry_id = _two_devices(url, tmp_path)
    folder = next(n["id"] for n in phone.list_nodes() if n["name"] == "Servers")

    phone.create_entry(folder, "offline-note", [{"key": "password", "value": "x", "sensitive": True}])
    phone.delete_node(folder)
    assert _trashed_entries(phone) == 2

    phone_client = _client(phone, url)
    assert phone_client.full_resync_blocker() is None
    phone_client.full_resync(confirmed=True)
    assert _trashed_entries(phone) == 2

    pushed = phone_client.push()
    assert pushed["accepted"] and not pushed["conflicts"]
    assert _trashed_entries(_vault_reader(url, tmp_path)) == 2
    laptop.lock()
    phone.lock()
