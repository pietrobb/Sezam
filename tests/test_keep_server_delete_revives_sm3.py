"""Stateful test finding SM3: keeping another device's folder delete stranded work.

The phone renamed a folder and saved a new entry in it while the laptop
deleted the folder. The rename came back as a conflict; keeping the server
copy deleted the folder on the phone, but the unsent entry stayed live below
it. The server refuses an item below a deleted folder, the phone recorded no
conflict for that, and every sync refused the entry again with no way out.
Resolving now brings the folder back for the unsent work, as a pull does.
"""

from __future__ import annotations

from tests.test_integration_client_server import _client, _entry_value, server  # noqa: F401
from tests.test_lost_update_base_version_sm1 import _two_devices, _vault_reader


def test_keeping_a_folder_delete_does_not_strand_an_entry_saved_in_it(server, tmp_path):
    url, _db = server
    laptop, phone, _entry_id = _two_devices(url, tmp_path)
    folder = next(n["id"] for n in phone.list_nodes() if n["name"] == "Servers")
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)

    laptop.delete_node(folder)
    assert laptop_client.push()["accepted"]
    phone.rename_node(folder, "Servers (phone)")
    phone.create_entry(folder, "db02", [{"key": "password", "value": "new", "sensitive": True}])

    phone_client.push()
    phone_client.pull()
    assert folder in {c["id"] for c in phone_client.get_pull_conflicts()}
    phone_client.resolve_conflict(folder, "server")

    pushed = phone_client.push()
    assert not pushed["conflicts"], pushed["conflicts"]
    assert phone_client.dirty_object_count() == 0
    assert _entry_value(_vault_reader(url, tmp_path), "Servers", "db02", "password") == "new"
    laptop.lock()
    phone.lock()
