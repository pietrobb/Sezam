"""Stateful test finding SM59: a folder revived elsewhere comes back under its own DEK.

The laptop deleted a folder and the server collected the tombstone; the
laptop's full resync then held the folder's DEK (the server keeps it, its
parent_ref still naming the folder) but no folder, so the DEK was unbound.
The phone, which had added an entry to the folder meanwhile, brought the
folder back. The laptop pulled it with no DEK naming it and bound it to its
parent's (the root DEK): the phone's entry did not open there, and a member
the folder was shared with seemed to have lost it. The unbound DEK now
remembers its folder and takes it back when the folder returns.
"""

from __future__ import annotations

from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def test_folder_revived_elsewhere_is_bound_to_its_own_dek(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "old", [{"key": "k", "value": "v"}])
    laptop_client.push()
    phone_client.pull()
    own_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]

    laptop.delete_node(folder)
    laptop_client.push()
    _gc(db)
    assert laptop_client.full_resync(confirmed=True)["full_resync"]
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (folder,)) is None

    entry = phone.create_entry(folder, "vpn", [{"key": "password", "value": "f-pw", "sensitive": True}])
    phone_client.push()
    assert phone_client.full_resync(confirmed=True)["full_resync"]
    phone_client.push()
    assert not phone.db.fetchone("SELECT 1 FROM entries WHERE id = ? AND id IN (SELECT object_id FROM outbox WHERE kind = 'write')", (entry,))
    laptop_client.pull()

    assert laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == own_dek
    assert "f-pw" in str(laptop.read_entry(entry))
    laptop.lock()
    phone.lock()
