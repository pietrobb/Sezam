"""Stateful test finding SM88: an entry moved out of a superseded re-key's folder.

Both devices of the admin removed the member from a shared folder; the
phone's re-key landed first. Before its own push the laptop moved an entry
of that folder into a subfolder with its own key, sealing it with that key.
The laptop's batch was refused as superseded and dropped; the move went out
on top of the phone's re-key, but sealed again with the server copy's key
(the folder's new key) while the entry now lives in the subfolder. No device
could open it there ('Decryption failed').
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rebase_review8 import (
    _assert_member_cut_off,
    _folder_shared_with_member,
    _server_entry_dek,
)


def _dek_of(vault, node_id):
    return vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))["dek_id"]


def test_entry_moved_out_before_a_superseded_rekey_stays_under_its_new_folder(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    laptop_client = _client(laptop, url)
    sub = laptop.create_node("Sub", parent_id=folder)
    laptop_client.push()
    _client(phone, url).pull()
    sub_dek = _dek_of(laptop, sub)
    assert sub_dek != old_dek_id

    assert laptop.rekey_after_revocation(member_id) == 1
    assert phone.rekey_after_revocation(member_id) == 1
    assert _client(phone, url).push()["conflicts"] == []
    _assert_member_cut_off(db, phone, folder, old_dek_id, member_id)

    laptop.move_entry(entry, sub)
    laptop_client.push()
    laptop_client.push()
    assert pending_states.rekey_batch(laptop.db) == {}

    assert _server_entry_dek(db, entry) == sub_dek, "the moved entry went out under its old folder's key"
    meta = bytes(laptop.db.fetchone("SELECT encrypted_meta FROM entries WHERE id = ?", (entry,))[0])
    assert bytes_to_ulid(parse_envelope(meta).dek_id) == sub_dek
    assert laptop.read_entry(entry)["name"] == "vpn"
    _client(phone, url).pull()
    row = phone.db.fetchone("SELECT node_id FROM entries WHERE id = ?", (entry,))
    assert row["node_id"] == sub
    assert phone.read_entry(entry)["name"] == "vpn"
    laptop.lock()
    phone.lock()
