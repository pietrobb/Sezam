"""Stateful test finding SM55: a dropped re-key left a folder under the revoked key.

The laptop made a subfolder in a folder shared with a member and pushed it;
its name is sealed with the folder's DEK. Both devices of the admin removed
the member. The laptop's re-key sealed the subfolder's name again with its
new DEK, one version above the server's; the phone had not pulled the
subfolder and its re-key landed first without it. The laptop's batch was
refused, the pull bound the folder to the phone's DEK, and dropping the
superseded batch took the subfolder for "dirty only because its folder moved
to a new DEK": it was never sent again, and the server kept its name under
the DEK the removed member holds.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rebase_review8 import (
    _assert_member_cut_off,
    _folder_shared_with_member,
    _server_object,
)


def test_a_superseded_rekey_still_sends_the_folder_it_resealed(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    laptop_client = _client(laptop, url)
    sub = laptop.create_node("Sub", parent_id=folder)
    laptop_client.push()

    assert laptop.rekey_after_revocation(member_id) == 1
    assert phone.rekey_after_revocation(member_id) == 1
    assert _client(phone, url).push()["conflicts"] == []
    phone_dek = _assert_member_cut_off(db, phone, folder, old_dek_id, member_id)

    laptop_client.push()
    laptop_client.push()
    assert pending_states.rekey_batch(laptop.db) == {}
    sealed = bytes_to_ulid(parse_envelope(bytes(_server_object(db, sub)["payload"])).dek_id)
    assert sealed != old_dek_id, "the subfolder's name stayed under the removed member's key"
    assert sealed == phone_dek
    _client(phone, url).pull()
    assert phone.db.fetchone("SELECT version FROM nodes WHERE id = ?", (sub,))["version"] == 2
    laptop.lock()
    phone.lock()
