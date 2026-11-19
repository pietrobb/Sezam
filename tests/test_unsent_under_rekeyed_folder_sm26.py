"""Stateful test finding SM26: unsent items went out under the key a removed member holds.

The laptop created an entry and a folder in a folder shared with Bob, then
pulled the phone's re-key that removed him, before pushing. Both were still
sealed with the folder's old DEK, which Bob holds, and the server took them
so. Before a push, an unsent item sealed with a retired folder DEK is sealed
again with that folder's current DEK.
"""

from __future__ import annotations

from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _sealed_with(db, object_id: str) -> str:
    obj = next(o for o in db._storage["vault_objects"] if o["id"] == object_id)
    payload = bytes(obj["payload"])
    if obj["object_type"] == "entry":
        payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
    return bytes_to_ulid(parse_envelope(payload).dek_id)


def test_unsent_items_are_sealed_with_the_key_the_rekey_gave_their_folder(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    old_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]

    entry = laptop.create_entry(folder, "new", [{"key": "password", "value": "after", "sensitive": True}])
    sub = laptop.create_node("Sub", parent_id=folder)
    assert revocation.revoke_member(phone, phone_client, bob_id) == 1
    laptop_client.pull()
    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek != old_dek
    assert not laptop_client.push()["conflicts"]

    assert _sealed_with(db, entry) == new_dek
    assert _sealed_with(db, sub) == new_dek
    phone_client.pull()
    assert {e["name"] for e in phone.list_entries(folder)} == {"vpn", "new"}
    assert "after" in str(phone.read_entry(entry))
    laptop.lock()
    phone.lock()
