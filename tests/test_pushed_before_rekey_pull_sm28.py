"""Stateful test finding SM28: items pushed before the re-key was pulled kept the old key.

The laptop created an entry and a folder in a folder shared with Bob while
the phone removed him and re-keyed it. The laptop pushed before it pulled:
the server took both as new objects, sealed with the DEK Bob holds, and SM26
(unsent items only) never saw them again. After a pull, this device's own
write held by the server under a retired folder DEK is sealed again one
version up and sent as a change.
"""

from __future__ import annotations

from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_unsent_under_rekeyed_folder_sm26 import _sealed_with


def test_own_writes_the_server_took_under_a_retired_key_are_sealed_again(
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
    assert not laptop_client.push()["conflicts"]
    assert _sealed_with(db, entry) == old_dek

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
