"""Stateful test finding SM37: a re-key rebase dropped an edit without a conflict.

The laptop shared a folder with Bob and edited one of its entries. The phone,
which had not seen the grant, removed Bob and moved that entry into a
subfolder with its own key. The laptop's re-key took the entry along; refused,
it was rebased: the server copy, now sealed with the subfolder's key, was
taken over and the laptop's edit was gone without a conflict. The entry now
leaves the batch and stays a conflict with the server copy.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_rekey_rebase_keeps_an_edit_of_an_entry_moved_under_another_key(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    sub = laptop.create_node("Sub", parent_id=folder)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    phone_client.pull()
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)

    assert revocation.revoke_member(phone, phone_client, bob_id) == 0
    laptop.update_entry(entry, name="vpn-laptop")
    phone.move_entry(entry, sub)
    assert not phone_client.push()["conflicts"]

    revocation.push_with_queued_revocations(laptop, laptop_client)
    laptop_client.pull()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert not _bob_envelopes_live(db, bob_id)
    assert entry in {c["id"] for c in laptop_client.get_pull_conflicts()}
    assert laptop.read_entry(entry)["name"] == "vpn-laptop"
    laptop.lock()
    phone.lock()
