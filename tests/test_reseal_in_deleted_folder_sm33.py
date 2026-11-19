"""Stateful test finding SM33: a resealed write in a folder deleted elsewhere never left.

The laptop shared a folder with Bob, then deleted it. The phone, which had
not seen either, created an entry in it and removed Bob (re-keying nothing,
SM23). The laptop's push re-keyed the folder and sent the delete. The phone's
pull resealed its entry under the folder's new key (SM28) and marked it
unsent, after the pull had already revived folders holding unsent work: the
entry was refused ('parent folder is deleted') on every push. The reseal now
revives such a folder too.
"""

from __future__ import annotations

from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_resealed_entry_in_a_folder_deleted_elsewhere_goes_out(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    laptop.delete_node(folder)

    entry = phone.create_entry(folder, "new", [{"key": "password", "value": "x", "sensitive": True}])
    assert not phone_client.push()["conflicts"]
    assert revocation.revoke_member(phone, phone_client, bob_id) == 0

    revocation.push_with_queued_revocations(laptop, laptop_client)
    phone_client.pull()
    assert not phone_client.push()["conflicts"]
    assert not phone.db.fetchone("SELECT 1 FROM entries WHERE id = ? AND id IN (SELECT object_id FROM outbox WHERE kind = 'write')", (entry,))
    laptop.lock()
    phone.lock()
