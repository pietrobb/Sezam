"""Stateful test finding SM24: a grant the restored server lost was dropped by the full resync.

The laptop shared a folder with Bob; the server was then restored from a
backup taken before the grant. The laptop's full resync kept only the
envelopes the server returned (or of a DEK the server lost), so Bob's
envelope was deleted and he lost the folder for good. A grant of this
account the server does not hold now stays and goes out again, while its
folder key does: when it was never sent, or when the server went back.
"""

from __future__ import annotations

import copy

from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices, sees_rollback


def test_full_resync_sends_again_a_grant_the_restored_server_lost(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    backup = copy.deepcopy(db._storage)

    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    _restore(db, backup)
    assert not _bob_envelopes_live(db, bob_id)

    assert sees_rollback(laptop_client)
    laptop_client.full_resync(confirmed=True)
    assert not laptop_client.push()["conflicts"]
    assert sees_rollback(phone_client)
    phone_client.full_resync(confirmed=True)
    assert not phone_client.push()["conflicts"]

    dek_id = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert [o["parent_ref"] for o in _bob_envelopes_live(db, bob_id)] == [dek_id]
    for device in (laptop, phone):
        assert device.db.fetchone(
            "SELECT 1 FROM access_envelopes WHERE user_id = ? AND dek_id = ?", (bob_id, dek_id)
        )
        device.lock()
