"""Stateful test (second admin, run 60d): a grant lost to a superseded re-key.

The phone shared the folder with Carol and pushed. The laptop, not pulled,
removed Bob and re-keyed the folder from the envelopes it knew of, so the new
key reached Bob's replacement set without Carol (SM62 / run 140: the phone's
pull seals Carol's grant again on the new key). But the phone had removed Bob
too: its own re-key deleted Carol's old envelope locally until the batch was
sent. Its pull then brought that envelope back from the server, counted it as
pulled (someone else's grant, which a pull never seals again: H2), and the
superseded batch was dropped. Carol held only the retired key on every device.
"""

from __future__ import annotations

import time

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_grant_under_rekeyed_key_sm62 import _invite_carol
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_own_grant_survives_a_rekey_superseded_by_another_device(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    carol_id = _invite_carol(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    revocation.grant_member(phone, phone_client, carol_id, folder, confirm_fingerprint=lambda _fp: True)
    assert _bob_envelopes_live(db, carol_id)
    time.sleep(0.005)

    revocation.revoke_member(laptop, laptop_client, bob_id)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert phone.rekey_after_revocation(bob_id) == 1

    for _ in range(3):
        revocation.push_with_queued_revocations(phone, phone_client)
        phone_client.pull()
        laptop_client.push()
        laptop_client.pull()
    assert not (pending_states.rekey_batch(phone.db) or None)
    current = laptop.db.fetchone(
        "SELECT id FROM deks WHERE node_id = ? AND scope = 'folder'", (folder,)
    )["id"]
    assert current in {o["parent_ref"] for o in _bob_envelopes_live(db, carol_id)}, (
        "Carol lost the folder: no envelope on its current key"
    )
    assert not _bob_envelopes_live(db, bob_id)
    laptop.lock()
    phone.lock()
