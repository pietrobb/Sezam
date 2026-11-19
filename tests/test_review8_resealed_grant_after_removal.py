"""Review a159e97 (state machine, seed 616161): a re-sealed grant outlived the member's removal.

The laptop shared a folder with Bob; the phone rotated the account identity,
which re-seals every grant under a new envelope id. Bob was then revoked by an
admin without the folder key, and the laptop, not having pulled the rotation,
re-keyed the folder and withdrew the one envelope of Bob's it held. The
re-sealed copy came in live on its next pull and nothing named it: Bob kept a
live envelope and every device looked settled. A key this account re-keyed to
remove Bob now queues his re-key when his envelope on it arrives live, and the
next push withdraws it.
"""

from __future__ import annotations

from sezam.vault import pending_states, revocation
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_a_resealed_grant_pulled_after_the_removal_is_withdrawn(
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
    granted = {o["id"] for o in _bob_envelopes_live(db, bob_id)}
    phone_client.pull()

    phone_client.prepare_key_change()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    _client(phone, url).push()
    resealed = {o["id"] for o in _bob_envelopes_live(db, bob_id)}
    assert resealed and not resealed & granted

    # A second admin without the folder key removes Bob: no re-key there.
    next(u for u in db._storage["users"] if u["id"] == bob_id)["status"] = "revoked"
    try:
        _client(laptop, url)
    except KeyEpochStale:
        pass
    laptop_client.adopt_rotated_key_material(laptop, PASSWORD)
    laptop_client = _client(laptop, url)
    # Review 4acfdde R11 #3: the re-key meets the server before its first send,
    # so the pull brings the re-sealed copy in the same push: it is queued and
    # withdrawn there, and the folder re-keyed once is still reported.
    assert revocation.push_with_queued_revocations(laptop, laptop_client)["rekeyed"] == {bob_id: 1}
    assert not _bob_envelopes_live(db, bob_id)

    laptop_client.pull()
    assert not pending_states.pending_states(laptop)
    revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not _bob_envelopes_live(db, bob_id)
    assert not revocation.queued_revocations(laptop)
    laptop.lock()
    phone.lock()
