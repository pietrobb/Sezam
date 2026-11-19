"""Stateful test finding SM36: an identity rotation that landed with its reply lost.

The laptop shared a folder with Bob and rotated its identity. The rotation
re-seals Bob's envelope as a new one and goes out as one atomic batch; the
server took it, but the reply never came. The next pull brought the re-sealed
envelope back, so it counted as held by the server and was no longer
collected, while the pending batch still required it: 'Atomic re-key batch is
missing 1 local object(s)' on every sync. An envelope the server holds is not
missing from the batch.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rotation_whose_reply_was_lost_closes_after_a_pull(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    before = {o["id"] for o in _bob_envelopes_live(db, bob_id)}

    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    laptop_client = _client(laptop, url)
    undo = _fail_once(laptop_client, "POST", "/api/sync", "after")
    try:
        laptop_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(laptop.db) or None)
    resealed = {o["id"] for o in _bob_envelopes_live(db, bob_id)}
    assert resealed and not resealed & before  # the rotation is on the server

    laptop_client.pull()
    laptop_client.push()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert not laptop_client.has_pending_key_change()
    assert {o["id"] for o in _bob_envelopes_live(db, bob_id)} == resealed
    laptop.lock()
    phone.lock()
