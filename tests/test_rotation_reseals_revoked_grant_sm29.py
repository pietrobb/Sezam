"""Stateful test finding SM29: a rotation re-sealed a grant for a removed member.

The laptop shared a folder with Bob. The phone removed him, but its re-key
did not reach the server yet, so Bob's envelope was still live there and on
the laptop. The laptop then rotated its identity: the rotation re-seals every
envelope it made, Bob's included. The server refuses a live envelope for a
revoked user, and with it the whole atomic rotation, on every sync. The
refused envelope now stays local and the rotation goes out without it.
"""

from __future__ import annotations

import pytest

from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live, _status
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rotation_goes_out_without_the_envelope_of_a_removed_member(
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

    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(phone, phone_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert _status(db, bob_id) == "revoked"
    assert (pending_states.rekey_batch(phone.db) or None)

    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    laptop_client = _client(laptop, url)
    result = laptop_client.push()
    assert not laptop_client.has_pending_key_change(), result

    # The phone takes the rotated keys over, as after any change made elsewhere.
    with pytest.raises(KeyEpochStale):
        phone_client.push()
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    phone_client = _client(phone, url)
    revocation.push_with_queued_revocations(phone, phone_client)
    assert not (pending_states.rekey_batch(phone.db) or None)
    assert not _bob_envelopes_live(db, bob_id)
    laptop_client.pull()
    assert {e["name"] for e in laptop.list_entries(folder)} == {"vpn"}
    laptop.lock()
    phone.lock()
