"""Stateful test finding SM57: SM54 with a folder shared with a member.

The phone rotated its identity key while the account had shared a folder with
Bob, so the rotation re-sealed Bob's envelope (the outbox ``rekey`` row with
``identity_rotation``). The push failed; the laptop meanwhile shared another
folder with Bob (its envelope sealed with the old key) and the server
collected a tombstone past the phone's checkpoint. The rotation needs the new DEK, the
pull for it was a 410, and the full resync stayed refused for the re-sealed
envelopes, naming 'sezam abandon-rekey', which refuses an identity rotation:
the phone could never sync again. The resync now goes through and the rotation
re-seals the envelopes the server has, the laptop's included.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam import cli
from sezam.crypto.envelope_crypto import open_envelope
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once
from tests.test_tombstone_gc_orphans_r5k1 import _gc

import pytest


def test_identity_rotation_with_shared_folder_goes_out_after_the_server_compacted(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    doomed = laptop.create_entry(folder, "old", [{"key": "k", "value": "v"}])
    laptop_client.push()

    invitation = laptop_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    bob_sk = bytes(bob.keypair.encryption_sk)
    bob.lock()
    laptop_client.approve_user(bob_id)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    phone_client.prepare_key_change()
    phone.change_password(PASSWORD, "phone-pw-sm57!", rotate_identity=True)
    new_encryption_pk = bytes(phone._keypair.encryption_pk)
    phone_client = _client(phone, url)
    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        phone_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(phone.db) or None)

    other = laptop.create_node("G", parent_id=laptop.db.get_meta("root_node_id"))
    entry = laptop.create_entry(other, "vpn", [{"key": "password", "value": "g-pw", "sensitive": True}])
    laptop.delete_entry(doomed)
    laptop_client.push()
    revocation.grant_member(laptop, laptop_client, bob_id, other, confirm_fingerprint=lambda _fp: True)
    _gc(db)

    with pytest.raises(RuntimeError, match="full resync"):
        phone_client.push()
    assert phone_client.full_resync_blocker() is None
    assert phone_client.full_resync(confirmed=True)["full_resync"]
    assert "g-pw" in str(phone.read_entry(entry))
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    assert not (pending_states.rekey_batch(phone.db) or None)

    envelopes = [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and not o.get("is_deleted")
        and o.get("target_user_id") == bob_id
    ]
    assert len(envelopes) == 2  # both folders, the one the laptop shared after the rotation too
    for envelope in envelopes:
        open_envelope(bytes(envelope["payload"]), bob_sk, new_encryption_pk)
    laptop.lock()
    phone.lock()
