"""Stateful test finding SM46: no pinned key for a member granted on another device.

The laptop shared a folder with Bob and Carol. The phone (same admin account)
pulled the envelopes but never synced a record of Carol, so it had no pinned
key for her. Removing Bob from the phone re-keys the folder for Carol, and
rotating the phone's identity re-seals her envelope: both failed for good
('Missing verified encryption key'). The phone now takes the server's key for
Carol when it opens the account's own envelope for her - and only then.
"""

from __future__ import annotations

import pytest
from nacl.public import PrivateKey

from sezam.vault import pending_states
from sezam import cli
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _invite(url, admin_client, tmp_path, monkeypatch, name: str) -> str:
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    member = _vault(tmp_path / name, name)
    cli._server_register_and_upload(
        url, member, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    member_id = member.db.get_meta("user_id")
    member.lock()
    admin_client.approve_user(member_id)
    return member_id


def _shared_with_two(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob = _invite(url, laptop_client, tmp_path, monkeypatch, "bob")
    carol = _invite(url, laptop_client, tmp_path, monkeypatch, "carol")
    yes = lambda _fp: True  # noqa: E731
    revocation.grant_member(laptop, laptop_client, bob, folder, confirm_fingerprint=yes)
    revocation.grant_member(laptop, laptop_client, carol, folder, confirm_fingerprint=yes)
    phone_client.pull()
    assert phone.db.fetchone("SELECT 1 FROM known_keys WHERE user_id = ?", (carol,)) is None
    return url, db, laptop, phone, phone_client, bob, carol


def test_rekey_on_the_device_that_did_not_grant(server, tmp_path, monkeypatch):  # noqa: F811
    _url, db, laptop, phone, phone_client, bob, carol = _shared_with_two(server, tmp_path, monkeypatch)
    assert revocation.revoke_member(phone, phone_client, bob) == 1
    assert not (pending_states.rekey_batch(phone.db) or None)
    assert not _bob_envelopes_live(db, bob)
    assert _bob_envelopes_live(db, carol)
    laptop.lock()
    phone.lock()


def test_identity_rotation_on_the_device_that_did_not_grant(server, tmp_path, monkeypatch):  # noqa: F811
    url, db, laptop, phone, phone_client, _bob, carol = _shared_with_two(server, tmp_path, monkeypatch)
    before = {e["id"] for e in _bob_envelopes_live(db, carol)}
    phone_client.prepare_key_change()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    phone_client = _client(phone, url)
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    after = {e["id"] for e in _bob_envelopes_live(db, carol)}
    assert after and after != before  # re-sealed under the rotated key
    laptop.lock()
    phone.lock()


def test_a_key_that_does_not_open_the_envelope_is_not_pinned(server, tmp_path, monkeypatch):  # noqa: F811
    _url, db, laptop, phone, phone_client, bob, carol = _shared_with_two(server, tmp_path, monkeypatch)
    swapped = bytes(PrivateKey.generate().public_key)
    real = phone_client.verified_encryption_pk

    def server_swapped_carols_key(user_id):
        pinned = real(user_id)  # pins what the server said
        return swapped if user_id == carol else pinned

    monkeypatch.setattr(phone_client, "verified_encryption_pk", server_swapped_carols_key)
    with pytest.raises(revocation.RekeyPending):
        revocation.revoke_member(phone, phone_client, bob)
    assert phone.db.fetchone("SELECT 1 FROM known_keys WHERE user_id = ?", (carol,)) is None
    laptop.lock()
    phone.lock()
