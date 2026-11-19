"""Review 688edcb, medium findings around identity rotation (#270).

* grant-access to a member who rotated their identity returned the existing
  envelope, sealed for the member's retired key: the member never got the
  folder back. A grant now seals for the member's current key and withdraws
  the dead envelope.
"""

from __future__ import annotations

import shutil

import pytest

from sezam.vault import pending_states
from sezam.crypto.envelope_crypto import open_envelope
from sezam.vault.crud import Vault
from sezam.vault.revocation import grant_member
from sezam.vault.sync_client import KeyEpochStale, SyncClient, TofuKeyChangeError
from tests.test_cross_client_password_change import _web_login
from tests.test_grant_folder_access import _envelopes, _readable_passwords, _yes, team  # noqa: F401
from tests.test_identity_rotation import _hex, _rotate, _user
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401


def test_grant_after_the_members_rotation_seals_for_the_new_key(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    old_id = grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    assert _readable_passwords(_web_login(url, "bob", PASSWORD, {})) == {"vpn": "ops-pw"}

    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    try:
        result = _rotate(bob, monkeypatch)
        assert result.exit_code == 0, result.output
    finally:
        Vault.lock(bob)
    # The old envelope is sealed for a key Bob no longer has.
    assert _readable_passwords(_web_login(url, "bob", PASSWORD, {})) == {}

    # The admin confirms Bob's new key and grants the folder again.
    client = _client(admin, url)
    with pytest.raises(TofuKeyChangeError) as raised:
        client.verified_encryption_pk(bob_id)
    client.confirm_tofu_key_change(raised.value, raised.value.new_fingerprint)
    new_id = grant_member(admin, client, bob_id, folders["Ops"], confirm_fingerprint=_yes)

    assert new_id != old_id
    assert [e["id"] for e in _envelopes(db, bob_id)] == [new_id]
    assert admin.db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (old_id,)) is None
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    assert _readable_passwords(member) == {"vpn": "ops-pw"}
    # A further grant of the same access is a no-op again.
    assert grant_member(admin, client, bob_id, folders["Ops"], confirm_fingerprint=_yes) == new_id
    assert (pending_states.rekey_batch(admin.db) or None) in (None, {})


def test_lost_response_of_own_rotation_is_recognised(team, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    real_request = SyncClient._request

    def lost_reply(self, method, path, body=None, **kwargs):
        resp = real_request(self, method, path, body, **kwargs)
        if path == "/api/sync" and method == "POST" and body and body.get("key_rotation"):
            raise RuntimeError("Network error: connection reset")
        return resp

    monkeypatch.setattr(SyncClient, "_request", lost_reply)
    result = _rotate(admin, monkeypatch)
    assert "server was not updated" in result.output, result.output
    monkeypatch.setattr(SyncClient, "_request", real_request)
    # The server took the rotation; only its answer was lost.
    assert _hex(_user(db, admin_id)["signing_pk"]) == admin.keypair.signing_pk.hex()

    # Before: the login with the retired key got 409 'Identity key rotated'
    # and the device reported keys changed by another device (KeyEpochStale).
    later = _client(admin, url)
    assert later.push()["conflicts"] == []
    assert (pending_states.key_change_journal(admin.db) or None) is None
    assert (pending_states.rekey_batch(admin.db) or None) in (None, {})
    assert _client(admin, url).pull() is not None
    member = _web_login(url, "bob", PASSWORD, {})
    assert _readable_passwords(member) == {"vpn": "ops-pw"}


def test_lost_offline_rotation_sends_no_envelope_under_its_key(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    shutil.copytree(tmp_path / "admin", tmp_path / "admin2")
    other = Vault(tmp_path / "admin2")
    other.unlock(PASSWORD)
    try:
        # The second device rotates offline; the first one rotates online.
        real_push = SyncClient.push
        monkeypatch.setattr(SyncClient, "push", lambda self: (_ for _ in ()).throw(
            RuntimeError("Network error: connection refused")
        ))
        assert "server was not updated" in _rotate(other, monkeypatch).output
        lost_key = other.keypair.encryption_pk
        monkeypatch.setattr(SyncClient, "push", real_push)
        assert _rotate(admin, monkeypatch).exit_code == 0
        winner = admin.keypair

        client = SyncClient(other.db, url, other.keypair, admin_id)
        client.set_dek_manager(other.dek_mgr)
        with pytest.raises(KeyEpochStale):
            client.push()
        client.adopt_rotated_key_material(other, PASSWORD)
        assert other.keypair.signing_pk == winner.signing_pk
        client.pull()
        assert client.push()["conflicts"] == []
        assert (pending_states.rekey_batch(other.db) or None) in (None, {})
        # Every envelope the device holds opens under the account's key.
        for row in other.db.fetchall("SELECT user_id, encrypted_dek FROM access_envelopes"):
            recipient = client.verified_encryption_pk(row["user_id"])
            open_envelope(
                bytes(row["encrypted_dek"]), winner.to_nacl_private_key().encode(), recipient
            )
    finally:
        Vault.lock(other)

    # Nothing sealed with the lost rotation's key reached the server.
    [envelope] = _envelopes(db, bob_id)
    bob_pk = _client(admin, url).verified_encryption_pk(bob_id)
    open_envelope(bytes(envelope["payload"]), winner.to_nacl_private_key().encode(), bob_pk)
    assert lost_key != winner.encryption_pk
    member = _web_login(url, "bob", PASSWORD, {})
    assert _readable_passwords(member) == {"vpn": "ops-pw"}
