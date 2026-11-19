"""Idea #11: a leaked identity key can be replaced (sezam rotate-identity).

PATCH /rotate-keys is disabled (it swapped the public keys while the stored
keypair kept the old private ones), so a leaked signing/encryption key had
no way out. The rotation now rides the key-epoch advancing push: new public
keys, the new encrypted keypair, the DEK rewrap, the rotation certificate
(new key) and its authorization (old key) are applied in one server
transaction. The admin's own clients keep verifying what the old key signed
(through the certified archive), a member reads the shared folder again
through an envelope sealed with the new key, and a member who pinned the old
key is warned instead of silently trusting the new one.
"""

from __future__ import annotations

import shutil

import pytest
from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.revocation import grant_member
from sezam.vault.sync_client import KeyEpochStale, SyncClient, TofuKeyChangeError
from tests.test_cross_client_password_change import _web_login
from tests.test_grant_folder_access import _envelopes, _readable_passwords, _yes, team  # noqa: F401
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401


def _user(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


def _hex(value) -> str:
    return value if isinstance(value, str) else bytes(value).hex()


def _rotate(admin: Vault, monkeypatch):
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_get_password", lambda *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)
    return CliRunner().invoke(cli.main, ["rotate-identity"])


def test_rotated_identity_reaches_server_clients_and_members(team, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    [old_envelope] = _envelopes(db, bob_id)
    pinned_browser: dict = {}
    assert _readable_passwords(_web_login(url, "bob", PASSWORD, pinned_browser)) == {
        "vpn": "ops-pw"
    }
    admin_browser: dict = {}
    assert _web_login(url, "admin", PASSWORD, admin_browser)["error"] is None
    old_signing_pk = admin.keypair.signing_pk
    old_epoch = int(admin.db.get_meta("key_epoch"))

    result = _rotate(admin, monkeypatch)
    assert result.exit_code == 0, result.output
    new_keypair = admin.keypair
    assert new_keypair.signing_pk != old_signing_pk
    assert new_keypair.fingerprint in result.output

    # Server: new keys current, old ones archived with the certificate.
    user = _user(db, admin_id)
    assert _hex(user["signing_pk"]) == new_keypair.signing_pk.hex()
    assert _hex(user["encryption_pk"]) == new_keypair.encryption_pk.hex()
    keys = _client(admin, url)._request("GET", f"/api/users/{admin_id}/keys", auth=True)
    assert [a["signing_pk"] for a in keys["archived_keys"]] == [old_signing_pk.hex()]
    assert keys["archived_keys"][0]["successor_signing_pk"] == new_keypair.signing_pk.hex()
    assert int(admin.db.get_meta("key_epoch")) == old_epoch + 1
    assert (pending_states.key_change_journal(admin.db) or None) is None
    assert (pending_states.rekey_batch(admin.db) or None) in (None, {})

    # The envelope was sealed again with the new key; the old one is withdrawn.
    [new_envelope] = _envelopes(db, bob_id)
    assert new_envelope["id"] != old_envelope["id"]
    assert new_envelope["parent_ref"] == old_envelope["parent_ref"]

    # The admin's own desktop pulls everything the old key signed.
    fresh = SyncClient(admin.db, url, admin.keypair, admin_id)
    fresh.set_dek_manager(admin.dek_mgr)
    fresh.pull()
    assert old_signing_pk in fresh._get_signing_pks(admin_id)
    assert fresh.push()["conflicts"] == []

    # The admin on a new browser and on the one that cached the old keypair:
    # the new keypair opens and the records read.
    for browser in ({}, admin_browser):
        web_admin = _web_login(url, "admin", PASSWORD, browser)
        assert web_admin["error"] is None, web_admin
        assert _readable_passwords(web_admin) == {"vpn": "ops-pw", "payroll": "hr-pw"}

    # A member's new browser reads the shared folder through the new envelope.
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    assert _readable_passwords(member) == {"vpn": "ops-pw"}

    # A member who pinned the old key is warned, not silently switched over.
    pinned = _web_login(url, "bob", PASSWORD, pinned_browser)
    assert pinned["error"] == "error.tofu_key_changed", pinned
    assert pinned["entries"] == []


def test_member_desktop_that_pinned_the_old_key_pulls_after_confirming(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    try:
        bob_client = _client(bob, url)
        assert bob_client.pull()["pulled"] > 0
        assert bob.db.fetchone("SELECT 1 FROM known_keys WHERE user_id = ?", (admin_id,))
        old_signing_pk = admin.keypair.signing_pk

        assert _rotate(admin, monkeypatch).exit_code == 0

        # The same process that pinned the old key: warned, then accepted.
        with pytest.raises(TofuKeyChangeError) as raised:
            bob_client.pull()
        change = raised.value
        assert change.user_id == admin_id
        assert change.new_fingerprint == admin.keypair.fingerprint
        bob_client.confirm_tofu_key_change(change, change.new_fingerprint)
        # Records the old key signed (the admin's audit trail) still verify.
        bob_client.pull()
        assert old_signing_pk in bob_client._get_signing_pks(admin_id)
    finally:
        bob.lock()


def test_another_desktop_of_the_account_takes_the_new_identity_over(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    # A second device of the admin account, holding the old keypair.
    shutil.copytree(tmp_path / "admin", tmp_path / "admin2")
    assert _rotate(admin, monkeypatch).exit_code == 0
    other = Vault(tmp_path / "admin2")
    other.unlock(PASSWORD)
    try:
        client = SyncClient(other.db, url, other.keypair, admin_id)
        client.set_dek_manager(other.dek_mgr)
        # Before: a bare 401 the device had no way past.
        with pytest.raises(KeyEpochStale):
            client.pull()
        with pytest.raises(RuntimeError, match="Wrong current account password"):
            client.adopt_rotated_key_material(other, "not the password")
        assert other.keypair.signing_pk != admin.keypair.signing_pk

        client.adopt_rotated_key_material(other, PASSWORD)
        assert other.keypair.signing_pk == admin.keypair.signing_pk
        assert client.pull()["pulled"] >= 0
        assert _entry_value(other, "Ops", "vpn", "password") == "ops-pw"
        assert client.push()["conflicts"] == []
    finally:
        other.lock()
    # The new keypair is the one this vault keeps.
    reopened = Vault(tmp_path / "admin2")
    reopened.unlock(PASSWORD)
    try:
        assert reopened.keypair.signing_pk == admin.keypair.signing_pk
    finally:
        reopened.lock()


def test_rotation_without_the_old_keys_authorization_changes_nothing(
    team, monkeypatch  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    before = dict(_user(db, admin_id))
    real_seal = Vault._seal_identity_rotation

    def forged(self, user_id, old_keypair, new_keypair):
        identity = real_seal(self, user_id, old_keypair, new_keypair)
        identity["authorization_signature"] = new_keypair.to_nacl_signing_key().sign(
            b"not the rotation message"
        ).signature.hex()
        return identity

    monkeypatch.setattr(Vault, "_seal_identity_rotation", forged)
    result = _rotate(admin, monkeypatch)
    assert "server was not updated" in result.output, result.output
    assert "did not authorize" in result.output
    after = _user(db, admin_id)
    assert _hex(after["signing_pk"]) == _hex(before["signing_pk"])
    assert _hex(after["encrypted_keypair"]) == _hex(before["encrypted_keypair"])
    assert not db._storage.get("user_key_archives")


def test_offline_rotation_is_sent_by_a_later_push(team, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    old_signing_pk = admin.keypair.signing_pk
    real_push = SyncClient.push

    def offline_push(self):
        raise RuntimeError("Network error: connection refused")

    monkeypatch.setattr(SyncClient, "push", offline_push)
    result = _rotate(admin, monkeypatch)
    assert "server was not updated" in result.output, result.output
    assert _hex(_user(db, admin_id)["signing_pk"]) == old_signing_pk.hex()

    # A new process: the server still knows only the old key, which the
    # journal keeps for the login; the push then lands the rotation.
    monkeypatch.setattr(SyncClient, "push", real_push)
    later = _client(admin, url)
    assert old_signing_pk in later._get_signing_pks(admin_id)
    later.push()
    assert _hex(_user(db, admin_id)["signing_pk"]) == admin.keypair.signing_pk.hex()
    assert (pending_states.key_change_journal(admin.db) or None) is None
    # Logging in now works with the new key alone.
    assert _client(admin, url).token
    web_admin = _web_login(url, "admin", PASSWORD, {})
    assert web_admin["error"] is None, web_admin


def test_patch_rotate_keys_stays_disabled(team):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    with pytest.raises(RuntimeError, match="410"):
        admin_client._request(
            "PATCH", f"/api/users/{admin.db.get_meta('user_id')}/rotate-keys", {}, auth=True
        )
