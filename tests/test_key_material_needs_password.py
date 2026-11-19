"""Review 688edcb K1: a stolen identity key must not take the account over.

Every key-epoch advance (password change, rotate-identity) replaced the
account's key material on the strength of a challenge signed by the identity
key alone. Whoever stole the keypair - the very case rotate-identity exists
for - could set their own password and keys, and the owner's correct
password stopped working for good. The push now has to prove the CURRENT
password (or carry an org recovery proof, or an admin's one-time key-reset
grant for a user who recovered without the old password).
"""

from __future__ import annotations

import os
import shutil

import pytest

from sezam.vault import pending_states
from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
from sezam.vault import sync_client as sync_client_module
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)


def _user(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


def _hex(value) -> str:
    return value if isinstance(value, str) else bytes(value).hex()


def _owner_recovers(vault: Vault, url: str, username: str) -> dict:
    """What a new device of the owner does: /recover with the password."""
    params = Argon2Params.from_dict(vault.db.get_meta_json("argon2_params"))
    _, proof = derive_kek_and_proof(
        PASSWORD, bytes.fromhex(vault.db.get_meta("argon2_salt")), params
    )
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    return client._request(
        "POST", "/api/auth/recover", {"username": username, "auth_proof": proof.hex()}
    )


def _thief(admin: Vault, tmp_path) -> Vault:
    """A copy holding the admin's keypair (the test opens it with the password
    only to get at the keypair; the forged push below never proves it)."""
    shutil.copytree(tmp_path / "admin", tmp_path / "thief")
    thief = Vault(tmp_path / "thief")
    thief.unlock(PASSWORD)
    return thief


@pytest.mark.parametrize("rotate_identity", [True, False])
def test_stolen_keypair_alone_cannot_replace_the_key_material(
    team, tmp_path, monkeypatch, rotate_identity  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    before = dict(_user(db, admin_id))
    thief = _thief(admin, tmp_path)
    try:
        thief.change_password(PASSWORD, "thief-password!", rotate_identity=rotate_identity)
        # No proof of the current password: the thief does not know it.
        monkeypatch.setattr(sync_client_module, "open_current_auth_proof", lambda *a: None, raising=False)
        client = SyncClient(thief.db, url, thief.keypair, admin_id)
        client.set_dek_manager(thief.dek_mgr)
        with pytest.raises(RuntimeError, match="403"):
            client.push()
    finally:
        thief.lock()

    after = _user(db, admin_id)
    for field in ("encrypted_keypair", "auth_proof_hash", "signing_pk", "argon2_salt"):
        assert _hex(after[field]) == _hex(before[field]), field
    assert not db._storage.get("user_key_archives")
    # The owner's password still opens the account; the owner's devices sync.
    assert _owner_recovers(admin, url, "admin")["user_id"] == admin_id
    assert _client(admin, url).push()["conflicts"] == []


def test_wrong_current_proofs_count_like_recover_and_lock(team, tmp_path, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    thief = _thief(admin, tmp_path)
    try:
        thief.change_password(PASSWORD, "thief-password!")
        monkeypatch.setattr(
            sync_client_module, "open_current_auth_proof",
            lambda *a: bytearray(os.urandom(32)), raising=False,
        )
        client = SyncClient(thief.db, url, thief.keypair, admin_id)
        client.set_dek_manager(thief.dek_mgr)
        with pytest.raises(RuntimeError, match="403.*Wrong current account password"):
            client.push()
        assert _user(db, admin_id)["recovery_attempts"] == 1
        _user(db, admin_id)["recovery_attempts"] = 19  # recovery_max_total=20
        with pytest.raises(RuntimeError, match="423"):
            client.push()
    finally:
        thief.lock()
    assert _user(db, admin_id)["recovery_locked"] == 1
    # The owner's correct proof is still accepted (lockout review #7).
    assert _owner_recovers(admin, url, "admin")["user_id"] == admin_id


def test_owner_password_change_proves_the_current_password(team):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    old_hash = _user(db, admin_id)["auth_proof_hash"]
    admin.change_password(PASSWORD, PASSWORD + "-new")
    journal = (pending_states.key_change_journal(admin.db) or None)
    assert "current_auth_proof" in journal
    _client(admin, url).push()
    assert _user(db, admin_id)["auth_proof_hash"] != old_hash
    assert (pending_states.key_change_journal(admin.db) or None) is None


def test_admin_key_reset_grant_lets_a_user_without_the_old_password_in_once(
    team, tmp_path, monkeypatch  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    # As after a desktop org recovery: no proof of the old password.
    monkeypatch.setattr(sync_client_module, "open_current_auth_proof", lambda *a: None, raising=False)
    try:
        bob.change_password(PASSWORD, "bob-new-password!")
        client = SyncClient(bob.db, url, bob.keypair, bob_id)
        client.set_dek_manager(bob.dek_mgr)
        with pytest.raises(RuntimeError, match="403.*key reset"):
            client.push()

        # An admin cannot grant it to their own account.
        with pytest.raises(RuntimeError, match="403"):
            admin_client.allow_key_reset(admin_id)
        admin_client.allow_key_reset(bob_id)
        client.push()
        assert (pending_states.key_change_journal(bob.db) or None) is None
        assert _user(db, bob_id)["key_reset_until"] is None

        # The grant was used up.
        bob.change_password("bob-new-password!", "bob-third-password!")
        with pytest.raises(RuntimeError, match="403"):
            client.push()
    finally:
        bob.lock()
