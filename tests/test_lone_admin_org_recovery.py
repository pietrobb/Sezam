"""Review e4cd15a #1: a lone admin after a desktop Shamir recovery never synced.

'sezam org-recovery' does not know the old password, and since K1 the server
then wanted another admin's key-reset grant - a lone admin has none: every
push was 403 for good, and the forgotten password stayed on the server. The
desktop setup now registers the recovery key on the server (with proof of
the current password: a stolen identity key must not plant its own), and the
recovery signs the server's challenge with it, as the web recovery does.
"""

from __future__ import annotations

import os
from pathlib import Path

from click.testing import CliRunner
from nacl.signing import SigningKey

from sezam.vault import pending_states
from sezam import cli
from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
from sezam.vault.crud import Vault
from sezam.vault.key_rotation import org_recovery_rewrap_message
from sezam.vault.sync_client import SyncClient
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)

RECOVERED = "recovered-password!"


def _user(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


def _store_body(**extra) -> dict:
    return {
        "wrapped_kek": os.urandom(72).hex(),
        "recovery_signing_pk": os.urandom(32).hex(),
        "threshold": 2,
        "total_shares": 3,
        "key_epoch": 0,
        **extra,
    }


def _recover(vault: Vault, url: str, password: str) -> dict:
    params = Argon2Params.from_dict(vault.db.get_meta_json("argon2_params"))
    _, proof = derive_kek_and_proof(
        password, bytes.fromhex(vault.db.get_meta("argon2_salt")), params
    )
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    return client._request(
        "POST", "/api/auth/recover", {"username": "admin", "auth_proof": proof.hex()}
    )


def test_a_new_recovery_key_needs_the_current_password(team):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    # A JWT from the identity key alone (what a thief of the keypair has).
    try:
        admin_client._request("POST", "/api/org-recovery/store", _store_body(), auth=True)
        raise AssertionError("stored without the password")
    except RuntimeError as exc:
        assert "403" in str(exc)
    assert not db._storage.get("org_recovery_blobs")
    try:
        admin_client._request(
            "POST", "/api/org-recovery/store",
            _store_body(current_auth_proof=os.urandom(32).hex()), auth=True,
        )
        raise AssertionError("stored with a wrong proof")
    except RuntimeError as exc:
        assert "Wrong current account password" in str(exc)
    assert _user(db, admin_id)["recovery_attempts"] == 1

    recovery_key = SigningKey.generate()
    body = _store_body(recovery_signing_pk=bytes(recovery_key.verify_key).hex())
    proof = admin.current_auth_proof(PASSWORD)
    admin_client.store_org_recovery(body, proof)
    assert db._storage["org_recovery_blobs"][0]["created_by"] == admin_id
    stored_blob = db._storage["org_recovery_blobs"][0]["wrapped_kek"]
    # Review d615826: the same recovery key with a blob the shares cannot
    # open (a thief with only the identity key) is refused...
    garbage = os.urandom(72)
    for extra in ({}, {"recovery_signature": SigningKey.generate().sign(
        org_recovery_rewrap_message(admin_id, 0, 2, 3, garbage)).signature.hex()}):
        try:
            admin_client._request(
                "POST", "/api/org-recovery/store",
                {**body, "wrapped_kek": garbage.hex(), **extra}, auth=True,
            )
            raise AssertionError("re-stored without the password or the recovery key")
        except RuntimeError as exc:
            assert "403" in str(exc)
    assert db._storage["org_recovery_blobs"][0]["wrapped_kek"] == stored_blob
    # ...and taken when the recovery key itself signed it (a re-wrapped KEK).
    rewrapped = os.urandom(72)
    admin_client._request(
        "POST", "/api/org-recovery/store",
        {**body, "wrapped_kek": rewrapped.hex(), "recovery_signature": recovery_key.sign(
            org_recovery_rewrap_message(admin_id, 0, 2, 3, rewrapped)).signature.hex()},
        auth=True,
    )
    assert db._storage["org_recovery_blobs"][0]["wrapped_kek"] == rewrapped
    # Another key does.
    try:
        admin_client._request("POST", "/api/org-recovery/store", _store_body(), auth=True)
        raise AssertionError("replaced without the password")
    except RuntimeError as exc:
        assert "403" in str(exc)


def test_lone_admin_syncs_after_a_desktop_org_recovery(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    shares = admin.setup_org_recovery(threshold=2, shares=3)
    admin_client.store_org_recovery(
        pending_states.org_recovery_registration(admin.db), admin.current_auth_proof(PASSWORD)
    )
    admin.lock()

    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(shares[:2], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)
    try:
        assert "recovery_secret" in (pending_states.key_change_journal(recovered.db) or None)
        client = _client(recovered, url)
        assert client.push()["conflicts"] == []
        assert (pending_states.key_change_journal(recovered.db) or None) is None
        user = _user(db, admin_id)
        assert not user.get("recovery_attempts")
        assert not user.get("key_reset_until")
        # The server took the new password; the forgotten one is gone.
        assert _recover(recovered, url, RECOVERED)["user_id"] == admin_id
        # The server blob now wraps the new KEK: web recovery stays usable.
        status = client._request("GET", "/api/org-recovery/status")
        assert status["configured"] and status["stale"] is False
        assert client.pull() is not None
    finally:
        recovered.lock()


def test_cli_org_recovery_setup_registers_the_key_on_the_server(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")
    laptop.lock()
    _cli_env(tmp_path / "laptop", monkeypatch)

    result = CliRunner().invoke(
        cli.main, ["org-recovery-setup", "-t", "2", "-n", "3"], input=f"{PASSWORD}\n"
    )
    assert result.exit_code == 0, result.output
    assert "The server knows this recovery" in result.output
    blob = db._storage["org_recovery_blobs"][0]
    assert blob["created_by"] == user_id
    vault = Vault(Path(tmp_path / "laptop"))
    vault.unlock(PASSWORD)
    try:
        assert vault.db.get_meta("org_recovery_pk")
    finally:
        vault.lock()


def test_web_setup_proves_the_current_password():
    src = (Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js").read_text(
        encoding="utf-8"
    )
    body = src.split("async function handleShamirGenerate", 1)[1].split("\nasync function ", 1)[0]
    assert "await currentPasswordProof(" in body
    assert "current_auth_proof: currentAuthProof" in body
    assert 'id="shamir-password"' in src
