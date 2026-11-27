"""Review e443cbc, goal #438 (4) (INV-2, R13-10 continued): an older org
recovery set up on the desktop put its blob back over the newer setup from
the web, voiding the web's shares.

Only one org recovery is valid at a time; the server's current one is the
newest of its blob and the keys the team log names (_current_recovery). The
web's setup stands although its anchor in the log failed: the log still
names the desktop's older key. A store signed by the recovery key needs no
password (a re-wrap after an org recovery, review d615826), and the server
let any key the log names for the admin re-wrap, current or not. Whoever
holds the threshold of the old, voided shares (the device that rebuilt them,
or the former share holders) replaced the current recovery without the
password: an emergency path with more power than the normal setup.

Invariant: without the password only the current org recovery's own key
re-wraps its blob."""

from __future__ import annotations

import os

from nacl.signing import SigningKey

from sezam.vault import team_migration
from sezam.vault.key_rotation import org_recovery_rewrap_message
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)


def _body(key: SigningKey, wrapped: bytes) -> dict:
    return {
        "wrapped_kek": wrapped.hex(), "recovery_signing_pk": bytes(key.verify_key).hex(),
        "threshold": 2, "total_shares": 3, "key_epoch": 0,
    }


def _signed(key: SigningKey, user_id: str, wrapped: bytes) -> dict:
    return {**_body(key, wrapped), "recovery_signature": key.sign(
        org_recovery_rewrap_message(user_id, 0, 2, 3, wrapped)).signature.hex()}


def _status(client) -> dict:
    return client._request("GET", "/api/org-recovery/status", auth=True)


def test_a_voided_recovery_key_does_not_put_its_blob_back(team):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    team_migration.found_team_log(admin, admin_client, confirm_fingerprint=lambda _u, _fp: True)
    old = SigningKey.generate()
    admin_client.store_org_recovery(_body(old, os.urandom(72)), admin.current_auth_proof(PASSWORD))
    admin.db.set_meta("org_recovery_signing_pk", bytes(old.verify_key).hex())
    admin_client.anchor_org_recovery()
    admin_client.flush_team_log()
    assert admin_client.team_state().org_recovery[admin_id] == bytes(old.verify_key).hex()

    # The web sets up a new one (its anchor in the log failed).
    new = SigningKey.generate()
    admin_client.store_org_recovery(_body(new, os.urandom(72)), admin.current_auth_proof(PASSWORD))
    assert _status(admin_client)["recovery_signing_pk"] == bytes(new.verify_key).hex()

    try:
        admin_client._request(
            "POST", "/api/org-recovery/store", _signed(old, admin_id, os.urandom(72)), auth=True,
        )
        raise AssertionError("the voided key put its blob back without the password")
    except RuntimeError as exc:
        assert "403" in str(exc)
    assert _status(admin_client)["recovery_signing_pk"] == bytes(new.verify_key).hex()

    # The current key still re-wraps its own blob without the password.
    rewrapped = os.urandom(72)
    admin_client._request("POST", "/api/org-recovery/store", _signed(new, admin_id, rewrapped), auth=True)
    assert db._storage["org_recovery_blobs"][0]["wrapped_kek"] == rewrapped
