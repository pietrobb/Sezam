"""Review 688edcb N2: older clients got a bare 422.

Lockout review N2 made argon2_params required on key material uploads and
key rotations (nothing may guess an account's KDF). Clients from before that
never send it, so a password change or onboarding on such a client died with
a pydantic "Field required" 422 that no client turns into anything readable.
The server still refuses (N2 stands), but with 426 Upgrade Required and a
sentence saying the app is too old and nothing changed.
"""

from __future__ import annotations

import os

import pytest

from server.app.routers.auth import OUTDATED_CLIENT_KDF
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    app_client,
    mock_db,
)

ADMIN = "ADMIN000000000000000000001"


def _material() -> dict:
    return {
        "encrypted_keypair": os.urandom(64).hex(),
        "argon2_salt": os.urandom(16).hex(),
        "auth_salt": os.urandom(16).hex(),
        "auth_proof": os.urandom(32).hex(),
    }


@pytest.mark.asyncio
async def test_keypair_upload_without_params_says_update_the_app(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    mock_db._storage["users"][0]["encrypted_keypair"] = None
    token = _create_jwt(ADMIN, "admin", True, scope="keypair_upload")
    resp = await app_client.put(
        "/api/me/keypair", json=_material(), headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 426, resp.text
    assert resp.json()["detail"] == OUTDATED_CLIENT_KDF
    assert mock_db._storage["users"][0]["encrypted_keypair"] is None


@pytest.mark.asyncio
async def test_rotation_push_without_params_says_update_the_app(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    token = _create_jwt(ADMIN, "admin", True)
    resp = await app_client.post("/api/sync", json={
        "objects": [],
        "atomic_batch": True,
        "key_epoch": 1,
        "key_rotation": {
            **_material(), "challenge": "00" * 40, "signature": "00" * 64,
            "current_auth_proof": "00" * 32,
        },
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 426, resp.text
    assert resp.json()["detail"] == OUTDATED_CLIENT_KDF
    assert all(row.get("key_epoch", 0) == 0 for row in mock_db._storage.get("sync_state", []))
