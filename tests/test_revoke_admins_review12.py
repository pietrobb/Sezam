"""Lockout review 2026-11-08 #12: user revocation was final and two admins
could revoke each other.

Every request checks "caller is an active admin" before the handler runs, so
two admins revoking each other at the same moment both passed that check and
the organisation ended up without an admin. The handler now re-reads the
active admins under row locks; the race is modelled by letting the request
dependency accept a caller that the other transaction already revoked.
"""

from __future__ import annotations

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    app_client,
    mock_db,
)

ADMIN_A = "ADMIN000000000000000000001"
ADMIN_B = "ADMIN000000000000000000002"
USER = "USER0000000000000000000001"


def _user(mock_db, user_id):
    return next(u for u in mock_db._storage["users"] if u["id"] == user_id)


def _auth(user_id, username, is_admin, token_epoch=0):
    token = _create_jwt(user_id, username, is_admin, token_epoch=token_epoch)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_admins_revoking_each_other_leave_one_admin(app_client, mock_db):
    from server.app.dependencies import require_admin
    from server.app.main import app

    _create_admin_user(mock_db._storage, ADMIN_A, "alice")
    _create_admin_user(mock_db._storage, ADMIN_B, "bob")

    first = await app_client.delete(f"/api/users/{ADMIN_B}", headers=_auth(ADMIN_A, "alice", True))
    assert first.status_code == 200

    # Bob's request passed its admin check before Alice's revoke committed.
    app.dependency_overrides[require_admin] = lambda: {
        "sub": ADMIN_B, "username": "bob", "is_admin": True,
    }
    try:
        second = await app_client.delete(f"/api/users/{ADMIN_A}")
    finally:
        app.dependency_overrides.pop(require_admin, None)

    assert second.status_code == 403
    assert _user(mock_db, ADMIN_A)["status"] == "active"
    assert _user(mock_db, ADMIN_B)["status"] == "revoked"


@pytest.mark.asyncio
async def test_revoked_user_can_be_reactivated_without_old_tokens(app_client, mock_db):
    _create_admin_user(mock_db._storage, ADMIN_A, "alice")
    _create_regular_user(mock_db._storage, USER, "carol")
    admin = _auth(ADMIN_A, "alice", True)
    old_token = _auth(USER, "carol", False)

    assert (await app_client.delete(f"/api/users/{USER}", headers=admin)).status_code == 200
    assert _user(mock_db, USER)["status"] == "revoked"

    resp = await app_client.patch(f"/api/users/{USER}/reactivate", headers=admin)
    assert resp.status_code == 200, resp.text
    assert _user(mock_db, USER)["status"] == "active"
    # A token from before the revocation does not come back to life.
    assert (await app_client.get("/api/sync", headers=old_token)).status_code == 401
    fresh = _auth(USER, "carol", False, token_epoch=_user(mock_db, USER)["token_epoch"])
    assert (await app_client.get("/api/sync", headers=fresh)).status_code == 200


@pytest.mark.asyncio
async def test_reactivation_is_admin_only_and_only_for_revoked(app_client, mock_db):
    _create_admin_user(mock_db._storage, ADMIN_A, "alice")
    _create_regular_user(mock_db._storage, USER, "carol")

    not_revoked = await app_client.patch(
        f"/api/users/{USER}/reactivate", headers=_auth(ADMIN_A, "alice", True)
    )
    assert not_revoked.status_code == 400

    _user(mock_db, USER)["status"] = "revoked"
    _create_regular_user(mock_db._storage, "USER0000000000000000000002", "dave")
    by_user = await app_client.patch(
        f"/api/users/{USER}/reactivate",
        headers=_auth("USER0000000000000000000002", "dave", False),
    )
    assert by_user.status_code == 403
    assert _user(mock_db, USER)["status"] == "revoked"
