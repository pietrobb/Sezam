"""Review 8595ec1 (R10-H): share links outlived the removal of their author.

A revoked account (DELETE /api/users/{id} or a signed member.remove) kept
every share link it had created: anyone with the link still got the secret
until it expired, though the organisation had just cut the author off.
"""

from __future__ import annotations

import time

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    app_client,
    mock_db,
)

ADMIN_ID = "ADMIN000000000000000000001"
USER_ID = "USER0000000000000000000001"


def _share(storage, share_id: str, author: str) -> None:
    now_ms = int(time.time() * 1000)
    storage["shared_links"].append({
        "id": share_id, "encrypted_blob": b"secret", "created_by": author,
        "created_at": now_ms, "expires_at": now_ms + 3_600_000,
        "max_views": 5, "view_count": 0, "pin_hash": None,
        "pin_attempts": 0, "is_locked": 0, "notify_on_view": 0,
    })


@pytest.fixture(autouse=True)
def _fast_failures(monkeypatch):
    from server.app.routers import share

    monkeypatch.setattr(share, "_SHARE_ERROR_MIN_SECONDS", 0)


@pytest.mark.asyncio
async def test_revoking_the_author_ends_their_share_links(app_client, mock_db):  # noqa: F811
    _create_admin_user(mock_db._storage)
    _create_regular_user(mock_db._storage)
    _share(mock_db._storage, "U" * 43, USER_ID)
    _share(mock_db._storage, "A" * 43, ADMIN_ID)

    resp = await app_client.delete(
        f"/api/users/{USER_ID}",
        headers={"Authorization": f"Bearer {_create_jwt(ADMIN_ID, 'admin', True)}"},
    )
    assert resp.status_code == 200

    assert (await app_client.post(f"/api/share/{'U' * 43}", json={})).status_code == 404
    assert [s["id"] for s in mock_db._storage["shared_links"]] == ["A" * 43]
    assert (await app_client.post(f"/api/share/{'A' * 43}", json={})).status_code == 200


@pytest.mark.asyncio
async def test_a_link_of_an_author_revoked_otherwise_is_not_served(app_client, mock_db):  # noqa: F811
    """Whatever revoked the account (a team log member.remove, a restored
    backup that still holds the link), the link is not served."""
    _create_admin_user(mock_db._storage)
    _create_regular_user(mock_db._storage)
    _share(mock_db._storage, "U" * 43, USER_ID)
    for user in mock_db._storage["users"]:
        if user["id"] == USER_ID:
            user["status"] = "revoked"

    assert (await app_client.post(f"/api/share/{'U' * 43}", json={})).status_code == 404
    share = next(s for s in mock_db._storage["shared_links"] if s["id"] == "U" * 43)
    assert share["view_count"] == 0
