"""Review e4cd15a (low): a push racing an identity rotation of the same account.

POST /api/sync read the account's signing key before its transaction. When
another device's rotation committed between that read and the push taking the
commit_counter lock, the batch was still verified with the retired key and
landed at a commit_seq behind the rotation's retired_seq - where every other
client refuses signatures of the old key, so nobody else ever saw the edit.
The key is now read after the lock that serializes every push and rotation.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from server.app.routers import sync as sync_router
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _push_object,
    app_client,
    mock_db,
)

USER = "ADMIN000000000000000000001"
NODE = "NODE0000000000000000000001"


def _rotation_commits_before_the_push(monkeypatch, mock_db, new_pk: bytes) -> None:
    """Another device's rotation commits after the request was read."""
    real = sync_router.run_transaction

    async def racing(db, fn, *args, **kwargs):
        mock_db._storage["users"][0]["signing_pk"] = new_pk
        return await real(db, fn, *args, **kwargs)

    monkeypatch.setattr(sync_router, "run_transaction", racing)


@pytest.mark.asyncio
async def test_batch_signed_by_the_key_retired_meanwhile_is_refused(
    app_client, mock_db, monkeypatch
):
    old_sk, _ = _create_admin_user(mock_db._storage)
    token = _create_jwt(USER, "admin", True)
    new_sk = SigningKey.generate()
    _rotation_commits_before_the_push(monkeypatch, mock_db, bytes(new_sk.verify_key))

    resp = await _push_object(app_client, token, old_sk, NODE, "node", None, 1, b"edit")
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == []
    assert not any(o.get("id") == NODE for o in mock_db._storage.get("vault_objects", []))


@pytest.mark.asyncio
async def test_batch_signed_by_the_current_key_is_taken(app_client, mock_db, monkeypatch):
    _create_admin_user(mock_db._storage)
    token = _create_jwt(USER, "admin", True)
    new_sk = SigningKey.generate()
    _rotation_commits_before_the_push(monkeypatch, mock_db, bytes(new_sk.verify_key))

    resp = await _push_object(app_client, token, new_sk, NODE, "node", None, 1, b"edit")
    assert resp.status_code == 200, resp.text
    assert [o["id"] for o in resp.json()["accepted"]] == [NODE]
