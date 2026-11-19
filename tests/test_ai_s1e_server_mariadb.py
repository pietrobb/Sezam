"""AI broker S1e: the server relays the signed ai_policy (real MariaDB).

It stores only what the account's key signed, keeps the epoch strictly
increasing (no replay of an older brake) and hands each account only its
own policy. Skipped without SEZAM_TEST_MARIADB, like the other server
tests that need a real database.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from nacl.signing import SigningKey

from server.app.models.schemas import AIPolicyPut
from server.app.routers.ai_policy import get_ai_policy, put_ai_policy
from sezam.mcp.remote_policy import RemotePolicy, sign_policy, verify_policy
from tests.test_review2_server_mariadb import _add_user, mariadb  # noqa: F401


def _req(sk: SigningKey, user_id: str, epoch: int, enabled: bool = False) -> AIPolicyPut:
    return AIPolicyPut(
        enabled=enabled, epoch=epoch, signature=sign_policy(sk, user_id, enabled, epoch)
    )


async def _put(db, user_id, req):
    return await put_ai_policy(req, db, {"sub": user_id})


async def _get(db, user_id):
    return (await get_ai_policy(db, {"sub": user_id})).policy


@pytest.mark.asyncio
async def test_signed_policy_round_trips_and_verifies_on_the_client(mariadb):  # noqa: F811
    user_id, sk = await _add_user(mariadb, "owner")
    assert await _get(mariadb, user_id) is None

    await _put(mariadb, user_id, _req(sk, user_id, 1_762_500_000_123))

    stored = await _get(mariadb, user_id)
    assert verify_policy(
        stored.model_dump(), user_id, bytes(sk.verify_key)
    ) == RemotePolicy(False, 1_762_500_000_123)


@pytest.mark.asyncio
async def test_epoch_only_grows(mariadb):  # noqa: F811
    user_id, sk = await _add_user(mariadb, "owner")
    await _put(mariadb, user_id, _req(sk, user_id, 100))

    for epoch in (100, 99):
        with pytest.raises(HTTPException) as exc:
            await _put(mariadb, user_id, _req(sk, user_id, epoch))
        assert exc.value.status_code == 409
    await _put(mariadb, user_id, _req(sk, user_id, 101))
    assert (await _get(mariadb, user_id)).epoch == 101


@pytest.mark.asyncio
async def test_policy_not_signed_by_the_account_is_refused(mariadb):  # noqa: F811
    user_id, sk = await _add_user(mariadb, "owner")
    other_id, other_sk = await _add_user(mariadb, "other")

    bad = [
        _req(other_sk, user_id, 5),           # someone else's key
        _req(sk, other_id, 5),                # signed for another account
        AIPolicyPut(enabled=True, epoch=5, signature=_req(sk, user_id, 5).signature),
    ]
    for req in bad:
        with pytest.raises(HTTPException) as exc:
            await _put(mariadb, user_id, req)
        assert exc.value.status_code == 400
    assert await _get(mariadb, user_id) is None


@pytest.mark.asyncio
async def test_each_account_sees_only_its_own_policy(mariadb):  # noqa: F811
    user_id, sk = await _add_user(mariadb, "owner")
    other_id, _ = await _add_user(mariadb, "other")
    await _put(mariadb, user_id, _req(sk, user_id, 7))

    assert await _get(mariadb, other_id) is None
    assert (await _get(mariadb, user_id)).user_id == user_id
