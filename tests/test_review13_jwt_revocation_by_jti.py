"""Review c78fd19 (R13, public repo): a logged-out token must stay revoked.

PyJWT up to 2.13.0 (GHSA-hxm8-2xgr-2p9m) accepted a compact JWS whose
signature segment carried characters outside the Base64URL alphabet, such as
a trailing '=' or '!!!!': the signature bytes and claims stayed the same, but
the token string changed. The server indexed revoked tokens by the SHA-256 of
the raw string, so the altered token of a logged-out session worked again.
Revocation is now keyed on the token's jti, and a non-canonical token is
refused before it is decoded.
"""

from __future__ import annotations

import asyncio

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _do_challenge_verify,
    _do_signed_refresh,
    app_client,
    mock_db,
)


def _variants(token: str) -> list[str]:
    return [token + "=", token + "==", token + "!!!!"]


async def _users(app_client, token):
    return await app_client.get("/api/users", headers={"Authorization": f"Bearer {token}"})


@pytest.mark.asyncio
async def test_a_logged_out_token_stays_revoked_in_any_serialization(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
    assert (await _users(app_client, token)).status_code == 200

    resp = await app_client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200

    assert (await _users(app_client, token)).status_code == 401
    for altered in _variants(token):
        assert (await _users(app_client, altered)).status_code == 401, altered[-6:]


@pytest.mark.asyncio
async def test_a_refreshed_token_stays_revoked_in_any_serialization(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    old = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
    await asyncio.sleep(1.1)
    assert (await _do_signed_refresh(app_client, old, sk, "admin")).status_code == 200

    for altered in [old, *_variants(old)]:
        assert (await _users(app_client, altered)).status_code == 401, altered[-6:]


@pytest.mark.asyncio
async def test_a_non_canonical_token_is_refused_even_before_logout(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
    for altered in _variants(token):
        assert (await _users(app_client, altered)).status_code == 401, altered[-6:]
    assert (await _users(app_client, token)).status_code == 200
