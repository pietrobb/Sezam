"""Review 18c300f R16-L5: /api/meta tells no one which names have an account.

A name without an account got one of two client default KDF params, but the
desktop calibrates its params (benchmark_argon2: time_cost 4, 5..., memory 128
or 64 MiB), so a real desktop account's params gave it away; a legacy account
without an auth salt answered auth_salt None, which no unknown name does. An
unknown name now gets params of the accounts on the server, picked per name
in proportion to how many use them, and always an auth salt.
"""

from __future__ import annotations

import json

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_regular_user,
    app_client,
    mock_db,
)

CALIBRATED = {"time_cost": 6, "memory_cost": 262144, "parallelism": 4, "hash_len": 64}
SLOW_MACHINE = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 64}
NAMES = [f"nobody{i}" for i in range(60)]


async def _meta(client, name: str) -> dict:
    response = await client.get(f"/api/meta?username={name}")
    assert response.status_code == 200
    return response.json()


@pytest.mark.asyncio
async def test_a_calibrated_account_looks_like_the_unknown_names(app_client, mock_db):  # noqa: F811
    _create_admin_user(mock_db._storage)
    _create_regular_user(mock_db._storage)
    users = mock_db._storage["users"]
    users[0]["argon2_params"] = json.dumps(CALIBRATED)  # 'sezam init' on a fast machine
    users[1]["argon2_params"] = json.dumps(SLOW_MACHINE)

    real = await _meta(app_client, "admin")
    assert real["argon2_params"] == CALIBRATED
    unknown = [(await _meta(app_client, name))["argon2_params"] for name in NAMES]
    # Before: only the two client defaults, never the admin's params.
    assert CALIBRATED in unknown and SLOW_MACHINE in unknown
    assert all(params in (CALIBRATED, SLOW_MACHINE) for params in unknown)
    # Stable per name, so asking again tells nothing either.
    assert [(await _meta(app_client, name))["argon2_params"] for name in NAMES] == unknown


@pytest.mark.asyncio
async def test_a_legacy_account_without_auth_salt_still_reports_one(app_client, mock_db):  # noqa: F811
    _create_admin_user(mock_db._storage)
    mock_db._storage["users"][0]["auth_salt"] = None

    real = await _meta(app_client, "admin")
    unknown = await _meta(app_client, "nobody")
    assert real["auth_salt"] is not None and unknown["auth_salt"] is not None  # before: None
    assert len(real["auth_salt"]) == len(unknown["auth_salt"]) == 32


@pytest.mark.asyncio
async def test_a_server_with_no_account_answers_a_client_default(app_client, mock_db):  # noqa: F811
    from server.app.models.schemas import CLIENT_DEFAULT_ACCOUNT_KDFS

    unknown = [(await _meta(app_client, name))["argon2_params"] for name in NAMES[:20]]
    assert all(params in CLIENT_DEFAULT_ACCOUNT_KDFS for params in unknown)
