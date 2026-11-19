"""Review main@d615826 (server): usernames were still enumerable.

/verify checked a challenge's MAC only for a real account, so a forged
challenge answered "Challenge not found or expired" for a real name and
"Authentication failed" for an unknown one. The periodic cleanup dropped an
unknown name's shadow counters after a quiet lock period, while a real
account kept its failure count: the next wrong proof locked a real name
(423) and left an unknown one at 401.
"""

# ruff: noqa: F811  (pytest fixtures as parameters)
from __future__ import annotations

import os
import time

import pytest

from server.app.dependencies import get_config
from server.app.main import _cleanup_recovery_name_limits
from tests.test_review2_server_medium import _recover_statuses, _with_proof
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    app_client,
    mock_db,
)


async def _verify(app_client, username: str, challenge: str) -> tuple[int, str]:
    resp = await app_client.post("/api/auth/verify", json={
        "username": username, "challenge": challenge, "signature": "00" * 64,
    })
    return resp.status_code, resp.json()["detail"]


@pytest.mark.asyncio
async def test_verify_answers_a_forged_challenge_alike_for_any_name(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    forged = os.urandom(40).hex()
    assert await _verify(app_client, "admin", forged) == await _verify(app_client, "ghost", forged)


@pytest.mark.asyncio
async def test_verify_answers_a_real_challenge_alike_for_any_name(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    answers = []
    for name in ("admin", "ghost"):
        challenge = (await app_client.post(
            "/api/auth/challenge", json={"username": name}
        )).json()["challenge"]
        answers.append(await _verify(app_client, name, challenge))
    assert answers[0] == answers[1]


@pytest.mark.asyncio
async def test_failures_expire_alike_for_a_real_and_an_unknown_name(app_client, mock_db):
    config = get_config()
    _create_admin_user(mock_db._storage)
    _with_proof(mock_db._storage["users"][0])
    almost = config.recovery_max_total - 1
    assert await _recover_statuses(app_client, "admin", almost) == [401] * almost
    mock_db._storage["recovery_ip_limits"] = []  # (one test address for both names)
    assert await _recover_statuses(app_client, "ghost", almost) == [401] * almost
    mock_db._storage["recovery_ip_limits"] = []

    # A quiet lock period later the cleanup drops the shadow counters.
    long_ago = int(time.time() * 1000) - (config.recovery_lock_seconds + 60) * 1000
    mock_db._storage["users"][0]["last_recovery_attempt"] = long_ago
    for shadow in mock_db._storage["recovery_name_limits"]:
        shadow["last_recovery_attempt"] = long_ago
    await _cleanup_recovery_name_limits(mock_db, config.recovery_lock_seconds)

    assert await _recover_statuses(app_client, "admin", 1) == await _recover_statuses(
        app_client, "ghost", 1
    )
