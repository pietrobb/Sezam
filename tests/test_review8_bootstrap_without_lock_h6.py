"""Review main@a159e97 H6: an anonymous POST /api/bootstrap took the lock
every push takes before it looked whether the server has users.

During a long push a wave of them waited on commit_counter, holding the
pool's connections; requests failed with 500, /health answered 503 and the
watchdog killed the worker. On a set-up server the 403 now comes from a plain
read, and the operator can turn bootstrap off (SEZAM_BOOTSTRAP_DISABLED).
Runs against a real MariaDB (SEZAM_TEST_MARIADB); skipped without it.
"""

from __future__ import annotations

import asyncio
import os

import pytest

pytest.importorskip("aiomysql")

from tests.test_review2_server_mariadb import _add_user, mariadb  # noqa: E402,F401
from tests.test_review7_server_mariadb import _client  # noqa: E402


def _bootstrap(client, name: str):
    return client.post("/api/bootstrap", json={
        "username": name, "signing_pk": os.urandom(32).hex(),
        "encryption_pk": os.urandom(32).hex(),
    })


@pytest.mark.asyncio
async def test_bootstrap_of_a_set_up_server_does_not_wait_for_a_push(mariadb, tmp_path):  # noqa: F811
    await _add_user(mariadb, "admin")
    held, release = asyncio.Event(), asyncio.Event()

    async def long_push():
        async with mariadb.transaction() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
                held.set()
                await release.wait()

    push = asyncio.create_task(long_push())
    await held.wait()
    try:
        async with await _client(mariadb, tmp_path) as client:
            responses = await asyncio.wait_for(
                asyncio.gather(*(_bootstrap(client, f"x{i}") for i in range(8))), timeout=10,
            )
    finally:
        release.set()
        await push
    assert [r.status_code for r in responses] == [403] * 8


@pytest.mark.asyncio
async def test_bootstrap_disabled_by_the_operator(mariadb, tmp_path):  # noqa: F811
    from server.app.dependencies import get_config

    async with await _client(mariadb, tmp_path) as client:
        get_config().bootstrap_disabled = True
        refused = await _bootstrap(client, "boss")
        get_config().bootstrap_disabled = False
        allowed = await _bootstrap(client, "boss")
    assert refused.status_code == 403 and "SEZAM_BOOTSTRAP_DISABLED" in refused.json()["detail"]
    assert allowed.status_code == 200
