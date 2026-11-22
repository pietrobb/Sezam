"""Review e443cbc, goal #440: an org recovery store racing an org.recovery
append (the check of 215a6ce) left the organization without a usable recovery.

Invariant: whichever way a store and an append of org.recovery interleave,
the current org recovery (recovery._current_recovery) is one whose blob the
shares open.

The append holds the blob row (FOR UPDATE) while it checks the record against
the stored blob. A store of a newer setup waited on that row, but it read the
team log head from the snapshot it took before the append committed: its blob
ranked below the record just appended (log_seq one short), so the log's key
became current, with no blob. Runs against a real MariaDB (SEZAM_TEST_MARIADB,
see tests/test_review2_server_mariadb.py); skipped without it.
"""

from __future__ import annotations

import asyncio
import time

import pytest

pytest.importorskip("aiomysql")

from tests.team_log_vectors import A, R1, R2, Log  # noqa: E402
from tests.test_review2_server_mariadb import mariadb  # noqa: E402,F401

_SECRET = "r15-440-test-secret-0123456789"


async def _add_admin(db) -> None:
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO users (id, username, signing_pk, encryption_pk, key_fingerprint, status, "
                "is_admin, created_at) VALUES (%s, 'alice', %s, %s, %s, 'active', 1, %s)",
                (A.uid, bytes.fromhex(A.spk), bytes.fromhex(A.epk), "f" * 64, int(time.time() * 1000)),
            )
        await conn.commit()


async def _append(db, records: list[dict]):
    from server.app.models.schemas import TeamLogAppend
    from server.app.routers.team_log import append_team_log

    return await append_team_log(TeamLogAppend(records=records), db, {"sub": A.uid})


async def _store(db, pk: str) -> None:
    from server.app.config import ServerConfig
    from server.app.models.schemas import OrgRecoveryStoreRequest
    from server.app.routers import recovery

    req = OrgRecoveryStoreRequest(wrapped_kek="00" * 60, recovery_signing_pk=pk, key_epoch=0)
    await recovery._store_recovery_blob(
        db, ServerConfig(hmac_server_secret=_SECRET), req, {"sub": A.uid},
        b"\0" * 60, bytes.fromhex(pk), int(time.time() * 1000),
    )


async def _current(db) -> dict | None:
    from server.app.routers import recovery

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            _stored, current, _state = await recovery._current_recovery(cur)
        await conn.commit()
    return current


@pytest.mark.asyncio
async def test_a_store_racing_an_org_recovery_append_keeps_a_usable_recovery(mariadb, monkeypatch):  # noqa: F811
    from server.app import team_log
    from server.app.routers import recovery

    async def password_checked(*_args, **_kwargs):
        return None

    monkeypatch.setattr(recovery, "_require_current_password", password_checked)
    await _add_admin(mariadb)
    log = Log().genesis(A)
    await _append(mariadb, log.records)
    await _store(mariadb, R1)  # the desktop's setup, stored before it names its key
    named = log.recovery(A, R1).records[-1]

    holds = asyncio.Event()
    real_check = team_log._check_against_users

    async def check_holding_the_blob(cur, body, *args, **kwargs):
        if body["type"] == "org.recovery" and not holds.is_set():
            holds.set()  # past _refuse_superseded_recovery: the blob row is locked
            await asyncio.sleep(0.5)  # the store of the newer setup starts meanwhile
        return await real_check(cur, body, *args, **kwargs)

    monkeypatch.setattr(team_log, "_check_against_users", check_holding_the_blob)
    append = asyncio.create_task(_append(mariadb, [named]))
    await holds.wait()
    store = asyncio.create_task(_store(mariadb, R2))  # the web's newer setup
    results = await asyncio.gather(append, store, return_exceptions=True)
    assert [r for r in results if isinstance(r, BaseException)] == [], results

    current = await _current(mariadb)
    # Before: the log's R1, with no blob (the store's log_seq missed the record).
    assert current is not None and current["recovery_signing_pk"] == R2, current
    assert current["blob"] is not None
