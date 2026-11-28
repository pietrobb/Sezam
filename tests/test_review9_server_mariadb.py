"""Review 1141a20 (R9-F) on a real MariaDB: team-log CAS across workers,
rollback of a refused append, the staged-gate queue, reserved ids, and a cold
replay that leaves the event loop free.

Skipped without SEZAM_TEST_MARIADB (see tests/test_review2_server_mariadb.py).
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
from nacl.signing import SigningKey

pytest.importorskip("aiomysql")

from fastapi import HTTPException  # noqa: E402
from ulid import ULID  # noqa: E402

from sezam import teamlog as core  # noqa: E402
from server.app import team_log  # noqa: E402
from server.app.models.schemas import TeamLogAppend  # noqa: E402
from server.app.routers import team_log as team_log_router  # noqa: E402
from tests.test_review2_server_mariadb import _push, _signed, mariadb  # noqa: E402,F401
from tests.test_review9_server_staged import _claim, _release  # noqa: E402


async def _user(db, name: str, admin: bool) -> dict:
    user_id, sk = str(ULID()), SigningKey.generate()
    enc = os.urandom(32)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO users (id, username, signing_pk, encryption_pk, "
                "key_fingerprint, status, is_admin, created_at) "
                "VALUES (%s, %s, %s, %s, %s, 'active', %s, %s)",
                (user_id, name, bytes(sk.verify_key), enc, "f" * 64, 1 if admin else 0,
                 int(time.time() * 1000)),
            )
    return {"id": user_id, "sk": sk, "keys": {"signing_pk": bytes(sk.verify_key).hex(), "encryption_pk": enc.hex()}}


class _Team:
    def __init__(self, admin, bob, carol):
        self.admin, self.bob, self.carol = admin, bob, carol
        self.state = core.TeamState()

    def record(self, kind: str, who: dict, data: dict, state=None) -> dict:
        return core.sign_record(core.next_body(state or self.state, kind, who["id"], data), who["sk"])

    def accept(self, *records):
        self.state = core.replay(list(records), self.state)

    def folder_keys(self, count: int, start: int = 0, folder: str = "01JF0000000000000000000001") -> list[dict]:
        records = []
        for gen in range(start, start + count):
            prev = None if gen == 0 else f"01JD{gen - 1:022d}"
            record = self.record("folder.key", self.admin, {
                "folder": folder, "gen": gen, "dek_id": f"01JD{gen:022d}", "prev_dek_id": prev,
            })
            self.accept(record)
            records.append(record)
        return records


async def _append(db, who: dict, records: list[dict]):
    return await team_log_router.append_team_log(TeamLogAppend(records=records), db, {"sub": who["id"]})


async def _founded(db) -> _Team:
    team_log.forget_cache()
    team = _Team(await _user(db, "admin", True), await _user(db, "bob", False), await _user(db, "carol", False))
    genesis = team.record("genesis", team.admin, {"org": str(ULID()), "user_id": team.admin["id"], **team.admin["keys"]})
    team.accept(genesis)
    bob = team.record("member.add", team.admin, {"user_id": team.bob["id"], **team.bob["keys"], "role": "member"})
    team.accept(bob)
    carol = team.record("member.add", team.admin, {"user_id": team.carol["id"], **team.carol["keys"], "role": "member"})
    team.accept(carol)
    await _append(db, team.admin, [genesis, bob, carol])
    return team


async def _scalar(db, sql: str, args=()):
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, args)
            row = await cur.fetchone()
    return row[0] if row else None


@pytest.mark.asyncio
async def test_workers_appending_onto_one_head_land_exactly_one(mariadb, monkeypatch):  # noqa: F811
    team = await _founded(mariadb)
    # Separate workers: no shared in-process gate, no warm cache.
    monkeypatch.setattr(team_log_router, "_push_gate", lambda: asyncio.Lock())
    monkeypatch.setattr(team_log, "_remember", lambda entry, stale: None)
    base = team.state
    rivals = [
        team.record("folder.key", team.admin, {
            "folder": "01JF0000000000000000000001", "gen": 0, "dek_id": f"01JD{i:022d}", "prev_dek_id": None,
        }, state=base)
        for i in range(8)
    ]
    results = await asyncio.gather(*(_append(mariadb, team.admin, [r]) for r in rivals), return_exceptions=True)
    landed = [r for r in results if not isinstance(r, BaseException)]
    refused = [r for r in results if isinstance(r, HTTPException)]
    assert len(landed) == 1 and len(refused) == 7, results
    assert {r.status_code for r in refused} == {409}
    assert await _scalar(mariadb, "SELECT COUNT(*) FROM team_log") == 4
    team_log.forget_cache()
    monkeypatch.undo()
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            state = await team_log.load_state(cur)
    assert state.head_seq == 3 and len(state.folders["01JF0000000000000000000001"]) == 1


@pytest.mark.asyncio
async def test_a_refused_append_rolls_the_users_table_back(mariadb):  # noqa: F811
    team = await _founded(mariadb)
    epoch = await _scalar(mariadb, "SELECT token_epoch FROM users WHERE id = %s", (team.bob["id"],))
    second_admin = team.record("member.role", team.admin, {"user_id": team.bob["id"], "role": "admin"})
    with pytest.raises(HTTPException) as refused:
        await _append(mariadb, team.admin, [second_admin])  # one admin per organisation
    assert refused.value.status_code == 400
    assert await _scalar(mariadb, "SELECT is_admin FROM users WHERE id = %s", (team.bob["id"],)) == 0
    assert await _scalar(mariadb, "SELECT token_epoch FROM users WHERE id = %s", (team.bob["id"],)) == epoch
    assert await _scalar(mariadb, "SELECT COUNT(*) FROM team_log") == 3


@pytest.mark.asyncio
async def test_a_member_cannot_take_an_id_the_log_announced(mariadb):  # noqa: F811
    team = await _founded(mariadb)
    await _append(mariadb, team.admin, team.folder_keys(1))
    taken = _signed(team.bob["sk"], "01JF0000000000000000000001", 1, "entry")
    result = await _push(mariadb, team.bob["id"], [taken])
    assert not result.accepted and "reserves this id" in result.conflicts[0].error, result
    assert await _scalar(mariadb, "SELECT COUNT(*) FROM vault_objects WHERE id = %s", (taken.id,)) == 0


@pytest.mark.asyncio
async def test_the_staged_gate_queue_on_mariadb(mariadb):  # noqa: F811
    order = []
    first = await _claim(mariadb, "USER0000000000000000000001")

    async def _take(user_id):
        claim_id = await _claim(mariadb, user_id)
        order.append(user_id)
        await asyncio.sleep(0.05)
        await _release(mariadb, user_id, claim_id)

    waiting = asyncio.create_task(_take("USER0000000000000000000002"))
    await asyncio.sleep(0.6)
    await _release(mariadb, "USER0000000000000000000001", first)
    again = asyncio.create_task(_take("USER0000000000000000000001"))
    await asyncio.wait_for(asyncio.gather(waiting, again), 10)
    assert order == ["USER0000000000000000000002", "USER0000000000000000000001"], order
    assert await _scalar(mariadb, "SELECT COUNT(*) FROM sync_staged_queue") == 0
    assert await _scalar(mariadb, "SELECT COUNT(*) FROM sync_staged_gate WHERE claim_id IS NOT NULL") in (0, None)


@pytest.mark.asyncio
async def test_a_cold_replay_leaves_the_event_loop_free(mariadb, monkeypatch):  # noqa: F811
    team = await _founded(mariadb)
    await _append(mariadb, team.admin, team.folder_keys(60))
    team_log.forget_cache()
    real_replay = core._replay

    def slow_replay(records, state, steps=False):
        time.sleep(0.01 * len(records))  # 63 records: ~0.6 s of replay
        return real_replay(records, state, steps)

    monkeypatch.setattr(core, "_replay", slow_replay)
    worst, done = 0.0, False

    async def ticker():
        nonlocal worst
        last = time.perf_counter()
        while not done:
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            worst, last = max(worst, now - last), now

    ticking = asyncio.create_task(ticker())
    started = time.perf_counter()
    answer = await team_log_router.get_team_log(-1, mariadb, {"sub": team.bob["id"]})
    took = time.perf_counter() - started
    done = True
    await ticking
    assert answer.head.seq == 62
    assert took > 0.5 and worst < 0.2, (took, worst)
