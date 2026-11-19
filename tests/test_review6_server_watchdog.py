"""Review d615826 #1 (capability run 136): a wedged worker must not stay down.

/health returning 503 only marks the container unhealthy; Docker with
`restart: unless-stopped` never restarts an unhealthy container (probed on
Docker 26: RestartCount stays 0). The watchdog exits the worker instead.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import pytest

from server.app import main


class _FlakyDb:
    def __init__(self, outcomes, exhausted=False, answers=True):
        self.outcomes = list(outcomes)
        self.exhausted = exhausted
        self.answers = answers
        self.outside_pings = 0

    def pool_exhausted(self):
        return self.exhausted

    async def ping_outside_pool(self, timeout):
        self.outside_pings += 1
        if not self.answers:
            raise OSError("database down")

    @asynccontextmanager
    async def acquire(self):
        if self.outcomes.pop(0) == "fail":
            raise RuntimeError("pool exhausted")
        yield _Conn()


class _Conn:
    @asynccontextmanager
    async def cursor(self):
        yield self

    async def execute(self, sql):
        assert sql == "SELECT 1"

    async def fetchone(self):
        return (1,)


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(main, "WATCHDOG_INTERVAL_S", 0)
    monkeypatch.setattr(main, "WATCHDOG_MAX_FAILURES", 3)


@pytest.mark.asyncio
async def test_a_pool_that_stays_unusable_exits_the_worker(fast):
    exits = []
    await main._db_watchdog(_FlakyDb(["fail"] * 3), exit_process=exits.append)
    assert exits == [1]


@pytest.mark.asyncio
async def test_a_good_ping_resets_the_count(fast):
    exits = []
    db = _FlakyDb(["fail", "fail", "ok", "fail", "fail", "fail"])
    await main._db_watchdog(db, exit_process=exits.append)
    assert exits == [1] and db.outcomes == []


@pytest.mark.asyncio
async def test_a_pool_busy_with_long_pushes_is_not_dead(fast):
    """Review a159e97: every connection in use while the database answers."""
    class _Busy(_FlakyDb):
        async def ping_outside_pool(self, timeout):
            await super().ping_outside_pool(timeout)
            if self.outside_pings == 8:
                self.exhausted = False  # the pushes ended

    exits = []
    # 8 busy rounds (more than WATCHDOG_MAX_FAILURES), then 3 real failures.
    db = _Busy(["fail"] * 8 + ["ok", "fail", "fail", "fail"], exhausted=True)
    await main._db_watchdog(db, exit_process=exits.append)
    assert db.outside_pings == 8
    assert exits == [1] and db.outcomes == []


@pytest.mark.asyncio
async def test_a_pool_busy_for_too_long_exits_the_worker(fast, monkeypatch):
    monkeypatch.setattr(main, "WATCHDOG_BUSY_MAX_S", 0)
    exits = []
    db = _FlakyDb(["fail"] * 3, exhausted=True)
    await main._db_watchdog(db, exit_process=exits.append)
    assert exits == [1]


@pytest.mark.asyncio
async def test_a_full_pool_of_a_database_that_does_not_answer_exits_the_worker(fast):
    exits = []
    db = _FlakyDb(["fail"] * 3, exhausted=True, answers=False)
    await main._db_watchdog(db, exit_process=exits.append)
    assert exits == [1] and db.outside_pings == 3


def test_the_default_exit_ends_the_process():
    assert main._db_watchdog.__defaults__ == (os._exit,)
