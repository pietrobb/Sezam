"""Review 8595ec1 (low): the GC clock guard was per worker, and GC days were not checked.

The guard against a server clock jumping forward (review d150605 N7) let the
GC clock move by the time elapsed in the worker that ran GC. The clock lives
in the database and is shared, so every new worker's first run moved it a
full day, and workers taking turns each added their own elapsed time: enough
worker restarts after a jump collected tombstones written a minute earlier.
SEZAM_TOMBSTONE_GC_DAYS=0 was taken as is and collected every tombstone.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from sezam import cli
from server.app import main
from server.app.config import ServerConfig
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)

DAY_S = 86_400


def _tombstones(db) -> set[str]:
    return {o["id"] for o in db._storage["vault_objects"] if o.get("is_deleted")}


def _fresh_tombstone(url, tmp_path) -> str:
    laptop = _vault(tmp_path / "laptop", "admin")
    gone = laptop.create_entry(laptop.create_node("F"), "gone", [{"key": "k", "value": "v"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.delete_entry(gone)
    assert _client(laptop, url).push()["conflicts"] == []
    laptop.lock()
    return gone


class _Clocks:
    """Fake wall and monotonic time for the GC runs of several workers."""

    def __init__(self, monkeypatch):
        self.wall = time.time()
        self.mono = 1000.0
        self.workers: dict[str, tuple[float, int] | None] = {}
        monkeypatch.setattr(main.time, "time", lambda: self.wall)
        monkeypatch.setattr(main.time, "monotonic", lambda: self.mono)
        monkeypatch.setattr(main, "_gc_clock_last_run", None)

    def gc(self, db, worker: str) -> None:
        main._gc_clock_last_run = self.workers.get(worker)
        asyncio.run(main._cleanup_tombstones(db, 90))
        self.workers[worker] = main._gc_clock_last_run

    def pass_time(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


def test_new_workers_after_a_clock_jump_do_not_collect_fresh_tombstones(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    gone = _fresh_tombstone(url, tmp_path)
    clocks = _Clocks(monkeypatch)
    clocks.gc(db, "w0")
    clocks.wall += 200 * DAY_S  # the clock jumps forward

    # Workers come and go (restarts, recycling); each new one runs GC once.
    for n in range(100):
        clocks.pass_time(60)
        clocks.gc(db, f"new-{n}")

    assert gone in _tombstones(db)
    assert db._storage["commit_counter"][0]["gc_floor_seq"] == 0


def test_workers_taking_turns_move_the_clock_by_the_time_that_passed(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    _fresh_tombstone(url, tmp_path)
    clocks = _Clocks(monkeypatch)
    clocks.gc(db, "a")
    clocks.gc(db, "b")
    start = db._storage["commit_counter"][0]["gc_clock_ms"]
    clocks.wall += 200 * DAY_S

    for _ in range(10):
        for worker in ("a", "b"):
            clocks.pass_time(3600)
            clocks.gc(db, worker)

    moved_ms = db._storage["commit_counter"][0]["gc_clock_ms"] - start
    # 20 hours passed; a minute of slack per run.
    assert moved_ms <= (20 * 3600 + 20 * 60 + 60) * 1000, moved_ms / 3_600_000


def test_the_clock_still_follows_the_time_that_passes(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    _fresh_tombstone(url, tmp_path)
    clocks = _Clocks(monkeypatch)
    clocks.gc(db, "a")
    start = db._storage["commit_counter"][0]["gc_clock_ms"]
    for worker in ("a", "b", "a", "c", "b"):
        clocks.pass_time(3600)
        clocks.gc(db, worker)
    assert db._storage["commit_counter"][0]["gc_clock_ms"] - start == 5 * 3600 * 1000


@pytest.mark.parametrize("days", ["0", "-1", "6"])
def test_tombstone_gc_days_below_the_minimum_is_refused(monkeypatch, days):
    monkeypatch.setenv("SEZAM_HMAC_SECRET", "x" * 32)
    monkeypatch.setenv("SEZAM_TOMBSTONE_GC_DAYS", days)
    with pytest.raises(ValueError, match="SEZAM_TOMBSTONE_GC_DAYS"):
        ServerConfig.from_env()


def test_tombstone_gc_days_default_and_valid(monkeypatch):
    monkeypatch.setenv("SEZAM_HMAC_SECRET", "x" * 32)
    monkeypatch.delenv("SEZAM_TOMBSTONE_GC_DAYS", raising=False)
    assert ServerConfig.from_env().tombstone_gc_days == 90
    monkeypatch.setenv("SEZAM_TOMBSTONE_GC_DAYS", "7")
    assert ServerConfig.from_env().tombstone_gc_days == 7
