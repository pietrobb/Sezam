"""Review d150605 N7: a server clock jump past the retention collected every tombstone.

Tombstone GC compared modified_at with the wall clock. A clock set forward by
more than 90 days (a bad NTP source, a reset RTC) made a tombstone written a
minute ago look expired: one run collected them all, and every device that had
not pulled them got a 410 and a full resync.
"""

from __future__ import annotations

import asyncio
import time

from sezam import cli
from server.app import main
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)

DAY_S = 86_400


def _tombstones(db) -> set[str]:
    return {o["id"] for o in db._storage["vault_objects"] if o.get("is_deleted")}


def _gc(db, monkeypatch, *, ahead_days: float = 0) -> None:
    real = time.time
    with monkeypatch.context() as m:
        m.setattr(main.time, "time", lambda: real() + ahead_days * DAY_S)
        asyncio.run(main._cleanup_tombstones(db, 90))


def test_a_clock_jump_does_not_collect_fresh_tombstones(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    gone = laptop.create_entry(folder, "gone", [{"key": "k", "value": "v"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.delete_entry(gone)
    assert _client(laptop, url).push()["conflicts"] == []
    laptop.lock()
    assert gone in _tombstones(db)

    _gc(db, monkeypatch)  # a normal run: nothing is 90 days old
    assert gone in _tombstones(db)

    _gc(db, monkeypatch, ahead_days=200)  # the clock jumps forward
    assert gone in _tombstones(db)

    monkeypatch.setattr(main, "_gc_clock_last_run", None)  # server restarted
    _gc(db, monkeypatch, ahead_days=200)
    assert gone in _tombstones(db)
    assert db._storage["commit_counter"][0]["gc_floor_seq"] == 0


def test_tombstones_older_than_the_retention_still_go(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    gone = laptop.create_entry(laptop.create_node("F"), "gone", [{"key": "k", "value": "v"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.delete_entry(gone)
    assert _client(laptop, url).push()["conflicts"] == []
    laptop.lock()

    _gc(db, monkeypatch)
    for obj in db._storage["vault_objects"]:
        if obj["id"] == gone:
            obj["modified_at"] = int((time.time() - 91 * DAY_S) * 1000)
    _gc(db, monkeypatch)
    assert gone not in _tombstones(db)
