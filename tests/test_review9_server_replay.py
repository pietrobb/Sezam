"""Review 1141a20 (R9-F): the server replayed the team log on the event loop
and deep-copied the whole state for every record.

A cold cache (restart, another worker appended) replays every record with an
Ed25519 check each, and an append of up to 1 000 records copied the state
1 000 times: the event loop stalled for every other request meanwhile.

Replay now runs in a worker thread, with one copy of the state per batch.
"""

from __future__ import annotations

import copy
import threading

import pytest

from sezam import teamlog as core
from server.app import team_log
from tests.test_team_log_server import ADMIN, BOB, CAROL, FOLDER, Team, _append, _auth, _founded
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)


def _keys(team: Team, count: int, start: int = 0) -> list[dict]:
    records = []
    for gen in range(start, start + count):
        dek = f"01JD{gen:022d}"
        prev = None if gen == 0 else f"01JD{gen - 1:022d}"
        record = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": gen, "dek_id": dek, "prev_dek_id": prev})
        team.accept(record)
        records.append(record)
    return records


@pytest.fixture
def watched(monkeypatch):
    """Copies of a TeamState and the threads team-log records are applied on."""
    seen = {"copies": 0, "threads": set()}
    real_copy, real_apply = copy.deepcopy, core._apply

    def counting_copy(value, *args, **kwargs):
        if isinstance(value, core.TeamState):
            seen["copies"] += 1
        return real_copy(value, *args, **kwargs)

    def watched_apply(state, record):
        seen["threads"].add(threading.get_ident())
        return real_apply(state, record)

    monkeypatch.setattr(core.copy, "deepcopy", counting_copy)
    monkeypatch.setattr(core, "_apply", watched_apply)
    return seen


@pytest.mark.asyncio
async def test_an_append_copies_the_state_once(app_client, mock_db, watched):  # noqa: F811
    team = Team(mock_db)
    await _founded(app_client, team)
    records = _keys(team, 40)
    watched["copies"] = 0
    resp = await _append(app_client, team, ADMIN, *records)
    assert resp.status_code == 200, resp.text
    assert resp.json()["head"]["seq"] == 42
    assert watched["copies"] <= 2, watched  # the batch's copy (+ the cache check's)


@pytest.mark.asyncio
async def test_replay_runs_off_the_event_loop(app_client, mock_db, watched):  # noqa: F811
    team = Team(mock_db)
    await _founded(app_client, team)
    assert (await _append(app_client, team, ADMIN, *_keys(team, 5))).status_code == 200
    loop_thread = threading.get_ident()
    watched["threads"].clear()
    team_log.forget_cache()  # a restarted worker: the whole log replays
    resp = await app_client.get("/api/team-log?since=-1", headers=_auth(team.token[BOB]))
    assert resp.status_code == 200
    pull = await app_client.get("/api/sync?since_commit_seq=0", headers=_auth(team.token[CAROL]))
    assert pull.json()["team_log_head"]["seq"] == 7
    assert watched["threads"] and loop_thread not in watched["threads"], watched
    more = _keys(team, 2, start=5)
    watched["threads"].clear()
    assert (await _append(app_client, team, ADMIN, *more)).status_code == 200
    assert watched["threads"] and loop_thread not in watched["threads"], watched


@pytest.mark.asyncio
async def test_a_refused_record_in_the_batch_still_refuses_the_whole_append(app_client, mock_db):  # noqa: F811
    team = Team(mock_db)
    await _founded(app_client, team)
    good = _keys(team, 3)
    bad = dict(good[2], sig="00" * 64)
    resp = await _append(app_client, team, ADMIN, good[0], good[1], bad)
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["team_log_code"] == "bad_signature" or "signature" in resp.text
    assert len(mock_db._storage["team_log"]) == 3
    head = (await app_client.get("/api/team-log", headers=_auth(team.token[BOB]))).json()["head"]
    assert head["seq"] == 2
