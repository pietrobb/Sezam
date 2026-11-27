"""Review c02cc47 (R17), open from review 9 (server): work done under the push lock.

- V3: POST /api/sync parsed and replayed its team log records only under the
  global commit_counter lock (POST /api/team-log does it before); every
  other push waited for it.
- _prepare parsed every body of a member's batch before the member limit
  refused it (up to 1000 records of 4 KiB).
- V5: whether the pusher is the admin came from the request's sign-in, not
  from the log under the lock: a handover landing meanwhile left the old
  admin's push the admin's rights.
- GET /api/team-log read every record after ``since`` and cut the page in
  Python, not in SQL.
- personal_tree.ever_admin parsed each of an account's records again under
  the push lock; the authors come with the cached replay.
"""

from __future__ import annotations

import pytest

from server.app import team_log
from tests.test_server_spec import MockCursor, app_client, mock_db  # noqa: F401  (fixtures)
from tests.test_team_log_server import ADMIN, BOB, CAROL, FOLDER, K1, K2, Team, _append, _auth
from tests.test_team_log_server_push import _errors, _obj, _push, _team_folder

LOCK = "SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE"


@pytest.fixture
def events(monkeypatch):
    seen: list[str] = []
    real_execute, real_prepare = MockCursor.execute, team_log._prepare

    async def execute(self, query, args=()):
        if " ".join(query.split()) == LOCK:
            seen.append("lock")
        return await real_execute(self, query, args)

    async def prepare(*args, **kwargs):
        seen.append("prepare")
        return await real_prepare(*args, **kwargs)

    monkeypatch.setattr(MockCursor, "execute", execute)
    monkeypatch.setattr(team_log, "_prepare", prepare)
    return seen


@pytest.mark.asyncio
async def test_a_sync_push_replays_its_team_log_records_before_the_lock(app_client, mock_db, events):  # noqa: F811
    team = Team(mock_db)
    await _team_folder(app_client, team)
    rekey = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 1, "dek_id": K2, "prev_dek_id": K1})
    team.accept(rekey)
    events.clear()
    resp = await _push(app_client, team, ADMIN, [
        _obj(team.sk[ADMIN], K2, "dek", b"wrapped K2" * 8, parent=FOLDER)], [rekey])
    assert resp.status_code == 200, resp.text
    assert events == ["prepare", "lock"], events


@pytest.mark.asyncio
async def test_a_members_oversized_batch_is_refused_before_a_body_is_parsed(
        app_client, mock_db, monkeypatch):  # noqa: F811
    team = Team(mock_db)
    await _team_folder(app_client, team)
    parsed = {"n": 0}
    real = team_log._parse

    def counting(record):
        parsed["n"] += 1
        return real(record)

    monkeypatch.setattr(team_log, "_parse", counting)
    junk = [{"body": "{" + "x" * 4000 + "}", "sig": "00" * 64}] * (team_log.MAX_RECORDS_FROM_MEMBER + 1)
    resp = await _append(app_client, team, BOB, *junk)
    assert resp.status_code == 400 and resp.json()["code"] == "team_log_refused", resp.text
    assert parsed["n"] == 0, parsed


@pytest.mark.asyncio
async def test_a_handover_meanwhile_leaves_the_old_admins_push_no_admin_rights(
        app_client, mock_db, monkeypatch):  # noqa: F811
    team = Team(mock_db)
    await _team_folder(app_client, team)
    promote = team.record("member.role", ADMIN, {"user_id": BOB, "role": "admin"})
    team.accept(promote)
    demote = team.record("member.role", ADMIN, {"user_id": ADMIN, "role": "member"})
    team.accept(demote)
    handed = {"done": False}
    real = MockCursor.execute

    async def handover_at_the_lock(self, query, args=()):
        if not handed["done"] and " ".join(query.split()) == LOCK:
            handed["done"] = True  # signed in as the admin; the handover lands first
            await team_log.append(self, [promote, demote], ADMIN)
        return await real(self, query, args)

    monkeypatch.setattr(MockCursor, "execute", handover_at_the_lock)
    envelope = _obj(team.sk[ADMIN], "01JV0000000000000000000009", "envelope", b"e" * 80,
                    parent=K1, target=CAROL, level="read")
    assert _errors(await _push(app_client, team, ADMIN, [envelope])) == ["target_user_id is admin only"]
    assert handed["done"]


@pytest.mark.asyncio
async def test_a_team_log_page_is_limited_in_sql(app_client, mock_db, monkeypatch):  # noqa: F811
    team = Team(mock_db)
    await _team_folder(app_client, team)
    seen: list[tuple] = []
    real = MockCursor.execute

    async def recording(self, query, args=()):
        if "FROM team_log WHERE seq >" in query:
            seen.append((" ".join(query.split()), tuple(args)))
        return await real(self, query, args)

    monkeypatch.setattr(MockCursor, "execute", recording)
    async with mock_db.acquire() as conn:
        async with conn.cursor() as cur:
            page = await team_log.records_after(cur, -1, limit=2)
    assert len(page) == 2
    assert seen and all(q.endswith("LIMIT %s") and a[-1] == 2 for q, a in seen), seen
    resp = await app_client.get("/api/team-log?since=-1", headers=_auth(team.token[BOB]))
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_after_a_restore_to_a_shorter_log_the_worker_replays_it_once(
        app_client, mock_db, monkeypatch):  # noqa: F811
    team = Team(mock_db)
    await _team_folder(app_client, team)
    assert (await app_client.get("/api/team-log?since=-1", headers=_auth(team.token[BOB]))).status_code == 200
    mock_db._storage["team_log"] = mock_db._storage["team_log"][:3]  # the server is put back
    replays = {"n": 0}
    real = team_log._replay_stored

    def counting(entry, rows):
        replays["n"] += 1
        return real(entry, rows)

    monkeypatch.setattr(team_log, "_replay_stored", counting)
    for _ in range(3):
        assert (await app_client.get("/api/org-recovery/status")).status_code == 200
    assert replays["n"] == 1, replays


@pytest.mark.asyncio
async def test_ever_admin_reads_no_log_bodies_once_replayed(app_client, mock_db, monkeypatch):  # noqa: F811
    from server.app import personal_tree

    team = Team(mock_db)
    await _team_folder(app_client, team)
    promote = team.record("member.role", ADMIN, {"user_id": BOB, "role": "admin"})
    team.accept(promote)
    demote = team.record("member.role", ADMIN, {"user_id": ADMIN, "role": "member"})
    team.accept(demote)
    assert (await _append(app_client, team, ADMIN, promote, demote)).status_code == 200
    seen: list[str] = []
    real = MockCursor.execute

    async def recording(self, query, args=()):
        seen.append(" ".join(query.split()))
        return await real(self, query, args)

    async with mock_db.acquire() as conn:
        async with conn.cursor() as cur:
            await team_log.load_state(cur)  # replayed once, as by any request
            monkeypatch.setattr(MockCursor, "execute", recording)
            # The former admin signed as one; Carol never did.
            assert await personal_tree.ever_admin(cur, ADMIN, {})
            assert not await personal_tree.ever_admin(cur, CAROL, {})
    bodies = [q for q in seen if "FROM team_log" in q and "body" in q]
    assert bodies == [], bodies
