"""Review c78fd19 (medium, server): work anyone could make the server do.

- /api/org-recovery/status and /blob (no sign-in) read every org.recovery
  record of each admin from the whole log, parsing each body on the event
  loop, on every call: 50 parallel calls made /health take 6.3 s. The seq of
  each admin's last org.recovery record now comes with the cached replay.
- A cold cache (a fresh worker) replayed the whole log in every request that
  found it cold at the same time (19-37 s); one replays, the rest wait for it.
- POST /api/auth/rejoin took the lock every push waits on before it checked
  that the log holds the keys at all; keys of one's own are now refused from
  a plain read.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from nacl.signing import SigningKey

from server.app import team_log
from server.app.auth import generate_bound_challenge
from sezam.vault.reseed import REJOIN_CONTEXT, reseed_message
from tests.test_review2_server_mariadb import mariadb  # noqa: F401  (fixture)
from tests.test_server_spec import MockCursor, app_client, mock_db  # noqa: F401  (fixtures)
from tests.test_team_log_server import ADMIN, BOB, FOLDER, Team, _append, _auth, _founded

SECRET = "test-server-secret-key-12345"  # app_client's hmac_server_secret


@pytest.fixture
def queries(monkeypatch):
    seen: list[str] = []
    real = MockCursor.execute

    async def recording(self, query, args=()):
        seen.append(" ".join(query.split()))
        return await real(self, query, args)

    monkeypatch.setattr(MockCursor, "execute", recording)
    return seen


@pytest.fixture
def replays(monkeypatch):
    count = {"n": 0}
    real = team_log._replay_stored

    def counting(entry, rows):
        count["n"] += 1
        return real(entry, rows)

    monkeypatch.setattr(team_log, "_replay_stored", counting)
    return count


def _folder_keys(team: Team, count: int) -> list[dict]:
    records = []
    for gen in range(count):
        record = team.record("folder.key", ADMIN, {
            "folder": FOLDER, "gen": gen, "dek_id": f"01JD{gen:022d}",
            "prev_dek_id": None if gen == 0 else f"01JD{gen - 1:022d}",
        })
        team.accept(record)
        records.append(record)
    return records


async def _with_logged_recovery(app_client, mock_db) -> tuple[Team, str]:  # noqa: F811
    team = Team(mock_db)
    await _founded(app_client, team)
    recovery_pk = bytes(SigningKey.generate().verify_key).hex()
    key = team.record("org.recovery", ADMIN, {"recovery_pk": recovery_pk})
    team.accept(key)
    wrap = team.record("org.recovery.wrap", ADMIN, {
        "wrapped_kek": os.urandom(72).hex(), "key_epoch": 0, "threshold": 2, "total_shares": 3,
    })
    team.accept(wrap)
    resp = await _append(app_client, team, ADMIN, key, wrap, *_folder_keys(team, 20))
    assert resp.status_code == 200, resp.text
    return team, recovery_pk


@pytest.mark.asyncio
async def test_recovery_status_reads_no_log_records_once_replayed(app_client, mock_db, queries):  # noqa: F811
    team, recovery_pk = await _with_logged_recovery(app_client, mock_db)
    team_log.forget_cache()
    first = (await app_client.get("/api/org-recovery/status", headers=_auth(team.token[BOB]))).json()
    assert first["configured"] and first["recovery_signing_pk"] == recovery_pk, first
    queries.clear()
    for path in ("/api/org-recovery/status", f"/api/org-recovery/blob?recovery_signing_pk={recovery_pk}"):
        resp = await app_client.get(path)
        assert resp.status_code == 200, resp.text
    read_log = [q for q in queries if "FROM team_log" in q and "body" in q]
    assert read_log == [], read_log


@pytest.mark.asyncio
async def test_the_last_logged_recovery_seq_still_ranks_against_the_stored_blob(app_client, mock_db):  # noqa: F811
    """The org.recovery record is seq 3: a blob stored at log head 2 is older,
    one stored at head 22 newer (review 4acfdde R11 #2)."""
    team, logged_pk = await _with_logged_recovery(app_client, mock_db)
    other_pk = bytes(SigningKey.generate().verify_key).hex()
    for log_seq, expected in ((2, logged_pk), (22, other_pk)):
        mock_db._storage["org_recovery_blobs"] = [{
            "id": 1, "wrapped_kek": os.urandom(72), "recovery_signing_pk": bytes.fromhex(other_pk),
            "threshold": 2, "total_shares": 3, "created_by": ADMIN, "created_at": 1,
            "key_epoch": 0, "log_seq": log_seq,
        }]
        status = (await app_client.get("/api/org-recovery/status", headers=_auth(team.token[BOB]))).json()
        assert status["recovery_signing_pk"] == expected, (log_seq, status)


@pytest.mark.asyncio
async def test_a_cold_worker_replays_the_log_once_for_parallel_requests(app_client, mock_db, replays):  # noqa: F811
    team, _pk = await _with_logged_recovery(app_client, mock_db)
    team_log.forget_cache()  # a fresh worker
    replays["n"] = 0
    answers = await asyncio.gather(
        *(app_client.get("/api/org-recovery/status") for _ in range(25)),
        *(app_client.get("/api/team-log?since=-1", headers=_auth(team.token[BOB])) for _ in range(25)),
    )
    assert {resp.status_code for resp in answers} == {200}
    assert replays["n"] == 1, replays
    # A later append replays only what it adds.
    more = team.record("folder.key", ADMIN, {
        "folder": FOLDER, "gen": 20, "dek_id": f"01JD{20:022d}", "prev_dek_id": f"01JD{19:022d}",
    })
    team.accept(more)
    assert (await _append(app_client, team, ADMIN, more)).status_code == 200
    assert (await app_client.get("/api/org-recovery/status")).status_code == 200


@pytest.mark.asyncio
async def test_the_team_log_is_indexed_by_author_also_after_an_upgrade(mariadb):  # noqa: F811
    """personal_tree reads a member's own records by author (MariaDB)."""
    async def indexed() -> bool:
        async with mariadb.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SHOW INDEX FROM team_log WHERE Key_name = 'idx_team_log_author'")
                return bool(await cur.fetchall())

    assert await indexed()
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("ALTER TABLE team_log DROP INDEX idx_team_log_author")
    assert not await indexed()
    await mariadb.create_schema()  # a server from before this review starts
    assert await indexed()


@pytest.mark.asyncio
async def test_a_rejoin_with_keys_the_log_does_not_hold_takes_no_lock(app_client, mock_db, queries):  # noqa: F811
    team = Team(mock_db)
    await _founded(app_client, team)
    mock_db._storage["users"] = [u for u in mock_db._storage["users"] if u["id"] != BOB]  # a restore lost bob
    for user_id, keys in (("01JM0000000000000000000009", None), (BOB, None), (ADMIN, "logged")):
        sk = team.sk[ADMIN] if keys else SigningKey.generate()
        signing_pk = bytes(sk.verify_key)
        encryption_pk = bytes.fromhex(team.state.members[ADMIN].encryption_pk) if keys else os.urandom(32)
        challenge, _ = generate_bound_challenge(SECRET, "bob")
        message = reseed_message(challenge, user_id, "bob", signing_pk, encryption_pk, 0, REJOIN_CONTEXT)
        queries.clear()
        resp = await app_client.post("/api/auth/rejoin", json={
            "username": "bob", "user_id": user_id, "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(), "key_epoch": 0, "challenge": challenge.hex(),
            "signature": sk.sign(message).signature.hex(),
        })
        # Not in the log, bob with keys of one's own: 401; the admin's account exists: 409.
        assert resp.status_code == (409 if keys else 401), (user_id, resp.text)
        locked = [q for q in queries if "FOR UPDATE" in q.upper()]
        assert locked == [], (user_id, locked)
