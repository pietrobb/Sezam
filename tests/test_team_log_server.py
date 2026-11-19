"""Server side of the team log (TL3, goal #346; docs/DESIGN_TEAM_LOG.md §5)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from sezam import teamlog as tl
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    _sign_sync_object,
    app_client,
    mock_db,
)

ADMIN = "01JM0000000000000000000001"
BOB = "01JM0000000000000000000002"
CAROL = "01JM0000000000000000000003"
ORG = "01JG0000000000000000000001"
FOLDER = "01JF0000000000000000000001"
K1, K2, K3 = "01JD0000000000000000000001", "01JD0000000000000000000002", "01JD0000000000000000000003"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _row(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


class Team:
    """Accounts in the mock server and a local copy of the log."""

    def __init__(self, db):
        self.db = db
        self.sk = {}
        self.sk[ADMIN], _ = _create_admin_user(db._storage, ADMIN, "admin")
        self.sk[BOB], _ = _create_regular_user(db._storage, BOB, "bob")
        self.sk[CAROL], _ = _create_regular_user(db._storage, CAROL, "carol")
        self.token = {
            ADMIN: _create_jwt(ADMIN, "admin", True),
            BOB: _create_jwt(BOB, "bob", False),
            CAROL: _create_jwt(CAROL, "carol", False),
        }
        self.state = tl.TeamState()

    def keys(self, user_id: str) -> dict:
        row = _row(self.db, user_id)
        return {"signing_pk": bytes(row["signing_pk"]).hex(), "encryption_pk": bytes(row["encryption_pk"]).hex()}

    def record(self, kind: str, author: str, data: dict, state: tl.TeamState | None = None) -> dict:
        base = state if state is not None else self.state
        return tl.sign_record(tl.next_body(base, kind, author, data), self.sk[author])

    def accept(self, *records: dict) -> None:
        self.state = tl.replay(list(records), self.state)

    def genesis(self) -> dict:
        return self.record("genesis", ADMIN, {"org": ORG, "user_id": ADMIN, **self.keys(ADMIN)})

    def add(self, user_id: str, role: str = "member") -> dict:
        return self.record("member.add", ADMIN, {"user_id": user_id, **self.keys(user_id), "role": role})


async def _append(client, team: Team, author: str, *records: dict):
    return await client.post("/api/team-log", json={"records": list(records)}, headers=_auth(team.token[author]))


async def _founded(client, team: Team) -> None:
    records = [team.genesis()]
    team.accept(records[0])
    records.append(team.add(BOB))
    team.accept(records[1])
    records.append(team.add(CAROL))
    team.accept(records[2])
    resp = await _append(client, team, ADMIN, *records)
    assert resp.status_code == 200, resp.text
    assert resp.json()["head"]["seq"] == 2


@pytest.mark.asyncio
async def test_no_log_until_an_admin_founds_one(app_client, mock_db):
    team = Team(mock_db)
    resp = await app_client.get("/api/team-log", headers=_auth(team.token[BOB]))
    assert resp.status_code == 200
    assert resp.json() == {"records": [], "head": None}
    pull = await app_client.get("/api/sync?since_commit_seq=0", headers=_auth(team.token[BOB]))
    assert pull.json()["team_log_head"] is None


@pytest.mark.asyncio
async def test_founded_log_is_served_and_announced_by_pull(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    resp = await app_client.get("/api/team-log?since=-1", headers=_auth(team.token[CAROL]))
    body = resp.json()
    assert tl.replay(body["records"]).to_json() == team.state.to_json()
    assert body["head"] == {"seq": 2, "hash": team.state.head_hash, "genesis_hash": team.state.genesis_hash}
    tail = await app_client.get("/api/team-log?since=1", headers=_auth(team.token[CAROL]))
    assert len(tail.json()["records"]) == 1
    pull = await app_client.get("/api/sync?since_commit_seq=0", headers=_auth(team.token[BOB]))
    assert pull.json()["team_log_head"]["hash"] == team.state.head_hash


@pytest.mark.asyncio
async def test_an_append_alone_reaches_the_next_pull(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    resp = await app_client.post("/api/sync", json={"objects": [_node(team.sk[ADMIN], FOLDER)]},
                                 headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200, resp.text
    pull = await app_client.get("/api/sync?since_commit_seq=0", headers=_auth(team.token[BOB]))
    seq = pull.json()["max_commit_seq"]
    key = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None})
    team.accept(key)
    assert (await _append(app_client, team, ADMIN, key)).status_code == 200
    # The append moves no commit_seq: the delta from the same seq still
    # carries the new log head (there is no 304 to hide it).
    after = await app_client.get(f"/api/sync?since_commit_seq={seq}", headers=_auth(team.token[CAROL]))
    assert after.status_code == 200
    assert after.json()["team_log_head"]["seq"] == 3


@pytest.mark.asyncio
async def test_an_append_not_on_the_head_is_refused(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    behind = tl.replay([], team.state)
    key = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None})
    team.accept(key)
    assert (await _append(app_client, team, ADMIN, key)).status_code == 200
    # Built on the head before `key`: a sibling change.
    stale = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 0, "dek_id": K2, "prev_dek_id": None},
                        state=behind)
    resp = await _append(app_client, team, ADMIN, stale)
    assert resp.status_code == 409
    assert resp.json()["code"] == "team_log_head_moved"
    assert len(mock_db._storage["team_log"]) == 4


@pytest.mark.asyncio
async def test_two_rekeys_of_one_folder_cannot_both_land(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    key = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None})
    team.accept(key)
    assert (await _append(app_client, team, ADMIN, key)).status_code == 200
    laptop = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 1, "dek_id": K2, "prev_dek_id": K1})
    phone = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 1, "dek_id": K3, "prev_dek_id": K1})
    assert (await _append(app_client, team, ADMIN, laptop)).status_code == 200
    resp = await _append(app_client, team, ADMIN, phone)
    assert resp.status_code == 409 and resp.json()["code"] == "team_log_head_moved"
    log = (await app_client.get("/api/team-log", headers=_auth(team.token[BOB]))).json()
    assert tl.current_key(tl.replay(log["records"]), FOLDER) == K2


@pytest.mark.asyncio
async def test_a_member_cannot_sign_team_changes(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    grab = team.record("member.role", BOB, {"user_id": BOB, "role": "admin"})
    resp = await _append(app_client, team, BOB, grab)
    assert resp.status_code == 400
    assert resp.json()["code"] == "team_log_refused"
    assert resp.json()["detail"]["team_log_code"] == "not_admin"
    assert _row(mock_db, BOB)["is_admin"] == 0


@pytest.mark.asyncio
async def test_only_your_own_records(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    # Carol relays a record the admin signed: refused, the admin sends it.
    relayed = team.record("member.role", ADMIN, {"user_id": BOB, "role": "admin"})
    resp = await _append(app_client, team, CAROL, relayed)
    assert resp.status_code == 403
    assert len(mock_db._storage["team_log"]) == 3


@pytest.mark.asyncio
async def test_genesis_needs_an_admin_with_the_keys_the_server_holds(app_client, mock_db):
    team = Team(mock_db)
    by_member = team.record("genesis", BOB, {"org": ORG, "user_id": BOB, **team.keys(BOB)})
    assert (await _append(app_client, team, BOB, by_member)).status_code == 400
    forged = team.record("genesis", ADMIN, {"org": ORG, "user_id": ADMIN, "signing_pk": team.keys(ADMIN)["signing_pk"],
                                            "encryption_pk": team.keys(CAROL)["encryption_pk"]})
    resp = await _append(app_client, team, ADMIN, forged)
    assert resp.status_code == 400 and resp.json()["code"] == "team_log_refused"
    assert mock_db._storage.get("team_log", []) == []


@pytest.mark.asyncio
async def test_member_add_must_name_the_accounts_real_keys(app_client, mock_db):
    team = Team(mock_db)
    genesis = team.genesis()
    team.accept(genesis)
    assert (await _append(app_client, team, ADMIN, genesis)).status_code == 200
    eve_keys = {"signing_pk": "11" * 32, "encryption_pk": "22" * 32}
    fake = team.record("member.add", ADMIN, {"user_id": BOB, **eve_keys, "role": "member"})
    resp = await _append(app_client, team, ADMIN, fake)
    assert resp.status_code == 400
    _row(mock_db, CAROL)["status"] = "pending"
    pending = team.add(CAROL)
    assert (await _append(app_client, team, ADMIN, pending)).status_code == 400


@pytest.mark.asyncio
async def test_removal_and_demotion_reach_the_users_table(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    mock_db._storage.setdefault("write_acl", []).append({"user_id": CAROL, "node_id": FOLDER, "granted_at": 1})
    remove = team.record("member.remove", ADMIN, {"user_id": CAROL})
    team.accept(remove)
    # TL7: one admin, so the role is handed over in one append.
    promote = team.record("member.role", ADMIN, {"user_id": BOB, "role": "admin"})
    team.accept(promote)
    demote = team.record("member.role", ADMIN, {"user_id": ADMIN, "role": "member"})
    team.accept(demote)
    before = _row(mock_db, ADMIN).get("token_epoch") or 0
    assert (await _append(app_client, team, ADMIN, remove, promote, demote)).status_code == 200
    carol = _row(mock_db, CAROL)
    assert carol["status"] == "revoked"
    assert [a for a in mock_db._storage["write_acl"] if a["user_id"] == CAROL] == []
    assert _row(mock_db, BOB)["is_admin"] == 1
    assert _row(mock_db, ADMIN)["is_admin"] == 0
    assert (_row(mock_db, ADMIN).get("token_epoch") or 0) == before + 1


@pytest.mark.asyncio
async def test_a_second_admin_is_refused_for_now(app_client, mock_db):
    """TL7: one admin per organisation until every client manages the team
    from the log; nothing of the refused append lands."""
    team = Team(mock_db)
    await _founded(app_client, team)
    promote = team.record("member.role", ADMIN, {"user_id": BOB, "role": "admin"})
    resp = await _append(app_client, team, ADMIN, promote)
    assert resp.status_code == 400 and resp.json()["code"] == "team_log_refused"
    assert "one admin" in resp.json()["detail"]["message"]
    assert len(mock_db._storage["team_log"]) == 3
    assert _row(mock_db, BOB)["is_admin"] == 0


@pytest.mark.asyncio
async def test_a_log_founded_with_two_admins_is_refused(app_client, mock_db):
    team = Team(mock_db)
    genesis = team.genesis()
    team.accept(genesis)
    resp = await _append(app_client, team, ADMIN, genesis, team.add(BOB, role="admin"))
    assert resp.status_code == 400 and "one admin" in resp.json()["detail"]["message"]
    assert mock_db._storage.get("team_log", []) == []


@pytest.mark.asyncio
async def test_unsigned_revoke_of_a_team_member_is_refused(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    resp = await app_client.delete(f"/api/users/{BOB}", headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 409 and resp.json()["code"] == "team_log_required"
    assert _row(mock_db, BOB)["status"] == "active"
    # An account the log never added (pending invitee, say) is revoked as before.
    _create_regular_user(mock_db._storage, "01JM0000000000000000000009", "dan")
    resp = await app_client.delete("/api/users/01JM0000000000000000000009", headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200


def test_the_docker_image_ships_the_shared_rules():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert "COPY --chown=sezam:sezam src/sezam/teamlog.py /app/server/app/teamlog_core.py" in (
        root / "Dockerfile").read_text(encoding="utf-8")
    assert not (root / "server" / "app" / "teamlog_core.py").exists()


def _node(sk, node_id: str, version: int = 1) -> dict:
    payload = b"node " + node_id.encode()
    payload_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": node_id, "object_type": "node", "payload": base64.b64encode(payload).decode(),
        "parent_ref": None, "version": version, "is_deleted": 0, "payload_hash": payload_hash,
        "signature": _sign_sync_object(sk, node_id, "node", None, None, 0, version, payload_hash),
    }


@pytest.mark.asyncio
async def test_a_refused_record_refuses_the_whole_push(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    bad = team.record("member.remove", ADMIN, {"user_id": ADMIN})  # last admin
    resp = await app_client.post("/api/sync", json={
        "objects": [_node(team.sk[ADMIN], FOLDER)], "atomic_batch": True, "team_log": [bad],
    }, headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 400 and resp.json()["code"] == "team_log_refused"
    assert not [o for o in mock_db._storage.get("vault_objects", []) if o["id"] == FOLDER]


@pytest.mark.asyncio
async def test_records_and_objects_land_together(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    key = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None})
    team.accept(key)
    resp = await app_client.post("/api/sync", json={
        "objects": [_node(team.sk[ADMIN], FOLDER)], "atomic_batch": True, "team_log": [key],
    }, headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["accepted"]) == 1
    assert [r["seq"] for r in mock_db._storage["team_log"]] == [0, 1, 2, 3]
