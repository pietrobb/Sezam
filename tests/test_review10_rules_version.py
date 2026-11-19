"""Review 8595ec1 (medium, R10-B, goal #372): the team log's rules had no version.

A log the server stored under older rules (before review 1141a20 a member
could get a retired key back: remove + re-add, or a rotation back) no longer
replayed once the rules tightened, and every signed-in request of everyone
ended in a bare 500. A record's "v" now names the rules it is judged by; the
version never goes down along the log, and new records carry the newest. A
stored log that really does not replay (a damaged database) is answered with
503 team_log_unreadable instead of a 500.
"""

from __future__ import annotations

import time

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam import teamlog as tl
from server.app import team_log
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)
from tests.test_team_log_server import ADMIN, BOB, CAROL, FOLDER, K1, Team, _append, _auth

ROTATED = SigningKey.generate()
ROTATED_ENC = PrivateKey.generate().public_key.encode().hex()


def _signed(team: Team, kind: str, author: str, data: dict, rules: int, signer=None) -> dict:
    body = tl.next_body(team.state, kind, author, data)
    body["v"] = rules
    record = tl.sign_record(body, signer or team.sk[author])
    team.accept(record)
    return record


def _rules_1_log(team: Team) -> list[dict]:
    """Founded under rules 1: bob rotates, is removed and comes back on his
    retired keys (refused since review 1141a20)."""
    bob = team.keys(BOB)
    records = [
        _signed(team, "genesis", ADMIN, {"org": "01JG0000000000000000000001", "user_id": ADMIN,
                                         **team.keys(ADMIN)}, 1),
        _signed(team, "member.add", ADMIN, {"user_id": BOB, **bob, "role": "member"}, 1),
        _signed(team, "member.add", ADMIN, {"user_id": CAROL, **team.keys(CAROL), "role": "member"}, 1),
    ]
    new_spk = ROTATED.verify_key.encode().hex()
    proof = ROTATED.sign(tl.new_key_message(team.state.head_hash, BOB, new_spk, ROTATED_ENC)).signature.hex()
    records.append(_signed(team, "member.keys", BOB, {
        "user_id": BOB, "signing_pk": new_spk, "encryption_pk": ROTATED_ENC, "new_key_sig": proof,
    }, 1))
    records.append(_signed(team, "member.remove", ADMIN, {"user_id": BOB}, 1))
    records.append(_signed(team, "member.add", ADMIN, {"user_id": BOB, **bob, "role": "member"}, 1))
    return records


def _store(db, records: list[dict]) -> None:
    """What a server before the rule change accepted and kept."""
    rows = db._storage.setdefault("team_log", [])
    prev = tl.ZERO_HASH
    for seq, record in enumerate(records):
        rows.append({
            "seq": seq, "prev": prev, "hash": tl.record_hash(record), "body": record["body"],
            "sig": record["sig"], "author": tl.parse_body(record["body"])["author"],
            "created_at": int(time.time() * 1000),
        })
        prev = tl.record_hash(record)
    team_log.forget_cache()


@pytest.mark.asyncio
async def test_a_log_stored_under_older_rules_still_serves_and_signs_in(app_client, mock_db):  # noqa: F811
    team = Team(mock_db)
    _store(mock_db, _rules_1_log(team))

    resp = await app_client.get("/api/team-log?since=-1", headers=_auth(team.token[CAROL]))
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["records"]) == 6
    pull = await app_client.get("/api/sync?since_commit_seq=0", headers=_auth(team.token[BOB]))
    assert pull.status_code == 200, pull.text
    assert pull.json()["team_log_head"]["seq"] == 5

    # The next record follows today's rules and the log goes on.
    key = tl.sign_record(tl.next_body(team.state, "folder.key", ADMIN, {
        "folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None}), team.sk[ADMIN])
    assert tl.parse_body(key["body"])["v"] == tl.FORMAT_VERSION == 2
    resp = await _append(app_client, team, ADMIN, key)
    assert resp.status_code == 200, resp.text
    team.accept(key)
    team_log.forget_cache()
    state = tl.replay([{"body": r["body"], "sig": r["sig"]} for r in mock_db._storage["team_log"]])
    assert state.rules == 2 and state.to_json() == team.state.to_json()

    # ... and never back to the older rules.
    back = tl.next_body(team.state, "access.set", ADMIN, {"folder": FOLDER, "user_id": BOB, "level": "read"})
    back["v"] = 1
    resp = await _append(app_client, team, ADMIN, tl.sign_record(back, team.sk[ADMIN]))
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["team_log_code"] == "rules_outdated"
    # The rules themselves refuse it as well (every client replays by them).
    with pytest.raises(tl.TeamLogError) as refused:
        tl.apply_record(team.state, tl.sign_record(back, team.sk[ADMIN]))
    assert refused.value.code == "rules_downgrade"


@pytest.mark.asyncio
async def test_a_log_still_at_rules_1_takes_no_new_rules_1_record(app_client, mock_db):  # noqa: F811
    """Review c78fd19 (medium): the server accepted records under the old rules
    v1 while the stored log had not moved past them. Bob's retired key back,
    signed as rules 1, replays (the rules of that record allow it), but no new
    record follows the old rules: the server refuses it and nothing is stored."""
    team = Team(mock_db)
    records = _rules_1_log(team)[:5]  # bob rotated and was removed, still rules 1
    _store(mock_db, records)
    state = tl.replay(records)
    readd = {"user_id": BOB, **team.keys(BOB), "role": "member"}
    old = tl.next_body(state, "member.add", ADMIN, readd)
    old["v"] = 1
    back = tl.sign_record(old, team.sk[ADMIN])
    assert tl.apply_record(state, back).members[BOB].active  # rules 1 allow it
    resp = await _append(app_client, team, ADMIN, back)
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["team_log_code"] == "rules_outdated"
    assert len(mock_db._storage["team_log"]) == 5

    # Under today's rules the same re-add is a retired key reused.
    today = tl.sign_record(tl.next_body(state, "member.add", ADMIN, readd), team.sk[ADMIN])
    resp = await _append(app_client, team, ADMIN, today)
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["team_log_code"] == "key_reused"


@pytest.mark.asyncio
async def test_a_damaged_stored_log_is_named_not_a_500(app_client, mock_db):  # noqa: F811
    team = Team(mock_db)
    records = _rules_1_log(team)
    records[4] = dict(records[4], sig="00" * 64)
    _store(mock_db, records)

    for path, who in (("/api/team-log?since=-1", CAROL), ("/api/sync?since_commit_seq=0", BOB)):
        resp = await app_client.get(path, headers=_auth(team.token[who]))
        assert resp.status_code == 503, resp.text
        assert resp.json()["code"] == "team_log_unreadable"
        assert resp.json()["detail"]["seq"] == 4
