"""Deep stateful run on c6d3dff (R16-Z SM6): a record withdrawn on a 409 and
taken when sent again stayed withdrawn.

INV-7 (docs/ROOT_CAUSE_PLAN.md): an honest server leaves no device stuck.
The server answered a team-log append 'team_log_head_moved' (its log was
lost and the device put it back; here: its head did not move after all); the
device withdrew the records (R16-H1), rebuilt the same change on the same
head, got the same records and the server took them. They stayed withdrawn:
the next record, signed on them, was withdrawn with them, and when that
record's reply was lost and the server held it, every pull of that device
answered 'holds record N, which this device withdrew' for good.

A record in the device's own log is not withdrawn (team_log_withdrawn.py
note_stored; the page's noteWebTeamRecordsTaken; the phone's remake append).
"""

from __future__ import annotations

import json

import pytest

from sezam import teamlog as tl
from sezam.models import new_ulid
from sezam.vault import team_log_withdrawn
from sezam.vault.sync_common import ServerError
from tests.node_support import node_problem
from tests.team_log_fork_vectors import _base
from tests.team_log_vectors import B, F1, K
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_r16_fork_following import _web_run
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401

# The page sends its last two records: 409 first, then taken as they are.
WEB_TAKEN = """
    const store = new Map();
    idbKeysRequest = async (mode, op) => op({
        get: id => store.get(id), put: row => { store.set(row.id, row); },
    });
    state.kek = new Uint8Array(32).fill(7);
    state.userId = ids.A;
    const prefix = RECORDS.slice(0, -2), mine = RECORDS.slice(-2);
    apiFetch = async (url) => {
        const since = Number(/since=(-?\\d+)/.exec(url)[1]);
        return { records: RECORDS.slice(since + 1, since + 3) };
    };
    const moved = new Error('409 the team log moved on'); moved.status = 409;
    try { await sendWebTeamRecords(mine, async () => { throw moved; }, sodium); } catch (err) { /* rebuilt */ }
    await sendWebTeamRecords(mine, async () => ({}), sodium);
    const withdrawn = [...(await loadWebTeamLedger(sodium)).withdrawn];
    try {
        const got = await syncWebTeamLog(head(RECORDS), { records: prefix, team: teamOf(prefix) }, null, sodium);
        return { withdrawn, head: got.team.headSeq };
    } catch (err) { return { withdrawn, error: err.message }; }
"""


def _key() -> tuple:
    return ("folder.key", {"folder": new_ulid(), "dek_id": new_ulid(), "prev_dek_id": None})


def test_a_record_taken_on_the_second_try_is_not_withdrawn(team, monkeypatch):
    _db, _admin, admin_client, bob, _bob_client = team
    _found_with_bob(admin_client, bob)
    original = admin_client._request
    sent = {"moved": 1, "lost": 0}

    def request(method, path, body=None, auth=False, **kw):
        records = (body or {}).get("records") or (body or {}).get("team_log") or []
        if method == "POST" and records and sent["moved"]:
            sent["moved"] -= 1
            raise ServerError(409, json.dumps({"detail": {"message": "the team log moved on"},
                                               "code": "team_log_head_moved"}))
        answer = original(method, path, body, auth=auth, **kw)
        if method == "POST" and records and sent["lost"]:
            sent["lost"] -= 1
            raise RuntimeError("Connection reset: the reply was lost")
        return answer

    monkeypatch.setattr(admin_client, "_request", request)
    taken = admin_client.append_team_log([_key()])
    held = {row["hash"] for row in admin_client._db.fetchall("SELECT hash FROM team_log")}
    assert not held & team_log_withdrawn.withdrawn(admin_client._db), "a record in its own log is withdrawn"

    sent["lost"] = 1
    with pytest.raises(RuntimeError, match="reply was lost"):
        admin_client.append_team_log([_key()])
    monkeypatch.undo()
    # The server holds it: the next pull follows it.
    admin_client._refresh_team_log()
    state = admin_client.team_state()
    assert state.head_seq == taken.head_seq + 1
    assert tl.parse_body(admin_client._db.fetchone(
        "SELECT body FROM team_log WHERE seq = ?", (state.head_seq,))["body"])["type"] == "folder.key"


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_page_takes_back_a_withdrawn_record_the_server_took():
    result = _web_run(WEB_TAKEN, _base())
    assert result.get("error") is None and result["withdrawn"] == [], result
