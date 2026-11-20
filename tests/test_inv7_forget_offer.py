"""INV-7 (docs/ROOT_CAUSE_PLAN.md, review 8bc70f7 H4/M2): "forget the pinned team
log" is offered exactly where the team's log is lost for good — the server has
none while the device holds, pins or confirmed one, or it starts with another
genesis — and never for a server that lies (behind, a fork, a log that does not
replay, short of its head, TL7).

tests/vectors/team_log_mismatch.json holds every combination of what a device
holds (nothing, a left log, a log, a log and its confirmed genesis, only a
confirmed genesis) and what the server serves (nothing, the same, more, less, a
fork, another genesis, short of its head, a forged record, two admins), with the
answer of an oracle that knows no client code (tests/team_log_mismatch_vectors.py).
Each client follows the server's log through its own code and must give every
answer: the desktop (TeamLogMixin._sync_team_log) and the page (syncWebTeamLog)
here, the phone (syncTeamLog) in mobile/test/team_log_mismatch_vectors_test.dart.

What a user sees decides "offered": the desktop's message names 'sezam team-log
forget-pin', the page's error carries teamLogLost (the sign-in screen's and Team
trust's offer) and names "Forget the pinned team log". Before this list each
client decided it at its own throw sites: on 8bc70f7 the page offered it nowhere
on a refused login (H4).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sezam import teamlog as tl
from sezam.vault.db import VaultDB
from sezam.vault.team_log_local import (
    CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META, TeamLogMismatch, TeamLogMixin,
)
from tests.team_log_mismatch_vectors import VECTORS_PATH, build_vectors, dump
from tests.test_review_web import _function, _run_source
from tests.test_team_log_web_rekey import FUNCTIONS, TEAMLOG_JS
from tests.node_support import node_problem

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
CASES = VECTORS["cases"]


def _seq(record: dict) -> int:
    return tl.parse_body(record["body"])["seq"]


class _Device(TeamLogMixin):
    """The desktop's team log follower over a real vault database; the server
    serves ``served`` and refuses every restore (a restore that lands is INV-2)."""

    def __init__(self, db: VaultDB, served: list[dict]):
        self._db = db
        self._served = served
        self._team_state_cache = None

    def _request(self, method, path, body=None, auth=False):
        assert method == "GET" and path.startswith("/api/team-log?since="), path
        since = int(path.split("since=", 1)[1])
        return {"records": [r for r in self._served if _seq(r) > since]}

    def _restore_server_team_log(self, local, server_head):
        return False


def _desktop(tmp_path: Path, case: dict) -> dict:
    db = VaultDB(tmp_path / (case["name"].replace("/", "-") + ".db"))
    db.open()
    db.create_schema()
    try:
        held = case["device"]
        device = _Device(db, case["server"]["records"])
        if held["records"]:
            device._store_team_log(held["records"], tl.replay(held["records"]))
            db.set_meta(GENESIS_META, tl.replay(held["records"]).genesis_hash)
        if held["confirmed_genesis"]:
            db.set_meta(CONFIRMED_GENESIS_META, held["confirmed_genesis"])
        if held["forgotten_genesis"]:
            db.set_meta_json(FORGOTTEN_GENESIS_META, held["forgotten_genesis"])
        try:
            state = device._sync_team_log(case["server"]["head"])
        except TeamLogMismatch as exc:
            return {"refused": True, "forget": "sezam team-log forget-pin" in str(exc),
                    "cause": getattr(exc, "cause", None)}
        return {"follows": None if state is None else state.head_seq}
    finally:
        db.close()


def _answer(case: dict) -> dict:
    expect = case["expect"]
    if "follows" in expect:
        return {"follows": expect["follows"]}
    return {"refused": True, "forget": expect["forget"]}


def _seen(got: dict) -> dict:
    return {k: v for k, v in got.items() if k != "cause"}


def test_the_vectors_are_the_builders():
    assert VECTORS_PATH.read_text(encoding="utf-8") == dump(build_vectors())


def test_the_desktop_offers_to_forget_exactly_where_the_log_is_lost(tmp_path):
    got = {case["name"]: _desktop(tmp_path, case) for case in CASES}
    assert {n: _seen(g) for n, g in got.items()} == {c["name"]: _answer(c) for c in CASES}


WEB_SCRIPT = """
    const cases = %s;
    const out = {};
    restoreWebTeamLog = async () => false;  // a restore that lands is INV-2
    for (const c of cases) {
        state.confirmedTeamGenesis = c.device.confirmed_genesis;
        state.forgottenTeamGenesis = c.device.forgotten_genesis;
        const local = c.device.records ? { records: c.device.records, team: TL.replay(c.device.records, sodium) } : null;
        const pin = local ? teamLogPin(local.team) : null;
        apiFetch = async url => {
            const since = Number(url.split('since=')[1]);
            return { records: c.server.records.filter(r => JSON.parse(r.body).seq > since) };
        };
        try {
            const got = await syncWebTeamLog(c.server.head, local, pin, sodium);
            out[c.name] = { follows: got ? got.team.headSeq : null };
        } catch (err) {
            if (!String(err.message).startsWith('TEAM LOG MISMATCH')) throw err;
            out[c.name] = { refused: true,
                            forget: err.teamLogLost === true && err.message.includes('Forget the pinned team log'),
                            cause: err.teamLogCause ?? null };
        }
    }
    return out;
"""


def _web() -> dict:
    helpers = (TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000, "
               "BLOB_KIND = { NODE_META: 1 };\n" + "\n".join(_function(n) for n in FUNCTIONS))
    script = "const TL = globalThis.SezamTeamLog;\n" + WEB_SCRIPT % json.dumps(CASES)
    return _run_source(helpers, "(async () => {" + script + "\n})()")


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_page_offers_to_forget_exactly_where_the_log_is_lost():
    got = _web()
    assert {n: _seen(g) for n, g in got.items()} == {c["name"]: _answer(c) for c in CASES}


def _js_table() -> dict:
    body = _function("teamLogMismatch")
    literal = body[body.index("Object.freeze({") + len("Object.freeze({"):body.index("})")]
    return {k: v == "true" for k, v in re.findall(r"(\w+):\s*(true|false)", literal)}


def _dart_table() -> dict:
    source = (ROOT / "mobile/lib/services/team_log_client.dart").read_text(encoding="utf-8")
    literal = source[source.index("const teamLogMismatchForget = <String, bool>{"):]
    literal = literal[:literal.index("};")]
    return {k: v == "true" for k, v in re.findall(r"'(\w+)':\s*(true|false)", literal)}


def test_every_client_carries_the_one_list():
    from sezam.vault.team_log_local import MISMATCH_CAUSES

    assert MISMATCH_CAUSES == VECTORS["causes"]
    assert _js_table() == VECTORS["causes"]
    assert _dart_table() == VECTORS["causes"]
    # The offer follows from the cause, as the oracle names it.
    for case in CASES:
        expect = case["expect"]
        if "refused" in expect:
            assert VECTORS["causes"][expect["refused"]] is expect["forget"], case["name"]


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_every_client_names_the_same_cause(tmp_path):
    web = _web()
    for case in CASES:
        want = case["expect"].get("refused")
        if want is None:
            continue
        assert _desktop(tmp_path, case)["cause"] == want, case["name"]
        assert web[case["name"]]["cause"] == want, case["name"]
