"""Review c02cc47 R17-L: a restore upload part ended inside an append batch.

A readmit (member.remove, then the same admin's member.add of the account,
one append on the main path) keeps the member's share links. Every client
cut the records the server lost into parts of a fixed size; a part ending
between the two made the server take the removal alone and delete the
links. Each client now ends a part where the shared rule says
(tests/vectors/team_log_restore_parts.json), and the server counts a re-add
only in the same author's run of records.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sezam import teamlog as tl
from sezam.vault import team_log_local
from tests.node_support import node_problem
from tests.test_review_web import _run_source
from tests.test_team_log_web_pull import TEAMLOG_JS

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "team_log_restore_parts.json").read_text(encoding="utf-8")
)
EXPECTED = {c["name"]: c["end"] for c in VECTORS["cases"]}


def _bodies(case: dict) -> list[dict]:
    return [{"type": t, "author": a, "data": {"user_id": u}} for t, a, u in case["records"]]


def test_the_python_core_ends_every_part_where_the_vectors_say():
    got = {c["name"]: tl.restore_part_end(_bodies(c), c["start"], c["limit"]) for c in VECTORS["cases"]}
    assert got == EXPECTED


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_core_ends_every_part_where_the_vectors_say():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const out = {};
        for (const c of %s) {
            const bodies = c.records.map(([type, author, user_id]) => ({ type, author, data: { user_id } }));
            out[c.name] = globalThis.SezamTeamLog.restorePartEnd(bodies, c.start, c.limit);
        }
        return out;
    })()""" % json.dumps(VECTORS["cases"]))
    assert got == EXPECTED


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self, _sql, _params):
        return self.rows


class _Desktop(team_log_local.TeamLogMixin):
    def __init__(self, rows):
        self._db = _Rows(rows)
        self.parts: list[list[str]] = []

    def _identity_link(self, _local):
        return None

    def _landed_rotation_link(self, _local):
        return None

    def _request(self, method, path, body, auth=False):
        self.parts.append([tl.parse_body(r["body"])["type"] for r in body["records"]])
        return {"head": None}


def test_the_desktop_never_splits_a_readmit(monkeypatch):
    kinds = ["access.set", "member.remove", "member.add", "access.set"]
    rows = [{"body": tl.canonical({"seq": seq, "type": kind, "author": "A", "data": {"user_id": "u1"}}),
             "sig": ""} for seq, kind in enumerate(kinds)]
    monkeypatch.setattr(team_log_local, "TEAM_LOG_APPEND_MAX", 2)
    desktop = _Desktop(rows)
    desktop._restore_server_team_log(tl.TeamState(head_seq=len(rows) - 1), None)
    assert desktop.parts == [["access.set"], ["member.remove", "member.add"], ["access.set"]]
