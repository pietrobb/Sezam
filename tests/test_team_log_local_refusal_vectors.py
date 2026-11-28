"""U7f (docs/CORE_UNIFICATION.md, capability run 707):
tests/vectors/team_log_local_refusal.json through the core as the desktop
asks it, and through the page's WASM core. The phone runs the same file
(mobile/test/team_log_local_refusal_vectors_test.dart)."""

from __future__ import annotations

import inspect
import json

import pytest

from sezam.vault import sync_core
from tests.node_support import node_problem
from tests.team_log_local_refusal_vectors import VECTORS_PATH, build_vectors, dump
from tests.test_review_web import _run_source
from tests.test_team_log_web_pull import TEAMLOG_JS

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
ARGS = ("unreadable", "anchor", "forgotten", "confirmed", "pins", "held", "copy_error")


def test_the_builder_still_gives_the_file():
    assert dump(build_vectors()) == VECTORS_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_each_case(case):
    assert sync_core.call("team_log_local_refusal", **{k: case[k] for k in ARGS}) == case["expect"]


def test_held_genesis_is_the_cores():
    assert sync_core.call("team_log_held_genesis", genesis="aa" * 32, stored="aa" * 32) == "aa" * 32
    assert sync_core.call("team_log_held_genesis", genesis="aa" * 32, stored="bb" * 32) is None
    assert sync_core.call("team_log_held_genesis", genesis=None, stored="bb" * 32) is None


def test_the_desktop_has_no_rules_of_its_own():
    from sezam.vault import team_log_state

    for fn in (team_log_state._local_team_state, team_log_state.held_genesis,
               team_log_state.record_account_anchor, team_log_state.import_account_anchor):
        text = inspect.getsource(fn)
        for copy in ("pin != ", "_anchor_conflicts", "own == ", "not in (readable_forgotten"):
            assert copy not in text, (fn.__name__, copy)
    assert not hasattr(team_log_state, "_anchor_conflicts")


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_gives_each_case():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const out = {};
        for (const c of %s) {
            const { name, expect, ...input } = c;
            out[name] = globalThis.SezamSyncCore.call('team_log_local_refusal', input);
        }
        return out;
    })()""" % json.dumps(VECTORS["cases"]))
    assert got == {c["name"]: c["expect"] for c in VECTORS["cases"]}


def test_the_page_has_no_rules_of_its_own():
    text = (VECTORS_PATH.parents[2] / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = text.index("function webLocalTeamLogRefusal(")
    body = text[start:text.index("\n}\n", start)]
    assert "genesis !== anchor" not in body and ".includes(anchor)" not in body
    assert "'team_log_local_refusal'" in body
