"""U7d (docs/CORE_UNIFICATION.md): tests/vectors/team_log_fork_follow.json
through the core as the desktop's follow_fork runs it - split, replay what is
served (signatures checked here), take; the page the same through its
WASM core and libsodium. The phone runs the same file
(mobile/test/team_log_fork_follow_vectors_test.dart)."""

from __future__ import annotations

import json

import pytest

from sezam import teamlog as tl
from sezam.vault import sync_core
from tests.node_support import node_problem
from tests.team_log_fork_follow_vectors import VECTORS_PATH, build_vectors, dump
from tests.test_review_web import _run_source
from tests.test_team_log_web_pull import TEAMLOG_JS

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def follow(case: dict) -> dict:
    split = sync_core.call(
        "team_log_fork_split", local=case["local"], served=case["served"], pins=case["pins"],
        user_id=case["user_id"], held_keys=case["held_keys"], withdrawn=case["withdrawn"],
    )
    if "fork" not in split:
        return split
    fork = split["fork"]
    try:
        state = tl.replay(case["served"])
    except tl.TeamLogError:
        return {"stand": True}
    take = sync_core.call(
        "team_log_fork_take", state=state.to_core(), head=case["head"], lost=case["local"][fork:],
        missing=split["missing"], user_id=case["user_id"], held_keys=case["held_keys"],
        old_signing_pk=case["old_signing_pk"],
    )
    if "follow" in take:
        take["follow"] = {"fork": fork, **take["follow"]}
    return take


def test_the_builder_still_gives_the_file():
    assert dump(build_vectors()) == VECTORS_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_each_case(case):
    assert follow(case) == case["expect"]


def test_the_desktop_has_no_rules_of_its_own():
    from sezam.vault import team_log_fork

    source = team_log_fork.__file__
    text = open(source, encoding="utf-8").read()
    for copy in ("REQUEUED_KINDS", "rotation_linked_again", "fork_refusal", "admin_policy_refusal", "zip(rows"):
        assert copy not in text, copy


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for teamlog.js")
def test_the_page_gives_each_case():
    got = _run_source(TEAMLOG_JS, """(async () => {
        const TL = globalThis.SezamTeamLog;
        const out = {};
        for (const c of %s) {
            const split = TL.forkSplit(c.local, c.served, c.pins, c.user_id, c.held_keys, new Set(c.withdrawn));
            if (split.fork === undefined) { out[c.name] = split; continue; }
            let team;
            try { team = TL.replay(c.served, sodium); } catch { out[c.name] = { stand: true }; continue; }
            const take = TL.forkTake(team, c.head, c.local.slice(split.fork), split.missing, c.user_id,
                                     c.held_keys, c.old_signing_pk);
            out[c.name] = take.follow ? { follow: { fork: split.fork, ...take.follow } } : take;
        }
        return out;
    })()""" % json.dumps(VECTORS["cases"]))
    assert got == {c["name"]: c["expect"] for c in VECTORS["cases"]}


def test_the_page_has_no_rules_of_its_own():
    text = (VECTORS_PATH.parents[2] / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = text.index("async function followWebTeamLogFork(")
    body = text[start:text.index("\n}\n", start)]
    for copy in ("REMADE_KINDS", "forkRefusal", "adminPolicyRefusal", "recordHash", "forkAbandoned"):
        assert copy not in body, copy
    assert "went_back" not in text[text.index("async function syncWebTeamLog("):start]
