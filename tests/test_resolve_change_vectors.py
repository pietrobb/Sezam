"""tests/vectors/resolve_change.json on the desktop: a queued team change is
made again by the core (docs/CORE_UNIFICATION.md U7a,
core/src/teamlog/resolve.rs). core/tests/resolve_change_vectors.rs checks the
core itself; the page and the phone call the same operation (resolveChange),
exercised on forks by tests/test_r16_fork_following.py and
mobile/test/r16_fork_following_test.dart."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from sezam import teamlog
from sezam.vault.team_log_state import resolve_change

V = json.loads((Path(__file__).parent / "vectors" / "resolve_change.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", V["cases"], ids=lambda c: f"{c['state']}-{c['kind']}")
def test_the_desktop_resolves_as_the_vectors_say(case):
    state = teamlog.TeamState.from_core(copy.deepcopy(V["states"][case["state"]]))
    expect = case["expect"]
    if "refused" in expect:
        with pytest.raises(teamlog.TeamLogError) as exc:
            resolve_change(state, case["kind"], copy.deepcopy(case["data"]))
        assert (exc.value.code, exc.value.seq) == (expect["refused"], expect["seq"])
    else:
        assert resolve_change(state, case["kind"], copy.deepcopy(case["data"])) == expect["data"]


def test_a_state_built_here_resolves_as_one_the_core_gave():
    """A TeamState built on the desktop (not from_core) goes to the core whole."""
    core = V["states"]["team"]
    given = teamlog.TeamState.from_core(copy.deepcopy(core))
    built = teamlog.TeamState.from_core(copy.deepcopy(core))
    del built.__dict__["_core"]
    for case in V["cases"]:
        if case["state"] != "team" or "refused" in case["expect"]:
            continue
        assert resolve_change(built, case["kind"], case["data"]) == resolve_change(given, case["kind"], case["data"])
