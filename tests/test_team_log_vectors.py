"""Team log decision vectors: the Python reference (TL1, goal #346).

tests/vectors/team_log.json is the contract for all three clients and the
server (docs/DESIGN_TEAM_LOG.md). Web and mobile run the same file.
"""

from __future__ import annotations

import json

import pytest

from sezam import teamlog as tl
from tests.team_log_vectors import VECTORS_PATH, build_vectors, dump

VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
SCENARIOS = VECTORS["scenarios"]

QUESTIONS = {
    "may_write": tl.may_write,
    "key_recipients": lambda s, f: [list(r) for r in tl.key_recipients(s, f)],
    "current_key": tl.current_key,
    "key_generation": lambda s, f, d: list(tl.key_generation(s, f, d)),
    "is_team_folder": tl.is_team_folder,
    "is_stale": tl.is_stale,
    "may_seal": tl.may_seal,
    "is_admin": tl.is_admin,
    "may_hold_key": tl.may_hold_key,
    "envelope_valid": tl.envelope_valid,
    "item_refusal": tl.item_refusal,
    "tombstone_refusal": tl.tombstone_refusal,
    "move_refusal": tl.move_refusal,
    "admin_policy_refusal": tl.admin_policy_refusal,
}


def test_the_builder_still_produces_the_stored_vectors():
    assert dump(build_vectors()) == VECTORS_PATH.read_text(encoding="utf-8")


def test_vectors_cover_every_question_and_refusal():
    asked = {q["fn"] for s in SCENARIOS for q in s.get("questions", [])}
    assert asked == set(QUESTIONS)
    codes = {s["error"]["code"] for s in SCENARIOS if "error" in s}
    assert {
        "bad_encoding", "bad_schema", "bad_seq", "bad_prev", "bad_signature", "bad_genesis",
        "not_member", "not_admin", "not_self", "not_active", "member_exists", "last_admin",
        "key_reused", "unchanged", "folder_unknown", "bad_generation", "dek_reused",
        "bad_new_key_signature",
    } <= codes


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_python_reference_replays_the_vectors(scenario):
    if "error" in scenario:
        with pytest.raises(tl.TeamLogError) as info:
            tl.replay(scenario["records"])
        assert (info.value.seq, info.value.code) == (scenario["error"]["seq"], scenario["error"]["code"])
        return
    state = tl.replay(scenario["records"])
    assert state.to_json() == scenario["state"]
    for q in scenario["questions"]:
        assert QUESTIONS[q["fn"]](state, *q["args"]) == q["answer"], q


def test_a_refused_record_leaves_the_state_untouched():
    good = next(s for s in SCENARIOS if s["name"] == "basic")
    bad = next(s for s in SCENARIOS if s["name"] == "sibling_rekey")
    state = tl.replay(good["records"])
    before = state.to_json()
    with pytest.raises(tl.TeamLogError):
        tl.replay(bad["records"][len(good["records"]):], state)
    assert state.to_json() == before


def test_incremental_replay_equals_full_replay():
    scenario = next(s for s in SCENARIOS if s["name"] == "remove_member_then_rekey")
    records = scenario["records"]
    state = tl.replay(records[:3])
    for record in records[3:]:
        state = tl.apply_record(state, record)
    assert state.to_json() == scenario["state"]
