"""Builds tests/vectors/team_log_local_refusal.json (docs/CORE_UNIFICATION.md
step U7f, core/src/teamlog/local.rs; capability run 707): why a device
refuses its own team log before asking the server - a trust record it cannot
open or a damaged copy (local_damaged), or account keys naming another log
than it holds or pins (anchor_conflict) - and whether forgetting is offered.

``_refusal`` is the desktop's rule on 9c7c0e3 (team_log_state.forgotten_genesis,
_anchor_conflicts with held_genesis, _local_team_state), with the database,
the unsealing and the replay taken out (the client's). One change, the
phone's rule since capability run 418: the held genesis counts only when the
first record replays (its signature checked), not already when it hashes to
the hash stored with it (case ``forged_first_record``: the desktop said
anchor_conflict, now the damaged copy says local_damaged). Run
``python -m tests.team_log_local_refusal_vectors`` to write the file; never
regenerate it to make a client pass.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log_local_refusal.json"

A, B, C = "aa" * 32, "bb" * 32, "cc" * 32
FORGET = {"local_damaged": False, "anchor_conflict": True}


def _held_genesis(held):
    if held is None or held["genesis"] is None:
        return None
    return None if held.get("stored") not in (None, held["genesis"]) else held["genesis"]


def _refusal(unreadable, anchor, forgotten, confirmed, pins, held, copy_error):
    def out(cause, what, detail):
        return {"cause": cause, "what": what, "detail": detail, "forget": FORGET[cause]}

    if unreadable is not None:  # forgotten_genesis raises first
        return out("local_damaged", "trust", unreadable)
    if anchor is not None and anchor not in forgotten and any(
            pin is not None and pin != anchor for pin in (confirmed, *pins, _held_genesis(held))):
        return out("anchor_conflict", "anchor", None)
    if copy_error is not None:  # the replay or the stored hashes of the copy
        return out("local_damaged", "copy", copy_error)
    return None


HELD = {
    "none": None,
    "valid_a": {"genesis": A, "stored": A},
    "valid_b": {"genesis": B, "stored": B},
    "damaged_b": {"genesis": None, "stored": B},  # the record no longer hashes to what is stored
    "unstored_b": {"genesis": B, "stored": None},  # the phone and the page store no hash
    "mismatch": {"genesis": B, "stored": A},
}


def build_cases() -> list[dict]:
    cases = []

    def case(name, *, unreadable=None, anchor=A, forgotten=(), confirmed=None, pins=(), held=None,
             copy_error=None):
        inputs = {
            "unreadable": unreadable, "anchor": anchor, "forgotten": list(forgotten),
            "confirmed": confirmed, "pins": list(pins), "held": held, "copy_error": copy_error,
        }
        expect = _refusal(unreadable, anchor, list(forgotten), confirmed, list(pins), held, copy_error)
        cases.append({"name": name, **inputs, "expect": expect})

    for anchor, forgotten, confirmed, pins, held in itertools.product(
            (A, None), ((), (A,)), (None, A, B), ((), (B,), (None, A)), HELD):
        name = "anchor_%s_forgot_%s_confirmed_%s_pins_%s_held_%s" % (
            "a" if anchor else "none", "a" if forgotten else "none",
            {None: "none", A: "a", B: "b"}[confirmed],
            "-".join({None: "none", A: "a", B: "b"}[p] for p in pins) or "empty", held,
        )
        case(name, anchor=anchor, forgotten=forgotten, confirmed=confirmed, pins=pins, held=HELD[held])
    case("unreadable_list_first", unreadable="list of logs left", confirmed=B, copy_error="bad record")
    case("unreadable_without_anchor", unreadable="confirmed genesis", anchor=None)
    case("damaged_copy", held=HELD["valid_a"], copy_error="does not replay")
    case("damaged_copy_no_anchor", anchor=None, held=HELD["valid_b"], copy_error="stored hashes")
    case("conflict_before_damage", confirmed=B, copy_error="does not replay")
    case("forged_first_record", held={"genesis": None, "stored": B}, copy_error="bad signature")
    case("other_forgotten", forgotten=(C,), pins=(B,))
    return cases


def build_vectors() -> dict:
    return {
        "_comment": (
            "U7f (docs/CORE_UNIFICATION.md): why a device refuses its own team log before asking the "
            "server (local_damaged, anchor_conflict) and whether forgetting is offered. Built by "
            "tests/team_log_local_refusal_vectors.py from the desktop's rule on 9c7c0e3 (one case, "
            "forged_first_record, takes the phone's held genesis). Never regenerate it to make a "
            "client pass."
        ),
        "cases": build_cases(),
    }


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(dump(build_vectors()), encoding="utf-8", newline="\n")
    print(VECTORS_PATH, len(build_cases()))
