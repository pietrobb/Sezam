"""Builds tests/vectors/team_log_anchor_pin.json (docs/CORE_UNIFICATION.md
step U7f, core/src/teamlog/local.rs anchor_pin; capability run 709): what a
device does with the genesis its account keys name at unlock and import -
the anchor it notes, whether it pins it as the confirmed genesis, and whether
it conflicts with a log the device pins or holds (an import refuses the keys).

``_anchor_pin`` is the desktop's rule on bb12402
(team_log_state.record_account_anchor, import_account_anchor) with the
database taken out (the client's). ``unreadable`` stands for a trust record
that does not open (the desktop: the list of logs left); its list is then
not passed. Run ``python -m tests.team_log_anchor_pin_vectors`` to write the
file; never regenerate it to make a client pass.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

from tests.team_log_local_refusal_vectors import HELD, A, B, C, _refusal

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log_anchor_pin.json"


def _anchor_pin(unreadable, anchor, forgotten, confirmed, pins, held, copy_error):
    # import_account_anchor: local_refusal(db, genesis, forgotten or []) raises
    conflict = _refusal(None, anchor, forgotten, confirmed, pins, held, None) is not None
    # record_account_anchor: a left log is dropped, else noted ...
    if anchor is None or anchor in forgotten:
        return {"note": None, "pin": False, "conflict": conflict}
    # ... and pinned while the list opens and nothing is refused
    pin = unreadable is None and _refusal(None, anchor, forgotten, confirmed, pins, held, None) is None
    return {"note": anchor, "pin": pin, "conflict": conflict}


def build_cases() -> list[dict]:
    cases = []

    def case(name, *, unreadable=None, anchor=A, forgotten=(), confirmed=None, pins=(), held=None,
             copy_error=None):
        inputs = {
            "unreadable": unreadable, "anchor": anchor, "forgotten": list(forgotten),
            "confirmed": confirmed, "pins": list(pins), "held": held, "copy_error": copy_error,
        }
        expect = _anchor_pin(unreadable, anchor, list(forgotten), confirmed, list(pins), held, copy_error)
        cases.append({"name": name, **inputs, "expect": expect})

    label = {None: "none", A: "a", B: "b"}
    for unreadable, anchor, forgotten, confirmed, pins, held in itertools.product(
            (None, "list of logs left"), (A, None), ((), (A,)), (None, A, B), ((), (B,), (None, A)), HELD):
        if unreadable and forgotten:
            continue  # a list that does not open is not passed
        name = "%sanchor_%s_forgot_%s_confirmed_%s_pins_%s_held_%s" % (
            "unreadable_" if unreadable else "", label[anchor], "a" if forgotten else "none",
            label[confirmed], "-".join(label[p] for p in pins) or "empty", held,
        )
        case(name, unreadable=unreadable, anchor=anchor, forgotten=forgotten, confirmed=confirmed,
             pins=pins, held=HELD[held])
    case("damaged_copy_still_pins", held=HELD["valid_a"], copy_error="does not replay")
    case("damaged_copy_conflict", held=HELD["valid_b"], copy_error="stored hashes")
    case("other_forgotten_conflict", forgotten=(C,), pins=(B,))
    case("other_forgotten_pins", forgotten=(C,), confirmed=A)
    case("unreadable_pin", unreadable="confirmed genesis")
    return cases


def build_vectors() -> dict:
    return {
        "_comment": (
            "U7f (docs/CORE_UNIFICATION.md, capability run 709): the anchor a device notes from its "
            "account keys at unlock and import, whether it pins it, and whether it conflicts (an import "
            "refuses the keys). Built by tests/team_log_anchor_pin_vectors.py from the desktop's rule "
            "on bb12402. Never regenerate it to make a client pass."
        ),
        "cases": build_cases(),
    }


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(dump(build_vectors()), encoding="utf-8", newline="\n")
    print(VECTORS_PATH, len(build_cases()))
