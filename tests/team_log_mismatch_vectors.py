"""Builds tests/vectors/team_log_mismatch.json — when a device refuses the
server's team log, and when it offers to forget its pin (INV-7, docs/ROOT_CAUSE_PLAN.md).

Every combination of what a device holds and what the server serves, with the
answer an oracle gives that knows nothing of any client's code:

* the device holds no log, no pin, nothing confirmed: it follows any log that
  replays, reaches its head and passes TL7; no log is no log (a device that
  left one waits for the team's new one instead);
* the server's log is missing while the device holds, pins or confirmed one,
  or it starts with another genesis than that one: the team's log is lost for
  good, refused, and leaving it ("forget the pinned team log") is offered,
  always as a risk (INV-8): a hostile server drops its log or serves a new
  genesis just as easily, and no device tells that from a reseed, so the offer
  carries "risk_marker" wherever it is shown;
* anything else that does not continue what the device saw (behind, a fork,
  does not replay, short of its head, TL7) is a server that lies: refused, and
  forgetting is never offered;
* the head the pull announces is unsigned (goal #440): "lost" or "another
  genesis" is what the served records carry, checked against the device's
  genesis. A head that says no log, or names another genesis, over records
  that start with the device's own genesis is a lie (head_genesis), and records
  past the announced head were appended after the pull: followed up to it.

"causes" is the one list of why a device refuses, and whether forgetting is
offered for it; the core holds it (team_log_mismatch_causes, core/src/teamlog/follow.rs)
and every client takes it from there (docs/CORE_UNIFICATION.md U7b).
Run ``python -m tests.team_log_mismatch_vectors`` to write the file;
tests/test_inv7_forget_offer.py checks the builder still gives it byte for byte.
"""

from __future__ import annotations

import json
from pathlib import Path

from sezam import teamlog as tl
from tests.team_log_vectors import A, B, C, D, E, Log

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log_mismatch.json"

CAUSES = {
    "confirmed_genesis": True, "log_gone": True, "other_genesis": True,
    "left_earlier_log": False, "went_back": False, "differs": False, "does_not_replay": False,
    "short_of_head": False, "head_genesis": False, "refused_at_head": False,
    "local_damaged": False, "anchor_conflict": True,
}


def _team() -> Log:
    return Log().genesis().member(B).member(C)


def _head(records: list[dict]) -> dict:
    state = tl.replay(records)
    return {"genesis_hash": state.genesis_hash, "seq": state.head_seq, "hash": state.head_hash}


def _servers() -> dict:
    """name -> (records served, the head the pull announces), and how it relates to the team's log."""
    team = _team().records
    extended = _team().member(D).records
    forked = Log().genesis().member(B).member(D).records  # another record at seq 2
    forged = _team().records + [_team().member(D).records[-1] | {"sig": E.sk.sign(b"x").signature.hex()}]
    two_admins = _team().add("member.role", A, {"user_id": C.uid, "role": "admin"}).records
    reseeded = Log().genesis(D).member(B, by=D).records
    lying_genesis = _head(team) | {"genesis_hash": _head(reseeded)["genesis_hash"]}
    return {
        "none": ([], None),
        "same": (team, _head(team)),
        "extended": (extended, _head(extended)),
        "behind": (team[:2], _head(team[:2])),
        "forked": (forked, _head(forked)),
        "another_genesis": (reseeded, _head(reseeded)),
        "short_of_head": (team, _head(extended)),
        "forged": (forged, _head(extended)),
        "two_admins": (two_admins, _head(two_admins)),
        # Goal #440: the head is unsigned. A head that says "no log" or names
        # another genesis over records that carry the team's own is a lie, and
        # records past the head were appended after the pull.
        "no_head_over_the_log": (team, None),
        "no_head_over_another_genesis": (reseeded, None),
        "head_names_another_genesis": (team, lying_genesis),
        "records_past_the_head": (extended, _head(team)),
    }


DEVICES = ("fresh", "left_a_log", "holds", "holds_confirmed", "confirmed_only")


def _oracle(device: str, server: str) -> dict:
    holds = device in ("holds", "holds_confirmed")
    confirmed = device in ("holds_confirmed", "confirmed_only")
    anchored = holds or confirmed  # the device names a genesis
    if server == "head_names_another_genesis":
        return {"refused": "head_genesis", "forget": False}
    if server == "records_past_the_head":
        return {"follows": 2}
    if server.startswith("no_head_over_"):
        if anchored:
            # What the records carry decides, never the unsigned head alone.
            if server == "no_head_over_the_log":
                return {"refused": "head_genesis", "forget": False}
            return {"refused": "confirmed_genesis" if confirmed else "other_genesis", "forget": True, "risk": True}
        server = "none"  # a device that names no genesis does not look past a missing head
    if server == "none":
        if confirmed:
            return {"refused": "confirmed_genesis", "forget": True, "risk": True}
        if holds:
            return {"refused": "log_gone", "forget": True, "risk": True}
        if device == "left_a_log":
            return {"refused": "left_earlier_log", "forget": False}
        return {"follows": None}
    if anchored and server == "another_genesis":
        return {"refused": "confirmed_genesis" if confirmed else "other_genesis", "forget": True, "risk": True}
    lies = {"short_of_head": "short_of_head", "forged": "does_not_replay", "two_admins": "refused_at_head"}
    if holds:
        lies |= {"behind": "went_back", "forked": "differs"}
    if server in lies:
        return {"refused": lies[server], "forget": False}
    return {"follows": {"same": 2, "extended": 3, "behind": 1, "forked": 2, "another_genesis": 1}[server]}


def build_vectors() -> dict:
    team = _team().records
    cases = []
    for device in DEVICES:
        for name, (served, head) in _servers().items():
            cases.append({
                "name": f"{device}/{name}",
                "device": {
                    "records": team if device.startswith("holds") else None,
                    "confirmed_genesis": _head(team)["genesis_hash"] if "confirmed" in device else None,
                    "forgotten_genesis": [_head(team)["genesis_hash"]] if device == "left_a_log" else [],
                },
                "server": {"records": served, "head": head},
                "expect": _oracle(device, name),
            })
    return {
        "_comment": (
            "INV-7 (docs/ROOT_CAUSE_PLAN.md): when a device refuses the server's team log and when it "
            "offers to forget its pin. Built by tests/team_log_mismatch_vectors.py from an oracle of its "
            "own; every client must give these answers. Never regenerate it to make a client pass."
        ),
        "causes": CAUSES,
        "risk_marker": "RISK:",
        "cases": cases,
    }


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(dump(build_vectors()), encoding="utf-8", newline="\n")
    print(VECTORS_PATH)
