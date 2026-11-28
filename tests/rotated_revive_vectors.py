"""Builds tests/vectors/rotated_seals.json and tests/vectors/revive_folders.json
(docs/CORE_UNIFICATION.md step U7e; core/src/teamlog/rotated.rs,
core/src/revive.rs).

rotated_seals: which current team keys an admin device seals again to a
member who rotated its identity (review 1141a20 H1, goal #369), and whether
the marker moves to the head. revive_folders: which folders deleted
elsewhere come back for the queued work in them, at which version
(capability review 100, R16-Z SM18).

The answers came from the desktop on f399842: ``_seals`` is
sync_rekey._seal_to_rotated_members and ``_revive`` one level of
sync_state._revive_folders_of_unsent, with the database and the crypto taken
out (a key the device does not hold, an envelope it sealed already: the
client's). Run ``python -m tests.rotated_revive_vectors`` to write the files;
never regenerate them to make a client pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from sezam import teamlog as tl
from tests.team_log_vectors import A, B, B2, C, D, F1, F2, K, Log

ROTATED_PATH = Path(__file__).parent / "vectors" / "rotated_seals.json"
REVIVE_PATH = Path(__file__).parent / "vectors" / "revive_folders.json"


def _seals(state, done, bodies, user_id, trusted, blocked, withheld, projected):
    """sync_rekey._seal_to_rotated_members on f399842, without the database."""
    if blocked:
        return {"seal": [], "advance": False}
    rotated = {
        tl.parse_body(text)["data"]["user_id"] for text in bodies
        if done < tl.parse_body(text)["seq"] <= state.head_seq and tl.parse_body(text)["type"] == "member.keys"
    } - {user_id}
    if not rotated:
        return {"seal": [], "advance": done < state.head_seq}
    if tl.is_admin(state, user_id) and not trusted:
        return {"seal": [], "advance": False}
    seal, waiting = [], False
    for folder in sorted(state.folders) if tl.is_admin(state, user_id) else ():
        dek_id = tl.current_key(state, folder)
        if tl.may_seal(state, folder) and projected is not None and not tl.may_seal(projected, folder):
            waiting = True
            continue
        if not tl.may_seal(state, folder):
            continue
        for uid, encryption_pk, level in tl.key_recipients(state, folder):
            if uid in rotated and uid not in withheld:
                seal.append({"folder": folder, "dek_id": dek_id, "user_id": uid,
                             "encryption_pk": encryption_pk, "level": level})
    return {"seal": seal, "advance": not waiting}


def _team() -> Log:
    # A admin; B and C members; F1 (B write, C read), F2 (C read)
    return (Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write")
            .access(F1, C, "read").key(F2, 0, K[2], None).access(F2, C, "read"))


def rotated_cases() -> list[dict]:
    cases = []

    def case(name, log: Log, *, done=-1, user=A, trusted=True, blocked=False, withheld=(), projected=None):
        state = log.state
        bodies = [r["body"] for r in log.records]
        inputs = {
            "state": state.to_core(), "done": done, "bodies": bodies, "user_id": user.uid,
            "trusted": trusted, "blocked": blocked, "withheld": sorted(withheld),
            "projected": None if projected is None else projected.to_core(),
        }
        expect = _seals(state, done, bodies, user.uid, trusted, blocked, set(withheld), projected)
        cases.append({"name": name, **inputs, "expect": expect})

    team = _team()
    seen = team.state.head_seq
    case("nothing_rotated", team)
    case("seen_to_the_head", team, done=seen)
    b_rotated = _team().rotate(B, B2)
    case("member_rotated", b_rotated, done=seen)
    case("member_rotated_seen_from_the_start", b_rotated)
    case("member_rotated_before_done", b_rotated.key(F2, 1, K[3], K[2]), done=seen + 1)
    case("own_rotation", _team().rotate(A, D), done=seen)
    case("two_members_rotated", _team().rotate(B, B2).rotate(C, D), done=seen)
    case("blocked", b_rotated, done=seen, blocked=True)
    case("founder_not_confirmed", b_rotated, done=seen, trusted=False)
    case("member_device", b_rotated, done=seen, user=C)
    case("member_device_not_confirmed", b_rotated, done=seen, user=C, trusted=False)
    case("withheld", _team().rotate(B, B2).rotate(C, D), done=seen, withheld={C.uid})
    # A queued removal of C leaves F1 and F2 stale: they wait for its re-key.
    rc = _team().rotate(B, B2).rotate(C, D)
    queued = tl.apply_change(rc.state, "member.remove", A.uid, {"user_id": C.uid})
    case("queued_removal_leaves_folders_stale", rc, done=seen, withheld={C.uid}, projected=queued)
    case("projected_unchanged", rc, done=seen, projected=rc.state)
    # Removed on the log: F1 is stale until its re-key, which seals to the new keys.
    case("stale_folder", _team().rotate(B, B2).remove(C), done=seen)
    case("stale_folder_rekeyed", _team().rotate(B, B2).remove(C).key(F1, 1, K[3], K[1]), done=seen)
    return cases


def _revive(deleted, work_in):
    """One round of sync_state._revive_folders_of_unsent on f399842."""
    due = {}
    for d in deleted:
        if d["id"] in set(work_in):
            due[d["id"]] = max(due.get(d["id"], 0), max(d["version"], d.get("sent") or 0) + 1)
    return [{"id": i, "version": v} for i, v in sorted(due.items())]


def revive_cases() -> list[dict]:
    cases = []

    def case(name, deleted, work_in):
        cases.append({"name": name, "deleted": deleted, "work_in": work_in, "expect": _revive(deleted, work_in)})

    case("nothing_deleted", [], [F1])
    case("no_work_in_it", [{"id": F1, "version": 3}], [F2])
    case("work_in_it", [{"id": F1, "version": 3}], [F1])
    case("work_in_two", [{"id": F2, "version": 5}, {"id": F1, "version": 3}], [F1, F2, F1])
    case("above_what_this_device_sent", [{"id": F1, "version": 3, "sent": 4}], [F1])
    case("sent_below_the_tombstone", [{"id": F1, "version": 6, "sent": 4}], [F1])
    case("sent_unknown", [{"id": F1, "version": 6, "sent": None}], [F1])
    case("one_of_two", [{"id": F1, "version": 3}, {"id": F2, "version": 2}], [F2])
    return cases


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


def build_rotated() -> dict:
    return {
        "_comment": (
            "U7e (docs/CORE_UNIFICATION.md): which team keys an admin device seals again to a member "
            "who rotated its identity, and whether the marker moves. Built by "
            "tests/rotated_revive_vectors.py from the desktop's _seal_to_rotated_members on f399842. "
            "Never regenerate it to make a client pass."
        ),
        "cases": rotated_cases(),
    }


def build_revive() -> dict:
    return {
        "_comment": (
            "U7e (docs/CORE_UNIFICATION.md): which folders deleted elsewhere come back for the queued "
            "work in them, and at which version (one round). Built by tests/rotated_revive_vectors.py "
            "from the desktop's _revive_folders_of_unsent on f399842. Never regenerate it to make a "
            "client pass."
        ),
        "cases": revive_cases(),
    }


if __name__ == "__main__":
    ROTATED_PATH.write_text(dump(build_rotated()), encoding="utf-8", newline="\n")
    REVIVE_PATH.write_text(dump(build_revive()), encoding="utf-8", newline="\n")
    print(ROTATED_PATH, REVIVE_PATH)
