"""Builds tests/vectors/team_log_fork_follow.json - when a device follows a
server team log that forks from its copy, and what it makes again
(docs/CORE_UNIFICATION.md step U7d; core/src/teamlog/fork_follow.rs).

Each case is a device's copy (``local``), the server's records up to the head
it announces (``served``, ``head``) and what the device knows (``pins``,
``user_id``, ``held_keys``, ``withdrawn``, ``old_signing_pk``: the signing key
of its identity rotation the server has not taken). ``expect``:

* ``{"stand": true}``: the mismatch stands (another genesis, one log a prefix
  of the other, a pin the copy no longer holds, a served log that does not
  replay or reach the head, a lost record bound to its head);
* ``{"refusal": why}``: it stands, and why (fork_refusal,
  tests/vectors/team_log_fork.json);
* ``{"follow": {fork, remake, link, abandoned}}``: the device follows from
  record ``fork``, makes the bodies in ``remake`` again, signs the rotation
  ``link`` again, and withdraws the hashes in ``abandoned``.

The answers came from the desktop's team_log_fork.follow_fork on f399842
(``_followed`` below is its decision with the I/O taken out; the page's and
the phone's pin check added). Run ``python -m tests.team_log_fork_follow_vectors``
to write the file; never regenerate it to make a client pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from sezam import teamlog as tl
from tests.team_log_fork_vectors import _base, _handover, _other, _rotate_again
from tests.team_log_vectors import A, B, D, E, F1, K, Log

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log_fork_follow.json"

REQUEUED_KINDS = frozenset({
    "member.add", "member.role", "member.remove", "access.set", "folder.key", "org.recovery",
    "org.recovery.wrap",
})


def _followed(local, served, head, pins, user_id, held, withdrawn, old_signing_pk):
    """team_log_fork.follow_fork on f399842, without the fetch and the store."""
    for pin in pins:
        if not (0 <= pin["seq"] < len(local)) or tl.record_hash(local[pin["seq"]]) not in pin["hashes"]:
            return {"stand": True}
    fork = next((i for i, (mine, theirs) in enumerate(zip(local, served))
                 if tl.record_hash(theirs) != tl.record_hash(mine)), None)
    if not fork:
        return {"stand": True}
    try:
        reason, missing = tl.fork_refusal(local[fork:], served[fork:], user_id,
                                          None if held is None else tuple(held), set(withdrawn))
    except tl.TeamLogError:
        return {"stand": True}
    if reason:
        return {"refusal": reason}
    lost = [tl.parse_body(r["body"]) for r in local[fork:]]
    bodies = [body for body in lost if body["seq"] in missing]
    links = [body for body in bodies if body["type"] == "member.keys"]
    changes = [body for body in bodies if body["type"] != "member.keys"]
    if any(body["type"] not in REQUEUED_KINDS for body in changes) or len(links) > 1:
        return {"stand": True}
    try:
        state = tl.replay(served)
    except tl.TeamLogError:
        return {"stand": True}
    if state.head_seq != head["seq"] or state.head_hash != head.get("hash") or tl.admin_policy_refusal(state):
        return {"stand": True}
    if links:  # rotation_linked_again
        data, member = links[0]["data"], state.members.get(user_id)
        if (data.get("user_id") != user_id or member is None or not member.active or held is None
                or (data.get("signing_pk"), data.get("encryption_pk")) != tuple(held)
                or old_signing_pk is None or member.signing_pk != old_signing_pk
                or tl.signing_key_retired(state, user_id, old_signing_pk)):
            return {"stand": True}
    return {"follow": {
        "fork": fork, "remake": changes, "link": links[0] if links else None,
        "abandoned": tl.fork_abandoned(local[fork:], user_id),
    }}


def _head(log: Log) -> dict:
    return {"seq": log.state.head_seq, "hash": log.state.head_hash}


def build_cases() -> list[dict]:
    cases = []

    def case(name, local: Log, served: Log, *, head=None, pins=(), user=A, held=A, withdrawn=(), old=None,
             served_records=None):
        records = served.records if served_records is None else served_records
        head = _head(served) if head is None else head
        inputs = {
            "local": local.records, "served": records, "head": head, "pins": list(pins),
            "user_id": None if user is None else user.uid,
            "held_keys": None if held is None else [held.spk, held.epk],
            "withdrawn": list(withdrawn), "old_signing_pk": old,
        }
        expect = _followed(local.records, records, head, inputs["pins"], inputs["user_id"],
                           inputs["held_keys"], inputs["withdrawn"], old)
        cases.append({"name": name, **inputs, "expect": expect})

    own = _base().key(F1, 0, K[1], None).access(F1, B, "write")
    shorter = _other(_base())
    case("own_fork_shorter", own, shorter)
    case("own_fork_again", own, _other(_base()).key(F1, 0, K[1], None).access(F1, B, "write"))
    case("server_a_prefix_of_the_copy", own, _base())
    case("copy_a_prefix_of_the_server", _base(), shorter)
    case("same_log", own, own)
    case("another_genesis", own, Log().genesis(B).member(A, by=B))
    case("pin_held", own, shorter, pins=[{"seq": 3, "hashes": [tl.record_hash(own.records[3])]}])
    case("pin_not_held", own, shorter, pins=[{"seq": 3, "hashes": [tl.record_hash(shorter.records[3])]}])
    case("pin_past_the_copy", own, shorter, pins=[{"seq": 9, "hashes": [tl.record_hash(own.records[3])]}])
    case("head_hash_not_served", own, shorter, head={"seq": shorter.state.head_seq, "hash": "00" * 32})
    case("head_seq_not_served", own, shorter, head={"seq": shorter.state.head_seq + 1,
                                                     "hash": shorter.state.head_hash})
    case("served_does_not_replay", own, shorter, served_records=shorter.records[:3] + [
        {**shorter.records[3], "sig": "00" * 64}])
    removal = _base().remove(B)
    case("handover_the_server_kept", removal, _handover(_base()))
    case("withdrawn_record", _base().key(F1, 0, K[1], None), removal,
         withdrawn=[tl.record_hash(removal.records[3])])
    case("member_before_the_admin_made_it_again", own, shorter, user=B, held=B)
    case("member_after_the_admin_made_it_again", own,
         _other(_base()).key(F1, 0, K[1], None).access(F1, B, "write"), user=B, held=B)
    case("no_account", own, shorter, user=None, held=None)
    # Goal #442: this device rotated (A -> E) and the server lost it; the
    # push signs the link again from the old keys the served log still names.
    rotated = _base().rotate(A, E)
    case("own_rotation_linked_again", rotated, shorter, held=E, old=A.spk)
    case("own_rotation_without_the_old_keys", rotated, shorter, held=E)
    case("own_rotation_old_keys_not_named", rotated, shorter, held=E, old=D.spk)
    case("own_rotation_keys_not_held", rotated, shorter, held=D, old=A.spk)
    case("own_rotation_and_a_change", _base().rotate(A, E).key(F1, 0, K[1], None), shorter, held=E, old=A.spk)
    case("two_own_rotations", _rotate_again(_base().rotate(A, E), E, D), shorter, held=D, old=A.spk)
    return cases


def build_vectors() -> dict:
    return {
        "_comment": (
            "U7d (docs/CORE_UNIFICATION.md): when a device follows a server team log that forks from its "
            "copy, and what it makes again. Built by tests/team_log_fork_follow_vectors.py from the "
            "desktop's follow_fork on f399842; every client runs team_log_fork_split, replays 'served', "
            "then team_log_fork_take. Never regenerate it to make a client pass."
        ),
        "cases": build_cases(),
    }


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(dump(build_vectors()), encoding="utf-8", newline="\n")
    print(VECTORS_PATH)
