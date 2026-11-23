"""Builds tests/vectors/team_log_fork.json — when a device follows a server
team log that forks from its own copy (review 18c300f R16-H1).

A server keeps every record a device signed, also one it refused and one the
device withdrew. On 18c300f a fork of the admin's own records was followed
whatever it held: the server served a hand-over the admin had sent and seen
refused (the admin had removed Bob since), and Bob was the admin; or an
identity rotation the admin had dropped, and the log named keys nobody held.

Every case says by hand what a device must answer (fork_refusal in each
client: src/sezam/teamlog.py, web/static/js/teamlog.js, mobile team_log.dart):

* a record of this account on the server's side that the device withdrew,
  a role change of this account there that was not lost here, or a key change
  of this account there that was not lost here and names keys the device
  does not hold: refused;
* a lost change of another account that is not on the server's side: refused
  (its device makes it again there; until then nothing this device saw is
  dropped);
* otherwise followed, with the seqs of this account's lost changes that are
  not on the server's side, for the device to make again.

Run ``python -m tests.team_log_fork_vectors`` to write the file;
tests/test_r16_fork_following.py checks the builder still gives it byte for
byte. Never regenerate it to make a client pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from sezam import teamlog as tl
from tests.team_log_vectors import A, B, B2, C, D, E, F1, K, Log

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log_fork.json"


def _base() -> Log:
    return Log().genesis().member(B).member(C)  # seq 0..2, the part both sides hold


def _from(log: Log) -> list[dict]:
    return log.records[3:]


def _handover(log: Log, to=B) -> Log:
    return log.add("member.role", A, {"user_id": to.uid, "role": "admin"}).add(
        "member.role", A, {"user_id": A.uid, "role": "member"})


def _hash(record: dict) -> str:
    return tl.record_hash(record)


def build_cases() -> list[dict]:
    cases = []

    def case(name, lost, theirs, *, user=A, held=A, withdrawn=(), refusal=None, missing=()):
        cases.append({
            "name": name,
            "user_id": None if user is None else user.uid,
            "held_keys": None if held is None else [held.spk, held.epk],
            "withdrawn": list(withdrawn),
            "lost": lost,
            "theirs": theirs,
            "expect": {"refusal": refusal, "missing": list(missing)},
        })

    removal = _from(_base().remove(B))
    handed = _from(_handover(_base()))
    # The reviewer's take-over: the admin sent a hand-over to Bob, the server
    # refused it and kept it; the admin removed Bob; the server served the hand-over.
    case("handover_the_server_kept", removal, handed,
         refusal="its record 3 changes a role this device did not lose")
    case("withdrawn_record", removal, handed, withdrawn=[_hash(handed[0])],
         refusal="its record 3 is one this device withdrew")
    case("withdrawn_removal", _from(_base().key(F1, 0, K[1], None)), removal, withdrawn=[_hash(removal[0])],
         refusal="its record 3 is one this device withdrew")
    # The reviewer's lock-out: an identity rotation the admin dropped.
    rotated = _from(_base().rotate(A, E))
    case("rotation_to_keys_nobody_holds", removal, rotated,
         refusal="its record 3 names keys this device does not hold")
    case("rotation_to_the_keys_held", removal, rotated, held=E, missing=[3])
    case("rotation_that_was_lost", rotated, _from(_base().member(D).rotate(A, E)), held=E)
    case("handover_that_was_lost", handed, _from(_handover(_base().member(D))))
    # A readmit (member.remove + member.add, one append) the server serves
    # half of: Bob out for good. Neither half is made again whole.
    readmit = _from(_base().remove(B).member(B2))
    case("readmit_split_removal_kept", readmit, _from(_base().member(D).remove(B)),
         refusal="it holds one half of the readmit at record 3")
    case("readmit_neither_half", readmit, _from(_base().member(D)), missing=[3, 4])
    case("readmit_whole", readmit, _from(_base().member(D).remove(B).member(B2)))
    # Goal #442: another device of this account put back a shorter copy.
    own = _from(_base().key(F1, 0, K[1], None).access(F1, B, "write"))
    case("own_fork_shorter", own, _from(_base().member(D)), missing=[3, 4])
    case("own_fork_again", own, _from(_base().member(D).key(F1, 0, K[1], None).access(F1, B, "write")))
    case("own_fork_partly_again", own, _from(_base().member(D).key(F1, 0, K[1], None)), missing=[4])
    # A member's device (R16-H1, honest server): what it saw is on the
    # server's side once the admin's device made it again there.
    case("member_before_the_admin_made_it_again", own, _from(_base().member(D)), user=B, held=B,
         refusal="record 3 this device saw is not on the server's side (it follows once its author makes that change again)")
    case("member_after_the_admin_made_it_again", own,
         _from(_base().member(D).key(F1, 0, K[1], None).access(F1, B, "write")), user=B, held=B)
    case("member_sees_another_accounts_role_change", own,
         _from(_handover(_base().key(F1, 0, K[1], None).access(F1, B, "write"), to=C)), user=B, held=B)
    case("no_account", own, _from(_base().member(D)), user=None, held=None,
         refusal="record 3 this device saw is not on the server's side (it follows once its author makes that change again)")
    return cases


def build_vectors() -> dict:
    return {
        "_comment": (
            "R16-H1 (review 18c300f): when a device follows a server team log that forks from its copy. "
            "Built by tests/team_log_fork_vectors.py, every answer written by hand; every client's "
            "fork_refusal must give them. Never regenerate it to make a client pass. 'prefix': records "
            "0..2, which both sides of every case hold."
        ),
        "prefix": _base().records,
        "cases": build_cases(),
    }


def dump(vectors: dict) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(dump(build_vectors()), encoding="utf-8", newline="\n")
    print(VECTORS_PATH)
