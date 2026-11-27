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
  a role change or a member added by this account there that was not lost
  here (also next to every lost change made again), or a key change
  of this account there that was not lost here and names keys the device
  does not hold: refused;
* a lost change of another account that is not on the server's side: refused
  (its device makes it again there; until then nothing this device saw is
  dropped);
* otherwise followed, with the seqs of this account's lost changes that are
  not on the server's side, for the device to make again, and the seqs of
  this account's lost records it withdraws (fork_abandoned, capability
  finding 505: a server that serves them again later is refused).

Run ``python -m tests.team_log_fork_vectors`` to write the file;
tests/test_r16_fork_following.py checks the builder still gives it byte for
byte. Never regenerate it to make a client pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from sezam import teamlog as tl
from tests.team_log_vectors import R1, W1, A, Actor, B, B2, C, D, E, F1, F2, K, Log

VECTORS_PATH = Path(__file__).parent / "vectors" / "team_log_fork.json"


def _base() -> Log:
    return Log().genesis().member(B).member(C)  # seq 0..2, the part both sides hold


def _from(log: Log) -> list[dict]:
    return log.records[3:]


def _other(log: Log) -> Log:
    # What another device of the admin made on the server's side meanwhile: a
    # new folder's key (never a member or a role, which a fork may not bring).
    return log.key(F2, 0, K[2], None)


def _handover(log: Log, to=B) -> Log:
    return log.add("member.role", A, {"user_id": to.uid, "role": "admin"}).add(
        "member.role", A, {"user_id": A.uid, "role": "member"})


def _rotate_again(log: Log, current: Actor, new: Actor) -> Log:
    """A's account moves on from the keys of ``current`` to those of ``new``."""
    proof = new.sk.sign(tl.new_key_message(log.state.head_hash, A.uid, new.spk, new.epk)).signature.hex()
    return log.add("member.keys", A, {
        "user_id": A.uid, "signing_pk": new.spk, "encryption_pk": new.epk, "new_key_sig": proof,
    }, signer=current)


def _hash(record: dict) -> str:
    return tl.record_hash(record)


def build_cases() -> list[dict]:
    cases = []

    def case(name, lost, theirs, *, user=A, held=A, withdrawn=(), refusal=None, missing=(), remade=(),
             abandoned=()):
        expect = {"refusal": refusal, "missing": list(missing)}
        if refusal is None:
            # R16-M5: each missing change as the device makes it again on the
            # server's head ([kind, data]), or the code it is refused with.
            expect["remade"] = remade if isinstance(remade, str) else [list(c) for c in remade]
            # Finding 505: the seqs of this account's lost records the device
            # withdraws as it follows (fork_abandoned).
            expect["abandoned"] = list(abandoned)
        cases.append({
            "name": name,
            "user_id": None if user is None else user.uid,
            "held_keys": None if held is None else [held.spk, held.epk],
            "withdrawn": list(withdrawn),
            "lost": lost,
            "theirs": theirs,
            "expect": expect,
        })

    def member_data(who: Actor) -> dict:
        return {"user_id": who.uid, "signing_pk": who.spk, "encryption_pk": who.epk, "role": "member"}

    key_f1 = ("folder.key", {"folder": F1, "gen": 0, "dek_id": K[1], "prev_dek_id": None})
    access_b = ("access.set", {"folder": F1, "user_id": B.uid, "level": "write"})

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
    case("rotation_to_the_keys_held", removal, rotated, held=E, missing=[3],
         remade=[("member.remove", {"user_id": B.uid})], abandoned=[3])
    case("rotation_that_was_lost", rotated, _from(_other(_base()).rotate(A, E)), held=E, abandoned=[3])
    case("handover_that_was_lost", handed, _from(_handover(_other(_base()))), abandoned=[3, 4])
    # R16-Z SM21: this device rotated twice (A -> E -> D); the server lost
    # the log, and a stale device of the account that took D over put it back
    # with one link A -> D. The rotation onto E lost here is moot.
    twice = _from(_rotate_again(_base().rotate(A, E), E, D))
    case("two_rotations_put_back_as_one_link", twice, _from(_base().rotate(A, D)), held=D, abandoned=[3, 4])
    # A readmit (member.remove + member.add, one append) the server serves
    # half of: Bob out for good. Neither half is made again whole.
    readmit = _from(_base().remove(B).member(B2))
    case("readmit_split_removal_kept", readmit, _from(_other(_base()).remove(B)),
         refusal="it holds one half of the readmit at record 3")
    case("readmit_neither_half", readmit, _from(_other(_base())), missing=[3, 4],
         remade=[("member.remove", {"user_id": B.uid}), ("member.add", member_data(B2))], abandoned=[3, 4])
    case("readmit_whole", readmit, _from(_other(_base()).remove(B).member(B2)), abandoned=[3, 4])
    # Goal #442: another device of this account put back a shorter copy.
    own = _from(_base().key(F1, 0, K[1], None).access(F1, B, "write"))
    shorter = _from(_other(_base()))
    case("own_fork_shorter", own, shorter, missing=[3, 4], remade=[key_f1, access_b], abandoned=[3, 4])
    case("own_fork_again", own, _from(_other(_base()).key(F1, 0, K[1], None).access(F1, B, "write")),
         abandoned=[3, 4])
    case("own_fork_partly_again", own, _from(_other(_base()).key(F1, 0, K[1], None)), missing=[4],
         remade=[access_b], abandoned=[3, 4])
    # R17-N8 (state machine seed 20261127): the access lost here went to a
    # member another device removed since; the removal took it, so nothing
    # is made again (made again, the log refused it as not_active for good).
    case("own_fork_access_of_a_member_removed_since", own,
         _from(_other(_base()).key(F1, 0, K[1], None).remove(B)), missing=[4], abandoned=[3, 4])
    # Capability finding 505: the device followed the shorter copy, withdrew
    # its records 3 and 4, and set their changes aside (the server refused
    # them made again); a server that serves the originals again is refused.
    case("own_fork_original_returns_after_set_aside", shorter, own, withdrawn=[_hash(r) for r in own],
         refusal="its record 3 is one this device withdrew")
    # R16-M5: what a browser made itself (an org recovery key and its KEK
    # wrap) goes out again; a folder another device re-keyed meanwhile does not.
    recovery = _from(_base().recovery(A, R1).wrap(A, W1))
    case("own_fork_recovery_made_here", recovery, _from(_other(_base())), missing=[3, 4], remade=[
        ("org.recovery", {"recovery_pk": R1}),
        ("org.recovery.wrap", {"wrapped_kek": W1, "key_epoch": 0, "threshold": 2, "total_shares": 3}),
    ], abandoned=[3, 4])
    case("own_fork_folder_keyed_elsewhere", _from(_base().key(F1, 0, K[1], None)),
         _from(_base().key(F1, 0, K[3], None)), missing=[3], remade="folder_key_moved", abandoned=[3])
    # Review 18c300f capability finding 498: every lost change made again and
    # one more own record the server kept: a fork holds what was lost, not more.
    def again() -> Log:
        return _other(_base()).key(F1, 0, K[1], None).access(F1, B, "write")
    case("own_fork_again_and_a_handover", own, _from(_handover(again())),
         refusal="its record 6 changes a role this device did not lose")
    case("own_fork_again_and_a_member_added", own, _from(again().member(D)),
         refusal="its record 6 adds a member this device did not lose")
    case("own_fork_again_and_a_rotation", own, _from(again().rotate(A, E)),
         refusal="its record 6 names keys this device does not hold")
    # A member's device (R16-H1, honest server): what it saw is on the
    # server's side once the admin's device made it again there.
    case("member_before_the_admin_made_it_again", own, _from(_other(_base())), user=B, held=B,
         refusal="record 3 this device saw is not on the server's side (it follows once its author makes that change again)")
    case("member_after_the_admin_made_it_again", own,
         _from(_other(_base()).key(F1, 0, K[1], None).access(F1, B, "write")), user=B, held=B)
    case("member_sees_another_accounts_role_change", own,
         _from(_handover(_base().key(F1, 0, K[1], None).access(F1, B, "write"), to=C)), user=B, held=B)
    case("no_account", own, _from(_other(_base())), user=None, held=None,
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
