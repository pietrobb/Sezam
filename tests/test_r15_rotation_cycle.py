"""Review e443cbc H1: a member stopped every server worker with three records.

A member.keys may move a member onto keys it already holds in the other role
(signing <-> encryption: both checks compare one role only), so a member that
swaps its keys there and back writes the rotations X -> Y -> X. Under rules 1
a member could also rotate back to a retired key (B -> B2 -> B). The restore
check walked the member's rotations with ``while start in rotated`` and never
left that cycle: the worker spun forever and its memory grew ~110 MB/s.

Two causes, both fixed:
- the rules (all three clients and the server, tests/vectors/team_log.json
  ``rotation_swaps_its_own_keys``): a rotation names two keys the member does
  not hold yet, so under rules 2 the rotations of a member never form a cycle;
- the walk (``server/app/team_log.py`` ``_after``) visits each key once, so
  an upload the rules accept under rules 1 (or any later hole in the rules)
  cannot make it loop.

``test_rotation_walk_terminates`` (Hypothesis) builds arbitrary member uploads,
cycles included, and fails when the walk asks for more steps than the upload
has rotations. Red on e443cbc: ``python -m pytest -q
tests/test_r15_rotation_cycle.py`` -> the walk test fails (step bound) and the
restore test times out in its child process.
"""

from __future__ import annotations

import asyncio
import hashlib
import multiprocessing
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from nacl.signing import SigningKey

from sezam import teamlog
from server.app import team_log
from server.app.errors import ApiError

EXAMPLES = int(os.environ.get("SEZAM_PROPERTY_EXAMPLES", "0")) or 300
A_ID, B_ID = "0A" + "0" * 24, "0B" + "0" * 24
ORG = "0G" + "0" * 24


def _sk(n: int) -> SigningKey:
    return SigningKey(hashlib.sha256(b"r15-h1-%d" % n).digest())


def _pk(n: int) -> str:
    return bytes(_sk(n).verify_key).hex()


class _Bounded(dict):
    """The rotation map; fails once a walk asks more than ``limit`` times."""

    def __init__(self, data: dict, limit: int):
        super().__init__(data)
        self.limit, self.asked = limit, 0

    def __contains__(self, key) -> bool:
        self.asked += 1
        if self.asked > self.limit:
            raise AssertionError(f"the rotation walk did not stop after {self.limit} steps")
        return super().__contains__(key)


def _reachable(rotated: dict, start) -> list:
    """Reference: the keys ``start`` rotates to, in order, each once."""
    chain, seen = [], {start}
    while start in rotated and rotated[start] not in seen:
        start = rotated[start]
        seen.add(start)
        chain.append(start)
    return chain


KEY_PAIRS = st.tuples(st.integers(0, 3), st.integers(0, 3)).map(lambda p: (_pk(p[0]), _pk(p[1])))
BODIES = st.lists(
    st.tuples(st.sampled_from(["member.keys", "member.keys", "member.keys", "member.add"]), KEY_PAIRS),
    min_size=1, max_size=8,
)


@settings(max_examples=EXAMPLES, deadline=None, derandomize=not os.environ.get("SEZAM_PROPERTY_EXAMPLES"))
@given(BODIES, KEY_PAIRS)
def test_rotation_walk_terminates(uploads, account):
    """Any upload a member sends: the restore check's walk ends, each key once."""
    bodies = [{"type": kind, "data": {"user_id": B_ID, "signing_pk": s, "encryption_pk": e}}
              for kind, (s, e) in uploads]
    keys, rotated = team_log._own_rotations(teamlog.TeamState(), bodies, B_ID)
    for start in {account, *keys}:
        walk = _Bounded(rotated, limit=len(rotated) + 1)
        assert team_log._after(walk, start) == _reachable(rotated, start)


# --- the rules: no rotation onto keys the member already holds -------------


def _rotation(state, sk: SigningKey, signing_pk: str, encryption_pk: str) -> dict:
    sig = sk.sign(teamlog.new_key_message(state.head_hash, B_ID, signing_pk, encryption_pk)).signature.hex()
    return {"user_id": B_ID, "signing_pk": signing_pk, "encryption_pk": encryption_pk, "new_key_sig": sig}


def _swap_log(rules: int) -> tuple[list, str]:
    """A founds, adds B on (k1, k2); B rotates to (k2, k1), then back."""
    records, state = [], teamlog.TeamState()

    def add(kind, author, data, sk):
        nonlocal state
        body = teamlog.next_body(state, kind, author, data)
        body["v"] = rules
        record = teamlog.sign_record(body, sk)
        records.append(record)
        try:
            state = teamlog.apply_record(state, record)
        except teamlog.TeamLogError as exc:
            return exc.code
        return None

    add("genesis", A_ID, {"org": ORG, "user_id": A_ID, "signing_pk": _pk(10), "encryption_pk": _pk(11)}, _sk(10))
    add("member.add", A_ID, {"user_id": B_ID, "signing_pk": _pk(1), "encryption_pk": _pk(2),
                             "role": "member"}, _sk(10))
    code = add("member.keys", B_ID, _rotation(state, _sk(2), _pk(2), _pk(1)), _sk(1))
    if code is None:
        code = add("member.keys", B_ID, _rotation(state, _sk(1), _pk(1), _pk(2)), _sk(2))
    return records, code


@pytest.mark.parametrize("rules", teamlog.RULES_VERSIONS)
def test_a_rotation_never_lands_on_keys_the_member_holds(rules):
    _, code = _swap_log(rules)
    assert code == "key_reused"


# --- the server: a restore of such a log finishes ---------------------------


def _rules_1_cycle() -> list:
    """Rules 1 lets B rotate back to its retired keys: B -> B2 -> B."""
    records, state = [], teamlog.TeamState()

    def add(kind, author, data, sk):
        nonlocal state
        body = teamlog.next_body(state, kind, author, data)
        body["v"] = 1
        record = teamlog.sign_record(body, sk)
        state = teamlog.apply_record(state, record)
        records.append(record)

    add("genesis", A_ID, {"org": ORG, "user_id": A_ID, "signing_pk": _pk(10), "encryption_pk": _pk(11)}, _sk(10))
    add("member.add", A_ID, {"user_id": B_ID, "signing_pk": _pk(1), "encryption_pk": _pk(2),
                             "role": "member"}, _sk(10))
    add("member.keys", B_ID, _rotation(state, _sk(3), _pk(3), _pk(4)), _sk(1))
    add("member.keys", B_ID, _rotation(state, _sk(1), _pk(1), _pk(2)), _sk(3))
    return records


def _restore(records: list, uploader: str) -> str:
    from tests.test_server_spec import MockDatabase, _create_regular_user

    db = MockDatabase()
    asyncio.run(db.create_schema())
    for uid, name in ((A_ID, "alice"), (B_ID, "bob")):
        _create_regular_user(db._storage, uid, name)
    rows = {u["id"]: u for u in db._storage["users"]}
    rows[A_ID].update(is_admin=1, signing_pk=bytes.fromhex(_pk(10)), encryption_pk=bytes.fromhex(_pk(11)))
    rows[B_ID].update(signing_pk=bytes.fromhex(_pk(1)), encryption_pk=bytes.fromhex(_pk(2)))
    team_log.forget_cache()

    async def go():
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
                await cur.fetchone()
                await team_log.restore(cur, records, uploader)

    try:
        asyncio.run(go())
    except ApiError as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return "refused:" + str(detail.get("team_log_code") or exc.status_code)
    return "accepted"


def _child(case: str, out) -> None:
    if case == "swap":
        out.put(_restore(_swap_log(2)[0], B_ID))
    else:
        out.put(_restore(_rules_1_cycle(), A_ID))


@pytest.mark.parametrize("case, expected", [
    ("swap", "refused:key_reused"),  # the reviewer's three records
    ("rules_1_cycle", "accepted"),  # a log the rules take; the admin puts it back
])
def test_restore_of_a_rotation_cycle_finishes(case, expected):
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    child = ctx.Process(target=_child, args=(case, out), daemon=True)
    child.start()
    child.join(90)
    if child.is_alive():
        child.kill()
        child.join()
        pytest.fail(f"restore of {case} did not finish in 90 s (rotation walk loops)")
    assert child.exitcode == 0
    assert out.get(timeout=5) == expected
