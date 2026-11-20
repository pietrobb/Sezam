"""Stabilization ST4: one table says what each pending state refuses.

pending_states.BLOCKS lists, per operation and by priority, the pending state
that refuses it and the message naming the way out. Every state is built
here (offline and connected) and every operation asked: the answer must be
the expected state, every rule must decide at least one case, and
'sezam status' must name a way out of every state.
"""

from __future__ import annotations

import re

import pytest

from sezam.vault import oplock
from sezam.vault import pending_states as ps
from tests.test_integration_client_server import _vault

OBJ = "01M7OBJECT0000000000000000"
URL = "http://127.0.0.1:9"
NO_DROP = (ps.ABANDON_REKEY, ps.ABANDON_QUEUED, ps.ABANDON_KEY_CHANGE)


def _set(db, state: str) -> None:
    with oplock.exclusive(db.path):  # INV-6: an earlier session left the state
        _seed(db, state)


def _seed(db, state: str) -> None:
    if state in ("epoch", "journal", "journal_rewraps", "identity_rewraps", "identity_plain"):
        db.set_meta("key_epoch", "2")
        ps.set_last_pushed_key_epoch(db, 1)
    journals = {
        "journal": {"epoch": 2},
        "journal_rewraps": {"epoch": 2, "old_kek": "00"},
        "identity_rewraps": {"epoch": 2, "old_kek": "00", "identity": {}},
        "identity_plain": {"epoch": 2, "identity": {}},
    }
    if state in journals:
        ps.set_key_change_journal(db, journals[state])
    if state == "rekey":
        ps.set_rekey_batch(db, {"revoked_user_id": "M", "object_ids": [OBJ]})
    if state in ("identity_rewraps", "identity_plain"):
        ps.set_rekey_batch(db, {"identity_rotation": True, "object_ids": [OBJ]})
    if state == "queue":
        ps.set_revocation_queue(db, ["M"])


# state -> operation -> (blocking state when connected, when offline).
# KEY_CHANGE is asked without rotate_identity; RESOLVE_CONFLICT for OBJ.
N, K, R, Q = None, "key_change", "rekey", "queued_revocations"
NOTHING = {ps.ABANDON_REKEY: (R, R), ps.ABANDON_QUEUED: (Q, Q), ps.ABANDON_KEY_CHANGE: (K, K)}
EXPECTED: dict[str, dict[str, tuple]] = {
    "none": {},
    "epoch": {ps.FULL_RESYNC: (K, K), ps.REKEY: (K, N), ps.ABANDON_KEY_CHANGE: (N, N)},
    "journal": {
        ps.FULL_RESYNC: (K, K), ps.KEY_CHANGE: (K, N), ps.REKEY: (K, N),
        ps.ABANDON_KEY_CHANGE: (N, N),
    },
    "journal_rewraps": {ps.KEY_CHANGE: (K, N), ps.REKEY: (K, N), ps.ABANDON_KEY_CHANGE: (N, N)},
    "rekey": {
        ps.FULL_RESYNC: (R, R), ps.KEY_CHANGE: (R, N), ps.GRANT_AGAIN: (R, R),
        ps.REKEY: (R, R), ps.RESOLVE_CONFLICT: (R, R), ps.ABANDON_REKEY: (N, N),
    },
    "identity_rewraps": {
        ps.KEY_CHANGE: (K, N), ps.GRANT_AGAIN: (R, R), ps.REKEY: (R, R),
        ps.RESOLVE_CONFLICT: (R, R), ps.ABANDON_REKEY: (K, K), ps.ABANDON_KEY_CHANGE: (N, N),
    },
    "identity_plain": {
        ps.FULL_RESYNC: (K, K), ps.KEY_CHANGE: (K, N), ps.GRANT_AGAIN: (R, R),
        ps.REKEY: (R, R), ps.RESOLVE_CONFLICT: (R, R), ps.ABANDON_REKEY: (K, K),
        ps.ABANDON_KEY_CHANGE: (N, N),
    },
    "queue": {ps.ABANDON_QUEUED: (N, N)},
}
CASES = [
    (state, connected) for state in EXPECTED for connected in (True, False)
]


@pytest.fixture
def make_db(tmp_path):
    vaults = []

    def make(state: str, connected: bool):
        vault = _vault(tmp_path / f"v{len(vaults)}.db", "alice")
        vaults.append(vault)
        if connected:
            vault.db.set_meta("server_url", URL)
        _set(vault.db, state)
        return vault

    yield make
    for vault in vaults:
        vault.lock()


def _ctx(operation: str) -> dict:
    return {"object_id": OBJ} if operation == ps.RESOLVE_CONFLICT else {}


def test_every_operation_has_rules_and_every_rule_a_known_operation():
    assert {rule.operation for rule in ps.BLOCKS} == set(ps.OPERATIONS)
    with pytest.raises(ValueError):
        ps.blocker(None, "push_twice")


@pytest.mark.parametrize("state,connected", CASES)
def test_each_state_refuses_exactly_what_the_table_says(make_db, state, connected):
    vault = make_db(state, connected)
    for operation in ps.OPERATIONS:
        default = NOTHING.get(operation, (N, N))
        want = EXPECTED[state].get(operation, default)[0 if connected else 1]
        found = ps.blocker(vault.db, operation, **_ctx(operation))
        assert (found.state if found else None) == want, (state, connected, operation)
        if found is None:
            ps.refuse_if_blocked(vault.db, operation, **_ctx(operation))
            continue
        rule = next(
            r for r in ps.BLOCKS if r.operation == operation and r.message == found.message
        )
        assert rule.state == found.state and rule.error is found.error
        with pytest.raises(found.error, match="^" + re.escape(found.message)):
            ps.refuse_if_blocked(vault.db, operation, **_ctx(operation))


def test_every_rule_decides_some_case_and_names_the_way_out(make_db):
    fired = set()
    for state, connected in CASES:
        vault = make_db(state, connected)
        for operation in ps.OPERATIONS:
            found = ps.blocker(vault.db, operation, **_ctx(operation))
            if found:
                fired.add((operation, found.message))
        vault.lock()
    assert fired == {(rule.operation, rule.message) for rule in ps.BLOCKS}
    for rule in ps.BLOCKS:
        if rule.operation not in NO_DROP:
            assert "push" in rule.message or "abandon" in rule.message, rule


def test_rotate_identity_is_refused_offline_during_a_rekey(make_db):
    vault = make_db("rekey", False)
    assert ps.blocker(vault.db, ps.KEY_CHANGE) is None
    assert ps.blocker(vault.db, ps.KEY_CHANGE, rotate_identity=True).state == R
    assert ps.blocker(vault.db, ps.RESOLVE_CONFLICT, object_id="OTHER") is None


@pytest.mark.parametrize("kind,setup", [
    ("key_change", lambda db: _set(db, "journal")),
    ("rekey", lambda db: _set(db, "rekey")),
    ("queued_revocations", lambda db: _set(db, "queue")),
    ("org_recovery_registration", lambda db: ps.set_org_recovery_registration(db, {})),
    ("org_recovery_rewrap", lambda db: ps.set_org_recovery_rewrap(db, {})),
    ("server_reseed", lambda db: ps.set_reseed_state(db, f"push {URL}")),
    ("bootstrap_upload", lambda db: ps.mark_bootstrap_upload_pending(db, True)),
])
def test_status_names_a_way_out_of_every_state(make_db, kind, setup):
    vault = make_db("none", True)
    with oplock.exclusive(vault.db.path):
        setup(vault.db)
    listed = {state.key: state for state in ps.pending_states(vault)}
    assert kind in listed, listed
    assert "'sezam " in listed[kind].resolve
    if kind in ("server_reseed", "bootstrap_upload"):
        assert URL in listed[kind].resolve
