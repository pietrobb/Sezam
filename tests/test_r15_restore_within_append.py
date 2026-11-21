"""Review e443cbc H3 (INV-2, docs/ROOT_CAUSE_PLAN.md): POST /api/team-log/restore
took six kinds of records the main path refuses, and refused the honest
history of a team that re-added a member.

Restore now runs the append's checks on the history (server/app/team_log.py
``_refuse_rules_beyond_appends``, ``_check_against_users(history=True)``,
``_refuse_superseded_recovery(restored=...)``); keys from a membership the
member left count only where it was admin (``_own_rotations``). Each case
below was taken (or, for the re-add, refused) on e443cbc.
"""
import copy

import pytest

import tests.test_inv2_restore_within_append as T
from sezam import teamlog

IDS = T.IDS


@pytest.fixture(autouse=True)
def _no_hypothesis_events(monkeypatch):
    monkeypatch.setattr(T, "coverage_event", lambda *a: None)


def _honest_with_b(**kw) -> T.Honest:
    h = T.Honest(T.Keys(), **kw)
    if IDS["B"] not in h.state.members:
        assert h._commit("A", [("member.add", "A", {
            "user_id": IDS["B"], "signing_pk": h.current("B").pk,
            "encryption_pk": h.current("B").enc, "role": "member"})])
    return h


def _lost(h: T.Honest) -> dict:
    storage = copy.deepcopy(h.snapshots[-1][1])
    storage["team_log"] = []
    return storage


def _refused(h: T.Honest, storage: dict, forger: T.Forger, me: str, stolen=None) -> str:
    """The restore's refusal ('' when it took the upload), checked against the
    main path: every case here is one it refuses."""
    upload = h.records + forger.records
    assert T.NormalPath(storage, me, stolen).takes(h.records, upload), "the main path takes it"
    T.REFUSED.clear()
    if T.restore(T._db(storage), upload, IDS[me]):
        return ""
    return T.REFUSED[-1]["message"]


def test_a_second_admin_on_the_way():
    """The admin adds C as a second admin, and C (whose key it stole) removes
    the admin: one admin at the end, two after the admin's append."""
    h = _honest_with_b()
    assert h._commit("A", [("member.add", "A", {
        "user_id": IDS["C"], "signing_pk": h.current("C").pk,
        "encryption_pk": h.current("C").enc, "role": "member"})])
    f = T.Forger(h, "A", teamlog.replay(h.records), stolen="C")
    f._try("member.role", IDS["A"], {"user_id": IDS["C"], "role": "admin"}, f._key_of(IDS["A"]))
    f._try("member.remove", IDS["C"], {"user_id": IDS["A"]}, f._key_of(IDS["C"]))
    assert f.labels == ["member.role(A->C)", "member.remove(C->A)"]
    assert "more than one admin after record" in _refused(h, _lost(h), f, "A", stolen="C")


def test_another_admins_superseded_org_recovery():
    """B holds the admin's stolen identity key and puts back an org.recovery
    of the admin naming a key its stored blob does not hold."""
    h = _honest_with_b()
    pk = h.keys.recovery_pk()
    h.db._storage["org_recovery_blobs"] = [{"id": 1, "created_by": IDS["A"], "recovery_signing_pk": bytes.fromhex(pk)}]
    assert h._commit("A", [("org.recovery", "A", {"recovery_pk": pk})])
    f = T.Forger(h, "B", teamlog.replay(h.records), stolen="A")
    f._try("org.recovery", IDS["A"], {"recovery_pk": h.keys.recovery_pk()}, f._key_of(IDS["A"]))
    assert f.labels == ["org.recovery(A->-)"]
    assert "a newer org recovery was set up" in _refused(h, _lost(h), f, "B", stolen="A")


def test_the_uploaders_own_org_recovery_after_a_backup_stands():
    """E5: the admin's devices put back its own newer org.recovery while the
    server's blob came back older (a backup); its author stores a blob for
    any key on the main path."""
    h = _honest_with_b()
    old = h.keys.recovery_pk()
    h.db._storage["org_recovery_blobs"] = [{"id": 1, "created_by": IDS["A"], "recovery_signing_pk": bytes.fromhex(old)}]
    assert h._commit("A", [("org.recovery", "A", {"recovery_pk": old})])
    kept, backup = h.snapshots[-1]
    new = h.keys.recovery_pk()
    h.db._storage["org_recovery_blobs"][0]["recovery_signing_pk"] = bytes.fromhex(new)
    assert h._commit("A", [("org.recovery", "A", {"recovery_pk": new})])
    T.REFUSED.clear()
    assert T.restore(T._db(backup), h.records[kept:], IDS["A"]), T.REFUSED


def test_a_revoked_account_without_key_material_re_added():
    h = _honest_with_b()
    assert h._commit("A", [("member.add", "A", {
        "user_id": IDS["C"], "signing_pk": h.current("C").pk,
        "encryption_pk": h.current("C").enc, "role": "member"})])
    assert h._commit("A", [("member.remove", "A", {"user_id": IDS["C"]})])
    storage = _lost(h)
    next(u for u in storage["users"] if u["id"] == IDS["C"])["encrypted_keypair"] = None
    f = T.Forger(h, "A", teamlog.replay(h.records))
    f._try("member.add", IDS["A"], {"user_id": IDS["C"], "signing_pk": h.current("C").pk,
                                    "encryption_pk": h.current("C").enc, "role": "member"}, f._key_of(IDS["A"]))
    assert "without key material" in _refused(h, storage, f, "A")


def test_a_waiting_account_added_and_removed_again():
    """P registered and was never approved: the main path names no such
    account, and a restore took it once it was gone again at the end."""
    h = _honest_with_b()
    f = T.Forger(h, "A", teamlog.replay(h.records))
    key = f._key_of(IDS["A"])
    f._try("member.add", IDS["A"], {"user_id": IDS["P"], "signing_pk": h.current("P").pk,
                                    "encryption_pk": h.current("P").enc, "role": "member"}, key)
    f._try("member.remove", IDS["A"], {"user_id": IDS["P"]}, key)
    assert f.labels == ["member.add(A->P)", "member.remove(A->P)"]
    assert "approved account" in _refused(h, _lost(h), f, "A")


def test_a_genesis_under_a_made_up_founder():
    """The server's admin founds a log as D (no account), which makes it the
    admin and steps down: the founder registered before anyone else."""
    h = _honest_with_b()
    f = T.Forger(h, "A", teamlog.TeamState())
    key = h.keys.new()
    f.held.append(key)
    f._try("genesis", IDS["D"], {"org": "0H" + "0" * 24, "user_id": IDS["D"],
                                 "signing_pk": key.pk, "encryption_pk": key.enc}, key)
    f._try("member.add", IDS["D"], {"user_id": IDS["A"], "signing_pk": h.current("A").pk,
                                    "encryption_pk": h.current("A").enc, "role": "admin"}, key)
    f._try("member.role", IDS["D"], {"user_id": IDS["D"], "role": "member"}, key)
    assert f.labels == ["genesis(D->D)", "member.add(D->A)", "member.role(D->D)"]
    honest = copy.copy(h)
    honest.records = []
    assert "founder with no account" in _refused(honest, _lost(h), f, "A")


def test_rules_1_records_today_take_back_a_retired_key():
    """A log still at rules 1: B rotates away and back to its first keys
    (rules 2 retire a key for its owner too); the admin, holding B's key as
    well, puts it back."""
    h = T.Honest(T.Keys(), legacy=True)
    f = T.Forger(h, "A", teamlog.replay(h.records), stolen="B")
    first = h.current("B")
    new = h.keys.new()
    f.held.append(new)
    _, _, payload = T._rotation(f.state, "B", new)
    f._try("member.keys", IDS["B"], payload, f._key_of(IDS["B"]))
    _, _, payload = T._rotation(f.state, "B", first)
    f._try("member.keys", IDS["B"], payload, new)
    assert f.labels == ["member.keys(B->B)", "member.keys(B->B)"]
    assert f.state.rules == 1
    storage = _lost(h)  # the account signs in with its first keys again
    row = next(u for u in storage["users"] if u["id"] == IDS["B"])
    assert bytes(row["signing_pk"]).hex() == first.pk
    assert "a key the log retired" in _refused(h, storage, f, "A", stolen="B")


def test_the_admin_puts_back_a_log_with_a_re_added_member():
    """B left, its account signs in with new keys (onboarded again), and the
    admin re-added it on them; the server then lost its log. e443cbc refused
    this honest history for good (B's first keys link to no account key)."""
    h = _honest_with_b()
    assert h._commit("A", [("member.remove", "A", {"user_id": IDS["B"]})])
    new = h.keys.new()
    T._set_keys(h.db, IDS["B"], new)
    h.account["B"].append(new)
    next(u for u in h.db._storage["users"] if u["id"] == IDS["B"])["status"] = "active"
    assert h._commit("A", [("member.add", "A", {"user_id": IDS["B"], "signing_pk": new.pk,
                                                "encryption_pk": new.enc, "role": "member"})]), T.REFUSALS[-1:]
    T.REFUSED.clear()
    assert T.restore(T._db(_lost(h)), h.records, IDS["A"]), T.REFUSED


def test_an_uploader_without_an_account_is_not_the_team_admin(monkeypatch):
    """Review e443cbc P2 (mutant O4, "allow when unsure"): B's rotation is lost
    with a backup; only the team admin puts it back (review c78fd19 #2), and
    an uploader the server has no row for is not one (an account deleted
    after the request signed in: the router's check is past)."""
    monkeypatch.setattr(T, "_active", lambda db, uid: True)
    h = _honest_with_b()
    kept, backup = h.snapshots[-1]
    new = h.keys.new()
    assert h._commit("B", [T._rotation(h.state, "B", new)], rotate=new), T.REFUSALS[-1:]
    assert not any(u["id"] == IDS["D"] for u in backup["users"])
    T.REFUSED.clear()
    assert not T.restore(T._db(copy.deepcopy(backup)), h.records[kept:], IDS["D"])
    assert "only the team admin puts back the key rotation" in T.REFUSED[-1]["message"]
    T.REFUSED.clear()
    assert T.restore(T._db(copy.deepcopy(backup)), h.records[kept:], IDS["A"]), T.REFUSED


def test_a_former_admin_membership_still_needs_its_keys():
    """Keys of a membership the member left count where it was admin: a
    forged genesis under A on keys the forger holds, then A re-added on its
    real keys, stays refused (review 8bc70f7 H2, capability run 385)."""
    h = _honest_with_b()
    f = T.Forger(h, "B", teamlog.TeamState())
    fake = h.keys.new()
    f.held.append(fake)
    f._try("genesis", IDS["A"], {"org": "0H" + "0" * 24, "user_id": IDS["A"],
                                 "signing_pk": fake.pk, "encryption_pk": fake.enc}, fake)
    f._try("member.add", IDS["A"], {"user_id": IDS["B"], "signing_pk": h.current("B").pk,
                                    "encryption_pk": h.current("B").enc, "role": "admin"}, fake)
    f._try("member.role", IDS["A"], {"user_id": IDS["A"], "role": "member"}, fake)
    f._try("member.remove", IDS["B"], {"user_id": IDS["A"]}, f._key_of(IDS["B"]))
    f._try("member.add", IDS["B"], {"user_id": IDS["A"], "signing_pk": h.current("A").pk,
                                    "encryption_pk": h.current("A").enc, "role": "admin"}, f._key_of(IDS["B"]))
    f._try("member.role", IDS["B"], {"user_id": IDS["B"], "role": "member"}, f._key_of(IDS["B"]))
    assert len(f.labels) == 6, f.labels
    T.REFUSED.clear()
    assert not T.restore(T._db(_lost(h)), f.records, IDS["B"])
    assert "keys the account does not sign in with" in T.REFUSED[-1]["message"]
