"""Review 8595ec1 (R10-G): what the deep stateful runs of the second admin
machine found, as scripted steps (random runs seldom line them up again)."""

from __future__ import annotations

import sys

import pytest

from tests import test_sync_state_machine as sm
from tests.test_sync_state_machine import SecondAdminMachine, _Scripted, loopback_server  # noqa: F401


@pytest.fixture(autouse=True)
def _outside_hypothesis(monkeypatch):
    monkeypatch.setattr(sys.modules[sm.__name__], "coverage_event", lambda _name: None)


def test_a_resent_rotation_meets_a_grant_the_second_admin_revoked(loopback_server):  # noqa: F811
    """Seed 377002: B's identity rotation landed and its reply was lost, so it
    goes out again with the grant it re-sealed for a member. The second admin
    revoked that member meanwhile and the server holds a newer copy of the
    envelope. Before the fix the server called it a plain version conflict
    (not 'revoked_envelope'), the client had no way out, and every push of B
    raised 409 atomic_batch_conflict."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        (folder,) = machine.granted[member]
        machine.rotate_identity(_Scripted(device="B"), "after")
        machine.delete_folder(_Scripted(device="B", folder=folder))
        machine.server_lies_into_full_resync(_Scripted(device="A"), "gone", False)
        machine._member_sync(admin)
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        assert member in machine.revoked, machine._trace()
        # A withdraws the re-sealed envelope of the removed member (v2).
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="A"), None)
        machine.push(_Scripted(device="B"), None)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_a_resent_rotation_meets_a_folder_key_a_revocation_replaced(loopback_server):  # noqa: F811
    """Seed 377002, second run: B's identity rotation landed and its reply was
    lost. The second admin then revoked a member and re-keyed the member's
    folder; a full resync took the new folder key, which left the old one
    unbound on B. The resend carried that old key with no folder (the same
    wrap as stored). Before the fix the server took the missing folder for a
    different object, refused B's batch on every push and the devices never
    settled ('key_change' pending on B)."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        machine.rotate_identity(_Scripted(device="B"), "after")
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        assert member in machine.revoked, machine._trace()
        # The server says 'gone' and B resyncs in full, taking the re-key
        # (and the old wraps) before its resend goes out.
        machine.server_lies_into_full_resync(_Scripted(device="B"), "gone", True)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def _invariants(machine) -> None:
    # Hypothesis runs these after every step of the state machine.
    machine.no_folder_a_made_up_account_wrote()
    machine.no_key_for_made_up_accounts()
    machine.no_write_level_nobody_granted()
    machine.track_member_keys()


@pytest.mark.parametrize("first_rotation, revocation", [
    (None, "after"),  # shrunk on 8595ec1: m6 lost the folder
    # Shrunk on Linux with the first fix: the dropped batch was counted as
    # landed, m7 left the revocation queue and kept a live envelope (both
    # variants end in 'm6 lost the shared folder' on 8595ec1).
    ("after", None),
])
def test_reviewer_seed_the_second_admin_keeps_a_folder_shared_with_it(
        loopback_server, first_rotation, revocation):  # noqa: F811
    """The reviewer's seed 158597538126806268078852907907110507889 (300
    examples, Hypothesis 6.170.15), replayed step by step from its shrunk
    failing case. It fails only on Linux as a seed (Windows draws other
    examples); reproduced in a python:3.11 container on 8595ec1, blob
    @reproduce_failure('6.170.15', b'AXichZKNTsJAEIR3qJC0qZpAij8oFQygmKqBJxjfzDd39vYk
    kxJMm/vL3szs19qXfXMFjsEb0AAYKxrN/MjAtcVux0/OWXpBen2wWFtacR2FurM0gjq5Ay/BCz7nauTq
    w50QYFhq8UKAb+DDWZewAq/CoeEruM12O464N99oeASfwI1xYEre6bk/nz3nGHEROdR6w9ZY+CYR0Dxw
    r9vUY8drsO7hKuAo64PNH5dfk32WawRmKsn/QpUCW7hBzQlEaIiePluF07RMwkJYer7qdA4N3Ljeu0tb
    aM+FXO33ER2FGcoq4dXPUuVG9MFbp6PTmcMX8A/l7Dg7Ujv53YEfLRAuaw==').
    Second admin m6, two rotations of A, a lying server and full resyncs, m6
    revokes m7, B shares the folder with m6, B's password change fails after
    the server took it. In the settle A re-keys the folder for m7 without
    having pulled B's grant to m6, and B's own re-key of it is superseded and
    dropped. Before the fix the drop took B's grant with it (the folder had
    moved to A's key), nobody sealed A's key to m6 and the settle ended with
    'member m6 lost the shared folder ...: no live envelope for its DEK'.
    The reviewer's own blob (review_r377/zz_r377_replay.py on branch
    claude/fervent-newton-8jfk2s) fails 3/3 on Linux on 8595ec1 and does not
    reproduce with both fixes. The second fix: finish_queued_revocations
    counted the batch the push dropped (rekey_abandon, member requeued) as
    landed, so the revoked member left the queue with a live envelope."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        (f1,) = machine.granted[member]
        (f2,) = [r["id"] for r in machine.devices["A"].vault.db.fetchall(
            "SELECT id FROM nodes WHERE parent_id = ? AND is_deleted = 0", (f1,))]
        steps = [
            ("create_entry", dict(device="A", folder=f1), {}),
            ("rotate_identity", dict(device="A"), dict(failure=first_rotation)),
            ("rotate_identity", dict(device="A"), dict(failure=None)),
            ("member_write", dict(member=member), dict(op="add entry")),
            ("create_entry", dict(device="A", folder=f2), {}),
            ("delete_folder", dict(device="B", folder=f2), {}),
            ("server_lies_about_users", dict(device="B"), dict(lie="member_admin")),
            ("server_lies_into_full_resync", dict(device="A"), dict(trigger="gone", old_wraps=False)),
            ("second_admin_revokes", dict(admin=admin, member=member), dict(failure=revocation)),
            ("grant", dict(device="B", member=admin, folder=f1), dict(access="read")),
            ("change_password", dict(device="B"), dict(failure="after")),
            ("rotate_identity", dict(device="B"), dict(failure=None)),
            ("resolve_conflicts", dict(device="A"), {}),
            ("create_entry", dict(device="A", folder=f1), {}),
            ("server_lies_into_full_resync", dict(device="B"), dict(trigger="check_token", old_wraps=False)),
            ("rotate_identity", dict(device="A"), dict(failure="after")),
            ("change_password", dict(device="B"), dict(failure="before")),
            ("member_write", dict(member=admin), dict(op="add entry")),
            ("second_admin_revokes", dict(admin=admin), dict(failure=None)),
            ("rotate_identity", dict(device="A"), dict(failure="after")),
            ("change_password", dict(device="A"), dict(failure=None)),
            ("create_entry", dict(device="A", folder=f2), {}),
            ("change_password", dict(device="A"), dict(failure="before")),
            ("server_makes_up_a_member", dict(device="B", folder=f1, eve_writes="unknown parent"), {}),
            ("create_entry", dict(device="B", folder=f1), {}),
        ]
        _invariants(machine)
        for rule, draws, args in steps:
            getattr(machine, rule)(_Scripted(**draws), **args)
            _invariants(machine)
        # The failed password change ran (the server took it, the reply was lost).
        assert "B: push failed (after)" in machine.log, machine._trace()
    finally:
        machine.teardown()


def test_a_grant_whose_push_failed_still_counts_as_granted(loopback_server):  # noqa: F811
    """Deep run on 3662a06 (test_sync_state_machine, 300 examples, Linux):
    A's 'write' grant to a member raised 'The access envelope was not sent
    (...); it goes with the next push'. The model took that for 'not done',
    so when the next push sent the envelope no_write_level_nobody_granted
    reported a 'write' envelope nobody granted. The client is right (the
    grant is queued locally, as the message says); the model now counts it."""
    sm.SyncMachine.server = loopback_server
    machine = sm.SyncMachine()
    try:
        machine._invite_member("A")
        member = next(u for u in machine._active_members() if u not in machine.admins)
        folder = machine._folders("A")[0]
        undo = sm._fail_once(machine.devices["A"].client, "POST", "/api/sync", "before")
        try:
            machine._grant("A", member, folder, "write")
        finally:
            undo()
        assert any("goes with the next push" in line for line in machine.log), machine._trace()
        machine._push("A")
        _invariants(machine)
        machine._settle(lambda _obj: "server")
        _invariants(machine)
    finally:
        machine.teardown()


def test_a_folder_renamed_before_a_server_restore_reaches_every_device(loopback_server):  # noqa: F811
    """Deep run on ed9a3f1 (second admin machine, 300 examples, Linux; the
    blob replays on Windows too). A renamed the folder (v2), everyone synced
    it, then the server came back from an older backup (v1). B pushed its
    copy again and later resynced in full, keeping the server's v1. A sent
    v2 again; B's pull met it while B's queued re-key of m7 kept the folder
    dirty, and took it for B's own earlier push (same version and payload):
    skipped. The re-key was then dropped, the row went back to v1 behind a
    checkpoint past v2, and B showed the old name for good ('sync did not
    settle': F1 on B, F10 on A and C)."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        (f1,) = machine.granted[member]
        a_db = machine.devices["A"].vault.db
        (f2,) = [r["id"] for r in a_db.fetchall(
            "SELECT id FROM nodes WHERE parent_id = ? AND is_deleted = 0", (f1,))]
        e3 = a_db.fetchall("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (f1,))[0]["id"]
        (e5,) = [r["id"] for r in a_db.fetchall("SELECT id FROM entries WHERE node_id = ?", (f2,))]
        steps = [
            ("member_write", dict(member=admin), dict(op="add folder")),
            ("edit_entry", dict(device="A", entry=e3), {}),
            ("rename_folder", dict(device="A", folder=f1), {}),
            ("open_second_process", dict(device="A"), {}),
            ("second_process_write", dict(device="A", parent=f1), dict(op="add folder")),
            ("member_sync", dict(member=admin), {}),
            ("connect_another_device", {}, None),
            ("open_second_process", dict(device="B"), {}),
            ("server_backup", {}, None),
            ("_settle", {}, "server"),
            ("move_entry", dict(device="A", entry=e5, target=f1), {}),
            ("rotate_identity", dict(device="B"), dict(failure="after")),
            ("member_sync", dict(member=admin), {}),
            ("full_resync", dict(device="A"), {}),
            ("change_password", dict(device="A"), dict(failure="before")),
            ("server_withholds", dict(device="B"), dict(kind="envelope")),
            ("member_sync", dict(member=admin), {}),
            ("server_restore", {}, None),
            ("gc_tombstones", {}, None),
            ("server_backup", {}, None),
            ("second_admin_revokes", dict(admin=admin, member=member), dict(failure="before")),
        ]
        _invariants(machine)
        for rule, draws, args in steps:
            if args is None:
                getattr(machine, rule)()
            elif rule == "_settle":
                machine._settle(lambda _obj, keep=args: keep)
            else:
                getattr(machine, rule)(_Scripted(**draws), **args)
            _invariants(machine)
        assert "server: restored from backup" in machine.log, machine._trace()
        machine._settle(lambda _obj: "server")  # teardown's settle: every device agrees
    finally:
        machine.teardown()


def test_an_abandoned_rekey_keeps_the_sender_of_a_made_up_envelope(loopback_server):  # noqa: F811
    """Hunt seed 377001: the server made up an account with an envelope she
    sealed to herself. A revocation's re-key withdrew every envelope of the
    folder key and was abandoned; the restored envelopes all became this
    account's own. The next identity rotation re-sealed hers as a legacy
    grant of this account, so an admin key reached the made-up account."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.track_member_keys()  # an invariant; Hypothesis runs it after every step
        member = next(u for u in machine._active_members() if u not in machine.admins)
        (folder,) = machine.granted[member]
        machine.server_makes_up_a_member(_Scripted(device="B", folder=folder, eve_writes=None))
        assert machine.made_up, machine._trace()
        machine._settle(lambda _obj: "server")
        machine.revoke(_Scripted(device="B", member=member), "before")
        assert machine._member_rekey_pending() == ["B"], machine._trace()
        machine.abandon_rekey(_Scripted(device="B"))
        machine.rotate_identity(_Scripted(device="B"), None)
        machine.track_member_keys()
        machine.no_key_for_made_up_accounts()
        machine._settle(lambda _obj: "server")
        machine.no_key_for_made_up_accounts()
    finally:
        machine.teardown()


def test_withholding_rekey_archives_leaves_no_copy_on_sync_client():
    """Public CI on d14d368: a seed replay withheld re-key archives and put the
    method back as a copy on SyncClient, so the later split test found
    _order_pulled_objects defined twice (SyncClient and PullMixin)."""
    original = sm.SyncClient._order_pulled_objects
    with sm._withholding_rekey_archives():
        objs = [{"id": "a", "object_type": "dek_archive"}, {"id": "b", "object_type": "folder"}]
        assert [o["id"] for o in sm.SyncClient._order_pulled_objects(objs)] == ["b"]
    assert "_order_pulled_objects" not in vars(sm.SyncClient)
    assert sm.SyncClient._order_pulled_objects is original
