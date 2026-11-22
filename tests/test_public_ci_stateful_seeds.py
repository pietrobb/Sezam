"""What the deep stateful runs of the public CI found (runs 44260509986 on
02e4f02 and 44281542877 on a408813), as scripted steps (random runs seldom
line them up again)."""

from __future__ import annotations

import sys

import pytest

from sezam.vault.pending_states import revocation_queue
from tests import test_sync_state_machine as sm
from tests.test_sync_state_machine import (  # noqa: F401
    SecondAdminMachine,
    SyncMachine,
    _Scripted,
    loopback_server,
    snapshot,
)


@pytest.fixture(autouse=True)
def _outside_hypothesis(monkeypatch):
    monkeypatch.setattr(sys.modules[sm.__name__], "coverage_event", lambda _name: None)


def test_a_full_resync_tells_another_write_at_the_base_version(loopback_server):  # noqa: F811
    """C edited an entry at version 2 (A's move). A deleted it and tombstone
    GC collected it; B's older edit came back as a new version 2. C's push
    conflicted, its full resync then took B's copy for the very one C's edit
    was made on (same version), and C's next push overwrote B's change without
    a conflict."""
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        vault = machine.devices["A"].vault
        entry = machine._entries("A")[0]
        current = snapshot(vault)[entry][2]
        target = next(f for f in machine._folders("A") if f != current)
        machine.move_entry(_Scripted(device="A", entry=entry, target=target))
        machine.push(_Scripted(device="A"), None)
        machine.edit_entry(_Scripted(device="B", entry=entry))  # on version 1
        machine.connect_another_device()  # C takes version 2
        machine.delete_entry(_Scripted(device="A", entry=entry))
        machine.push(_Scripted(device="A"), None)
        machine.gc_tombstones()
        machine.edit_entry(_Scripted(device="C", entry=entry))  # on version 2
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_a_full_resync_does_not_reseal_a_member_queued_for_removal(loopback_server):  # noqa: F811
    """The second admin revoked m7 (re-keyed nothing). A rotated its identity
    and revoked the second admin; both stayed queued, with m7's re-key ahead
    (since c7a0e49 m7's waits for the rotation to go out).
    A full resync re-sealed A's grant to m7 under the folder key that re-key
    replaces, and every push of A was refused ("envelope references unknown
    DEK")."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        assert member in machine.revoked, machine._trace()
        machine.rotate_identity(_Scripted(device="A"), "before")
        machine.revoke(_Scripted(device="A", member=admin), "before")
        # m7's re-key waits for A's unpushed rotation (c7a0e49,
        # queue_revoked_holders); the second admin's revocation is queued.
        assert admin in set(revocation_queue(machine.devices["A"].vault.db)), machine._trace()
        machine.full_resync(_Scripted(device="A"))
        # No key sealed for m7 since: what A holds for m7 is the server's.
        on_server = {obj["id"] for obj in machine.db._storage["vault_objects"]}
        held = {
            row["id"] for row in machine.devices["A"].vault.db.fetchall(
                "SELECT id FROM access_envelopes WHERE user_id = ?", (member,)
            )
        }
        assert held <= on_server, machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_a_pull_that_left_folders_out_does_not_keep_its_etag(loopback_server):  # noqa: F811
    """Run 44281542877 on a408813: the server left two new folders out of A's
    pull and moved the checkpoint back before them, but its ETag still named
    the head. A kept the ETag, every later pull got 304 and A never saw the
    folders."""
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.open_web_tab()
        machine._settle(lambda _obj: "server")
        # In an existing folder from the web: no new key and no audit record,
        # so the two nodes are all the pull brings.
        parent = machine._folders("A")[0]
        for _ in range(2):
            machine.web_create_folder(_Scripted(parent=parent), None)
        machine.server_withholds(_Scripted(device="A"), "node")
        assert any("withholds 2 node from A" in line for line in machine.log), machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_a_rekey_batch_lets_go_of_an_entry_moved_out_on_both_sides(loopback_server):  # noqa: F811
    """Seed 828282 (#438): A edited an entry of the folder it shared with m7,
    the second admin revoked m7 and A's re-key of the folder stayed unsent. B
    moved the entry to another folder, A moved it there too and deleted it.
    Neither rebase pass looked at a copy outside the re-keyed folders on both
    sides: the batch sent it at its old base and every push of A was refused
    ("Atomic re-key batch conflict")."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        vault = machine.devices["A"].vault
        folder = machine._folders("A")[0]
        entry = next(e for e in machine._entries("A") if snapshot(vault)[e][2] == folder)
        # F2, under the shared folder but sealed with a key of its own.
        target = next(f for f in machine._folders("A") if f != folder)
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        machine.edit_entry(_Scripted(device="A", entry=entry))
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        assert member in machine.revoked, machine._trace()
        machine.push(_Scripted(device="A"), "before")
        machine.move_entry(_Scripted(device="B", entry=entry, target=target))
        machine.push(_Scripted(device="B"), None)
        machine.move_entry(_Scripted(device="A", entry=entry, target=target))
        machine.delete_entry(_Scripted(device="A", entry=entry))
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_a_damaged_account_keypair_while_taking_a_rotation_over_is_a_refusal(loopback_server):  # noqa: F811
    """Seed 828282 rerun on 303ca39 (#438): A rotated the account identity, so
    B's push said the account keys changed; the server then sent B a damaged
    RecoverResponse.encrypted_keypair. B refused ("Server keypair cannot be
    opened"), but the test took any failure of the take-over with the password
    for a dead end. Under that lie it is a refusal; without it B takes the
    rotation over and syncs."""
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), None)
        machine.push(_Scripted(device="A"), None)
        machine.track_member_keys()  # an invariant: Hypothesis runs it after each rule
        machine.server_lies_in_a_field(
            _Scripted(device="B"), key="RecoverResponse.encrypted_keypair", how=0
        )
        assert any("Server keypair cannot be opened" in line for line in machine.log), machine._trace()
        machine.push(_Scripted(device="B"), None)
        assert any(line.startswith("B: took the account keys over") for line in machine.log), machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()
