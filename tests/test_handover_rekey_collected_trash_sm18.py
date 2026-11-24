"""Deep stateful run on 6d4aa8a, finding R16-Z SM18 (TeamLogMachine): a new
admin's handover re-key stopped on a folder GC collected.

Bob holds a sub-folder's key through a grant, not its parent's (the folder's
name is sealed with the parent's key). The admin deleted the sub-folder,
Bob pulled the delete, and GC collected it. After the admin handed the role
to Bob, Bob's re-key moved the tombstone to the new key too; the server
refused it as collected and the push rebuilt it on the collected copy, which
had to seal the name again with the parent's key: "cannot be opened on this
device" on every push, and the re-key never landed.

A tombstone moves only off a retired key; under its parent's key it stays as
sealed, as a delete leaves it, and the re-key lands.
"""

from __future__ import annotations

import asyncio

from server.app.main import _cleanup_tombstones
from sezam import teamlog
from sezam.vault import pending_states, revocation
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)


def test_handover_rekey_lands_past_a_collected_folder_in_the_trash(team, server):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_id = bob.db.get_meta("user_id")
    parent = admin.create_node("Ops")
    shared = admin.create_node("Shared", parent_id=parent)
    gone = admin.create_node("Old", parent_id=parent)
    revocation.grant_member(admin, admin_client, bob_id, shared, "read")
    revocation.grant_member(admin, admin_client, bob_id, gone, "read")
    item = admin.create_entry(shared, "db", [{"key": "password", "value": "db-pw"}])
    assert admin_client.push()["conflicts"] == []
    bob_client.pull()

    admin.delete_node(gone)
    assert admin_client.push()["conflicts"] == []
    assert [o["is_deleted"] for o in db._storage["vault_objects"] if o["id"] == gone] == [1]
    bob_client.pull()
    for obj in db._storage["vault_objects"]:
        if obj.get("is_deleted"):
            obj["modified_at"] = 0
    asyncio.run(_cleanup_tombstones(db, 0))
    assert all(o["id"] != gone for o in db._storage["vault_objects"])

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    bob_client.pull()
    old_key = teamlog.current_key(bob_client.team_state(), shared)

    # Before: RuntimeError "... cannot be opened on this device".
    result = revocation.push_with_queued_revocations(bob, bob_client)
    assert result["conflicts"] == []
    assert not pending_states.rekey_batch(bob.db)
    assert bob.db.fetchone("SELECT COUNT(*) AS n FROM outbox WHERE kind = 'write'")["n"] == 0
    bob_client.pull()
    assert teamlog.current_key(bob_client.team_state(), shared) != old_key
    assert bob.get_field_value(item, "password") == "db-pw"
    assert [o["is_deleted"] for o in db._storage["vault_objects"] if o["id"] == gone] in ([], [1])
