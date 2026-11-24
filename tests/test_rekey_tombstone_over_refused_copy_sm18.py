"""Deep stateful run on 6d4aa8a, finding R16-Z SM18 (TeamLogMachine): a new
admin's re-key batch carried a folder deleted here over a server copy this
device refused.

The admin deleted a folder shared with Bob, Bob pulled the delete; the admin
restored it and handed the role to Bob. Bob's pull refused the restore (by the
log it holds now the former admin may not write there) and kept the
tombstone. Bob's handover re-key moved the tombstone to the new key on its old
base; the server holds the restore one version above, so the batch was
refused on every push ("Atomic re-key batch conflict"). The rebase that puts
a refused copy's batch object above it (SM5) skipped tombstones.

The tombstone goes one version above the refused copy, as a live object does.
"""

from __future__ import annotations

from sezam.vault import pending_states, revocation, trash
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)


def test_rekey_puts_a_tombstone_above_a_refused_server_copy(team):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_id = bob.db.get_meta("user_id")
    shared = admin.create_node("Shared")
    old = admin.create_node("Old", parent_id=shared)
    revocation.grant_member(admin, admin_client, bob_id, shared, "read")
    item = admin.create_entry(shared, "db", [{"key": "password", "value": "db-pw"}])
    assert admin_client.push()["conflicts"] == []
    bob_client.pull()

    admin.delete_node(old)
    assert admin_client.push()["conflicts"] == []
    bob_client.pull()
    kept = bob.db.fetchone("SELECT version FROM nodes WHERE id = ?", (old,))["version"]
    trash.restore_node(admin, old)
    admin.delete_node(old)
    assert admin_client.push()["conflicts"] == []
    again = next(o for o in db._storage["vault_objects"] if o["id"] == old)
    assert again["is_deleted"] and again["version"] > kept

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    bob_client.pull()  # the former admin's second delete is refused here
    assert bob.db.fetchone("SELECT version FROM nodes WHERE id = ?", (old,))["version"] == kept

    # Before: RuntimeError "Atomic re-key batch conflict; it stays pending ...".
    result = revocation.push_with_queued_revocations(bob, bob_client)
    assert result["conflicts"] == []
    assert not pending_states.rekey_batch(bob.db)
    assert bob_client.dirty_object_count() == 0
    bob_client.pull()
    assert bob.get_field_value(item, "password") == "db-pw"
    server_copy = next(o for o in db._storage["vault_objects"] if o["id"] == old)
    assert server_copy["is_deleted"] and server_copy["version"] > again["version"]
