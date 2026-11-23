"""A new admin's re-key over a server copy it refused (R16-Z SM4, deep stateful run on 736ade3).

TeamLogMachine counterexample: the admin's web tab deleted an item, then the
admin handed the role over. The new admin's pull refused that delete (by the
log it holds now the former admin may not write there) and kept its copy, so
no conflict shadow came. Its re-key batch then sent the item at the version
the server already had and was refused on every push ('Atomic re-key batch
conflict'), and the new admin could not hand the role back. The batch builds
on the refused copy now: the device's own copy goes one version above it.
"""

from __future__ import annotations

from sezam.vault import revocation
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)


def test_the_new_admins_rekey_builds_on_a_refused_server_copy(team):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_id = bob.db.get_meta("user_id")
    folder = admin.create_node("Ops")
    item = admin.create_entry(folder, "db", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, admin_client, bob_id, folder, "read")
    assert admin_client.push()["conflicts"] == []
    bob_client.pull()
    assert bob.read_entry(item)["fields"][0]["value"] == "ops-pw"

    admin.delete_entry(item)
    assert admin_client.push()["conflicts"] == []
    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)

    bob_client.pull()  # the former admin's delete is refused here
    result = revocation.push_with_queued_revocations(bob, bob_client)
    assert result["conflicts"] == []
    assert bob_client.push()["conflicts"] == []  # the re-key landed: nothing waits
    assert bob_client.dirty_object_count() == 0
    assert bob.read_entry(item)["fields"][0]["value"] == "ops-pw"
