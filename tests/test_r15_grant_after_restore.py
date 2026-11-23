"""A team grant pushed to a server restored from a backup (R15, goal #441).

Found by the saved seed TeamLogMachine@7 on 17945a3: the admin shared a
folder after the server had gone back to a backup it had not seen yet. The
push was refused as a rollback and applied nothing, yet the grant's
folder.key + access.set were dropped as sent while its envelope stayed
queued. The full resync then sent the envelope alone, and the server refused
it ("another account gets a key only with an access.set") on every push, for
good. The grant now stays queued and goes out whole after the resync.
"""

from __future__ import annotations

import copy

from sezam.vault import revocation
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_rollback_commit_token_sm7 import _restore, sees_rollback
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob, team  # noqa: F401


def test_a_grant_refused_as_a_rollback_goes_out_whole_after_the_resync(team):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    ops = admin.create_node("Ops")
    entry = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []
    backup = copy.deepcopy(db._storage)
    admin.create_entry(ops, "db", [{"key": "password", "value": "db-pw"}])
    assert admin_client.push()["conflicts"] == []
    _restore(db, backup)
    _forget_server_cache()

    envelope = revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    assert envelope in admin_client.pending_team_grants()  # nothing landed: still the grant's

    assert sees_rollback(admin_client)
    admin_client.full_resync(confirmed=True)
    assert admin_client.push()["conflicts"] == []
    assert admin_client.push()["conflicts"] == []  # sync settles
    assert admin_client.pending_team_grants() == {}
    assert admin_client.team_state().access[ops] == {bob_id: "read"}

    bob_client.pull()
    assert bob.get_field_value(entry, "password") == "ops-pw"
