"""Stateful test finding R16-Z SM19b: the admin's identity rotation landed,
its reply was lost, and then the server lost its team log.

The server took the rotation (the users row holds the new keys, member.keys
went into its log) but the admin's desktop never heard back, so its log copy
still names the old keys and the rotation stays pending. The server then lost
its log (restored from a backup without it). The admin's next push put the
log back as its copy held it: the server refused it ("gives <admin> keys the
account does not sign in with"), and every push and pull of the admin stopped
with TeamLogMismatch for good.

Invariant (INV-7, docs/ROOT_CAUSE_PLAN.md; INV-2 on the server): the admin
device that holds the lost log puts it back on its next sync, its own
rotation the server took included (member.keys from the old keys to the ones
it signs in with), as the rotation itself would have.
"""

from __future__ import annotations

from sezam.vault import pending_states
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_review9_team_identity import _rotate
from tests.test_review9_team_log_restore import _pull_confirming
from tests.test_sync_state_machine import _fail_once, _injected
from tests.test_team_log_desktop import (  # noqa: F401
    _confirm_founder,
    _forget_server_cache,
    _found_with_bob,
    team,
)


def test_the_admin_puts_back_a_lost_log_after_its_rotation_reply_was_lost(team, server):  # noqa: F811
    url, _ = server
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    uid = admin.db.get_meta("user_id")

    rotated = _rotate(admin, client, url)
    undo = _fail_once(rotated, "POST", "/api/sync", "after")
    try:
        rotated.push()
    except Exception as exc:  # noqa: BLE001
        assert _injected(exc), exc
    finally:
        undo()
    new_pk = bytes(admin.keypair.signing_pk).hex()
    user = next(u for u in db._storage["users"] if u["id"] == uid)
    assert bytes(user["signing_pk"]).hex() == new_pk  # the server took the rotation

    admin.rename_node(admin.db.get_meta("root_node_id"), "Renamed")
    db._storage["team_log"] = []
    _forget_server_cache()

    rotated = _client(admin, url)
    rotated.push()
    rotated.pull()

    assert not pending_states.key_change_journal(admin.db)
    server_state = rotated.team_state()
    assert server_state.members[uid].signing_pk == new_pk
    assert db._storage["team_log"], "the log was not put back"
    _pull_confirming(bob_client)
    assert bob_client.team_state().members[uid].signing_pk == new_pk
