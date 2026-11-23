"""An admin command on a server restored from a backup (R16-Z, deep stateful run on 736ade3).

TeamLogMachine counterexample: the server went back to a backup, then the
admin desktop handed the admin role over. ``hand_over_admin`` pulls first and
the pull answered with a rollback warning (the checkpoint is ahead of the
server), which it ignored: the role moved on a server that had lost what this
account wrote after the backup. ``unsent_work`` saw nothing unsent, since the
device had sent it, so the guarantee "what this account has not sent goes out
first" did not hold, and every later pull of that device stopped on the
rollback. Invariant: a team-log command of the admin acts only on a server
this device has not seen go back; until a full resync it is refused and
nothing is sent.
"""

from __future__ import annotations

import copy

import pytest

from sezam import teamlog
from sezam.vault import team_migration
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import (  # noqa: F401  (fixture)
    _confirm_founder,
    _forget_server_cache,
    _found_with_bob,
    team,
)


def _server_log(admin_client) -> teamlog.TeamState:
    admin_client._refresh_team_log()
    return admin_client.team_state()


def _restored_after_admin_wrote(db, admin, admin_client):
    backup = copy.deepcopy(db._storage)
    folder = admin.create_node("After the backup")
    admin.create_entry(folder, "lost", [{"key": "password", "value": "lost-pw"}])
    assert admin_client.push()["conflicts"] == []
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    _forget_server_cache()


@pytest.mark.parametrize("command", ["hand_over_admin", "add_member", "readmit_member"])
def test_an_admin_command_waits_for_the_full_resync(team, command):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    _restored_after_admin_wrote(db, admin, admin_client)
    before = [r["seq"] for r in db._storage["team_log"]]

    with pytest.raises(RuntimeError, match="full-resync"):
        getattr(team_migration, command)(admin, admin_client, bob_id, lambda fingerprint: True)

    assert [r["seq"] for r in db._storage["team_log"]] == before, "a refused command sent records"
    assert teamlog.is_admin(_server_log(admin_client), admin_id)
    assert not teamlog.is_admin(_server_log(admin_client), bob_id)


def test_after_the_full_resync_the_handover_goes_through_with_the_lost_writes(team):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_id = bob.db.get_meta("user_id")
    _restored_after_admin_wrote(db, admin, admin_client)
    with pytest.raises(RuntimeError, match="full-resync"):
        team_migration.hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)

    admin_client.full_resync(confirmed=True)
    team_migration.hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    assert teamlog.is_admin(_server_log(admin_client), bob_id)
    assert admin_client.dirty_object_count() == 0, "the handover went out before the lost writes"
