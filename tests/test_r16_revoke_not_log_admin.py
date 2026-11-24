"""R16-Z deep run on 84d55f2 (also on 18c300f): the operator flagged a member
admin on the server, but the team log does not hold the account as an admin.
Its desktop's revoke signed a member.remove the rules refuse, and the raw
TeamLogError ('team log record N: not_admin/not_member') escaped
revoke_member. It is refused as a RuntimeError that names why, as the web
does (webTeamRekeyPlan), and nothing is queued or sent."""
from __future__ import annotations

import pytest

from sezam.vault import revocation
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401


def test_a_server_only_admin_cannot_remove_and_is_told_why(team):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    admin_id = admin.db.get_meta("user_id")
    next(u for u in db._storage["users"] if u["id"] == bob.db.get_meta("user_id"))["is_admin"] = 1
    assert bob_client.team_state().members[admin_id].active

    with pytest.raises(RuntimeError, match="not an admin in the team log"):
        revocation.revoke_member(bob, bob_client, admin_id)

    assert bob_client.pending_team_changes() == []
    assert bob_client.team_state().members[admin_id].active
    assert next(u for u in db._storage["users"] if u["id"] == admin_id)["status"] == "active"
