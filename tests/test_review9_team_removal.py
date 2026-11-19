"""Review 1141a20 H4: refused removals remain durable, blocked and observable."""
from __future__ import annotations

import pytest

from sezam.vault import revocation
from sezam.vault.sync_common import ServerError, queued_for_removal
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401
from tests.test_team_log_desktop_changes import _ops


@pytest.mark.parametrize("shared", [False, True])
def test_refused_removal_is_not_success_and_survives_retry(team, monkeypatch, shared):
    db, admin, client, bob, bob_client = team
    uid = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    if shared:
        revocation.grant_member(admin, client, uid, _ops(admin), "read")
    real = client._request

    def refuse(method, path, *args, **kwargs):
        if method == "POST" and path == "/api/team-log":
            raise ServerError(400, '{"code":"team_log_refused","detail":"refused"}')
        return real(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", refuse)
    with pytest.raises(revocation.RekeyPending):
        revocation.revoke_member(admin, client, uid)
    assert client.pending_team_changes() == [["member.remove", {"user_id": uid}]]
    assert uid in queued_for_removal(admin.db)
    assert client.team_state().members[uid].active
    assert next(u for u in db._storage["users"] if u["id"] == uid)["status"] == "active"

    monkeypatch.setattr(client, "_request", real)
    revocation.push_with_queued_revocations(admin, client)
    assert not client.pending_team_changes()
    assert not client.team_state().members[uid].active
    assert uid not in queued_for_removal(admin.db)
