"""Desktop team changes go into the team log (TL4b; docs/DESIGN_TEAM_LOG.md §4.3.1, §5).

Once the organisation has a log, the admin's real desktop code shares a folder
with a member only by an ``access.set`` (and the folder's first ``folder.key``),
removes a member with a signed ``member.remove`` and re-keys the folder to the
next generation, sealed to exactly the members the log names, at the log's level.
An account the log does not name gets nothing, whatever /api/users says.
"""

from __future__ import annotations

import json

import pytest

from sezam import cli, teamlog
from sezam.models import new_ulid
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_revoke_member_review8 import _bob_envelopes_live, _status
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_cross_client_password_change import _web_login
from tests.test_grant_folder_access import _readable_passwords
from tests.test_review_web import pytestmark  # noqa: F401  (node)


def _ops(admin) -> str:
    return admin.db.fetchone("SELECT id FROM nodes WHERE dek_id IS NOT NULL AND is_deleted = 0 "
                             "AND id IN (SELECT node_id FROM deks)")["id"]


def _member(vault) -> dict:
    return {
        "user_id": vault.db.get_meta("user_id"),
        "signing_pk": bytes(vault.keypair.signing_pk).hex(),
        "encryption_pk": bytes(vault.keypair.encryption_pk).hex(),
        "role": "member",
    }


def _carol(url, admin_client, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    invitation = admin_client.create_invitation()
    carol = _vault(tmp_path / "carol", "carol")
    cli._server_register_and_upload(
        url, carol, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    admin_client.approve_user(carol.db.get_meta("user_id"))
    return carol


def _reads(url, username, user_id, genesis) -> dict:
    """What the member reads with a genesis independently confirmed by the desktop."""
    from tests.team_log_vectors import Log
    from tests.test_team_log_web_rekey import _run
    from tests.test_web_old_kek_records import FAKE_IDB

    stored = _run(FAKE_IDB + f"""
        state.userId = {json.dumps(user_id)};
        state.teamLog = null;
        await saveConfirmedTeamGenesis({json.dumps(genesis)}, sodium);
        return [...records.values()];
    """, Log().genesis())
    browser = {"idb": {"keys": [{"id": row["id"], "__json": json.dumps(row)} for row in stored]}}
    result = _web_login(url, username, PASSWORD, browser)
    assert result["error"] is None, result
    return _readable_passwords(result)


def _server_head(db) -> int:
    return max(r["seq"] for r in db._storage["team_log"])


def test_grant_goes_into_the_log_and_the_member_reads(team, server):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []

    revocation.grant_member(admin, admin_client, bob_id, ops, "write")

    state = admin_client.team_state()
    assert state.access[ops] == {bob_id: "write"}
    assert teamlog.current_key(state, ops) == admin.dek_mgr.get_dek_for_node(ops)[0]
    assert len(state.folders[ops]) == 1
    assert _server_head(db) == state.head_seq == 3
    assert not admin_client.pending_team_changes()
    [envelope] = _bob_envelopes_live(db, bob_id)
    assert envelope["access_level"] == "write"
    # The same grant again adds no record.
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    assert admin_client.team_state().head_seq == 3

    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob_client.team_state().to_json() == state.to_json()
    assert _reads(url, "bob", bob_id, state.genesis_hash) == {"vpn": "ops-pw"}


def test_an_account_the_log_does_not_name_gets_nothing(team):
    db, admin, admin_client, bob, bob_client = team
    admin_client.found_team_log(new_ulid())  # Bob is approved on the server, not in the log
    with pytest.raises(ValueError, match="member of the team log"):
        revocation.grant_member(admin, admin_client, bob.db.get_meta("user_id"), _ops(admin), "read")
    assert _bob_envelopes_live(db, bob.db.get_meta("user_id")) == []
    assert admin_client.team_state().head_seq == 0
    assert not admin_client.pending_team_changes()


def test_removal_is_signed_and_rekeys_to_the_next_generation_for_the_log_members(
    team, server, tmp_path, monkeypatch  # noqa: F811
):
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    carol = _carol(url, admin_client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    admin_client.append_team_log([("member.add", _member(carol))])
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    revocation.grant_member(admin, admin_client, carol_id, ops, "read")
    old_key = teamlog.current_key(admin_client.team_state(), ops)

    assert revocation.revoke_member(admin, admin_client, bob_id) == 1

    state = admin_client.team_state()
    assert not state.members[bob_id].active
    new_key = teamlog.current_key(state, ops)
    assert new_key != old_key and new_key == admin.dek_mgr.get_dek_for_node(ops)[0]
    assert len(state.folders[ops]) == 2
    assert not teamlog.is_stale(state, ops)
    assert _server_head(db) == state.head_seq
    assert _status(db, bob_id) == "revoked"
    assert _bob_envelopes_live(db, bob_id) == []
    # Carol's new envelope comes from the log, with the log's level.
    [carol_env] = [o for o in _bob_envelopes_live(db, carol_id) if o["parent_ref"] == new_key]
    assert carol_env["access_level"] == "read"
    assert _reads(url, "carol", carol_id, state.genesis_hash) == {"vpn": "ops-pw"}
    carol.lock()


def test_removal_that_cannot_be_sent_now_goes_with_the_next_push(team, monkeypatch):
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    head = _server_head(db)

    real = admin_client._request

    def offline(method, path, *a, **k):
        if path.startswith("/api/team-log") or path.startswith("/api/sync"):
            raise RuntimeError("Network error: connection refused")
        return real(method, path, *a, **k)

    monkeypatch.setattr(admin_client, "_request", offline)
    with pytest.raises(revocation.RekeyPending):
        revocation.revoke_member(admin, admin_client, bob_id)
    assert _server_head(db) == head
    assert admin_client.pending_team_changes() == [["member.remove", {"user_id": bob_id}]]

    monkeypatch.setattr(admin_client, "_request", real)
    revocation.push_with_queued_revocations(admin, admin_client)
    state = admin_client.team_state()
    assert not admin_client.pending_team_changes()
    assert not state.members[bob_id].active
    assert len(state.folders[ops]) == 2
    assert _server_head(db) == state.head_seq
    assert _status(db, bob_id) == "revoked"
    assert _bob_envelopes_live(db, bob_id) == []
