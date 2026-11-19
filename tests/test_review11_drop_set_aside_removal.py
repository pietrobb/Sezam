"""Review 4acfdde R11 (low): dropping a set-aside member.remove after the re-key.

'sezam team-log discard' warned "The member then keeps the access the removal
would have taken". The re-key does not wait for the removal: a member whose
folders were re-keyed has no key to them after the drop (only the account and
the membership stay). The warning now says what the drop really leaves.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from sezam import cli
from sezam.vault import revocation
from sezam.vault.sync_common import ServerError
from sezam.vault.team_log_local import _set_queued_changes
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


def _refuse_team_log(client, monkeypatch):
    real = client._request

    def refuse(method, path, body=None, *args, **kwargs):
        if method == "POST" and path == "/api/team-log":
            seq = json.loads(body["records"][0]["body"])["seq"]
            raise ServerError(400, json.dumps({"code": "team_log_refused", "detail": {
                "message": "refused here", "seq": seq}}))
        return real(method, path, body, *args, **kwargs)

    monkeypatch.setattr(client, "_request", refuse)
    return real


def _discard(admin, monkeypatch):
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault: None)
    monkeypatch.setattr(admin, "lock", lambda: None)
    out = CliRunner().invoke(cli.main, ["team-log", "discard", "1"], input="y\n")
    assert out.exit_code == 0, out.output
    return out.output


def _granted(fixture):
    db, admin, client, bob, _ = fixture
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "read")
    return db, admin, client, bob_id, ops


def test_dropping_a_removal_after_the_re_key_does_not_promise_the_folders(team, monkeypatch):  # noqa: F811
    db, admin, client, bob_id, ops = _granted(team)
    real = _refuse_team_log(client, monkeypatch)
    assert revocation.revoke_member(admin, client, bob_id) == 1  # re-keyed, the removal set aside
    monkeypatch.setattr(client, "_request", real)
    assert not _bob_envelopes_live(db, bob_id)

    out = _discard(admin, monkeypatch)
    assert "keeps the access" not in out
    assert "stays an active member" in out and "stay closed to them" in out
    assert client.team_state().members[bob_id].active
    client.push()
    assert not _bob_envelopes_live(db, bob_id)  # as the warning said
    revocation.grant_member(admin, client, bob_id, ops, "read")  # the way back it names
    assert len(_bob_envelopes_live(db, bob_id)) == 1


def test_dropping_a_removal_before_the_re_key_says_the_member_keeps_the_folders(team, monkeypatch):  # noqa: F811
    db, admin, client, bob_id, ops = _granted(team)
    _set_queued_changes(client._db, [["member.remove", {"user_id": bob_id}]])
    real = _refuse_team_log(client, monkeypatch)
    client.push()
    monkeypatch.setattr(client, "_request", real)
    assert len(_bob_envelopes_live(db, bob_id)) == 1

    out = _discard(admin, monkeypatch)
    assert "keep the folders this device shared with them" in out
    client.push()
    assert len(_bob_envelopes_live(db, bob_id)) == 1
