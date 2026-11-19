"""Review 8595ec1 (R10-F): phone findings #6, #7 and the phone's medium/low ones."""
from __future__ import annotations

from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401


def test_phone_without_team_log_takes_over_anchor_password(team, server, tmp_path, monkeypatch):  # noqa: F811
    """#6: the phone last pulled before the log was founded; the admin then
    publishes the anchor (a new password). Taking the password over fetched no
    log and every unlock after it failed with 'cached log is missing'."""
    from click.testing import CliRunner
    from sezam import cli
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD
    from tests.test_team_log_desktop_changes import _ops

    url, _db = server
    _, admin, client, bob, _ = team
    new_password = "r10f-anchor-password!"
    admin.create_entry(admin.create_node("Pre-log"), "before-log", [{"key": "password", "value": "pre-log-secret"}])
    assert client.push()["conflicts"] == []

    def anchored():
        _found_with_bob(client, bob)
        admin.create_entry(_ops(admin), "after-log", [{"key": "password", "value": "post-log-secret"}])
        assert client.push()["conflicts"] == []
        (tmp_path / "phone" / "genesis.txt").write_text(client.team_state().genesis_hash, encoding="utf-8")
        with monkeypatch.context() as m:
            m.setattr(cli, "_open_vault", lambda: admin)
            m.setattr(cli, "_get_password",
                      lambda prompt="", *a, **k: new_password if "new" in prompt.lower() else PASSWORD)
            m.setattr(cli, "_check_rate_limit", lambda: None)
            m.setattr(cli, "_clear_failed_attempts", lambda: None)
            m.setattr(cli, "_clear_session", lambda: None)
            out = CliRunner().invoke(cli.main, ["team-log", "publish-anchor"])
        assert out.exit_code == 0, out.output

    out = _phone(url, tmp_path, {
        "username": "admin", "user_id": admin.db.get_meta("user_id"),
        "password": PASSWORD, "new_password": new_password,
    }, {"anchored": anchored}, "test/review10_phone_anchor_test.dart")
    assert "All tests passed!" in out, out


def test_phone_team_row_held_back_does_not_block_push(team, server, tmp_path):  # noqa: F811
    """Medium: a queued row in a team folder the phone may not send yet (the
    founder is not confirmed there) threw for the whole push, so none of the
    phone's other changes reached the server."""
    from sezam.vault import revocation
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, bob_client = team
    assert bob_client.push()["conflicts"] == []  # bob's own root key
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
    ops = _ops(admin)
    admin.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {bob.db.get_meta("user_id"): bob.keypair.fingerprint})

    def founded():
        _found_with_bob(client, bob)
        revocation.grant_member(admin, client, bob.db.get_meta("user_id"), ops, "write")
        assert client.push()["conflicts"] == []

    out = _phone(url, tmp_path, {"password": PASSWORD, "ops": ops},
                 {"founded": founded, "pushed": lambda: None},
                 "test/review10_phone_push_test.dart")
    assert "All tests passed!" in out, out


def test_phone_biometric_unlock_compares_account(team, server, tmp_path):  # noqa: F811
    """Low: the biometric unlock took whatever account id the server signed in."""
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD

    url, _db = server
    _, _admin, _client_, bob, bob_client = team
    assert bob_client.push()["conflicts"] == []
    out = _phone(url, tmp_path, {"password": PASSWORD, "user_id": bob.db.get_meta("user_id")}, {},
                 "test/review10_phone_biometric_test.dart")
    assert "All tests passed!" in out, out


def _link(url: str, invitation: dict) -> str:
    from urllib.parse import urlencode
    return url + "/?" + urlencode({"invite": invitation["invitation_token"]}) + "#g=" + invitation["genesis_hash"]


def test_phone_refused_invitation_registration_can_be_retried(team, server, tmp_path):  # noqa: F811
    """#7: after a 404/410/409 the pending registration stayed stored and the
    phone never connected to any server again ('Finish the pending invitation
    registration first')."""
    import json
    import urllib.request
    from nacl.public import PrivateKey
    from nacl.signing import SigningKey
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD

    url, db = server
    _, _admin, client, bob, _ = team
    _found_with_bob(client, bob)
    used = client.create_invitation()
    request = urllib.request.Request(url + "/api/users/register", method="POST", data=json.dumps({
        "invitation_token": used["invitation_token"], "username": "someone-else",
        "signing_pk": SigningKey.generate().verify_key.encode().hex(),
        "encryption_pk": PrivateKey.generate().public_key.encode().hex(),
    }).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request) as response:
        assert response.status < 300
    valid = client.create_invitation()

    out = _phone(url, tmp_path, {
        "password": PASSWORD, "invitation": _link(url, valid), "used": _link(url, used),
    }, {}, "test/review10_phone_invitation_test.dart")
    assert "All tests passed!" in out, out
    assert any(u["username"] == "invited-phone" for u in db._storage["users"])
