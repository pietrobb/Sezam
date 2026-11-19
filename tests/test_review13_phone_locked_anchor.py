"""Review c78fd19 high #4: a locked phone could not unlock after the team anchor.

The phone last pulled before the log was founded and is locked when the admin
publishes the anchor (a new password). prepareInitialTeamLog skipped the log
without a current KEK, and the unlock failed on 'cached log is missing' with
no way out but wiping the app (and its unsent changes).
"""
from __future__ import annotations

from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401


def test_a_locked_phone_unlocks_with_the_anchor_password(team, server, tmp_path, monkeypatch):  # noqa: F811
    from click.testing import CliRunner
    from sezam import cli
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD
    from tests.test_team_log_desktop_changes import _ops

    url, _db = server
    _, admin, client, bob, _ = team
    new_password = "r13-locked-anchor-password!"
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
    }, {"anchored": anchored}, "test/review13_phone_locked_anchor_test.dart")
    assert "All tests passed!" in out, out
