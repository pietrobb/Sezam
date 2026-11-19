"""Review 4acfdde R11 (low): a desktop member of an organisation shared before
the team log saw only "(empty)" in 'sezam list'.

The folder names are sealed under keys the desktop takes only through the
team log, so the tree left them out without a word ('sezam status' named the
way out, 'list' did not). The list now says how many folders wait and how.
"""

from __future__ import annotations

from click.testing import CliRunner

from sezam import cli
from sezam.vault import revocation, team_migration
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


def _list(vault, monkeypatch) -> str:
    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_unlock_vault", lambda v: None)
    monkeypatch.setattr(vault, "lock", lambda: None)
    out = CliRunner().invoke(cli.main, ["list"])
    assert out.exit_code == 0, out.output
    return out.output


def test_list_names_the_folders_shared_before_the_log(team, monkeypatch):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    ops = _ops(admin)
    admin.create_entry(ops, "db", [{"key": "password", "value": "s3cret", "sensitive": True}])
    admin_client.push()
    revocation.grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, "read",
                            confirm_fingerprint=lambda _fp: True)
    bob_client.pull()

    out = _list(bob, monkeypatch)
    assert "1 folder(s) shared with you before the organisation had a team log" in out
    assert "team-log init" in out and "confirm-founder" in out
    assert "team log" not in _list(admin, monkeypatch)  # the admin's own folders open

    team_migration.found_team_log(admin, admin_client, confirm_fingerprint=lambda _u, _fp: True)
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert "team log" not in _list(bob, monkeypatch)  # the folder opens now
    assert [e["name"] for e in bob.list_entries(ops)] == ["db"]
