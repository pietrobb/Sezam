"""Review 4acfdde R11 (low): a new desktop against a server not updated yet.

A server older than TL7 (``d150605``) refuses every top-level node of a
member, so a member's personal folder came back as a bare
'write_acl denied (top-level)' conflict. Now the device says what waits and
why ('sezam status'), the rest of the push goes through, and once the server
is updated the next push sends the folder and the state clears.
"""

from __future__ import annotations

from click.testing import CliRunner

from sezam import cli
from sezam.vault.pending_states import pending_states
from sezam.vault.personal_root import PERSONAL_ROOTS_WAITING_META
from sezam.vault.team_migration import found_team_log
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, team  # noqa: F401  (fixture)
from tests.test_team_log_migration import org  # noqa: F401  (fixture)


async def _pre_tl7(*_args, **_kwargs) -> bool:
    return False


def test_personal_root_waits_for_an_old_server(org, server, monkeypatch):  # noqa: F811
    db, admin, admin_client, _bob, _bob_client, carol, _ids, ops, _dan = org
    found_team_log(admin, admin_client, lambda _uid, _fp: True)
    _confirm_founder(admin, carol)
    carol_client = _client(carol, server[0])
    carol_client.pull()

    with monkeypatch.context() as old_server:
        old_server.setattr("server.app.routers.sync._sealed_with_own_dek", _pre_tl7)
        mine = carol.create_personal_folder("Moje")
        bank = carol.create_entry(mine, "bank", [{"key": "password", "value": "p"}])
        conflicts = carol_client.push()["conflicts"]
        refused = [c for c in conflicts if c["id"] == mine]
        assert [c["error"] for c in refused] == ["write_acl denied (top-level)"]
        assert carol.db.get_meta_json(PERSONAL_ROOTS_WAITING_META) == [mine]
        waiting = {s.key: s for s in pending_states(carol)}
        assert "personal_root_waits_for_server" in waiting
        assert "updates the server" in waiting["personal_root_waits_for_server"].resolve
        assert not any(o["id"] == mine for o in db._storage["vault_objects"])

        monkeypatch.setattr(cli, "_open_vault", lambda: carol)
        monkeypatch.setattr(cli, "_load_session", lambda: None)
        monkeypatch.setattr(cli, "_get_password", lambda *_a, **_k: PASSWORD)
        result = CliRunner().invoke(cli.main, ["push"])
        assert result.exit_code == 0, result.output
        assert "server is older than this app" in result.output, result.output

    # The server is updated: the next push sends the folder, the state clears.
    result = CliRunner().invoke(cli.main, ["push"])
    assert result.exit_code == 0, result.output
    assert "server is older" not in result.output
    carol.unlock(PASSWORD)
    assert any(o["id"] == mine and o["parent_ref"] is None for o in db._storage["vault_objects"])
    assert carol.db.get_meta_json(PERSONAL_ROOTS_WAITING_META) == []
    assert "personal_root_waits_for_server" not in {s.key for s in pending_states(carol)}
    assert any(o["id"] == bank for o in db._storage["vault_objects"])
    carol.lock()
    admin.lock()
