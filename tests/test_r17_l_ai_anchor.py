"""Review c02cc47 R17-L (AI): the anchor of the AI switch.

- A home was made on, and 'sezam ai on' moved it to, whatever server_url
  vault_meta named: an agent under the owner's OS user wrote its own server
  there first. The server a password named is sealed (name_server); another
  one needs the owner's word at 'sezam ai on'.
- A server move kept the anchor id, so the old server's records still
  verified for the new home (test_review14_ai_anchor_fail_closed).
- 'sezam ai off --terminate-remote' anchored the 'off' first: its requests
  wait up to 30 s each on a slow sync server, the AI's shells stayed open.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import remote_policy
from sezam.vault import ai_access
from tests.test_review6_ai_off_agent_logins import PASSWORD, cli_vault, vault  # noqa: F401

SERVER = "http://127.0.0.1:9"
USER = "U" * 26


def _named_in_the_file(vault) -> None:  # noqa: F811 (not the fixture)
    vault.rebind_server_identity(USER)  # the keypair is bound to the account id
    vault.db.set_meta("server_url", SERVER)  # written into the file, not named


def test_no_home_is_made_on_a_server_no_password_named(vault):  # noqa: F811
    _named_in_the_file(vault)
    with pytest.raises(ai_access.AnchorUnverifiable):
        ai_access.anchor_home(vault)
    ai_access.name_server(vault, SERVER)  # 'sezam connect', with the password
    assert ai_access.anchor_home(vault).server_url == SERVER


def test_ai_on_asks_the_owner_about_a_server_no_password_named(vault, monkeypatch):  # noqa: F811
    _named_in_the_file(vault)
    vault.lock()
    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda v, prompt: v.unlock(PASSWORD))
    monkeypatch.setattr(cli, "_interactive", lambda: True)

    refused = CliRunner().invoke(cli.main, ["ai", "on"], input="n\n")
    assert refused.exit_code != 0 and "no master password confirmed" in refused.output
    vault.unlock(PASSWORD)
    with pytest.raises(ai_access.AnchorUnverifiable):  # still no home there
        ai_access.anchor_home(vault)
    vault.lock()

    confirmed = CliRunner().invoke(cli.main, ["ai", "on"], input="y\n")
    assert confirmed.exit_code == 0, confirmed.output
    assert f"anchored on {SERVER}" in confirmed.output


def test_terminate_remote_ends_the_logins_before_the_anchor_waits(cli_vault, monkeypatch):  # noqa: F811
    vault_, fake = cli_vault
    vault_.unlock(PASSWORD)
    vault_.db.set_meta("server_url", SERVER)
    vault_.lock()
    anchored_after = []

    def anchor_off(self, epoch):
        anchored_after.append(len(fake.commands))
        return True

    monkeypatch.setattr(remote_policy.ServerAnchor, "anchor_off", anchor_off)
    result = CliRunner().invoke(cli.main, ["ai", "off", "--terminate-remote"])
    assert result.exit_code == 0, result.output
    assert anchored_after == [1]  # the web login was already ended
    assert "not anchored" not in result.output
