"""Review c02cc47 A1 (part left open): 'sezam ai off' on a locked vault with no
broker running anchored nothing, so an agent under the owner's OS user could
write a saved 'on' back. Only the unlocked vault signs the anchor; at a
terminal the CLI now asks for the master password AFTER the brake (Enter
skips) and anchors the 'off'. Without a terminal it never prompts.
"""

from __future__ import annotations

from click.testing import CliRunner

from sezam import cli
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)
from tests.test_review7_ai_switch_replay_h6 import _write_rows
from tests.test_review13_ai_switch_anchor import _broker, _stop, laptop  # noqa: F401  (fixture)
from tests.test_review14_ai_off_anchored import _anchored_on, _no_running_brokers, _refused  # noqa: F401


def _cli_off(monkeypatch, path, interactive: bool, typed: str):
    # The vault under test, never the one in the home directory: without it
    # CI (no ~/.sezam) took the no-vault branch (push CI run 46051811849).
    monkeypatch.setenv("SEZAM_VAULT", str(path))
    monkeypatch.setattr(cli, "_open_vault", lambda: Vault(path))
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(cli, "_interactive", lambda: interactive, raising=False)
    return CliRunner().invoke(cli.main, ["ai", "off"], input=typed)


def test_a_locked_brake_at_a_terminal_is_anchored_after_the_password(laptop, monkeypatch):  # noqa: F811
    saved = _anchored_on(laptop)
    result = _cli_off(monkeypatch, laptop.path, True, PASSWORD + "\n")
    assert result.exit_code == 0, result.output
    assert "AI access is OFF" in result.output
    assert "not anchored" not in result.output
    _write_rows(laptop, saved)
    assert ai_access.read_state(laptop).enabled  # on disk: the replayed copy
    second = _broker(laptop)
    try:
        assert _refused(second) == "ai_disabled"
    finally:
        _stop(second)


def test_enter_skips_and_says_it_is_not_anchored(laptop, monkeypatch):  # noqa: F811
    _anchored_on(laptop)
    result = _cli_off(monkeypatch, laptop.path, True, "\n")
    assert result.exit_code == 0, result.output
    assert not ai_access.read_state(laptop).enabled
    assert "not anchored" in result.output


def test_without_a_terminal_the_brake_never_prompts(laptop, monkeypatch):  # noqa: F811
    _anchored_on(laptop)
    result = _cli_off(monkeypatch, laptop.path, False, "")
    assert result.exit_code == 0, result.output
    assert "Master password" not in result.output
    assert "not anchored on the sync server (the vault is locked)" in result.output
