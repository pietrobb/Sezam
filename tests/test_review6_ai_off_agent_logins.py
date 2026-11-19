"""Review main@d615826: SSH logins made through 'sezam ssh-agent' outlived 'ai off'.

The agent only signs the login; the AI's own ssh client then holds a shell on
the server that the brake never touched, and nothing told the owner.
'sezam ai off' now lists the logins the agent signed since AI access was
turned on, and '--terminate-remote' kills the other sessions of each
plain-key account (a certificate login is left to the host's reaper).
"""

from __future__ import annotations

import json
import re

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import agent_sessions, control
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS

PASSWORD = "agent-logins-master-password"


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def _entry(vault, name: str, **fields) -> str:
    root = vault.db.get_meta("root_node_id")
    return vault.create_entry(root, name, [{"key": k, "value": v} for k, v in fields.items()])


def _signed(vault, entry_id: str, host: str, username: str, **extra) -> None:
    payload = {"entry_id": entry_id, "operation": "agent_sign", "host": host, "port": 22,
               "username": username, "approval": "auto", **extra}
    vault._audit_log("mcp_ssh", json.dumps(payload, sort_keys=True).encode(), strict=True)


class _FakeSSH:
    def __init__(self):
        self.commands = []

    def execute(self, entry, command, timeout=60):
        self.commands.append((entry["name"], command))
        mark = re.search(agent_sessions.DONE_MARK + r" [0-9a-f]{16}", command).group(0)
        return {"status": "ok", "stdout": mark + "\n", "exit_code": 0}

    def close_all(self):
        pass


def _setup(vault):
    plain = _entry(vault, "web", host="web.example", username="ai")
    ca = _entry(vault, "ca", host="db.example", username="ai", ssh_ca="yes")
    _signed(vault, plain, "old.example", "ai")  # before AI access was turned on again
    ai_access.disable(vault, "cli")
    ai_access.enable(vault, "cli")
    _signed(vault, plain, "web.example", "ai")
    _signed(vault, plain, "web.example", "ai")
    _signed(vault, ca, "db.example", "ai", cert_key_id="sezam-ai:x:1:ab")
    return plain, ca


def test_logins_since_ai_on_are_listed_once_each(vault):
    _setup(vault)
    logins = agent_sessions.agent_logins(vault)
    assert sorted((l.target, l.certificate) for l in logins) == [
        ("ai@db.example:22", True), ("ai@web.example:22", False),
    ]


def test_terminate_kills_plain_key_sessions_and_leaves_certificates_to_the_reaper(vault):
    _setup(vault)
    fake = _FakeSSH()
    outcomes = {
        l.target: agent_sessions.terminate(vault, l, manager=fake)
        for l in agent_sessions.agent_logins(vault)
    }
    assert outcomes["ai@web.example:22"] == agent_sessions.KILLED
    assert "reaper" in outcomes["ai@db.example:22"]
    assert [name for name, _ in fake.commands] == ["web"]


@pytest.fixture
def cli_vault(vault, monkeypatch):
    _setup(vault)
    vault.lock()
    monkeypatch.setattr(cli, "_has_local_vault", lambda: True)
    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(cli, "_unlock_vault", lambda v, password=None: v.unlock(PASSWORD))
    monkeypatch.setattr(control, "send_all", lambda *a, **k: [])
    fake = _FakeSSH()
    monkeypatch.setattr(agent_sessions, "SSHManager", lambda: fake)
    return vault, fake


def test_ai_off_without_a_session_still_warns(cli_vault):
    vault, fake = cli_vault
    result = CliRunner().invoke(cli.main, ["ai", "off"])
    assert result.exit_code == 0, result.output
    assert "AI access is OFF" in result.output
    assert "are not ended by this" in result.output
    assert fake.commands == []


def test_ai_off_terminate_remote_ends_the_agent_logins(cli_vault):
    vault, fake = cli_vault
    result = CliRunner().invoke(cli.main, ["ai", "off", "--terminate-remote"])
    assert result.exit_code == 0, result.output
    assert f"ai@web.example:22: {agent_sessions.KILLED}" in result.output
    assert "ai@db.example:22: certificate login" in result.output
    assert [name for name, _ in fake.commands] == ["web"]
    assert not vault.is_unlocked
    assert not ai_access.read_state(vault).enabled
