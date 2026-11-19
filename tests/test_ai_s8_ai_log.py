"""AI broker TODO section 8 (S8): ``sezam ai log [--since 1h] [--entry PATH]``.

A readable list of what AI agents did: time, agent, entry, action, command
or paths, result, bytes, owner approvals and refusals (intent and outcome
records), SSH agent signatures with the certificate key id, and the kill
switch. The command is kept with the entry's secrets redacted, and nothing
the agent chose can drive the terminal.
"""

from __future__ import annotations

import sys
import time
import types

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp import audit_view
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_mcp_ssh import FakeSSHManager

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "s8-master-password"
SECRET = "never-return-this"
SSH_ACTIONS = ["ssh_execute", "ssh_session", "ssh_upload", "ssh_download"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    stored: dict = {}
    monkeypatch.setitem(
        sys.modules,
        "keyring",
        types.SimpleNamespace(
            set_password=lambda s, a, p: stored.update({(s, a): p}),
            get_password=lambda s, a: stored.get((s, a)),
            delete_password=lambda s, a: stored.pop((s, a), None),
        ),
    )
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
    monkeypatch.setattr(cli, "_attempt_tracker_path", lambda: tmp_path / "attempts.json")
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    servers = vault.create_node("Servers")
    vault.create_entry(servers, "Production", [
        {"key": "host", "value": "prod.example.test"},
        {"key": "username", "value": "deploy"},
        {"key": "password", "value": SECRET, "sensitive": True},
    ], tier=0, allowed_actions=SSH_ACTIONS)
    vault.create_entry(servers, "Approval", [
        {"key": "host", "value": "approval.example.test"},
        {"key": "username", "value": "root"},
        {"key": "password", "value": "approval-secret", "sensitive": True},
    ], tier=1, allowed_actions=["ssh_execute"])
    vault.create_entry(servers, "Closed", [
        {"key": "host", "value": "closed.example.test"},
        {"key": "username", "value": "root"},
        {"key": "password", "value": "closed-secret", "sensitive": True},
    ], tier=0, allowed_actions=[])
    yield vault
    vault.lock()


def _run(*args, input=None):
    return CliRunner().invoke(cli.main, list(args), input=input)


def _activity(vault):
    manager = ApprovalManager()
    broker = MCPBroker(vault, manager, ssh_manager=FakeSSHManager())
    assert broker.ssh_execute(
        "Servers/Production", f"echo {SECRET} | sudo -S systemctl restart nginx",
        agent_name="Claude",
    )["status"] == "ok"
    assert broker.ssh_upload("Servers/Production", "site/", "/var/www/site/", agent_name="Claude")["status"] == "ok"
    session = broker.ssh_session_open("Servers/Production", agent_name="Codex")["session_id"]
    broker.ssh_session_write(session, "ls\n", agent_name="Codex")
    broker.ssh_session_read(session, agent_name="Codex")
    broker.ssh_session_close(session, agent_name="Codex")

    manager.set_on_request(lambda r: manager.approve(r.request_id))
    assert broker.ssh_execute("Servers/Approval", "uptime", agent_name="Claude")["status"] == "ok"
    manager.set_on_request(lambda r: manager.deny(r.request_id))
    assert broker.ssh_execute("Servers/Approval", "rm -rf /", agent_name="Claude")["status"] == "denied"
    assert broker.ssh_execute("Servers/Closed", "id", agent_name="Claude")["status"] == "denied"
    ai_access.disable(vault, "cli")


def test_ai_log_lists_who_did_what_with_approvals_and_kill_switch(env):
    _activity(env)
    env.lock()
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0

    result = _run("ai", "log", "--since", "1h")
    assert result.exit_code == 0, result.output
    out = result.output
    lines = out.splitlines()

    assert SECRET not in out
    assert "$ echo [REDACTED] | sudo -S systemctl restart nginx" in out
    execute = next(line for line in lines if "ssh execute" in line and "ok, exit 0" in line)
    assert "Claude" in execute and "Servers/Production" in execute and "out 17 B" in execute
    assert any("ssh execute" in line and "started" in line for line in lines)
    assert "site/ -> /var/www/site/" in out
    assert any("ssh upload" in line and "2 file(s) 12 B" in line for line in lines)
    assert any("Codex" in line and "ssh session write" in line and "in 3 B" in line for line in lines)
    assert any("Codex" in line and "ssh session read" in line and "out 13 B" in line for line in lines)

    approvals = [line for line in lines if "approval ssh_execute" in line]
    assert any("Servers/Approval" in line and "APPROVED by owner" in line for line in approvals)
    assert any("Servers/Approval" in line and "DENIED by owner" in line for line in approvals)
    assert any("Servers/Closed" in line and "DENIED (policy)" in line for line in approvals)
    assert "$ uptime" in out and "rm -rf" not in out  # a refused command never ran
    assert any("AI OFF" in line for line in lines)
    assert "from cli on" in out


def test_ai_log_filters_by_entry_and_time(env):
    _activity(env)
    env.lock()
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0

    only = _run("ai", "log", "--entry", "servers/approval").output
    assert "Servers/Approval" in only
    assert "Servers/Production" not in only and "AI OFF" not in only

    assert _run("ai", "log", "--entry", "Servers/Nope").exit_code != 0
    assert _run("ai", "log", "--since", "soon").exit_code != 0

    env.unlock(PASSWORD)
    assert list(audit_view.ai_records(env, int((time.time() + 3600) * 1000))) == []
    assert len(list(audit_view.ai_records(env))) > 10


def test_ai_log_needs_the_vault_and_never_prompts_without_a_terminal(env):
    _activity(env)
    env.lock()
    result = _run("ai", "log", input="")
    assert result.exit_code != 0
    assert "locked" in result.output


def test_agent_sign_record_shows_certificate_key_id():
    record = audit_view.Record(int(time.time() * 1000), "mcp_ssh", {
        "entry_id": "E1", "operation": "agent_sign", "agent": "ssh-agent",
        "host": "web.example.test", "port": 22, "username": "ai-web",
        "cert_key_id": "sezam-ai:E1:3:abcd", "bound_host_key": "SHA256:x",
        "approval": "owner",
    })
    (line,) = audit_view.format_log([record], {"E1": "Servers/Web-AI"})
    assert "ssh-agent sign" in line and "ok (owner)" in line
    assert "ai-web@web.example.test:22 cert sezam-ai:E1:3:abcd" in line

    denied = audit_view.Record(record.at_ms, "mcp_ssh", {
        **record.detail, "operation": "agent_sign_denied", "reason": "host_key_mismatch",
        "bound_host_key": None,
    })
    (line,) = audit_view.format_log([denied], {"E1": "Servers/Web-AI"})
    assert "DENIED host_key_mismatch" in line and "(host not bound)" in line


def test_agent_chosen_text_cannot_drive_the_terminal():
    record = audit_view.Record(int(time.time() * 1000), "mcp_ssh", {
        "entry_id": "E1", "operation": "execute", "agent": "Cla\x1b[2Jude",
        "command": "ls\r\x1b[1A\u202eevil",
    })
    (line,) = audit_view.format_log([record], {})
    assert "\x1b" not in line and "\r" not in line and "\u202e" not in line
    assert "(deleted entry E1)" in line


def test_unreadable_details_are_shown_not_skipped(env):
    ai_access.enable(env, "cli")
    env.db.execute(
        "UPDATE audit_log SET encrypted_details = ? WHERE action = 'ai_on'", (b"x" * 80,)
    )
    records = list(audit_view.ai_records(env))
    assert records and records[-1].detail is None
    (line,) = audit_view.format_log(records[-1:], {})
    assert "AI ON" in line and "(details unreadable)" in line


def test_parse_since():
    assert audit_view.parse_since("90s") == 90
    assert audit_view.parse_since("1h") == 3600
    assert audit_view.parse_since("7d") == 7 * 86400
    for bad in ("", "0h", "1w", "-1h", "1 h"):
        with pytest.raises(ValueError):
            audit_view.parse_since(bad)
