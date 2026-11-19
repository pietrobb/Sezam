"""AI broker TODO section 1 (S1a): persistent kill switch.

`sezam ai off` needs no password and works on a locked vault, `sezam ai on`
needs the master password, the state survives a restart of the MCP server,
`mcp-serve` refuses to start while it is off, every MCP tool (including
SSH session read/write/resize) answers ai_disabled, and an unreadable
switch counts as off. Turning it off is always audited, if need be at the
next unlock.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.server import SezamMCPServer
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_mcp_ssh import FakeSSHManager, ssh_vault  # noqa: F401  (fixture)

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "s1a-master-password"


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
    Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
    return tmp_path


def _run(*args, input=None):
    return CliRunner().invoke(cli.main, list(args), input=input)


def _actions(path) -> list[str]:
    vault = Vault(Path(path))
    vault.unlock(PASSWORD)
    try:
        rows = vault.db.fetchall("SELECT action FROM audit_log ORDER BY rowid")
        return [row["action"] for row in rows if row["action"].startswith("ai_")]
    finally:
        vault.lock()


def test_existing_vault_starts_enabled(env):
    assert ai_access.read_state(Vault(env)) == ai_access.AIAccessState(True, 0)
    assert "AI access: ON (epoch 0)" in _run("ai", "status").output


def test_off_needs_no_password_and_bumps_epoch(env):
    result = _run("ai", "off", input="")
    assert result.exit_code == 0, result.output
    assert "OFF (epoch 1)" in result.output
    assert _run("ai", "off").exit_code == 0
    assert ai_access.read_state(Vault(env)) == ai_access.AIAccessState(False, 2)
    assert "AI access: OFF (epoch 2)" in _run("ai", "status").output


def test_off_on_a_locked_vault_is_audited_at_the_next_unlock(env):
    assert _run("ai", "off").exit_code == 0
    assert _actions(env) == ["ai_off"]
    assert _actions(env) == ["ai_off"]  # written once, queue cleared


def test_off_with_a_session_is_audited_at_once(env):
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0
    assert _run("ai", "off").exit_code == 0
    vault = Vault(env)
    vault.db.open()
    try:
        assert vault.db.get_meta(ai_access.PENDING_AUDIT_KEY) is None
    finally:
        vault.db.close()
    assert _actions(env) == ["ai_off"]


def test_on_requires_the_master_password(env):
    _run("ai", "off")
    assert _run("ai", "on", input="\n").exit_code != 0
    assert _run("ai", "on", input="wrong\n").exit_code != 0
    assert not ai_access.read_state(Vault(env)).enabled

    # A live CLI session is not enough: 'on' always asks again.
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0
    assert _run("ai", "on", input="").exit_code != 0
    assert not ai_access.read_state(Vault(env)).enabled

    result = _run("ai", "on", input=PASSWORD + "\n")
    assert result.exit_code == 0, result.output
    assert ai_access.read_state(Vault(env)) == ai_access.AIAccessState(True, 1)
    assert _actions(env) == ["ai_off", "ai_on"]


def test_mcp_serve_refuses_to_start_while_off(env, monkeypatch):
    started = []
    monkeypatch.setattr(SezamMCPServer, "run_stdio", lambda self: started.append(1))
    _run("ai", "off")
    result = _run("mcp-serve")
    assert result.exit_code != 0
    assert "AI access is turned off" in result.output
    assert started == []


ALL_TOOLS = {
    "vault_list": {},
    "vault_read": {"path": "Servers/Production"},
    "vault_search": {"query": "Production"},
    "vault_use": {"path": "Servers/Production", "action": "totp_code"},
    "ssh_execute": {"path": "Servers/Production", "command": "id"},
    "ssh_session_open": {"path": "Servers/Production"},
    "ssh_session_write": {"session_id": "session-capability", "data": "id\n"},
    "ssh_session_read": {"session_id": "session-capability"},
    "ssh_session_resize": {"session_id": "session-capability", "width": 80, "height": 24},
    "ssh_session_close": {"session_id": "session-capability"},
    "ssh_upload": {"path": "Servers/Production", "local_path": "a", "remote_path": "/b"},
    "ssh_download": {"path": "Servers/Production", "remote_path": "/b", "local_path": "a"},
}


def _server(vault, fake):
    server = SezamMCPServer(vault)
    server._broker = MCPBroker(vault, ApprovalManager(), ssh_manager=fake)
    return server


@pytest.mark.parametrize("tool", ALL_TOOLS)
def test_every_tool_answers_ai_disabled(ssh_vault, tool):  # noqa: F811
    fake = FakeSSHManager()
    server = _server(ssh_vault, fake)
    assert server.handle_tool_call("ssh_session_open", ALL_TOOLS["ssh_session_open"])["status"] == "ok"
    fake.calls.clear()

    ai_access.disable(ssh_vault, "test")
    result = server.handle_tool_call(tool, ALL_TOOLS[tool])
    assert result["status"] == "ai_disabled"
    assert fake.calls == [] and fake.closed

    # A new server process over the same vault is still off.
    restarted = _server(ssh_vault, FakeSSHManager())
    assert restarted.handle_tool_call(tool, ALL_TOOLS[tool])["status"] == "ai_disabled"


def test_switch_turned_off_during_approval_stops_the_action(ssh_vault):  # noqa: F811
    fake = FakeSSHManager()
    approvals = ApprovalManager()

    def approve_after_brake(request):
        ai_access.disable(ssh_vault, "test")
        approvals.approve(request.request_id)

    approvals.set_on_request(approve_after_brake)
    server = SezamMCPServer(ssh_vault)
    server._broker = MCPBroker(ssh_vault, approvals, ssh_manager=fake)
    result = server.handle_tool_call("ssh_execute", {"path": "Servers/Approval", "command": "id"})
    assert result["status"] == "ai_disabled"
    assert fake.calls == []


@pytest.mark.parametrize(
    "enabled, epoch",
    [("yes", "1"), ("1", "x"), ("1", "-3"), ("0", "4")],
)
def test_malformed_state_counts_as_off(ssh_vault, enabled, epoch):  # noqa: F811
    ssh_vault.db.set_meta(ai_access.ENABLED_KEY, enabled)
    ssh_vault.db.set_meta(ai_access.EPOCH_KEY, epoch)
    assert not ai_access.read_state(ssh_vault).enabled
    broker = MCPBroker(ssh_vault, ApprovalManager(), ssh_manager=FakeSSHManager())
    with pytest.raises(Exception) as caught:
        broker.vault_list()
    assert getattr(caught.value, "code", None) == "ai_disabled"


def test_unreadable_state_counts_as_off(ssh_vault, monkeypatch):  # noqa: F811
    def broken(key):
        raise OSError("disk")

    monkeypatch.setattr(ssh_vault.db, "get_meta", broken)
    assert ai_access.read_state(ssh_vault) == ai_access.AIAccessState(False, 0)


def test_on_requires_an_unlocked_vault(env):
    vault = Vault(env)
    ai_access.disable(vault, "test")
    with pytest.raises(PermissionError):
        ai_access.enable(vault, "test")
    assert not ai_access.read_state(vault).enabled
