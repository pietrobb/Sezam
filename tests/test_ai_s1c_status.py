"""AI broker TODO section 1/5 (S1c): `sezam ai status` overview.

Besides the kill switch it lists the running MCP servers with their SSH
sessions and every entry an AI agent can reach - path, tier, actions,
read_secret, local_root, max_session_minutes - resolved exactly as the MCP
tools resolve it, without any secret value. Tier 2 entries and everything
under a tier 2 folder are not listed.
"""

from __future__ import annotations

import sys
import types

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp import control
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker, MCPError
from sezam.vault import ai_access
from sezam.vault.crud import Vault

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "s1c-master-password"
SECRET = "s1c-ssh-password-value"


class _Sessions:
    def __init__(self, summaries):
        self.summaries = summaries

    def close_all(self):
        self.summaries = []

    def session_count(self):
        return len(self.summaries)

    def session_summaries(self):
        return list(self.summaries)


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
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    secret = [{"key": "password", "value": SECRET, "sensitive": True}]
    servers = vault.create_node("Servers", tier=0)
    web = vault.create_entry(
        servers, "web", [{"key": "host", "value": "h"}, *secret],
        allowed_actions=["ssh_session", "ssh_execute"],
    )
    vault.update_entry(web, local_root=str(tmp_path / "site"), max_session_minutes=30)
    vault.create_entry(servers, "db", secret, tier=1, allowed_actions=["ssh_execute"])
    broken = vault.create_entry(servers, "broken", secret, allowed_actions=["ssh_session"])
    vault.update_entry(broken, max_session_minutes="forever")
    vault.create_entry(servers, "root-only", secret, tier=2, allowed_actions=["ssh_session"])
    vault.create_entry(vault.create_node("Personal"), "bank", secret, ai_read_secret=True)
    vault_folder = vault.create_node("Vault", tier=2)
    vault.create_entry(vault_folder, "hidden", secret, tier=0, allowed_actions=["ssh_session"])
    vault.create_entry(vault.create_node("Deep", vault_folder, tier=0), "deeper", secret, tier=0)
    ids = {"web": web}
    vault.lock()
    yield types.SimpleNamespace(path=tmp_path, ids=ids)


def _run(*args, input=None):
    return CliRunner().invoke(cli.main, list(args), input=input)


def _overview(env) -> dict:
    vault = Vault(env.path)
    vault.unlock(PASSWORD)
    try:
        return {row["path"]: row for row in MCPBroker(vault, ApprovalManager()).access_overview()}
    finally:
        vault.lock()


def test_overview_lists_what_an_agent_can_reach(env):
    rows = _overview(env)

    assert set(rows) == {"Servers/web", "Servers/db", "Servers/broken", "Personal/bank"}
    web = rows["Servers/web"]
    assert web["tier"] == 0
    assert web["actions"] == ["ssh_execute", "ssh_session"]
    assert web["read_secret"] is False
    assert web["local_root"] == str(env.path / "site")
    assert web["max_session_minutes"] == 30
    assert rows["Servers/db"]["tier"] == 1
    assert rows["Servers/broken"]["max_session_minutes"] == "invalid"
    assert rows["Personal/bank"] == {
        **rows["Personal/bank"],
        "tier": 1,  # the default
        "actions": [],
        "read_secret": True,
        "local_root": None,
        "max_session_minutes": 60,
    }


def test_overview_matches_what_the_tools_see(env):
    rows = _overview(env)
    vault = Vault(env.path)
    vault.unlock(PASSWORD)
    try:
        broker = MCPBroker(vault, ApprovalManager())
        every = [
            "Servers/web", "Servers/db", "Servers/broken", "Servers/root-only",
            "Personal/bank", "Vault/hidden", "Vault/Deep/deeper",
        ]
        for path in every:
            visible = broker.vault_read(path)["status"] != "not_found"
            assert (path in rows) == visible, path
    finally:
        vault.lock()


def test_ai_status_with_a_session_prints_the_table(env):
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0

    result = _run("ai", "status")

    assert result.exit_code == 0, result.output
    out = result.output
    assert "AI access: ON (epoch 0)" in out
    assert "Running MCP servers: 0" in out and "SSH sessions: none" in out
    assert "Entries an AI agent can reach: 4" in out
    line = next(ln for ln in out.splitlines() if "Servers/web" in ln)
    assert "0 (auto)" in line and "ssh_execute,ssh_session" in line and "30" in line
    assert str(env.path / "site") in line
    assert "1 (approval)" in next(ln for ln in out.splitlines() if "Servers/db" in ln)
    assert "invalid" in next(ln for ln in out.splitlines() if "Servers/broken" in ln)
    for hidden in ("root-only", "hidden", "deeper"):
        assert hidden not in out
    assert SECRET not in out and PASSWORD not in out


def test_ai_status_without_a_session_never_prompts(env):
    result = _run("ai", "status", input="")

    assert result.exit_code == 0, result.output
    assert "AI access: ON (epoch 0)" in result.output
    assert "run 'sezam unlock' first" in result.output
    assert "Servers/web" not in result.output


def test_ai_status_still_lists_entries_while_ai_is_off(env):
    assert _run("ai", "off").exit_code == 0
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0

    out = _run("ai", "status").output

    assert "AI access: OFF (epoch 1)" in out
    assert "Servers/web" in out


def test_ai_status_shows_running_servers_and_their_sessions(env):
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0
    vault = Vault(env.path)
    vault.unlock(PASSWORD)
    sessions = _Sessions([
        {"entry_id": env.ids["web"], "agent": "claude\u202eevil", "open_seconds": 300, "idle_seconds": 20},
    ])
    broker = MCPBroker(vault, ApprovalManager(), sessions)
    server = control.ControlServer(
        control.broker_handlers(broker, lambda: None), control.endpoint(pid=4_100_001)
    )
    server.start()
    try:
        out = _run("ai", "status").output
    finally:
        server.stop()
        vault.lock()

    assert "Running MCP servers: 1" in out
    assert "AI on, vault unlocked, 1 SSH session(s)" in out
    line = next(ln for ln in out.splitlines() if "agent" in ln)
    assert "Servers/web" in line and "open 5 min" in line and "idle 20 s" in line
    assert "\u202e" not in out and "claude" in line


def test_overview_does_not_depend_on_the_kill_switch(env):
    vault = Vault(env.path)
    vault.unlock(PASSWORD)
    try:
        ai_access.disable(vault, "test")
        broker = MCPBroker(vault, ApprovalManager())
        with pytest.raises(MCPError):
            broker.vault_list("")
        assert len(broker.access_overview()) == 4
    finally:
        vault.lock()
