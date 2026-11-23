"""AI broker TODO section 1 (S1b): control channel of a running broker.

Each mcp-serve listens on an owner-only control endpoint. ``ai_off`` (no
authentication) sets the in-memory flag, closes every SSH session, persists
off + epoch and audits, in that order; ``status`` reports; ``lock`` locks
the vault; ``ai_on`` is refused. ``sezam ai off`` and ``sezam lock`` go
through it, and a real SSH shell closes within 2 s of ``sezam ai off``.
"""

from __future__ import annotations

import json
import os
import sys
import time
import types
from pathlib import Path

import paramiko
import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import control
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker, MCPError
from sezam.mcp.server import SezamMCPServer
from sezam.mcp.ssh import SSHManager, _fingerprint
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS, SSH_PASSWORD
from tests.test_ai_p3_session_limits import _Server as _ShellServer

PASSWORD = "s1b-master-password"
_next_pid = iter(range(4_000_000, 5_000_000))


def _endpoint() -> str:
    # Fake pids: several control servers in one test process.
    return control.endpoint(pid=next(_next_pid))


def _wait(predicate, seconds: float = 2.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _code(call) -> str:
    try:
        result = call()
    except MCPError as exc:
        return exc.code
    return result.get("code") or result.get("status")


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


class _FakeSSH:
    def __init__(self, events=None):
        self.events = events if events is not None else []
        self.sessions = 1

    def close_all(self):
        self.events.append("close_all")
        self.sessions = 0

    def session_count(self):
        return self.sessions

    def session_summaries(self):
        return []


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
    Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
    vault = Vault(tmp_path)
    vault.unlock(PASSWORD)
    servers: list = []

    def serve(broker, lock=None):
        server = control.ControlServer(
            control.broker_handlers(broker, lock or (lambda: (broker.close(), vault.lock()))),
            _endpoint(),
        )
        server.start()
        servers.append(server)
        return server

    yield types.SimpleNamespace(path=tmp_path, vault=vault, serve=serve)
    for server in servers:
        server.stop()
    vault.lock()


@pytest.fixture
def shell(env):
    """A real paramiko SSH server and a tier 0 entry with ssh_session."""
    server = _ShellServer()
    folder = env.vault.create_node("Servers")
    env.vault.create_entry(
        folder,
        "web",
        [
            {"key": "host", "value": "127.0.0.1"},
            {"key": "port", "value": str(server.port)},
            {"key": "username", "value": "deploy"},
            {"key": "password", "value": SSH_PASSWORD, "sensitive": True},
            {"key": "host_key_sha256", "value": _fingerprint(server.host_key)},
        ],
        tier=0,
        allowed_actions=["ssh_session"],
    )
    yield server
    server.close()


@pytest.fixture(autouse=True)
def no_user_known_hosts(monkeypatch):
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)


def _server_channels(server) -> list:
    return [c for c in server._transports if isinstance(c, paramiko.Channel)]


# ── Integration: real SSH shell closes within 2 s of 'sezam ai off' ──


def test_sezam_ai_off_closes_a_real_ssh_session_within_two_seconds(env, shell):
    manager = SSHManager()
    broker = MCPBroker(env.vault, ApprovalManager(), manager)
    env.serve(broker)
    opened = broker.ssh_session_open("Servers/web", agent_name="a")
    assert opened["status"] == "ok", opened
    sid = opened["session_id"]
    assert broker.ssh_session_write(sid, "id\n", agent_name="a")["status"] == "ok"
    assert _wait(lambda: _server_channels(shell))

    started = time.monotonic()
    result = _run("ai", "off")
    assert result.exit_code == 0, result.output
    assert manager.session_count() == 0
    assert _wait(lambda: all(c.closed for c in _server_channels(shell)), 2.0)
    assert time.monotonic() - started < 2.0
    assert "1 running MCP server(s) stopped" in result.output

    assert _code(lambda: broker.ssh_session_read(sid, agent_name="a")) == "ai_disabled"
    assert _code(lambda: broker.ssh_session_open("Servers/web", agent_name="a")) == "ai_disabled"
    # The broker persisted it once; the CLI did not bump the epoch again.
    assert ai_access.read_state(Vault(env.path)) == ai_access.AIAccessState(False, 1)
    broker.close()
    env.vault.lock()
    assert _actions(env.path) == ["ai_off"]


def test_ai_off_order_flag_close_persist_audit(env, monkeypatch):
    events: list = []
    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH(events))
    real_disable = ai_access.disable
    real_audit = env.vault._audit_log

    def disable(vault, source, *rest):
        events.append(("persist", broker._ai_off, source))
        return real_disable(vault, source, *rest)

    def audit(action, *args, **kwargs):
        events.append(("audit", action, ai_access.read_state(env.vault).enabled))
        return real_audit(action, *args, **kwargs)

    monkeypatch.setattr(ai_access, "disable", disable)
    monkeypatch.setattr(env.vault, "_audit_log", audit)
    real_close = broker._ssh.close_all
    broker._ssh.close_all = lambda: (events.append(("flag", broker._ai_off)), real_close())
    server = env.serve(broker)

    reply = control.send(server.path, "ai_off")

    assert reply == {"status": "ok", "ai_access": "off", "persisted": True, "epoch": 1}
    assert events == [
        ("flag", True),
        "close_all",
        ("persist", True, "control"),
        ("audit", "ai_off", False),
    ]


def test_ai_off_holds_in_memory_when_persisting_fails(env, monkeypatch):
    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH())
    server = env.serve(broker)

    def broken(vault, source, *rest):
        raise OSError("disk full")

    monkeypatch.setattr(ai_access, "disable", broken)
    reply = control.send(server.path, "ai_off")

    assert reply["status"] == "ok" and reply["persisted"] is False
    assert ai_access.read_state(env.vault).enabled  # nothing was written
    assert _code(lambda: broker.vault_list("")) == "ai_disabled"
    assert broker.enforce_kill_switch() is True


def test_cli_writes_the_switch_when_no_broker_persisted_it(env, monkeypatch):
    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH())
    env.serve(broker)
    monkeypatch.setattr(broker, "disable_ai", lambda source: None)

    result = _run("ai", "off")

    assert result.exit_code == 0, result.output
    assert ai_access.read_state(Vault(env.path)) == ai_access.AIAccessState(False, 1)


def test_cli_does_not_trust_an_ok_reply_while_the_vault_reads_on(env):
    # Something answering on a control endpoint claims it persisted ai_off.
    liar = control.ControlServer(
        {"ai_off": lambda: {"status": "ok", "persisted": True, "epoch": 9}}, _endpoint()
    )
    liar.start()
    try:
        assert _run("ai", "off").exit_code == 0
    finally:
        liar.stop()
    assert ai_access.read_state(Vault(env.path)) == ai_access.AIAccessState(False, 1)


def test_sezam_ai_on_with_password_lets_the_broker_serve_again(env):
    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH())
    server = env.serve(broker)
    assert control.send(server.path, "ai_off")["persisted"] is True
    assert _code(lambda: broker.vault_list("")) == "ai_disabled"

    ai_access.enable(env.vault, "test")  # what 'sezam ai on' does after the password

    assert _code(lambda: broker.vault_list("")) != "ai_disabled"
    assert broker.enforce_kill_switch() is False


def test_ai_on_is_never_accepted_on_the_control_channel(env):
    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH())
    server = env.serve(broker)
    assert control.send(server.path, "ai_off")["status"] == "ok"

    reply = control.send(server.path, "ai_on")

    assert reply["status"] == "error" and reply["code"] == "not_allowed"
    assert ai_access.read_state(env.vault).enabled is False
    assert _code(lambda: broker.vault_list("")) == "ai_disabled"
    with pytest.raises(ValueError):
        control.ControlServer({"ai_on": lambda: {}}, _endpoint())


@pytest.mark.parametrize(
    "raw, code",
    [(b"{nope\n", "bad_request"), (b"[1]\n", "unknown_command"), (b'{"command": "dump"}\n', "unknown_command")],
)
def test_malformed_requests_are_refused(raw, code):
    called = []
    handlers = {"ai_off": lambda: called.append(1) or {"status": "ok"}}
    assert control.handle_request(handlers, raw.rstrip(b"\n"))["code"] == code
    assert called == []


def test_status_reports_without_secrets(env, shell):
    manager = SSHManager()
    broker = MCPBroker(env.vault, ApprovalManager(), manager)
    server = env.serve(broker)
    assert broker.ssh_session_open("Servers/web", agent_name="a")["status"] == "ok"

    reply = control.send(server.path, "status")

    assert reply == {
        "status": "ok",
        "pid": os.getpid(),
        "ai_access": "on",
        "epoch": 0,
        "vault_unlocked": True,
        "ssh_sessions": 1,
        "sessions": [
            {"entry_id": reply["sessions"][0]["entry_id"], "agent": "a", "open_seconds": 0, "idle_seconds": 0}
        ],
        "remote_policy": "off",
        "anchor": "none",  # R16-L6: a vault on no server waits for no anchor
    }
    assert SSH_PASSWORD not in json.dumps(reply) and PASSWORD not in json.dumps(reply)
    broker.close()


def test_watcher_backstop_closes_sessions_when_the_vault_reads_off(env):
    ssh = _FakeSSH()
    broker = MCPBroker(env.vault, ApprovalManager(), ssh)
    watch = cli._watch_session_and_lock(
        env.vault, broker.close, interval=0.05, on_tick=broker.enforce_kill_switch
    )
    try:
        # Another process (GUI, a broker that did not get the message) wrote it.
        other = Vault(env.path)
        ai_access.disable(other, "elsewhere")
        assert _wait(lambda: ssh.sessions == 0, 2.0)
    finally:
        watch.set()


# ── lock ──


# Idea #9: the watcher thread re-unlocks the vault; under a loaded full run
# that took longer than a fixed 2 s. The slow case keeps it from regressing.
@pytest.mark.parametrize("unlock_delay", [0.0, 2.5], ids=["normal", "slow_unlock"])
def test_control_lock_locks_and_the_session_does_not_unlock_it_again(
    env, monkeypatch, unlock_delay
):
    if unlock_delay:
        real_unlock = Vault.unlock_with_kek

        def slow_unlock(self, kek):
            time.sleep(unlock_delay)
            return real_unlock(self, kek)

        monkeypatch.setattr(Vault, "unlock_with_kek", slow_unlock)
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0
    env.vault.lock()
    vault = Vault(env.path)
    server_mcp = SezamMCPServer(vault)
    ssh = _FakeSSH()
    server_mcp.broker._ssh = ssh
    watch = cli._watch_session_and_lock(vault, server_mcp.broker.close, interval=0.05)
    try:
        assert vault.is_unlocked
        server = env.serve(server_mcp.broker, watch.lock_now)

        assert control.send(server.path, "lock") == {"status": "ok", "locked": True}

        assert not vault.is_unlocked and ssh.sessions == 0
        time.sleep(0.3)  # several watcher ticks with the session still valid
        assert not vault.is_unlocked
        assert server_mcp.handle_tool_call("vault_list", {})["code"] == "vault_locked"

        assert _run("unlock", input=PASSWORD + "\n").exit_code == 0
        # Wait for the watcher's unlock itself, not for a fixed short time.
        assert _wait(lambda: vault.is_unlocked, seconds=30)
    finally:
        watch.set()
        # Through the watcher's mutex: is_unlocked turns true before its
        # unlock finishes (search index), and a bare lock() closed the
        # database under it (access violation in a full run).
        watch.lock_now()


def test_sezam_lock_locks_a_running_server_at_once(env):
    assert _run("unlock", input=PASSWORD + "\n").exit_code == 0
    env.vault.lock()
    vault = Vault(env.path)
    server_mcp = SezamMCPServer(vault)
    server_mcp.broker._ssh = _FakeSSH()
    # A watcher this slow would take a minute to notice the session is gone.
    watch = cli._watch_session_and_lock(vault, server_mcp.broker.close, interval=60)
    try:
        assert vault.is_unlocked
        env.serve(server_mcp.broker, watch.lock_now)

        result = _run("lock")

        assert result.exit_code == 0, result.output
        assert "Locked 1 running MCP server(s)." in result.output
        assert not vault.is_unlocked
    finally:
        watch.set()
        watch.lock_now()


def test_ai_off_and_lock_reach_every_running_broker(env):
    brokers = [MCPBroker(env.vault, ApprovalManager(), _FakeSSH()) for _ in range(2)]
    for broker in brokers:
        env.serve(broker)

    assert _run("ai", "off").exit_code == 0

    assert all(b._ai_off for b in brokers)
    assert all(b._ssh.sessions == 0 for b in brokers)


def test_mcp_serve_refuses_to_run_without_a_control_channel(env, monkeypatch):
    env.vault.lock()

    def unavailable(self):
        raise PermissionError("run directory is writable by other users")

    monkeypatch.setattr(control.ControlServer, "start", unavailable)
    result = _run("mcp-serve", "--transport", "stdio")

    assert result.exit_code != 0
    assert "control channel" in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket permissions")
def test_control_socket_is_owner_only_in_the_run_dir(env):
    import stat

    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH())
    server = env.serve(broker)
    path = Path(server.path)

    assert path.parent == control.run_dir()
    assert stat.S_ISSOCK(os.lstat(path).st_mode)
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.lstat(path.parent).st_mode) == 0o700
    server.stop()
    assert not path.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipe")
def test_control_pipe_name_cannot_be_taken_twice(env):
    broker = MCPBroker(env.vault, ApprovalManager(), _FakeSSH())
    server = env.serve(broker)
    second = control.ControlServer(control.broker_handlers(broker, lambda: None), server.path)
    with pytest.raises(OSError):
        second.start()
    assert control.send(server.path, "status")["status"] == "ok"
