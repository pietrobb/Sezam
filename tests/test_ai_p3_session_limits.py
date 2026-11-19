"""AI broker TODO P3: SSH sessions have a policy lifetime and are re-checked.

Real paramiko SSH server with an interactive shell. ``max_session_minutes``
(default 60) is read from the encrypted entry policy on every session
read/write/resize, so lowering it closes an already approved shell; reading
output no longer counts as activity for the idle timer.
"""

from __future__ import annotations

import socket
import sys
import threading
import types

import paramiko
import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh import SSHManager, _fingerprint
from sezam.vault.crud import Vault

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
MASTER = "p3-master-password"
SSH_PASSWORD = "p3-ssh-password"


class _Shell(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        ok = username == "deploy" and password == SSH_PASSWORD
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_window_change_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        def echo():
            while not channel.closed:
                data = channel.recv(1024)
                if not data:
                    return
                channel.sendall(b"echo:" + data)

        threading.Thread(target=echo, daemon=True).start()
        return True


class _Server:
    def __init__(self):
        self.host_key = paramiko.ECDSAKey.generate()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._transports: list = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_Shell())
            except Exception:
                continue
            threading.Thread(target=self._keep, args=(transport,), daemon=True).start()

    def _keep(self, transport):
        # A paramiko Channel closes itself when garbage collected.
        while transport.is_active():
            channel = transport.accept(1)
            if channel is not None:
                self._transports.append(channel)

    def close(self):
        self._sock.close()
        for transport in self._transports:
            transport.close()


@pytest.fixture(autouse=True)
def no_user_known_hosts(monkeypatch):
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)


@pytest.fixture
def env(tmp_path):
    server = _Server()
    vault = Vault.create(tmp_path / "vault", MASTER, FAST_PARAMS)
    folder = vault.create_node("Servers")

    def entry(name: str, **policy) -> str:
        entry_id = vault.create_entry(
            folder,
            name,
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
        if policy:
            vault.update_entry(entry_id, **policy)
        return entry_id

    manager = SSHManager()
    broker = MCPBroker(vault, ApprovalManager(), manager)
    yield types.SimpleNamespace(vault=vault, broker=broker, manager=manager, entry=entry)
    broker.close()
    vault.lock()
    server.close()


def _open(env, name: str) -> str:
    opened = env.broker.ssh_session_open(f"Servers/{name}", agent_name="a")
    assert opened["status"] == "ok", opened
    return opened["session_id"]


def _age(env, session_id: str, seconds: float) -> None:
    """Pretend the session was opened ``seconds`` ago."""
    env.manager._sessions[session_id].created_at -= seconds


def test_session_closes_after_entry_max_session_minutes(env):
    env.entry("web", max_session_minutes=1)
    sid = _open(env, "web")
    assert env.broker.ssh_session_write(sid, "ls\n", agent_name="a")["status"] == "ok"

    _age(env, sid, 61)
    result = env.broker.ssh_session_write(sid, "rm -rf /\n", agent_name="a")

    assert result["status"] == "error", result
    assert result["code"] in ("session_expired", "session_not_found"), result
    assert sid not in env.manager._sessions
    assert env.broker.ssh_session_read(sid, agent_name="a")["code"] == "session_not_found"


def test_default_lifetime_is_60_minutes(env):
    env.entry("web")
    sid = _open(env, "web")

    _age(env, sid, 59 * 60)
    assert env.broker.ssh_session_read(sid, agent_name="a")["status"] == "ok"
    _age(env, sid, 2 * 60)
    assert env.broker.ssh_session_read(sid, agent_name="a")["code"] in (
        "session_expired",
        "session_not_found",
    )
    assert sid not in env.manager._sessions


def test_lowering_max_session_minutes_closes_an_open_session(env):
    entry_id = env.entry("web", max_session_minutes=120)
    sid = _open(env, "web")
    _age(env, sid, 10 * 60)
    assert env.broker.ssh_session_read(sid, agent_name="a")["status"] == "ok"

    env.vault.update_entry(entry_id, max_session_minutes=5)
    result = env.broker.ssh_session_read(sid, agent_name="a")

    assert result["status"] == "error" and result["code"] == "session_expired", result
    assert sid not in env.manager._sessions


@pytest.mark.parametrize("bad", [0, -1, 24 * 60 + 1, "60", 1.5, True])
def test_malformed_max_session_minutes_refuses_open(env, bad):
    env.entry("web", max_session_minutes=bad)

    result = env.broker.ssh_session_open("Servers/web", agent_name="a")

    assert result["status"] == "error" and result["code"] == "policy_invalid", result
    assert env.manager._sessions == {}


def test_malformed_policy_after_open_revokes_the_session(env):
    entry_id = env.entry("web")
    sid = _open(env, "web")

    env.vault.update_entry(entry_id, max_session_minutes="forever")
    result = env.broker.ssh_session_write(sid, "id\n", agent_name="a")

    assert result["code"] == "policy_revoked", result
    assert sid not in env.manager._sessions


def test_reading_output_does_not_refresh_the_idle_timer(env):
    env.entry("web")
    sid = _open(env, "web")
    session = env.manager._sessions[sid]

    session.last_used_at -= 60
    before = session.last_used_at
    assert env.broker.ssh_session_read(sid, agent_name="a")["status"] == "ok"
    assert session.last_used_at == before

    assert env.broker.ssh_session_write(sid, "x\n", agent_name="a")["status"] == "ok"
    assert session.last_used_at > before

    session.last_used_at -= env.manager._session_idle_timeout + 1
    result = env.broker.ssh_session_read(sid, agent_name="a")
    assert result["status"] == "error" and result["code"] == "session_not_found", result


def test_cli_sets_max_session_minutes(tmp_path, monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "keyring",
        types.SimpleNamespace(
            set_password=lambda *a: None, get_password=lambda *a: None, delete_password=lambda *a: None
        ),
    )
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
    monkeypatch.setattr(cli, "_attempt_tracker_path", lambda: tmp_path / "attempts.json")
    vault = Vault.create(tmp_path, MASTER, FAST_PARAMS)
    vault.create_entry(vault.create_node("Servers"), "web", [{"key": "host", "value": "h"}])
    vault.lock()
    run = lambda *args: CliRunner().invoke(  # noqa: E731
        cli.main, ["mcp-policy", "Servers/web", *args], input=MASTER + "\n"
    )

    assert run("--max-session-minutes", "30").exit_code == 0
    assert run("--max-session-minutes", "0").exit_code != 0
    vault.unlock(MASTER)
    assert vault.find_entry_by_path("Servers/web")["max_session_minutes"] == 30
    vault.lock()
