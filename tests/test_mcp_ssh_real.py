"""T4 (code review HEAD 2c7e809): SSH broker against a real in-process SSH server.

The older test_mcp_ssh.py mocks paramiko.SSHClient, so it can never prove that
a pinned host key is checked during key exchange (before the password leaves
the machine) or that the connect/banner/command timeouts actually fire. These
tests run a real paramiko server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading
import time

import paramiko
import pytest

from sezam.mcp import ssh as ssh_mod
from sezam.mcp.ssh import SSHBrokerError, SSHManager, _fingerprint

PASSWORD = "s3cret-pass"


class _Server(paramiko.ServerInterface):
    def __init__(self, behaviour: str, auth_attempts: list):
        self.behaviour = behaviour
        self.auth_attempts = auth_attempts

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.auth_attempts.append((username, password))
        if username == "deploy" and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED_OPEN_REQUEST

    def check_channel_exec_request(self, channel, command):
        if self.behaviour == "hang":
            return True  # accept the command, then never answer

        def answer():
            # Paramiko replies CHANNEL_SUCCESS only after this method returns;
            # a CLOSE sent before it makes the client's exec_command fail with
            # "Channel closed." (the flaky run). The broker sends EOF only once
            # exec_command has returned, so waiting for it orders the reply first.
            deadline = time.monotonic() + 10
            while not channel.eof_received and time.monotonic() < deadline:
                time.sleep(0.01)
            channel.sendall(b"ran: " + bytes(command) + b"\n")
            channel.sendall_stderr(b"warn\n")
            channel.send_exit_status(3)
            channel.close()

        threading.Thread(target=answer, daemon=True).start()
        return True


class _SSHServer:
    """Real SSH server; ``behaviour`` = ok | hang | silent (no banner)."""

    def __init__(self, behaviour: str = "ok"):
        self.host_key = paramiko.ECDSAKey.generate()
        self.behaviour = behaviour
        self.auth_attempts: list = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._transports: list = []
        self._conns: list = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.host_key)

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self._conns.append(conn)
            if self.behaviour == "silent":
                continue  # TCP accepted, SSH banner never sent
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_Server(self.behaviour, self.auth_attempts))
            except Exception:
                continue
            threading.Thread(target=self._keep_channels, args=(transport,), daemon=True).start()

    def _keep_channels(self, transport):
        # A paramiko Channel closes itself when garbage collected.
        while transport.is_active():
            channel = transport.accept(1)
            if channel is not None:
                self._conns.append(channel)

    def close(self):
        self._stop = True
        self._sock.close()
        for transport in self._transports:
            transport.close()
        for conn in self._conns:
            conn.close()


@pytest.fixture
def server():
    servers = []

    def make(behaviour="ok"):
        srv = _SSHServer(behaviour)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


@pytest.fixture(autouse=True)
def no_user_known_hosts(monkeypatch):
    # Never let the developer's ~/.ssh/known_hosts decide a test.
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)


def _entry(port: int, fingerprint: str | None = None) -> dict:
    fields = [
        {"key": "host", "value": "127.0.0.1"},
        {"key": "port", "value": str(port)},
        {"key": "username", "value": "deploy"},
        {"key": "password", "value": PASSWORD},
    ]
    if fingerprint:
        fields.append({"key": "host_key_sha256", "value": fingerprint})
    return {"fields": fields}


def test_pinned_host_key_executes_and_returns_streams(server):
    srv = server()
    result = SSHManager().execute(_entry(srv.port, srv.fingerprint), "uptime", timeout=10)

    assert result["stdout"] == "ran: uptime\n"
    assert result["stderr"] == "warn\n"
    assert result["exit_code"] == 3
    assert srv.auth_attempts == [("deploy", PASSWORD)]


def test_wrong_pin_is_rejected_before_the_password_is_sent(server):
    srv = server()
    impostor = _fingerprint(paramiko.ECDSAKey.generate())

    with pytest.raises(SSHBrokerError) as exc:
        SSHManager().execute(_entry(srv.port, impostor), "uptime", timeout=10)

    assert exc.value.code == "host_key_mismatch"
    time.sleep(0.2)
    assert srv.auth_attempts == []


def test_unknown_host_without_pin_is_rejected_before_auth(server):
    srv = server()

    with pytest.raises(SSHBrokerError) as exc:
        SSHManager().execute(_entry(srv.port), "uptime", timeout=10)

    assert exc.value.code == "connection_failed"
    time.sleep(0.2)
    assert srv.auth_attempts == []


def test_server_that_never_sends_a_banner_times_out(server, monkeypatch):
    srv = server("silent")
    monkeypatch.setattr(ssh_mod, "DEFAULT_CONNECT_TIMEOUT", 1)

    started = time.monotonic()
    with pytest.raises(SSHBrokerError) as exc:
        SSHManager().execute(_entry(srv.port, srv.fingerprint), "uptime", timeout=10)

    assert exc.value.code == "connection_failed"
    assert time.monotonic() - started < 8


def test_command_that_never_exits_times_out(server):
    srv = server("hang")

    started = time.monotonic()
    with pytest.raises(SSHBrokerError) as exc:
        SSHManager().execute(_entry(srv.port, srv.fingerprint), "sleep infinity", timeout=1)

    assert exc.value.code == "timeout"
    assert time.monotonic() - started < 6
