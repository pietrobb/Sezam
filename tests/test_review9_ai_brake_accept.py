"""Review 1141a20 H7 (AI broker): the brake's accept loop died on EMFILE.

Every endpoint (control/brake, ssh-agent, MCP socket and pipe) served each
connection on its own thread without any bound, and the accept loop ended
on the first OSError or failed thread start. A peer in the ``sezam-ai``
group that opened connections and sent nothing (or a byte now and then)
used up the broker's descriptors; from then on ``sezam ai off`` and the GUI
switch reached nobody. Now:

* the accept loops back off and retry on any error; only a stop ends them;
* an endpoint holds a bounded number of connections, and on a shared
  endpoint a bounded number per OS user (uid / SID); the control channel
  cuts its oldest connection rather than refusing a new one, so a brake
  request never waits behind idle peers, and the client tries again;
* a control connection has a whole deadline (a trickling peer is cut);
* the MCP transports read at most MAX_LINE per JSON-RPC line;
* the systemd units set LimitNOFILE and TasksMax.

The real Linux run (EMFILE under a lowered RLIMIT_NOFILE, and a 300-peer
flood) is ``tests/wsl_brake_flood.py``, driven by the last tests here.
"""

from __future__ import annotations

import errno
import io
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
import types
import uuid
from pathlib import Path

import pytest

from sezam.mcp import control
from sezam.mcp import server as mcp_server
from sezam.mcp import service
from sezam.mcp.broker import MCPBroker
from tests.test_ai_s1b_control import _endpoint, _FakeSSH, env  # noqa: F401
from tests.test_review_cli_ipc import _bare_server

REPO = Path(__file__).resolve().parents[1]
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")


class _Listener:
    """accept() raises the queued errors first, then hands out the queued
    connections, then times out like an idle listening socket."""

    def __init__(self, errors=(), conns=()):
        self.errors = list(errors)
        self.conns = list(conns)

    def accept(self):
        if self.errors:
            raise self.errors.pop(0)
        if self.conns:
            return self.conns.pop(0), None
        time.sleep(0.02)
        raise socket.timeout()

    def listen(self, backlog):
        pass

    def settimeout(self, value):
        pass

    def close(self):
        pass


def _control_server(calls: list) -> control.ControlServer:
    def ai_off():
        calls.append("ai_off")
        return {"status": "ok", "ai_access": "off", "persisted": True}

    return control.ControlServer({"ai_off": ai_off, "status": lambda: {"status": "ok"}}, _endpoint())


def _ask(client: socket.socket, command: str) -> dict | None:
    client.settimeout(3)
    client.sendall(json.dumps({"command": command}).encode() + b"\n")
    data = b""
    try:
        while b"\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        return None
    return json.loads(data) if data.strip() else None


def _run_unix_loop(server: control.ControlServer, listener: _Listener) -> threading.Thread:
    server._sock = listener
    server._running = True
    t = threading.Thread(target=server._serve_unix, daemon=True)
    t.start()
    return t


def test_accept_loop_survives_emfile():
    calls: list = []
    server = _control_server(calls)
    client, conn = socket.socketpair()
    errors = [OSError(errno.EMFILE, "Too many open files")] * 3 + [OSError(errno.ENFILE, "x")]
    t = _run_unix_loop(server, _Listener(errors, [conn]))
    try:
        # Before: the loop ended on the first EMFILE and nobody answered.
        assert _ask(client, "ai_off") == {"status": "ok", "ai_access": "off", "persisted": True}
        assert calls == ["ai_off"] and t.is_alive()
    finally:
        server._running = False
        client.close()
    t.join(3)
    assert not t.is_alive()


def test_accept_loop_survives_a_thread_that_cannot_start(monkeypatch):
    calls: list = []
    server = _control_server(calls)
    first, first_conn = socket.socketpair()
    second, second_conn = socket.socketpair()
    t = _run_unix_loop(server, _Listener())
    real = threading.Thread
    failed: list = []

    class Flaky(real):
        def start(self):
            if not failed:
                failed.append(self.name)
                raise RuntimeError("can't start new thread")
            super().start()

    monkeypatch.setattr(control, "threading", types.SimpleNamespace(
        Thread=Flaky, Lock=threading.Lock, Event=threading.Event,
    ))
    server._sock.conns += [first_conn, second_conn]
    try:
        first.settimeout(3)
        assert first.recv(10) == b""  # dropped, not left hanging
        # Before: the RuntimeError ended the accept loop for good.
        assert _ask(second, "status") == {"status": "ok"}
        assert failed and _wait_empty(server)
    finally:
        server._running = False
        first.close()
        second.close()
    t.join(3)


def _wait_empty(server, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if len(server._admission) == 0:
            return True
        time.sleep(0.02)
    return False


def test_admission_cuts_the_oldest_of_the_same_peer_first():
    cut: list = []
    admission = control.Admission(total=4, per_peer=2, evict=True)
    slots = [admission.admit(peer, lambda n=n: cut.append(n)) for n, peer in enumerate("aabb")]
    assert all(slots) and len(admission) == 4
    # Peer a over its share: its own oldest goes, b keeps both.
    assert admission.admit("a", lambda: cut.append("new-a")) is not None
    assert cut == [0] and len(admission) == 4
    # A third peer while the endpoint is full: the endpoint's oldest goes.
    assert admission.admit("c", lambda: None) is not None
    assert cut == [0, 1]
    # A released slot frees its place.
    admission.release(slots[2])
    assert len(admission) == 3


def test_admission_refuses_newcomers_for_long_lived_sessions():
    admission = control.Admission(total=3, per_peer=2, evict=False)
    assert admission.admit(1000, lambda: None) and admission.admit(1000, lambda: None)
    assert admission.admit(1000, lambda: None) is None  # third of one user
    assert admission.admit(1001, lambda: None) is not None
    assert admission.admit(1002, lambda: None) is None  # endpoint full
    assert admission.admit(None, lambda: None) is None


def test_endpoint_bounds():
    assert control.ControlServer({"status": dict}, _endpoint())._admission.per_peer is None
    brake = control.ControlServer.__new__(control.ControlServer)
    control.OwnerOnlyServer.__init__(brake, "x", group="sezam-ai")
    assert brake._admission.per_peer == control.MAX_PEER_CONNECTIONS
    assert brake._admission.evict and brake.connection_deadline == control.CLIENT_TIMEOUT
    from sezam.mcp.ssh_agent import SSHAgentServer

    agent = SSHAgentServer.__new__(SSHAgentServer)
    control.OwnerOnlyServer.__init__(agent, "x", group="sezam-ai")
    assert not agent._admission.evict and agent.connection_deadline is None


# ── Real endpoints (named pipe here, Unix socket on Linux) ──


def _connect(path: str):
    if sys.platform == "win32":
        deadline = time.monotonic() + 5
        while True:
            try:
                return open(path, "r+b", buffering=0)
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(path)
    return sock


def _write(client, data: bytes) -> None:
    if sys.platform == "win32":
        client.write(data)
    else:
        client.sendall(data)


def _close(client) -> None:
    try:
        client.close()
    except OSError:
        pass


def test_a_trickling_peer_is_cut_at_the_connection_deadline():
    calls: list = []
    server = _control_server(calls)
    server.start()
    client = _connect(server.path)
    started = time.monotonic()
    cut_after = None
    try:
        while time.monotonic() - started < control.CLIENT_TIMEOUT + 4:
            try:
                _write(client, b" ")  # never a newline
            except OSError:
                cut_after = time.monotonic() - started
                break
            time.sleep(0.25)
        # Before: each byte restarted the wait (pipe: no timeout at all).
        assert cut_after is not None and cut_after < control.CLIENT_TIMEOUT + 1.5
        assert _wait_empty(server)
    finally:
        _close(client)
        server.stop()


def test_a_silent_flood_does_not_hold_back_the_brake_or_the_gui_switch(env, monkeypatch):  # noqa: F811
    broker = MCPBroker(env.vault, None, _FakeSSH())
    server = env.serve(broker)
    flood = [_connect(server.path) for _ in range(3 * control.MAX_CONNECTIONS)]
    try:
        started = time.monotonic()
        reply = control.send(server.path, "ai_off")
        assert reply is not None and reply["persisted"] is True
        assert time.monotonic() - started < 1.5
        assert len(server._admission) <= control.MAX_CONNECTIONS
        # The GUI switch ('sezam ai off' too) under the same flood.
        monkeypatch.setattr(control, "brokers", lambda: [[server.path]])
        result = control.pull_brake(env.vault, "gui")
        assert result.stopped == 1 and not result.state.enabled
    finally:
        for client in flood:
            _close(client)


# ── MCP transports ──


def test_mcp_accept_loop_survives_emfile(monkeypatch, tmp_path):
    client, conn = socket.socketpair()
    listener = _Listener([OSError(errno.EMFILE, "Too many open files")] * 2, [conn])
    monkeypatch.setattr(mcp_server, "bind_unix_socket", lambda path, group=None: listener)
    server = _bare_server()
    server._server_socket = None
    t = threading.Thread(
        target=server._run_unix_socket, args=(str(tmp_path / "mcp.sock"),), daemon=True
    )
    t.start()
    try:
        client.settimeout(3)
        client.sendall(b'{"id": 7}\n')
        assert json.loads(client.recv(65536)) == {"id": 7, "result": "pong"}  # before: closed
    finally:
        client.close()
        server._running = False
    t.join(3)
    assert not t.is_alive()


def test_mcp_endpoint_refuses_connections_over_its_bound(monkeypatch, tmp_path):
    pairs = [socket.socketpair() for _ in range(mcp_server.MCP_MAX_CONNECTIONS + 3)]
    listener = _Listener((), [conn for _, conn in pairs])
    monkeypatch.setattr(mcp_server, "bind_unix_socket", lambda path, group=None: listener)
    server = _bare_server()
    server._server_socket = None
    t = threading.Thread(
        target=server._run_unix_socket, args=(str(tmp_path / "mcp.sock"),), daemon=True
    )
    t.start()
    try:
        for client, _ in pairs[-3:]:
            client.settimeout(3)
            assert client.recv(10) == b""  # refused at once
        client = pairs[0][0]
        client.settimeout(3)
        client.sendall(b'{"id": 1}\n')
        assert json.loads(client.recv(65536)) == {"id": 1, "result": "pong"}
    finally:
        server._running = False
        for client, conn in pairs:
            client.close()
    t.join(5)


def test_mcp_socket_line_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_server, "MAX_LINE", 1024)
    client, conn = socket.socketpair()
    listener = _Listener((), [conn])
    monkeypatch.setattr(mcp_server, "bind_unix_socket", lambda path, group=None: listener)
    server = _bare_server()
    server._server_socket = None
    t = threading.Thread(
        target=server._run_unix_socket, args=(str(tmp_path / "mcp.sock"),), daemon=True
    )
    t.start()
    try:
        client.settimeout(3)
        client.sendall(b"x" * 3000)  # no newline: before, buffered without end
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = client.recv(65536)
            assert chunk, "closed without the error"
            reply += chunk
        assert json.loads(reply)["error"]["code"] == -32600
        assert client.recv(10) == b""
    finally:
        client.close()
        server._running = False
    t.join(3)


@windows_only
def test_mcp_pipe_line_is_bounded(monkeypatch):
    import win32file

    from tests.test_review_cli_ipc import _open_client

    monkeypatch.setattr(mcp_server, "MAX_LINE", 1024)
    name = rf"\\.\pipe\sezam_test_{uuid.uuid4().hex}"
    server = _bare_server()
    t = threading.Thread(target=server._run_named_pipe, args=(name,), daemon=True)
    t.start()
    big = _open_client(name)
    try:
        win32file.WriteFile(big, b"x" * 70000)
        closed = False
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                win32file.WriteFile(big, b"x")
            except Exception:
                closed = True
                break
            time.sleep(0.05)
        assert closed  # before: the server kept buffering
        other = _open_client(name)
        try:
            win32file.WriteFile(other, b'{"id": 4}\n')
            _, data = win32file.ReadFile(other, 65536)
            assert json.loads(data) == {"id": 4, "result": "pong"}
        finally:
            other.Close()
    finally:
        big.Close()
        server._running = False
        server._wake_pipe()
    t.join(5)


def test_mcp_stdio_line_is_bounded(monkeypatch):
    monkeypatch.setattr(mcp_server, "MAX_LINE", 1024)
    monkeypatch.setattr(sys, "stdin", io.StringIO("x" * 5000 + "\n" + '{"id": 2}\n'))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    _bare_server().run_stdio()
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32600
    assert lines[1] == {"id": 2, "result": "pong"}


def test_systemd_units_bound_descriptors_and_threads():
    text = service.systemd("/opt/sezam/bin/python", "sezam-broker", "sezam-ai", "alice")
    units = text.split("[Unit]")[1:]
    assert len(units) == 2
    for unit in units:
        assert "\nLimitNOFILE=4096\n" in unit and "\nTasksMax=512\n" in unit


# ── Real Linux (natively, or WSL from Windows) ──


def _linux_runner() -> list[str] | None:
    if sys.platform.startswith("linux"):
        return [sys.executable, str(REPO / "tests" / "wsl_brake_flood.py")]
    if sys.platform == "win32" and shutil.which("wsl"):
        try:
            path = subprocess.run(
                ["wsl", "-e", "wslpath", "-a", str(REPO / "tests" / "wsl_brake_flood.py")],
                capture_output=True, text=True, timeout=30,
            ).stdout.strip()
            probe = subprocess.run(["wsl", "-e", "python3", "-c", "import resource"], timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if path and probe.returncode == 0:
            return ["wsl", "-e", "python3", path]
    return None


LINUX = _linux_runner()


@pytest.mark.skipif(LINUX is None, reason="needs Linux or WSL with python3")
def test_real_unix_brake_answers_after_emfile():
    out = subprocess.run(LINUX + ["emfile"], capture_output=True, text=True, timeout=120)
    result = json.loads(out.stdout.strip().splitlines()[-1])
    # Before: accept_alive False, during and after None.
    assert result["accept_alive"] is True
    assert result["during"]["persisted"] is True
    assert result["after"]["persisted"] is True


@pytest.mark.skipif(LINUX is None, reason="needs Linux or WSL with python3")
def test_real_unix_brake_answers_at_once_under_a_flood():
    out = subprocess.run(LINUX + ["cap"], capture_output=True, text=True, timeout=120)
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["during"]["persisted"] is True and result["during_seconds"] < 1.0
    assert result["accept_alive"] is True
