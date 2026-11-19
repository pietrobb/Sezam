"""AI broker TODO section 2 (S2d): the real OpenSSH client through
``sezam ssh-agent``.

``ssh`` (>= 8.9, so it sends session-bind) with SSH_AUTH_SOCK on the agent
logs in to a local paramiko SSH server; the same key is refused for a server
with another host key; a forwarded agent cannot sign for an entry that does
not allow forwarding (but can for one that does); after ``ai_off`` the login
fails. No file written meanwhile contains the private keys.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from sezam.mcp import control, ssh_agent
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh_agent import (
    SSH_AGENT_FAILURE,
    SSH_AGENT_SIGN_RESPONSE,
    SSHAgentServer,
    SSHAgentService,
    default_endpoint,
    host_key_fingerprint,
)
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_s2a_ssh_agent import _audit, _openssh, _s, _ssh_entry
from tests.test_mcp_ssh import FAST_PARAMS

SSH = shutil.which("ssh")


def _ssh_version() -> tuple[int, int]:
    if not SSH:
        return (0, 0)
    out = subprocess.run([SSH, "-V"], capture_output=True, text=True, timeout=10)
    match = re.search(r"OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)", out.stderr + out.stdout)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


pytestmark = pytest.mark.skipif(
    _ssh_version() < (8, 9), reason="needs an OpenSSH client >= 8.9 (session-bind)"
)

USER = "ai-web"


def _key(pem: str) -> paramiko.Ed25519Key:
    import io

    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


class _Handler(paramiko.ServerInterface):
    def __init__(self, allowed: set[bytes]):
        self.allowed = allowed
        self.command = None
        self.exec_requested = threading.Event()
        self.agent_forwarding = False

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        if username == USER and key.asbytes() in self.allowed:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_forward_agent_request(self, channel):
        self.agent_forwarding = True
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode()
        self.exec_requested.set()
        return True


class _SSHServer:
    """A local SSH server that accepts ``allowed`` keys for USER, runs
    'echo-ok' and 'agent-test' (uses the forwarded agent)."""

    def __init__(self, allowed: set[bytes], agent_probe=None):
        self.host_key = _key(_openssh(ed25519.Ed25519PrivateKey.generate()))
        self.allowed = allowed
        self.agent_probe = agent_probe
        self.logins = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._connection, args=(conn,), daemon=True).start()

    def _connection(self, conn):
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)
        handler = _Handler(self.allowed)
        try:
            transport.start_server(server=handler)
            channel = transport.accept(15)
            if channel is None or not handler.exec_requested.wait(10):
                return
            self.logins += 1
            if handler.command == "agent-test" and self.agent_probe is not None:
                output = self.agent_probe(transport, handler)
            else:
                output = "ok"
            channel.sendall((output + "\n").encode())
            channel.send_exit_status(0)
            channel.shutdown_write()
            channel.close()
            # Let the client disconnect first: closing under it while it is
            # still sending its own close ends ssh with 255 (broken pipe).
            deadline = time.monotonic() + 10
            while transport.is_active() and time.monotonic() < deadline:
                time.sleep(0.05)
        except Exception:
            pass
        finally:
            transport.close()

    def known_hosts_line(self) -> str:
        return f"[127.0.0.1]:{self.port} {self.host_key.get_name()} {self.host_key.get_base64()}\n"

    def close(self):
        self._sock.close()


def _agent_request(channel, message: bytes) -> bytes:
    channel.sendall(_s(message))

    def read(size):
        data = b""
        while len(data) < size:
            chunk = channel.recv(size - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    return read(int.from_bytes(read(4), "big"))


@pytest.fixture(scope="module")
def pems():
    return {name: _openssh(ed25519.Ed25519PrivateKey.generate()) for name in ("web", "fwd")}


@pytest.fixture
def env(tmp_path, pems, monkeypatch):
    web_key, fwd_key = _key(pems["web"]), _key(pems["fwd"])

    def probe(transport, handler):
        """On the server: use the agent the client forwarded to us."""
        if not handler.agent_forwarding:
            return "no-forwarding"
        channel = transport.open_forward_agent_channel()
        results = []
        for key in (web_key, fwd_key):
            data = (
                _s(transport.session_id) + bytes([50]) + _s(USER) + _s("ssh-connection")
                + _s("publickey") + b"\x01" + _s("ssh-ed25519") + _s(key.asbytes())
            )
            reply = _agent_request(
                channel, bytes([13]) + _s(key.asbytes()) + _s(data) + (0).to_bytes(4, "big")
            )
            results.append(str(reply[0]))
        channel.close()
        return " ".join(results)

    web = _SSHServer({web_key.asbytes(), fwd_key.asbytes()}, probe)
    other = _SSHServer({web_key.asbytes()})
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(web.known_hosts_line() + other.known_hosts_line())
    (tmp_path / "ssh_config").write_text("")

    vault = Vault.create(tmp_path / "vault", "test", FAST_PARAMS)
    folder = vault.create_node("Servers")
    _ssh_entry(
        vault, folder, "Web", pems["web"], username=USER,
        extra=[
            {"key": "port", "value": str(web.port)},
            {"key": "host_key_sha256", "value": host_key_fingerprint(web.host_key.asbytes())},
        ],
    )
    # Unpinned: the agent checks the bound host key against known_hosts.
    _ssh_entry(
        vault, folder, "Fwd", pems["fwd"], username=USER, host="127.0.0.1",
        actions=("ssh_agent", "ssh_agent_forwarding"),
        extra=[{"key": "port", "value": str(web.port)}],
    )
    monkeypatch.setattr(ssh_agent, "known_hosts_path", lambda: str(known_hosts))
    agent = SSHAgentServer(SSHAgentService(MCPBroker(vault, ApprovalManager())), default_endpoint())
    agent.start()

    def ssh(server, command="echo-ok", *options):
        args = [
            SSH, "-F", (tmp_path / "ssh_config").as_posix(), "-p", str(server.port),
            "-o", f"UserKnownHostsFile={known_hosts.as_posix()}",
            "-o", "GlobalKnownHostsFile=" + (tmp_path / "none").as_posix(),
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "IdentityFile=" + (tmp_path / "no_such_key").as_posix(),
            "-o", "ConnectTimeout=10",
            *options,
            f"{USER}@127.0.0.1", command,
        ]
        return subprocess.run(
            args, env={**os.environ, "SSH_AUTH_SOCK": agent.path},
            capture_output=True, text=True, timeout=60,
        )

    yield type("Env", (), dict(vault=vault, web=web, other=other, ssh=staticmethod(ssh)))
    agent.stop()
    web.close()
    other.close()
    vault.lock()


def test_openssh_logs_in_with_the_vault_key(env, monkeypatch):
    records = _audit(env.vault, monkeypatch)
    result = env.ssh(env.web)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
    signed = [r for r in records if r["operation"] == "agent_sign"]
    assert signed and signed[-1]["bound_host_key"] == host_key_fingerprint(env.web.host_key.asbytes())
    assert signed[-1]["forwarded"] is False


def test_key_pinned_to_one_host_is_refused_for_another(env, monkeypatch):
    records = _audit(env.vault, monkeypatch)
    result = env.ssh(env.other)
    assert result.returncode != 0
    assert env.other.logins == 0
    assert "host_key_mismatch" in [r.get("reason") for r in records]


def test_forwarded_agent_signs_only_for_entries_that_allow_it(env, monkeypatch):
    records = _audit(env.vault, monkeypatch)
    result = env.ssh(env.web, "agent-test", "-o", "ForwardAgent=yes")
    assert result.returncode == 0, result.stderr
    # Web (no forwarding allowed) refused, Fwd (ssh_agent_forwarding) signed.
    assert result.stdout.split() == [str(SSH_AGENT_FAILURE), str(SSH_AGENT_SIGN_RESPONSE)]
    assert "forwarding_refused" in [r.get("reason") for r in records]
    assert [r["forwarded"] for r in records if r["operation"] == "agent_sign"][-1] is True


def test_unpinned_entry_signs_only_for_a_host_in_known_hosts(env, monkeypatch, tmp_path):
    records = _audit(env.vault, monkeypatch)
    monkeypatch.setattr(ssh_agent, "known_hosts_path", lambda: str(tmp_path / "empty_known_hosts"))
    result = env.ssh(env.web, "agent-test", "-o", "ForwardAgent=yes")
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [str(SSH_AGENT_FAILURE)] * 2
    assert "host_key_unknown" in [r.get("reason") for r in records]


def test_login_fails_after_ai_off(env):
    assert env.ssh(env.web).returncode == 0
    ai_access.disable(env.vault, "test")
    result = env.ssh(env.web)
    assert result.returncode != 0
    assert env.web.logins == 1


_written: list[str] = []
_watching = threading.Event()


def _record_writes(event, args):
    """Audit hook: every file this process opens for writing while watched."""
    if not _watching.is_set() or event != "open":
        return
    path, mode, flags = (tuple(args) + (None, None, None))[:3]
    writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
        isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND)
    )
    if writes and isinstance(path, (str, bytes, os.PathLike)):
        _written.append(os.fsdecode(path))


sys.addaudithook(_record_writes)


def test_private_keys_are_never_written_to_disk(env, pems, tmp_path):
    started = time.time() - 1
    _written.clear()
    _watching.set()
    try:
        assert env.ssh(env.web).returncode == 0
        assert env.ssh(env.web, "agent-test", "-o", "ForwardAgent=yes").returncode == 0
        env.ssh(env.other)
    finally:
        _watching.clear()

    needles = []
    for pem in pems.values():
        needles += [line.encode() for line in pem.splitlines()[2:-1] if len(line) > 20]
        needles.append(_key(pem)._signing_key.encode())  # raw 32-byte seed
    # Every file this process wrote, everything under the test and run
    # directories, and new files directly in the system temp directory.
    candidates = {Path(p) for p in _written}
    for root in (tmp_path, control.run_dir()):
        candidates.update(root.rglob("*"))
    temp = Path(tempfile.gettempdir())
    candidates.update(p for p in temp.iterdir() if p.is_file() and p.stat().st_mtime >= started)
    scanned = 0
    for path in candidates:
        try:
            if not path.is_file() or path.stat().st_size > 64 * 2**20:
                continue
            content = path.read_bytes()
        except OSError:
            continue
        scanned += 1
        assert not any(n in content for n in needles), path
    assert scanned  # at least the vault database
