"""Regression tests for the MCP/CLI security review findings.

1. Pinned SSH host keys must be verified before any credential is sent,
   even when the host is present in the user's known_hosts.
2. The local approval dialog must default to "No".
3. CLI sessions never hold the master password and privileged commands
   ignore the session entirely.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import sys
import threading
import types

import paramiko
import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp import approval
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.ssh import SSHBrokerError, SSHCredentials, SSHManager
from sezam.vault.crud import Vault


FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "review-master-password"


# ── 1. Pinned host key is checked before authentication ──


class _RecordingServer(paramiko.ServerInterface):
    def __init__(self):
        self.passwords: list[str] = []

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.passwords.append(password)
        return paramiko.AUTH_SUCCESSFUL


@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def ssh_server(host_key):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    server = _RecordingServer()
    transports = []
    stop = threading.Event()

    def serve():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            transports.append(transport)
            try:
                transport.start_server(server=server)
            except Exception:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield types.SimpleNamespace(port=port, key=host_key, server=server)
    stop.set()
    for transport in transports:
        transport.close()
    listener.close()
    thread.join(timeout=2)


def _fingerprint(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _credentials(port: int, pin: str | None) -> SSHCredentials:
    return SSHCredentials(
        host="127.0.0.1",
        port=port,
        username="alice",
        password="ssh-secret-must-not-leak",
        private_key=None,
        passphrase=None,
        host_key_sha256=pin,
        use_ssh_agent=False,
    )


def _trust_in_system_known_hosts(monkeypatch, port: int, key: paramiko.PKey):
    def load_system_host_keys(self, filename=None):
        self.get_host_keys().add(f"[127.0.0.1]:{port}", key.get_name(), key)

    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", load_system_host_keys)


def test_pin_mismatch_rejected_before_password_even_if_known_hosts_trusts(ssh_server, monkeypatch):
    _trust_in_system_known_hosts(monkeypatch, ssh_server.port, ssh_server.key)
    wrong_pin = "SHA256:" + base64.b64encode(b"\x01" * 32).decode().rstrip("=")

    with pytest.raises(SSHBrokerError) as raised:
        SSHManager()._connect(_credentials(ssh_server.port, wrong_pin))

    assert raised.value.code == "host_key_mismatch"
    assert ssh_server.server.passwords == []


def test_matching_pin_connects_without_known_hosts(ssh_server):
    client = SSHManager()._connect(_credentials(ssh_server.port, _fingerprint(ssh_server.key)))
    try:
        assert ssh_server.server.passwords == ["ssh-secret-must-not-leak"]
    finally:
        client.close()


def test_unpinned_unknown_host_is_rejected_before_password(ssh_server, monkeypatch):
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)

    with pytest.raises(SSHBrokerError):
        SSHManager()._connect(_credentials(ssh_server.port, None))

    assert ssh_server.server.passwords == []


# ── 2. Approval dialog defaults to "No" ──


def _request(manager: ApprovalManager):
    return manager.request_approval("req-1", "Servers/prod", "ssh_execute", "agent")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows MessageBox path")
def test_windows_approval_dialog_defaults_to_no(monkeypatch):
    import ctypes

    seen = {}

    def message_box(_hwnd, _text, _title, flags):
        seen["flags"] = flags
        return 7  # IDNO

    monkeypatch.setattr(ctypes.windll.user32, "MessageBoxW", message_box)
    manager = ApprovalManager()
    approval.install_desktop_approval_handler(manager)
    req = _request(manager)

    assert seen["flags"] & 0x00000F00 == 0x00000100  # MB_DEFBUTTON2 -> "No"
    assert req.status == "denied"


def test_tk_approval_dialog_defaults_to_no(monkeypatch):
    seen = {}

    def askyesno(title, message, **kwargs):
        seen.update(kwargs)
        return False

    fake_messagebox = types.SimpleNamespace(askyesno=askyesno, NO="no")
    fake_root = types.SimpleNamespace(withdraw=lambda: None, destroy=lambda: None)
    fake_tk = types.ModuleType("tkinter")
    fake_tk.Tk = lambda: fake_root
    fake_tk.messagebox = fake_messagebox
    monkeypatch.setitem(sys.modules, "tkinter", fake_tk)
    monkeypatch.setitem(sys.modules, "tkinter.messagebox", fake_messagebox)
    monkeypatch.setattr(sys, "platform", "linux")

    manager = ApprovalManager()
    approval.install_desktop_approval_handler(manager)
    req = _request(manager)

    assert seen["default"] == "no"
    assert req.status == "denied"


# ── 3. CLI session is KEK-only, time-limited, and not used for privileged commands ──


@pytest.fixture
def cli_vault(tmp_path, monkeypatch):
    stored = {}
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
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    folder = vault.create_node("Servers")
    vault.create_entry(folder, "prod", [{"key": "host", "value": "prod.example.test"}])
    vault.lock()
    return types.SimpleNamespace(path=tmp_path, stored=stored)


def test_unlock_session_never_contains_master_password(cli_vault):
    result = CliRunner().invoke(cli.main, ["unlock", "--ttl", "5"], input=PASSWORD + "\n")

    assert result.exit_code == 0, result.output
    record = cli_vault.stored[("sezam", "session")]
    assert PASSWORD not in record
    assert "5 min" in result.output

    listed = CliRunner().invoke(cli.main, ["list"], input="")
    assert listed.exit_code == 0, listed.output
    assert "prod" in listed.output


def test_mcp_policy_ignores_session_and_requires_master_password(cli_vault):
    assert CliRunner().invoke(cli.main, ["unlock"], input=PASSWORD + "\n").exit_code == 0

    denied = CliRunner().invoke(cli.main, ["mcp-policy", "Servers/prod", "--tier", "0"], input="\n")
    assert denied.exit_code != 0
    assert "Updated MCP policy" not in denied.output

    allowed = CliRunner().invoke(
        cli.main, ["mcp-policy", "Servers/prod", "--tier", "0"], input=PASSWORD + "\n"
    )
    assert allowed.exit_code == 0, allowed.output
    assert "Updated MCP policy" in allowed.output


def test_plaintext_export_ignores_session(cli_vault):
    assert CliRunner().invoke(cli.main, ["unlock"], input=PASSWORD + "\n").exit_code == 0
    dest = cli_vault.path / "out.csv"

    result = CliRunner().invoke(
        cli.main,
        ["export", str(dest), "--format", "csv", "--confirm-plaintext"],
        input="\n",
    )

    assert result.exit_code != 0
    assert not dest.exists()
