"""Review main@d615826 H5: 'sezam ai off' did not stop a running SSH call.

close_all() closed only the interactive sessions; an ssh_execute or an SFTP
transfer already running ran to the end, and the agent got its result a few
seconds after the brake. Now the manager tracks those clients too and cuts
them (cut_off), and the broker checks the switch again before it hands any
result over: a brake persisted by another process withholds it.
"""

from __future__ import annotations

import threading
import time

import paramiko
import pytest

from sezam.mcp import audit_view
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker, MCPError
from sezam.mcp.ssh import SSHBrokerError, SSHManager
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_mcp_ssh import FAST_PARAMS, FakeSSHManager
from tests.test_mcp_ssh_real import _entry, _SSHServer


@pytest.fixture
def hang_server(monkeypatch):
    monkeypatch.setattr(paramiko.SSHClient, "load_system_host_keys", lambda self, filename=None: None)
    srv = _SSHServer("hang")
    yield srv
    srv.close()


def _run(target) -> tuple[threading.Thread, dict]:
    outcome: dict = {}

    def work():
        try:
            outcome["result"] = target()
        except SSHBrokerError as exc:
            outcome["error"] = exc.code

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    return worker, outcome


def _cut_when_running(manager: SSHManager, worker: threading.Thread) -> float:
    deadline = time.monotonic() + 10
    while manager.running_count() == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert manager.running_count() == 1
    time.sleep(0.2)
    started = time.monotonic()
    manager.close_all()
    worker.join(5)
    assert not worker.is_alive()
    return time.monotonic() - started


def test_close_all_cuts_a_running_execute(hang_server):
    manager = SSHManager()
    entry = _entry(hang_server.port, hang_server.fingerprint)
    worker, outcome = _run(lambda: manager.execute(entry, "sleep infinity", timeout=60))

    took = _cut_when_running(manager, worker)

    assert outcome == {"error": "cut_off"} and took < 5
    assert manager.running_count() == 0


def test_close_all_cuts_a_running_sftp_transfer(hang_server, tmp_path, monkeypatch):
    class _SlowSFTP:
        def __init__(self, client):
            self.client = client

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def slow_upload(self, sftp, source, remote_path, **kwargs):
        # A transfer in progress: it only ends when its connection dies.
        while sftp.client.get_transport() is not None and sftp.client.get_transport().is_active():
            time.sleep(0.02)
        raise OSError("Socket is closed")

    monkeypatch.setattr(paramiko.SSHClient, "open_sftp", lambda self: _SlowSFTP(self))
    monkeypatch.setattr(SSHManager, "_upload_path", slow_upload)
    (tmp_path / "big.bin").write_bytes(b"z" * 1024)
    manager = SSHManager(transfer_root=tmp_path)
    entry = _entry(hang_server.port, hang_server.fingerprint)
    worker, outcome = _run(lambda: manager.upload(entry, "big.bin", "/tmp/big.bin"))

    _cut_when_running(manager, worker)

    assert outcome == {"error": "cut_off"}


def test_a_cut_while_connecting_still_cuts(hang_server, monkeypatch):
    manager = SSHManager()
    connect = SSHManager._connect

    def connect_then_brake(self, credentials):
        client = connect(self, credentials)
        self.close_all()  # the brake lands before the client is tracked
        return client

    monkeypatch.setattr(SSHManager, "_connect", connect_then_brake)

    with pytest.raises(SSHBrokerError) as exc:
        manager.execute(_entry(hang_server.port, hang_server.fingerprint), "sleep infinity", timeout=60)

    assert exc.value.code == "cut_off"


class _BrakeDuringExecute(FakeSSHManager):
    """'sezam ai off' in another process while the command runs: only the
    persisted state says off; this broker's in-memory flag does not."""

    def __init__(self, vault):
        super().__init__()
        self.vault = vault

    def execute(self, entry, command, **kwargs):
        result = super().execute(entry, command, **kwargs)
        ai_access.disable(self.vault, "cli")
        return result


def test_broker_withholds_a_result_finished_after_ai_off(tmp_path):
    vault = Vault.create(tmp_path, "test", FAST_PARAMS)
    try:
        servers = vault.create_node("Servers")
        vault.create_entry(
            servers, "Production",
            [{"key": "host", "value": "prod.example.test"}, {"key": "username", "value": "deploy"},
             {"key": "password", "value": "pw", "sensitive": True}],
            tier=0, allowed_actions=["ssh_execute"],
        )
        fake = _BrakeDuringExecute(vault)
        broker = MCPBroker(vault, ApprovalManager(), ssh_manager=fake)

        with pytest.raises(MCPError) as exc:
            broker.ssh_execute("Servers/Production", "cat /etc/shadow", agent_name="claude")

        assert exc.value.code == "ai_disabled"
        assert fake.calls and fake.closed
        paths = audit_view.entry_paths(vault)
        ssh_log = [
            audit_view.describe(r, paths)
            for r in audit_view.ai_records(vault) if r.kind == "mcp_ssh"
        ]
        assert ssh_log[-1]["result"] == "FAILED cut_off"
    finally:
        vault.lock()
