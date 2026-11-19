"""Security and integration tests for the Sezam MCP SSH broker."""

import time

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.server import SezamMCPServer
from sezam.mcp.ssh import SSHBrokerError, SSHCredentials, SSHManager
from sezam.vault.crud import Vault


FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
ALL_SSH_ACTIONS = ["ssh_execute", "ssh_session", "ssh_upload", "ssh_download"]


class FakeSSHManager:
    def __init__(self):
        self.calls = []
        self.sessions = {}
        self.closed = False

    def execute(self, entry, command, **kwargs):
        self.calls.append(("execute", entry, command, kwargs))
        return {
            "status": "ok",
            "stdout": "service is active",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
        }

    def open_session(self, entry, **kwargs):
        self.calls.append(("open", entry, kwargs))
        self.sessions["session-capability"] = entry["id"]
        return {"status": "ok", "session_id": "session-capability"}

    def session_entry_id(self, session_id, **kwargs):
        if session_id not in self.sessions:
            raise SSHBrokerError("session_not_found", "SSH session not found.")
        return self.sessions[session_id]

    def session_age(self, session_id, **kwargs):
        self.session_entry_id(session_id)
        return 0.0

    def write_session(self, session_id, data, **kwargs):
        self.calls.append(("write", session_id, data, kwargs))
        return {"status": "ok", "bytes_written": len(data.encode())}

    def read_session(self, session_id, **kwargs):
        self.calls.append(("read", session_id, kwargs))
        return {"status": "ok", "stdout": "root@host:~# ", "stderr": "", "closed": False, "exit_code": None}

    def resize_session(self, session_id, **kwargs):
        self.calls.append(("resize", session_id, kwargs))
        return {"status": "ok"}

    def close_session(self, session_id, **kwargs):
        self.calls.append(("close", session_id, kwargs))
        self.sessions.pop(session_id)
        return {"status": "ok"}

    def upload(self, entry, local_path, remote_path, **kwargs):
        self.calls.append(("upload", entry, local_path, remote_path, kwargs))
        return {"status": "ok", "files": 2, "bytes": 12}

    def download(self, entry, remote_path, local_path, **kwargs):
        self.calls.append(("download", entry, remote_path, local_path, kwargs))
        return {"status": "ok", "files": 1, "bytes": 6}

    def close_all(self):
        self.closed = True
        self.sessions.clear()


@pytest.fixture
def ssh_vault(tmp_path):
    vault = Vault.create(tmp_path, "test", FAST_PARAMS)
    servers = vault.create_node("Servers")
    vault.create_entry(
        servers,
        "Production",
        [
            {"key": "host", "value": "prod.example.test"},
            {"key": "port", "value": "2222"},
            {"key": "username", "value": "deploy"},
            {"key": "password", "value": "never-return-this", "sensitive": True},
            {"key": "private_key", "value": "never-return-this-key", "sensitive": True},
        ],
        tier=0,
        allowed_actions=ALL_SSH_ACTIONS,
    )
    vault.create_entry(
        servers,
        "Denied",
        [
            {"key": "host", "value": "denied.example.test"},
            {"key": "username", "value": "root"},
            {"key": "password", "value": "denied-secret", "sensitive": True},
        ],
        tier=0,
        allowed_actions=[],
    )
    vault.create_entry(
        servers,
        "Approval",
        [
            {"key": "host", "value": "approval.example.test"},
            {"key": "username", "value": "root"},
            {"key": "password", "value": "approval-secret", "sensitive": True},
        ],
        tier=1,
        allowed_actions=["ssh_execute"],
    )
    yield vault
    vault.lock()


@pytest.fixture
def broker(ssh_vault):
    fake = FakeSSHManager()
    return MCPBroker(ssh_vault, ApprovalManager(), ssh_manager=fake), fake


def test_allowed_actions_are_encrypted_metadata_round_trip(ssh_vault):
    entry = ssh_vault.find_entry_by_path("Servers/Production")
    assert entry["allowed_actions"] == ALL_SSH_ACTIONS

    ssh_vault.update_entry(entry["id"], allowed_actions=["ssh_execute"])

    updated = ssh_vault.find_entry_by_path("Servers/Production")
    assert updated["allowed_actions"] == ["ssh_execute"]


def test_move_preserves_allowed_actions(ssh_vault):
    entry = ssh_vault.find_entry_by_path("Servers/Production")
    destination = ssh_vault.create_node("Moved")

    ssh_vault.move_entry(entry["id"], destination)

    moved = ssh_vault.find_entry_by_path("Moved/Production")
    assert moved["allowed_actions"] == ALL_SSH_ACTIONS


def test_execute_uses_secret_internally_but_never_returns_it(broker):
    service, fake = broker

    result = service.ssh_execute("Servers/Production", "systemctl is-active app")

    assert result["status"] == "ok"
    assert result["stdout"] == "service is active"
    assert "never-return-this" not in repr(result)
    assert "never-return-this-key" not in repr(result)
    internal_entry = fake.calls[0][1]
    assert any(field["value"] == "never-return-this" for field in internal_entry["fields"])


def test_execute_requires_explicit_action(broker):
    service, fake = broker

    result = service.ssh_execute("Servers/Denied", "id")

    assert result["status"] == "denied"
    assert fake.calls == []


def test_tier_one_approval_shows_exact_command_and_is_single_use(ssh_vault):
    manager = ApprovalManager()
    fake = FakeSSHManager()
    service = MCPBroker(ssh_vault, manager, ssh_manager=fake)
    seen = []

    def approve(request):
        seen.append(request)
        manager.approve(request.request_id)

    manager.set_on_request(approve)
    result = service.ssh_execute(
        "Servers/Approval", "sh -s", stdin="uname -a\n", agent_name="Claude"
    )

    assert result["status"] == "ok"
    assert seen[0].agent_name == "Claude"
    assert seen[0].details["command"] == "sh -s"
    assert seen[0].details["stdin"] == "uname -a\n"
    assert manager.get_pending() == []


def test_interactive_session_lifecycle(broker):
    service, fake = broker

    opened = service.ssh_session_open("Servers/Production", agent_name="Claude")
    session_id = opened["session_id"]
    assert service.ssh_session_write(session_id, "pwd\n", agent_name="Claude")["status"] == "ok"
    assert service.ssh_session_read(session_id, agent_name="Claude")["stdout"] == "root@host:~# "
    assert service.ssh_session_resize(session_id, 160, 50, agent_name="Claude")["status"] == "ok"
    assert service.ssh_session_close(session_id, agent_name="Claude")["status"] == "ok"
    assert [call[0] for call in fake.calls] == ["open", "write", "read", "resize", "close"]


def test_upload_and_download_are_separate_capabilities(broker):
    service, fake = broker

    uploaded = service.ssh_upload(
        "Servers/Production", "local", "/remote", recursive=True
    )
    downloaded = service.ssh_download(
        "Servers/Production", "/remote/file", "local-file"
    )

    assert uploaded == {"status": "ok", "files": 2, "bytes": 12}
    assert downloaded == {"status": "ok", "files": 1, "bytes": 6}
    assert [call[0] for call in fake.calls] == ["upload", "download"]


def test_lock_closes_all_sessions(ssh_vault):
    fake = FakeSSHManager()
    service = MCPBroker(ssh_vault, ApprovalManager(), ssh_manager=fake)
    ssh_vault.lock()

    with pytest.raises(Exception) as raised:
        service.vault_list("")

    assert getattr(raised.value, "code", None) == "vault_locked"
    assert fake.closed is True


def test_mcp_initialize_and_notifications_follow_json_rpc(ssh_vault):
    server = SezamMCPServer(ssh_vault)

    initialized = server._dispatch_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "test", "version": "1"},
                "capabilities": {},
            },
        }
    )

    assert initialized["jsonrpc"] == "2.0"
    assert initialized["id"] == 1
    assert initialized["result"]["protocolVersion"] == "2025-06-18"
    assert initialized["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert server._dispatch_request(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    ) is None
    assert server._dispatch_request(
        {"jsonrpc": "2.0", "id": 2, "method": "ping"}
    ) == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_mcp_tools_list_has_standard_response_envelope(ssh_vault):
    server = SezamMCPServer(ssh_vault)

    response = server._dispatch_request(
        {"jsonrpc": "2.0", "id": "tools", "method": "tools/list", "params": {}}
    )

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == "tools"
    assert len(response["result"]["tools"]) == 14


def test_mcp_schema_has_no_password_or_private_key_parameters(ssh_vault):
    tools = SezamMCPServer(ssh_vault).get_tools()
    ssh_tools = [tool for tool in tools if tool["name"].startswith("ssh_")]

    assert {tool["name"] for tool in ssh_tools} == {
        "ssh_execute",
        "ssh_session_open",
        "ssh_session_write",
        "ssh_session_read",
        "ssh_session_resize",
        "ssh_session_close",
        "ssh_upload",
        "ssh_download",
    }
    schema_text = repr(ssh_tools).lower()
    assert "password" not in schema_text
    assert "private_key" not in schema_text
    assert "key_filename" not in schema_text


def test_server_dispatches_ssh_without_exposing_credentials(ssh_vault):
    server = SezamMCPServer(ssh_vault)
    fake = FakeSSHManager()
    server.broker._ssh = fake

    result = server.handle_tool_call(
        "ssh_execute",
        {"path": "Servers/Production", "command": "whoami"},
    )

    assert result["stdout"] == "service is active"
    assert "never-return-this" not in repr(result)


def test_credentials_accept_common_field_aliases():
    credentials = SSHCredentials.from_entry(
        {
            "fields": [
                {"key": "Server", "value": "host.example.test"},
                {"key": "Login", "value": "alice"},
                {"key": "SSH Password", "value": "secret"},
                {"key": "Port", "value": "2200"},
            ]
        }
    )

    assert credentials.host == "host.example.test"
    assert credentials.username == "alice"
    assert credentials.port == 2200
    assert credentials.password == "secret"


def test_credentials_fail_closed_without_authentication():
    with pytest.raises(SSHBrokerError) as raised:
        SSHCredentials.from_entry(
            {"fields": [{"key": "host", "value": "host"}, {"key": "username", "value": "user"}]}
        )

    assert raised.value.code == "invalid_entry"


def test_upload_rejects_symlink_before_connecting(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    source.write_text("secret")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("Symbolic links are unavailable on this platform")

    manager = SSHManager(transfer_root=tmp_path)
    monkeypatch.setattr(
        manager,
        "_connect",
        lambda credentials: pytest.fail("SSH connection must not be attempted"),
    )
    with pytest.raises(SSHBrokerError) as raised:
        manager.upload(
            {
                "fields": [
                    {"key": "host", "value": "host"},
                    {"key": "username", "value": "user"},
                    {"key": "password", "value": "secret"},
                ]
            },
            "link.txt",
            "/tmp/file",
        )

    assert raised.value.code == "symlink_denied"


def test_idle_session_is_closed_without_another_client_call(monkeypatch):
    class Channel:
        closed = False

        def settimeout(self, timeout):
            pass

        def close(self):
            self.closed = True

    class Client:
        def __init__(self):
            self.channel = Channel()
            self.closed = False

        def invoke_shell(self, **kwargs):
            return self.channel

        def close(self):
            self.closed = True

    manager = SSHManager(session_idle_timeout=1)
    client = Client()
    monkeypatch.setattr(manager, "_connect", lambda credentials: client)
    entry = {
        "id": "entry-id",
        "fields": [
            {"key": "host", "value": "host"},
            {"key": "username", "value": "user"},
            {"key": "password", "value": "secret"},
        ],
    }

    session_id = manager.open_session(entry, owner="agent")["session_id"]
    deadline = time.monotonic() + 2
    while not client.closed and time.monotonic() < deadline:
        time.sleep(0.05)

    assert client.closed is True
    with pytest.raises(SSHBrokerError):
        manager.session_entry_id(session_id, owner="agent")


def test_server_sanitizes_unexpected_ssh_errors(ssh_vault):
    class FailingSSH(FakeSSHManager):
        def execute(self, entry, command, **kwargs):
            raise RuntimeError("never-return-this internal detail")

    server = SezamMCPServer(ssh_vault)
    server.broker._ssh = FailingSSH()

    result = server.handle_tool_call(
        "ssh_execute", {"path": "Servers/Production", "command": "id"}
    )

    assert result["code"] == "operation_failed"
    assert "never-return-this" not in repr(result)
