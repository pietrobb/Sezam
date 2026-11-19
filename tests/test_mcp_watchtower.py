"""Tests for MCP broker, approval manager, and watchtower."""

import shutil
import tempfile
import threading
import time

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.server import SezamMCPServer
from sezam.vault.crud import Vault
from sezam.watchtower import Watchtower

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def vault_with_data(tmp_path):
    vault = Vault.create(tmp_path, "test", FAST_PARAMS)
    servers = vault.create_node("Servers")
    vault.create_entry(servers, "SSH Root", [
        {"key": "host", "value": "1.2.3.4"},
        {"key": "password", "value": "strong-P@ss!2026", "sensitive": True},
    ], tier=0)  # Tier 0: auto
    vault.create_entry(servers, "Restricted DB", [
        {"key": "host", "value": "5.6.7.8"},
        {"key": "password", "value": "db-secret", "sensitive": True},
    ], tier=1, ai_read_secret=True)  # Tier 1: capability + approval
    vault.create_entry(servers, "Top Secret", [
        {"key": "key", "value": "ultra-secret", "sensitive": True},
    ], tier=2)  # Tier 2: invisible
    # Weak + duplicate passwords for watchtower
    clients = vault.create_node("Clients")
    vault.create_entry(clients, "Client A", [
        {"key": "password", "value": "123", "sensitive": True},
    ])
    vault.create_entry(clients, "Client B", [
        {"key": "password", "value": "123", "sensitive": True},
    ])
    yield vault
    vault.lock()


# === Approval Manager ===

class TestApprovalManager:
    def test_request_and_approve(self):
        mgr = ApprovalManager()
        mgr.request_approval("r1", "path/a", "read_secret")
        assert mgr.approve("r1")
        assert mgr.check_and_consume("r1") == "approved"

    def test_request_and_deny(self):
        mgr = ApprovalManager()
        mgr.request_approval("r2", "path/b", "use_secret")
        assert mgr.deny("r2")
        assert mgr.check_and_consume("r2") == "denied"

    def test_single_use(self):
        mgr = ApprovalManager()
        mgr.request_approval("r3", "path/c", "read_secret")
        mgr.approve("r3")
        assert mgr.check_and_consume("r3") == "approved"
        assert mgr.check_and_consume("r3") == "not_found"  # consumed

    def test_expiry(self):
        mgr = ApprovalManager(default_ttl=0)  # Expire immediately
        mgr.request_approval("r4", "path/d", "read_secret")
        time.sleep(0.1)
        assert mgr.check_and_consume("r4") == "expired"

    def test_pending_list(self):
        mgr = ApprovalManager()
        mgr.request_approval("r5", "path/e", "read_secret")
        mgr.request_approval("r6", "path/f", "use_secret")
        pending = mgr.get_pending()
        assert len(pending) == 2

    def test_clear_all(self):
        mgr = ApprovalManager()
        mgr.request_approval("r7", "path/g", "read_secret")
        mgr.clear_all()
        assert mgr.get_pending() == []

    def test_callback(self):
        mgr = ApprovalManager()
        received = []
        mgr.set_on_request(lambda r: received.append(r.request_id))
        mgr.request_approval("r8", "path/h", "read_secret")
        assert received == ["r8"]


# === MCP Broker ===

class TestMCPBroker:
    def test_vault_list_root(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_list("")
        assert len(result["nodes"]) == 2  # Servers, Clients
        assert any(n["name"] == "Servers" for n in result["nodes"])

    def test_vault_list_hides_tier2(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_list("Servers")
        names = [e["name"] for e in result["entries"]]
        assert "SSH Root" in names
        assert "Restricted DB" in names
        assert "Top Secret" not in names  # Tier 2 invisible

    def test_inherited_tier2_folder_is_invisible_everywhere(self, vault_with_data):
        hidden = vault_with_data.create_node("Hidden", tier=2)
        nested = vault_with_data.create_node("Nested", parent_id=hidden)
        vault_with_data.create_entry(
            nested,
            "Inherited Secret",
            [{"key": "password", "value": "hidden-value", "sensitive": True}],
        )
        broker = MCPBroker(vault_with_data, ApprovalManager())

        root = broker.vault_list("")
        assert "Hidden" not in [node["name"] for node in root["nodes"]]
        assert broker.vault_list("Hidden") == {"nodes": [], "entries": []}
        assert broker.vault_read("Hidden/Nested/Inherited Secret") == {
            "status": "not_found"
        }
        assert broker.vault_search("Inherited Secret") == {"results": []}

    def test_folder_policy_is_inherited_by_entry(self, vault_with_data):
        readable = vault_with_data.create_node(
            "Readable", tier=0, ai_read_secret=True
        )
        vault_with_data.create_entry(
            readable,
            "Inherited Policy",
            [{"key": "token", "value": "folder-opt-in", "sensitive": True}],
        )
        broker = MCPBroker(vault_with_data, ApprovalManager())

        assert broker.vault_read("Readable/Inherited Policy", field="token") == {
            "status": "ok",
            "value": "folder-opt-in",
        }

    def test_vault_read_metadata(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_read("Servers/SSH Root")
        assert result["status"] == "ok"
        assert result["name"] == "SSH Root"
        assert "host" in result["fields"]
        assert "password" in result["fields"]

    def test_vault_read_tier0_denied_without_ai_flag(self, vault_with_data):
        """Tier 0 read_secret requires ai_read_secret=True (spec 3.2)."""
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_read("Servers/SSH Root", field="password")
        assert result["status"] == "denied"

    def test_vault_read_tier0_auto_with_ai_flag(self, vault_with_data, monkeypatch):
        """Tier 0 with ai_read_secret=True returns the value."""
        broker = MCPBroker(vault_with_data, ApprovalManager())
        # Monkey-patch find_entry_by_path to add ai_read_secret flag
        original_find = vault_with_data.find_entry_by_path
        def patched_find(path):
            entry = original_find(path)
            if entry is not None:
                entry["ai_read_secret"] = True
            return entry
        monkeypatch.setattr(vault_with_data, "find_entry_by_path", patched_find)
        result = broker.vault_read("Servers/SSH Root", field="password")
        assert result["status"] == "ok"
        assert result["value"] == "strong-P@ss!2026"

    def test_vault_read_tier2_not_found(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_read("Servers/Top Secret")
        assert result["status"] == "not_found"

    def test_vault_read_tier1_needs_approval(self, vault_with_data):
        mgr = ApprovalManager()
        broker = MCPBroker(vault_with_data, mgr)

        # Auto-approve in background thread
        def auto_approve():
            time.sleep(0.3)
            pending = mgr.get_pending()
            if pending:
                mgr.approve(pending[0].request_id)

        t = threading.Thread(target=auto_approve)
        t.start()

        result = broker.vault_read("Servers/Restricted DB", field="password")
        t.join()
        assert result["status"] == "ok"
        assert result["value"] == "db-secret"

    def test_tier1_approval_cannot_bypass_read_capability(self, vault_with_data):
        servers_id, _ = vault_with_data.resolve_path("Servers")
        vault_with_data.create_entry(
            servers_id,
            "No Raw Access",
            [{"key": "password", "value": "must-not-leak", "sensitive": True}],
            tier=1,
        )
        mgr = ApprovalManager()
        broker = MCPBroker(vault_with_data, mgr)

        result = broker.vault_read("Servers/No Raw Access", field="password")

        assert result["status"] == "denied"
        assert mgr.get_pending() == []

    def test_vault_search(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_search("SSH")
        assert len(result["results"]) >= 1
        assert any("SSH" in r["name"] for r in result["results"])

    def test_vault_search_excludes_tier2(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_search("Top Secret")
        names = [r["name"] for r in result["results"]]
        assert "Top Secret" not in names

    def test_vault_not_found(self, vault_with_data):
        broker = MCPBroker(vault_with_data, ApprovalManager())
        result = broker.vault_read("Nonexistent/Path")
        assert result["status"] == "not_found"


# === MCP Server ===

class TestMCPServer:
    def test_get_tools(self, vault_with_data):
        server = SezamMCPServer(vault_with_data)
        tools = server.get_tools()
        names = [t["name"] for t in tools]
        assert "vault_list" in names
        assert "vault_read" in names
        assert "vault_search" in names
        assert "vault_use" in names

    def test_handle_tool_call(self, vault_with_data):
        server = SezamMCPServer(vault_with_data)
        result = server.handle_tool_call("vault_list", {"path": ""})
        assert "nodes" in result
        assert "entries" in result


# === Watchtower ===

class TestWatchtower:
    def test_detect_weak_passwords(self, vault_with_data):
        wt = Watchtower()
        issues = wt.scan(vault_with_data)
        weak = [i for i in issues if i.issue_type == "weak"]
        assert len(weak) >= 2  # "123" passwords in Client A and B

    def test_detect_duplicate_passwords(self, vault_with_data):
        wt = Watchtower()
        issues = wt.scan(vault_with_data)
        dupes = [i for i in issues if i.issue_type == "duplicate"]
        assert len(dupes) >= 2  # Client A and B share same password

    def test_summary(self, vault_with_data):
        wt = Watchtower()
        issues = wt.scan(vault_with_data)
        summary = wt.summary(issues)
        assert summary["total"] > 0
        assert summary["critical"] >= 2  # weak passwords
        assert "weak" in summary["by_type"]

    def test_strong_password_no_issue(self, vault_with_data):
        wt = Watchtower()
        issues = wt.scan(vault_with_data)
        ssh_issues = [i for i in issues if i.entry_name == "SSH Root" and i.issue_type == "weak"]
        assert len(ssh_issues) == 0  # strong-P@ss!2026 is strong
