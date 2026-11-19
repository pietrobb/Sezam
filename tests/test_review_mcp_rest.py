"""Regressions for code review HEAD 2c7e809, MCP items 16 (bidi), 18 and 19."""

from __future__ import annotations

import json
import sys
import time
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp import ssh as ssh_mod
from sezam.mcp.approval import ApprovalManager, ApprovalRequest, approval_message
from sezam.mcp.broker import MCPBroker
from sezam.mcp.redact import RedactingStream, Redactor
from sezam.mcp.ssh import SSHBrokerError, SSHManager, _Session
from sezam.vault.crud import Vault

from tests.test_mcp_ssh import FakeSSHManager

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "review-master-password"
ENTRY = {
    "id": "E1",
    "fields": [
        {"key": "host", "value": "host"},
        {"key": "username", "value": "user"},
        {"key": "password", "value": "secret"},
    ],
}


# ── 16: approval text cannot be disguised ──


def test_approval_message_escapes_bidi_and_invisible_characters():
    request = ApprovalRequest(
        request_id="r",
        path="Servers/\u202eprod",
        action="ssh_execute",
        agent_name="Claude\u200b",
        details={"command": "ls\u2028rm -rf /"},
    )

    message = approval_message(request)

    for hidden in ("\u202e", "\u200b", "\u2028"):
        assert hidden not in message
    assert "\\u202e" in message and "\\u200b" in message and "\\u2028" in message
    assert message.count("\n") >= 5  # layout newlines stay readable


# ── 18: local_path is confined to the transfer directory ──


def _manager(tmp_path, monkeypatch) -> SSHManager:
    manager = SSHManager(transfer_root=tmp_path / "transfers")
    monkeypatch.setattr(
        manager, "_connect", lambda credentials: pytest.fail("must not connect")
    )
    return manager


@pytest.mark.parametrize(
    "local_path",
    ["~/.ssh/id_ed25519", "../outside.txt", "sub/../../outside.txt"],
)
def test_upload_outside_transfer_dir_is_refused_before_connecting(
    tmp_path, monkeypatch, local_path
):
    (tmp_path / "outside.txt").write_text("secret")

    with pytest.raises(SSHBrokerError) as raised:
        _manager(tmp_path, monkeypatch).upload(ENTRY, local_path, "/tmp/x")

    assert raised.value.code == "local_path_denied"


def test_download_cannot_target_files_outside_transfer_dir(tmp_path, monkeypatch):
    target = tmp_path / "home" / ".bashrc"

    with pytest.raises(SSHBrokerError) as raised:
        _manager(tmp_path, monkeypatch).download(ENTRY, "/etc/passwd", str(target))

    assert raised.value.code == "local_path_denied"
    assert not target.exists()


def test_relative_and_absolute_paths_inside_transfer_dir_are_accepted(tmp_path):
    root = tmp_path / "transfers"

    relative = ssh_mod._confine_local_path(root, "site/index.html")
    absolute = ssh_mod._confine_local_path(root, str(root / "a.txt"))

    assert relative == (root / "site" / "index.html").resolve()
    assert absolute == (root / "a.txt").resolve()
    assert ssh_mod.SSHManager(transfer_root=root)._local_root(None).is_dir()


# ── 19: tier 2 folder is a ceiling for search and read ──


@pytest.fixture
def hidden_vault(tmp_path):
    vault = Vault.create(tmp_path, "test", FAST_PARAMS)
    hidden = vault.create_node("Private", tier=2)
    sub = vault.create_node("Open", parent_id=hidden, tier=0)
    vault.create_entry(
        hidden, "bank", [{"key": "password", "value": "pw-bank"}], tier=0
    )
    vault.create_entry(
        sub, "nested", [{"key": "password", "value": "pw-nested"}], tier=0
    )
    yield vault
    vault.lock()


def test_lower_tier_entry_in_tier2_folder_stays_hidden(hidden_vault):
    broker = MCPBroker(hidden_vault, ApprovalManager(), ssh_manager=FakeSSHManager())

    assert broker.vault_read("Private/bank") == {"status": "not_found"}
    assert broker.vault_read("Private/Open/nested") == {"status": "not_found"}
    assert broker.vault_search("bank")["results"] == []
    assert broker.vault_search("nested")["results"] == []


# ── 19: SSH sessions are bounded and re-checked against policy ──


def test_session_older_than_max_lifetime_is_closed_even_if_active(monkeypatch):
    closed = []
    monkeypatch.setattr(ssh_mod, "_close_session", closed.append)
    manager = SSHManager(session_idle_timeout=3600, session_max_lifetime=60)
    now = time.monotonic()
    session = _Session(
        None, None, "Claude", "E1", created_at=now - 61, last_used_at=now, max_lifetime=60,
        stdout_filter=RedactingStream(Redactor([])), stderr_filter=RedactingStream(Redactor([])),
    )
    manager._sessions["s"] = session

    with manager._lock:
        manager._cleanup_expired_locked()

    assert closed == [session]
    assert manager._sessions == {}


def test_open_session_is_closed_when_policy_is_revoked(tmp_path):
    vault = Vault.create(tmp_path, "test", FAST_PARAMS)
    try:
        folder = vault.create_node("Servers")
        entry_id = vault.create_entry(
            folder,
            "prod",
            [{"key": "host", "value": "h"}, {"key": "password", "value": "pw"}],
            tier=0,
            allowed_actions=["ssh_session"],
        )
        fake = FakeSSHManager()
        broker = MCPBroker(vault, ApprovalManager(), ssh_manager=fake)
        session_id = broker.ssh_session_open("Servers/prod", agent_name="Claude")["session_id"]
        assert broker.ssh_session_write(session_id, "id\n", agent_name="Claude")["status"] == "ok"

        vault.update_entry(entry_id, allowed_actions=[])
        result = broker.ssh_session_read(session_id, agent_name="Claude")

        assert result["status"] == "error"
        assert result.get("code") == "policy_revoked" or "policy_revoked" in repr(result)
        assert session_id not in fake.sessions
        assert [c[0] for c in fake.calls][-1] == "close"
    finally:
        vault.lock()


# ── 19: mcp-serve never reads the password from stdin and follows the session ──


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
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
    Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
    return tmp_path


def test_mcp_serve_without_session_never_reads_password_from_stdin(cli_env):
    # AI TODO P5: without a session the server runs locked and answers
    # vault_locked; a password typed on stdin is just invalid JSON-RPC.
    call = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "vault_list", "arguments": {}}}
    )
    result = CliRunner().invoke(
        cli.main, ["mcp-serve", "--deny-tier1"], input=PASSWORD + "\n" + call + "\n"
    )

    assert result.exit_code == 0, result.output
    assert "sezam unlock" in result.output
    assert "Invalid JSON request" in result.output
    assert "vault_locked" in result.output
    assert "MCP server unlocked" not in result.output


def test_session_watch_locks_vault_when_session_ends(cli_env):
    assert CliRunner().invoke(cli.main, ["unlock"], input=PASSWORD + "\n").exit_code == 0
    vault = Vault(Path(cli_env))
    vault.unlock(PASSWORD)
    locked = []
    stop = cli._watch_session_and_lock(vault, lambda: locked.append(True), interval=0.05)
    try:
        time.sleep(0.2)
        assert vault.is_unlocked and locked == []

        cli._clear_session()
        deadline = time.monotonic() + 2
        # on_lock (closing the SSH sessions) runs first, the vault locks
        # right after it on the watcher thread (public CI run 44562360614).
        while (not locked or vault.is_unlocked) and time.monotonic() < deadline:
            time.sleep(0.05)

        assert locked == [True]
        assert not vault.is_unlocked
    finally:
        stop.set()
