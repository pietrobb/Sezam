"""AI broker TODO section 2 (S2c): tier 1 approval of an agent signature.

The dialog says who logs in where ("An AI agent wants to log in as X on
Y", with the verified host key). After an approval the owner may also allow
the same entry, host and user for N minutes (a separate question, default
No); the grant lives in memory and ends on expiry, lock, AI off or another
switch epoch. ``sezam ssh-agent --print-config`` prints ssh_config blocks,
and the authorized_keys limitation is documented.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import approval as approval_mod
from sezam.mcp import ssh_agent
from sezam.mcp.approval import ApprovalManager, ApprovalRequest, approval_message, grant_message
from sezam.mcp.broker import MCPBroker
from sezam.mcp.ssh_agent import (
    SSH_AGENT_FAILURE,
    AgentConnection,
    SSHAgentService,
    client_config,
    host_key_fingerprint,
)
from sezam.vault import ai_access
from tests.test_ai_s2a_ssh_agent import (  # noqa: F401  (fixtures)
    _audit,
    _pkey,
    _sign,
    _signature,
    _ssh_entry,
    _verify,
    keys,
    vault,
)
from tests.test_ai_s2b_session_bind import _bind, _known, _try, hosts  # noqa: F401

FAILURE = bytes([SSH_AGENT_FAILURE])


class _Owner:
    """Answers approval requests: approve or deny, accept the grant or not."""

    def __init__(self, approvals: ApprovalManager, *, approve=True, grant=False):
        self.approvals, self.approve, self.grant = approvals, approve, grant
        self.seen: list[ApprovalRequest] = []
        approvals.set_on_request(self)

    def __call__(self, request):
        self.seen.append(request)
        if self.approve:
            self.approvals.approve(request.request_id, grant=self.grant)
        else:
            self.approvals.deny(request.request_id)


@pytest.fixture
def approvals():
    return ApprovalManager()


@pytest.fixture
def make_service(vault, approvals):  # noqa: F811
    def make(grant_minutes=10):
        return SSHAgentService(MCPBroker(vault, approvals), grant_minutes=grant_minutes)

    return make


def _login(service, keys, connection=None):  # noqa: F811
    key = _pkey(keys["tier1"])
    if connection is None:
        data, reply = _sign(service, key, "ops", "ssh-ed25519")
    else:
        data, reply = _try(service, connection, key, connection.target.session_id, username="ops")
    return reply != FAILURE and _verify(key, data, _signature(reply))


def test_dialog_says_who_logs_in_where(vault, make_service, approvals, keys, hosts):  # noqa: F811
    folder = vault.resolve_path("Servers")[0]
    _ssh_entry(vault, folder, "AskPinned", keys["tier1"], username="ops", tier=1,
               extra=[{"key": "host_key_sha256", "value": host_key_fingerprint(hosts["web"].asbytes())}])
    owner = _Owner(approvals)
    service = make_service()
    connection = AgentConnection()
    sid = os.urandom(32)
    assert service.handle(_bind(hosts["web"], sid), connection) == bytes([6])
    assert _login(service, keys, connection)

    request = owner.seen[0]
    assert request.action == "use_secret:ssh_agent"
    assert request.grant_minutes == 10
    message = approval_message(request)
    assert message.startswith(
        "An AI agent wants to log in as ops on askpinned.example.test:22 with the vault key."
    )
    assert f"Host key (verified): {host_key_fingerprint(hosts['web'].asbytes())}" in message
    assert "Agent forwarded" not in message
    assert "NOT verified" not in message
    assert "for the next 10 minutes" in grant_message(request)


def test_dialog_says_when_the_host_is_not_verified(make_service, approvals, keys):  # noqa: F811
    owner = _Owner(approvals)
    assert _login(make_service(), keys)  # no session-bind; Ask allows ssh_agent_unbound
    request = owner.seen[0]
    assert "Host key: NOT verified (the client sent no session-bind" in approval_message(request)
    assert "Host key: NOT verified" in grant_message(request)


def test_approval_without_grant_asks_every_time(make_service, approvals, keys, vault, monkeypatch):  # noqa: F811
    records = _audit(vault, monkeypatch)
    owner = _Owner(approvals, grant=False)
    service = make_service()
    assert _login(service, keys) and _login(service, keys)
    assert len(owner.seen) == 2
    assert [r["approval"] for r in records if r["operation"] == "agent_sign"] == ["owner", "owner"]


def test_granted_login_skips_the_dialog_until_it_expires(make_service, approvals, keys, vault, monkeypatch):  # noqa: F811
    records = _audit(vault, monkeypatch)
    owner = _Owner(approvals, grant=True)
    service = make_service(grant_minutes=5)
    now = [1000.0]
    monkeypatch.setattr(ssh_agent.time, "monotonic", lambda: now[0])

    assert _login(service, keys)
    owner.approve = False  # from now on the owner would say no
    assert _login(service, keys)
    now[0] += 5 * 60 - 1
    assert _login(service, keys)
    assert len(owner.seen) == 1
    assert [r["approval"] for r in records if r["operation"] == "agent_sign"] == [
        "owner_grant", "grant", "grant",
    ]
    now[0] += 2
    assert not _login(service, keys)
    assert len(owner.seen) == 2


@pytest.mark.parametrize("end", ["ai_off_on", "lock", "clear"])
def test_grant_ends_with_lock_ai_off_and_clear(make_service, approvals, keys, vault, end):  # noqa: F811
    owner = _Owner(approvals, grant=True)
    service = make_service()
    assert _login(service, keys)
    if end == "ai_off_on":
        ai_access.disable(vault, "test")
        assert not _login(service, keys)
        ai_access.enable(vault, "test")
    elif end == "lock":
        vault.lock()
        assert not _login(service, keys)
        vault.unlock("test")
    else:
        service.clear_grants()
    owner.approve = False
    assert not _login(service, keys)
    assert len(owner.seen) == 2


def test_grant_is_per_host(vault, make_service, approvals, keys, hosts):  # noqa: F811
    owner = _Owner(approvals, grant=True)
    service = make_service()
    # Two host keys the Ask entry's host may present (known_hosts).
    _known("ask.example.test", hosts["web"])
    _known("ask.example.test", hosts["rsa"])
    first, second = AgentConnection(), AgentConnection()
    service.handle(_bind(hosts["web"], os.urandom(32)), first)
    service.handle(_bind(hosts["rsa"], os.urandom(32), algorithm="rsa-sha2-512"), second)
    assert _login(service, keys, first)
    assert _login(service, keys, first)
    assert len(owner.seen) == 1
    assert _login(service, keys, second)
    assert len(owner.seen) == 2


def test_no_grant_unless_offered(make_service, approvals, keys):  # noqa: F811
    owner = _Owner(approvals, grant=True)
    service = make_service(grant_minutes=0)
    assert _login(service, keys) and _login(service, keys)
    assert [r.grant_minutes for r in owner.seen] == [0, 0]
    assert not any(r.granted for r in owner.seen)


@pytest.mark.parametrize(
    "answers, offered, status, granted, asked",
    [
        ([True, True], 10, "approved", True, 2),
        ([True, False], 10, "approved", False, 2),
        ([False, True], 10, "denied", False, 1),
        ([True, True], 0, "approved", False, 1),
    ],
)
def test_desktop_dialog_asks_about_the_grant_separately(monkeypatch, answers, offered, status, granted, asked):
    questions: list[str] = []
    replies = iter(answers)

    def ask(message):
        questions.append(message)
        return next(replies)

    monkeypatch.setattr(approval_mod, "_ask", ask)
    manager = ApprovalManager()
    approval_mod.install_desktop_approval_handler(manager)
    request = manager.request_approval(
        "r1", "Servers/Ask", "use_secret:ssh_agent", "ssh-agent",
        target={"entry": "Ask", "host": "h", "port": 22, "username": "ops"},
        grant_minutes=offered,
    )
    assert len(questions) == asked
    assert manager.check_and_consume("r1") == status
    assert request.granted is granted


# ── --print-config ──


def test_print_config_lists_served_entries_without_secrets(vault, keys):  # noqa: F811
    folder = vault.resolve_path("Servers")[0]
    _ssh_entry(vault, folder, "Evil", keys["other"], username="x\n    ProxyCommand touch /tmp/p")
    text = client_config(MCPBroker(vault, ApprovalManager()), endpoint="\\\\.\\pipe\\agent")

    aliases = [line.split()[1] for line in text.splitlines() if line.startswith("Host ")]
    assert sorted(aliases) == ["sezam-servers-ask", "sezam-servers-ed", "sezam-servers-rsa"]
    assert "    HostName ed.example.test\n    Port 22\n    User ai-web\n" in text
    assert '    IdentityAgent "\\\\\\\\.\\\\pipe\\\\agent"' in text
    assert "ForwardAgent no" in text
    assert "ProxyCommand" not in text
    assert "# sezam-servers-evil: skipped, host or user has unsafe characters" in text
    assert "authorized_keys" in text
    for pem in keys.values():
        assert pem.split("\n")[3] not in text


def test_cli_print_config(tmp_path, keys, monkeypatch):  # noqa: F811
    from sezam.vault.crud import Vault
    from tests.test_mcp_ssh import FAST_PARAMS

    stored: dict = {}
    monkeypatch.setitem(sys.modules, "keyring", types.SimpleNamespace(
        set_password=lambda s, a, p: stored.update({(s, a): p}),
        get_password=lambda s, a: stored.get((s, a)),
        delete_password=lambda s, a: stored.pop((s, a), None),
    ))
    monkeypatch.setattr(cli, "_attempt_tracker_path", lambda: tmp_path / "attempts.json")
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "v"))
    vault = Vault.create(tmp_path / "v", "pw", FAST_PARAMS)
    _ssh_entry(vault, vault.create_node("Servers"), "Web", keys["ed"], username="ai-web")
    vault.lock()

    result = CliRunner().invoke(cli.main, ["ssh-agent", "--print-config"], input="pw\n")
    assert result.exit_code == 0, result.output
    assert "Host sezam-servers-web" in result.output
    assert "IdentityAgent" in result.output


def test_authorized_keys_limitation_is_documented():
    doc = (Path(__file__).parents[1] / "docs" / "TECHNICKA_DOKUMENTACIA.md").read_text(encoding="utf-8")
    assert "## 17. SSH agent pre AI" in doc
    assert "authorized_keys" in doc.split("## 17. SSH agent pre AI", 1)[1]
    assert "authorized_keys" in (cli.ssh_agent.help or "")
