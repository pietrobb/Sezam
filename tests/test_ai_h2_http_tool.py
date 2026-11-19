"""AI broker TODO section 9 (H2): the MCP ``http_request`` tool in the broker.

Same gates as the SSH and FTP tools: the explicit ``http`` action, tier
0/1/2, approval showing the real request (method + host from the entry +
checked path) and its encryption, a warning for plain HTTP, the kill switch
(also cutting a request in progress) and an audit record of intent and
outcome for ``sezam ai log``. The token never reaches results or the audit.
Runs against the local HTTPS server of the H1 tests.
"""

from __future__ import annotations

import json
import threading
import time

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import audit_view
from sezam.mcp.approval import ApprovalManager, approval_message
from sezam.mcp.broker import MCPBroker, MCPError
from sezam.mcp.http_api import PLAIN_HTTP_WARNING, HTTPManager
from sezam.mcp.server import SezamMCPServer
from sezam.vault.crud import Vault
from tests.test_ai_h1_http import TOKEN, _Server, https  # noqa: F401  (fixture)
from tests.test_mcp_ssh import FAST_PARAMS

MASTER = "h2-master"


class _Env:
    def __init__(self, tmp_path, server, *, tier=0, actions=("http",), timeout=10.0, **extra):
        self.vault = Vault.create(tmp_path / "vault", MASTER, FAST_PARAMS)
        values = {
            "base_url": f"{server.scheme}://127.0.0.1:{server.port}/wp-json",
            "auth_header": "Authorization: Bearer {token}",
            "allowed_methods": "GET POST",
            "allowed_path_prefixes": "/wp/v2",
        }
        if server.ca_pem:
            values["tls_ca_cert"] = server.ca_pem
        values.update(extra)
        fields = [{"key": k, "value": v} for k, v in values.items()]
        fields.append({"key": "token", "value": TOKEN, "sensitive": True})
        self.entry_id = self.vault.create_entry(
            self.vault.create_node("Sites"), "blog", fields, tier=tier, allowed_actions=list(actions)
        )
        self.approvals = ApprovalManager()
        self.asked: list = []
        self.http = HTTPManager(timeout=timeout)
        self.broker = MCPBroker(self.vault, self.approvals, http_manager=self.http)
        self.origin = f"{server.scheme}://127.0.0.1:{server.port}"

    def answer(self, approve: bool):
        def handle(request):
            self.asked.append(request)
            if approve:
                self.approvals.approve(request.request_id)
            else:
                self.approvals.deny(request.request_id)

        self.approvals.set_on_request(handle)

    def log(self) -> list[dict]:
        paths = audit_view.entry_paths(self.vault)
        return [
            audit_view.describe(r, paths)
            for r in audit_view.ai_records(self.vault)
            if r.kind in ("mcp_http", "mcp_approval")
        ]

    def raw_audit(self) -> str:
        return json.dumps([r.detail for r in audit_view.ai_records(self.vault)])


def test_http_needs_the_explicit_action(tmp_path, https):
    env = _Env(tmp_path, https, actions=("ftp",))

    result = env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo", agent_name="claude")

    assert result["status"] == "denied"
    assert https.seen == []
    assert env.log()[-1]["result"] == "DENIED (policy)"


def test_tier0_request_inserts_the_header_and_is_audited_without_it(tmp_path, https):
    env = _Env(tmp_path, https)

    result = env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo?page=2", agent_name="claude")

    assert result["status"] == "ok" and result["http_status"] == 200
    assert https.seen[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert https.seen[0]["path"] == "/wp-json/wp/v2/echo?page=2"
    assert "[REDACTED]" in result["body"]
    rows = env.log()
    assert [(r["action"], r["result"]) for r in rows] == [
        ("http request", "started"),
        ("http request", "ok, HTTP 200"),
    ]
    assert rows[1]["what"] == f"GET {env.origin}/wp-json/wp/v2/echo?page=2"
    assert rows[1]["bytes"].startswith("in 0 B, out ")
    assert all(r["agent"] == "claude" and r["entry"] == "Sites/blog" for r in rows)
    assert TOKEN not in json.dumps(result) + env.raw_audit()


def test_policy_refusal_is_audited_as_failure(tmp_path, https):
    env = _Env(tmp_path, https)

    method = env.broker.http_request("Sites/blog", "DELETE", "/wp/v2/posts/1", agent_name="claude")
    outside = env.broker.http_request("Sites/blog", "GET", "/wp/v2/../../admin", agent_name="claude")

    assert method["code"] == "method_denied" and outside["code"] == "invalid_path"
    assert https.seen == []
    assert [r["result"] for r in env.log()] == []  # refused before the intent record


def test_tier1_approval_shows_the_real_request(tmp_path, https):
    env = _Env(tmp_path, https, tier=1)
    env.answer(approve=True)

    result = env.broker.http_request(
        "Sites/blog", "post", "/wp/v2/echo", body='{"title": "x"}',
        headers={"Content-Type": "application/json"}, agent_name="claude",
    )

    assert result["status"] == "ok" and https.seen[0]["method"] == "POST"
    message = approval_message(env.asked[0])
    assert "Action: use_secret:http" in message
    assert f"Request: POST {env.origin}/wp-json/wp/v2/echo\n" in message
    assert "Encryption: TLS (certificate verified)" in message
    assert '"title' in message and "WARNING" not in message
    assert TOKEN not in message
    assert env.log()[0]["result"] == "APPROVED by owner"


def test_tier1_path_outside_the_prefixes_is_refused_without_asking(tmp_path, https):
    env = _Env(tmp_path, https, tier=1)
    env.answer(approve=True)

    result = env.broker.http_request("Sites/blog", "GET", "/wp/v1/users", agent_name="claude")

    assert result["status"] == "error" and result["code"] == "path_denied"
    assert env.asked == [] and https.seen == []


def test_denied_approval_never_connects(tmp_path, https):
    env = _Env(tmp_path, https, tier=1)
    env.answer(approve=False)

    result = env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo", agent_name="claude")

    assert result == {"status": "denied"}
    assert https.seen == []


def test_tier2_entry_is_invisible(tmp_path, https):
    env = _Env(tmp_path, https, tier=2)

    assert env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo") == {"status": "not_found"}
    assert https.seen == []


def test_plain_http_is_warned_in_the_dialog_and_in_every_result(tmp_path):
    server = _Server(tmp_path, tls=False)
    try:
        env = _Env(tmp_path, server, tier=1, allow_plain_http="true")
        env.answer(approve=True)
        ok = env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo", agent_name="claude")
        env.http._timeout = 0.5
        failed = env.broker.http_request("Sites/blog", "GET", "/wp/v2/slow", agent_name="claude")
    finally:
        server.close()

    message = approval_message(env.asked[0])
    assert message.startswith("WARNING: Plain HTTP")
    assert "Encryption: NONE - plain HTTP" in message
    assert ok["warning"] == PLAIN_HTTP_WARNING
    assert failed["code"] == "timeout" and failed["warning"] == PLAIN_HTTP_WARNING
    assert "PLAIN HTTP" in env.log()[-1]["what"]


def test_kill_switch_refuses_http(tmp_path, https):
    env = _Env(tmp_path, https)
    env.broker.disable_ai("test")

    with pytest.raises(MCPError) as exc:
        env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo", agent_name="claude")

    assert exc.value.code == "ai_disabled"
    assert https.seen == []


def test_kill_switch_cuts_a_running_request(tmp_path, https):
    env = _Env(tmp_path, https)
    outcome: dict = {}
    worker = threading.Thread(
        target=lambda: outcome.update(
            env.broker.http_request("Sites/blog", "GET", "/wp/v2/slow", agent_name="claude")
        )
    )
    worker.start()
    deadline = time.monotonic() + 5
    while not https.seen and time.monotonic() < deadline:
        time.sleep(0.02)
    started = time.monotonic()
    env.broker.disable_ai("test")
    worker.join(5)

    assert not worker.is_alive() and time.monotonic() - started < 2
    assert outcome["status"] == "error" and outcome["code"] == "cut_off"
    assert env.log()[-1]["result"] == "FAILED cut_off"


def test_mcp_server_exposes_the_http_request_tool(tmp_path, https):
    env = _Env(tmp_path, https)
    server = SezamMCPServer(env.vault)
    server._broker = env.broker

    tools = {t["name"]: t for t in server.get_tools()}
    ok = server.handle_tool_call(
        "http_request", {"path": "Sites/blog", "method": "GET", "request_path": "/wp/v2/echo"}
    )
    bad = server.handle_tool_call(
        "http_request",
        {"path": "Sites/blog", "method": "GET", "request_path": "/wp/v2/echo", "headers": "x"},
    )

    schema = tools["http_request"]["inputSchema"]
    assert schema["required"] == ["path", "method", "request_path"]
    assert "auth" not in json.dumps(schema["properties"]).lower().replace("authorization", "")
    assert ok["status"] == "ok" and ok["http_status"] == 200
    assert bad["code"] == "invalid_request"
    assert TOKEN not in json.dumps(ok)


def test_cli_policy_accepts_the_http_action(tmp_path, monkeypatch):
    import sys
    import types

    monkeypatch.setitem(
        sys.modules, "keyring",
        types.SimpleNamespace(set_password=lambda *a: None, get_password=lambda *a: None,
                              delete_password=lambda *a: None),
    )
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "v"))
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    vault = Vault.create(tmp_path / "v", MASTER, FAST_PARAMS)
    vault.create_entry(vault.create_node("Sites"), "blog", [{"key": "base_url", "value": "https://h"}])
    vault.lock()

    result = CliRunner().invoke(
        cli.main, ["mcp-policy", "Sites/blog", "--allow-action", "http"], input=MASTER + "\n"
    )

    assert result.exit_code == 0, result.output
    vault = Vault(tmp_path / "v")
    vault.unlock(MASTER)
    try:
        assert vault.find_entry_by_path("Sites/blog")["allowed_actions"] == ["http"]
    finally:
        vault.lock()
