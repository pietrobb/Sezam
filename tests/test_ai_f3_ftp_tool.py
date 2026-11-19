"""AI broker TODO section 6 (F3): the MCP ``ftp`` tool in the broker.

Same gates as the SSH tools: the explicit ``ftp`` action, tier 0/1/2,
approval showing the real target and its encryption (with a warning for
plain FTP, which the result repeats), the kill switch (also cutting a
transfer in progress), remote_root/local_root and an audit record of intent
and outcome for ``sezam ai log``. Runs against the real pyftpdlib servers of
the F2 tests.
"""

from __future__ import annotations

import json
import threading
import time

import pytest
from click.testing import CliRunner

pytest.importorskip("OpenSSL")
pytest.importorskip("pyftpdlib")

from sezam import cli  # noqa: E402
from sezam.mcp import audit_view  # noqa: E402
from sezam.mcp.approval import ApprovalManager, approval_message  # noqa: E402
from sezam.mcp.broker import MCPBroker, MCPError  # noqa: E402
from sezam.mcp.ftp import PLAIN_FTP_WARNING, FTPManager  # noqa: E402
from sezam.mcp.server import SezamMCPServer  # noqa: E402
from sezam.vault.crud import Vault  # noqa: E402
from tests.test_ai_f2_ftp import (  # noqa: E402,F401  (fixtures)
    FTP_PASSWORD,
    _Server,
    cert,
    explicit,
    plain,
    transfers,
)
from tests.test_mcp_ssh import FAST_PARAMS  # noqa: E402

MASTER = "f3-master"


class _Env:
    def __init__(self, tmp_path, transfers, server, *, tier=0, actions=("ftp",), ca=None, **extra):
        self.vault = Vault.create(tmp_path / "vault", MASTER, FAST_PARAMS)
        fields = [
            {"key": "host", "value": "127.0.0.1"},
            {"key": "port", "value": str(server.port)},
            {"key": "username", "value": "deploy"},
            {"key": "password", "value": FTP_PASSWORD, "sensitive": True},
        ]
        if ca:
            fields.append({"key": "tls_ca_cert", "value": ca})
        fields += [{"key": k, "value": v} for k, v in extra.items()]
        self.entry_id = self.vault.create_entry(
            self.vault.create_node("Hosting"), "web", fields, tier=tier, allowed_actions=list(actions)
        )
        self.approvals = ApprovalManager()
        self.asked: list = []
        self.ftp = FTPManager(transfer_root=transfers, connect_timeout=5, operation_timeout=5)
        self.broker = MCPBroker(self.vault, self.approvals, ftp_manager=self.ftp)

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
            if r.kind in ("mcp_ftp", "mcp_approval")
        ]

    def raw_audit(self) -> str:
        return json.dumps([r.detail for r in audit_view.ai_records(self.vault)])


def test_ftp_needs_the_explicit_action(tmp_path, transfers, explicit, cert):
    env = _Env(tmp_path, transfers, explicit, actions=("ssh_upload",), ca=cert[1])

    result = env.broker.ftp("Hosting/web", "list", "/", agent_name="claude")

    assert result["status"] == "denied"
    assert explicit.commands == []
    assert env.log()[-1]["result"] == "DENIED (policy)"


def test_tier0_upload_with_shared_policies_is_audited(tmp_path, transfers, explicit, cert):
    env = _Env(tmp_path, transfers, explicit, ca=cert[1])
    (explicit.home / "site").mkdir()
    (explicit.home / "secret.txt").write_bytes(b"db")
    env.vault.update_entry(env.entry_id, remote_root="/site")
    (transfers / "index.html").write_bytes(b"<h1>x</h1>")

    ok = env.broker.ftp("Hosting/web", "upload", "index.html", local_path="index.html", agent_name="claude")
    outside = env.broker.ftp("Hosting/web", "download", "/secret.txt", local_path="s.txt", agent_name="claude")
    listing = env.broker.ftp("Hosting/web", "list", ".", agent_name="claude")

    assert ok == {"status": "ok", "files": 1, "bytes": 10}
    assert (explicit.home / "site" / "index.html").read_bytes() == b"<h1>x</h1>"
    assert outside["status"] == "error" and outside["code"] == "remote_path_denied"
    assert [e["name"] for e in listing["entries"]] == ["index.html"]
    rows = env.log()
    assert [(r["action"], r["result"]) for r in rows] == [
        ("ftp upload", "started"),
        ("ftp upload", "ok"),
        ("ftp download", "started"),
        ("ftp download", "FAILED remote_path_denied"),
        ("ftp list", "started"),
        ("ftp list", "ok"),
    ]
    assert rows[1]["what"] == "index.html -> index.html" and rows[1]["bytes"] == "1 file(s) 10 B"
    assert all(r["agent"] == "claude" and r["entry"] == "Hosting/web" for r in rows)
    assert FTP_PASSWORD not in json.dumps([ok, outside, listing]) + env.raw_audit()


def test_tier1_approval_shows_target_and_encryption(tmp_path, transfers, explicit, cert):
    env = _Env(tmp_path, transfers, explicit, tier=1, ca=cert[1])
    env.answer(approve=True)

    result = env.broker.ftp("Hosting/web", "mkdir", "/site", agent_name="claude")

    assert result["status"] == "ok"
    message = approval_message(env.asked[0])
    assert "Action: use_secret:ftp" in message
    assert f"Host: 127.0.0.1\nPort: {explicit.port}\nUser: deploy\n" in message
    assert "Encryption: FTPS (explicit TLS, certificate verified)" in message
    assert '"op": "mkdir"' in message and "WARNING" not in message
    assert FTP_PASSWORD not in message
    assert env.log()[0]["result"] == "APPROVED by owner"


def test_denied_approval_never_connects(tmp_path, transfers, explicit, cert):
    env = _Env(tmp_path, transfers, explicit, tier=1, ca=cert[1])
    env.answer(approve=False)

    result = env.broker.ftp("Hosting/web", "delete", "/index.html", agent_name="claude")

    assert result == {"status": "denied"}
    assert explicit.commands == []


def test_plain_ftp_is_warned_in_the_dialog_and_in_every_result(tmp_path, transfers, plain):
    env = _Env(tmp_path, transfers, plain, tier=1, allow_plain_ftp="true")
    env.answer(approve=True)

    ok = env.broker.ftp("Hosting/web", "mkdir", "/site", agent_name="claude")
    failed = env.broker.ftp("Hosting/web", "delete", "/missing", agent_name="claude")

    message = approval_message(env.asked[0])
    assert message.startswith("WARNING: Plain FTP")
    assert "Encryption: NONE - plain FTP" in message
    assert ok["warning"] == PLAIN_FTP_WARNING
    assert failed["code"] == "remote_not_found" and failed["warning"] == PLAIN_FTP_WARNING
    assert "PLAIN FTP" in env.log()[-1]["what"]


def test_tls_entry_against_a_plain_server_fails_closed(tmp_path, transfers, plain):
    env = _Env(tmp_path, transfers, plain)

    result = env.broker.ftp("Hosting/web", "list", "/", agent_name="claude")

    assert result["status"] == "error" and result["code"] == "tls_unavailable"
    assert not plain.saw("PASS")


def test_kill_switch_refuses_ftp(tmp_path, transfers, explicit, cert):
    env = _Env(tmp_path, transfers, explicit, ca=cert[1])
    env.broker.disable_ai("test")

    with pytest.raises(MCPError) as exc:
        env.broker.ftp("Hosting/web", "list", "/", agent_name="claude")

    assert exc.value.code == "ai_disabled"
    assert explicit.commands == []


def test_kill_switch_cuts_a_running_transfer(tmp_path, transfers):
    server = _Server(tmp_path, "plain", throttle=32 * 1024)
    (server.home / "big.bin").write_bytes(b"z" * (2 * 1024 * 1024))
    env = _Env(tmp_path, transfers, server, allow_plain_ftp="true")
    outcome: dict = {}
    worker = threading.Thread(
        target=lambda: outcome.update(
            env.broker.ftp("Hosting/web", "download", "big.bin", local_path="big.bin", agent_name="claude")
        )
    )
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while env.ftp.active_count() == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        started = time.monotonic()
        env.broker.disable_ai("test")
        worker.join(5)
    finally:
        server.close()

    assert not worker.is_alive() and time.monotonic() - started < 5
    assert outcome["status"] == "error" and outcome["code"] == "cut_off"
    assert env.log()[-1]["result"] == "FAILED cut_off"


def test_mcp_server_exposes_the_ftp_tool(tmp_path, transfers, explicit, cert):
    env = _Env(tmp_path, transfers, explicit, ca=cert[1])
    server = SezamMCPServer(env.vault)
    server._broker = env.broker

    tools = {t["name"]: t for t in server.get_tools()}
    ok = server.handle_tool_call("ftp", {"path": "Hosting/web", "op": "mkdir", "remote_path": "/a"})
    bad = server.handle_tool_call("ftp", {"path": "Hosting/web", "op": "chmod", "remote_path": "/a"})
    missing = server.handle_tool_call("ftp", {"path": "Hosting/web", "op": "upload", "remote_path": "/a"})

    assert tools["ftp"]["inputSchema"]["properties"]["op"]["enum"] == [
        "list", "upload", "download", "delete", "mkdir", "rename"
    ]
    assert ok["status"] == "ok" and (explicit.home / "a").is_dir()
    assert bad["code"] == "invalid_request" and missing["code"] == "invalid_request"


def test_cli_policy_accepts_the_ftp_action(tmp_path, monkeypatch):
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
    vault.create_entry(vault.create_node("Hosting"), "web", [{"key": "host", "value": "h"}])
    vault.lock()

    result = CliRunner().invoke(
        cli.main, ["mcp-policy", "Hosting/web", "--allow-action", "ftp"], input=MASTER + "\n"
    )

    assert result.exit_code == 0, result.output
    vault = Vault(tmp_path / "v")
    vault.unlock(MASTER)
    try:
        assert vault.find_entry_by_path("Hosting/web")["allowed_actions"] == ["ftp"]
    finally:
        vault.lock()
