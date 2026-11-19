"""AI broker TODO section 1, phase 2 (S1e): the AI brake pulled on the phone.

The phone publishes a signed ``ai_policy`` ``{enabled, epoch}`` through the
sync server; every mcp-serve polls it (~30 s) and pulls the same brake as
``sezam ai off`` on an epoch newer than the last one it applied. The
signature is checked against the owner's key in the local vault, never
against anything the server supplies, and no policy turns AI access on.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from nacl.signing import SigningKey, VerifyKey

from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.remote_policy import RemotePolicyPoller, applied_epoch, sign_policy
from sezam.mcp.server import SezamMCPServer
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS
from tests.test_ai_s1b_control import _FakeSSH, _code, _run
from tests.test_ai_s1b_control import env  # noqa: F401  (fixture)

PASSWORD = "s1e-master-password"


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def _owner(vault) -> tuple[str, SigningKey]:
    return vault.db.get_meta("user_id"), vault.keypair.to_nacl_signing_key()


def _policy(vault, epoch: int, enabled: bool = False, key: SigningKey | None = None) -> dict:
    user_id, owner_key = _owner(vault)
    return {
        "user_id": user_id,
        "enabled": enabled,
        "epoch": epoch,
        "signature": sign_policy(key or owner_key, user_id, enabled, epoch),
        "updated_at": 0,
    }


def _poller(vault, broker, policy):
    box = {"policy": policy, "calls": 0}

    def fetch():
        box["calls"] += 1
        return box["policy"]

    return RemotePolicyPoller(vault, broker, fetch=fetch), box


def _ai_off_rows(vault) -> list:
    return vault.db.fetchall("SELECT id FROM audit_log WHERE action = 'ai_off'")


def test_owner_signed_policy_pulls_the_brake(vault):
    events: list = []
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH(events))
    poller, _ = _poller(vault, broker, _policy(vault, 100))

    assert poller.poll_once() == "applied"

    assert events == ["close_all"]
    assert not ai_access.read_state(vault).enabled
    assert _code(lambda: broker.vault_list("")) == "ai_disabled"
    assert applied_epoch(vault) == 100
    assert len(_ai_off_rows(vault)) == 1
    assert broker.status()["remote_policy"] == "off"  # not attached to this broker


def test_brake_audit_names_the_remote_epoch(vault, monkeypatch):
    seen: list = []
    real = vault._audit_log

    def spy(action, detail=None, **kwargs):
        if action == "ai_off":
            seen.append(json.loads(detail))
        return real(action, detail, **kwargs)

    monkeypatch.setattr(vault, "_audit_log", spy)
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
    poller, _ = _poller(vault, broker, _policy(vault, 7))

    poller.poll_once()

    assert seen and seen[0]["source"] == "remote_policy"
    assert seen[0]["remote_epoch"] == 7 and seen[0]["remote_enabled"] is False


def test_an_applied_policy_does_not_undo_a_local_ai_on(vault):
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
    poller, box = _poller(vault, broker, _policy(vault, 100))
    assert poller.poll_once() == "applied"

    ai_access.enable(vault, "cli")  # the owner, with the master password
    assert poller.poll_once() == "unchanged"  # the same (or a replayed) policy
    assert ai_access.read_state(vault).enabled
    broker.vault_list("")  # no ai_disabled any more

    box["policy"] = _policy(vault, 99)  # older than the applied one
    assert poller.poll_once() == "unchanged"
    assert ai_access.read_state(vault).enabled

    box["policy"] = _policy(vault, 101)  # a new brake from the phone
    assert poller.poll_once() == "applied"
    assert not ai_access.read_state(vault).enabled


def test_no_policy_can_turn_ai_access_on(vault):
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
    ai_access.disable(vault, "cli")
    poller, box = _poller(vault, broker, _policy(vault, 5, enabled=True))

    poller.poll_once()
    assert not ai_access.read_state(vault).enabled

    ai_access.enable(vault, "cli")
    box["policy"] = _policy(vault, 6, enabled=True)
    assert poller.poll_once() == "applied"  # a new epoch is a brake, whatever it says
    assert not ai_access.read_state(vault).enabled


def test_a_policy_the_owner_did_not_sign_is_ignored(vault):
    """The server cannot forge it: its own key, a key it claims is the
    owner's, a tampered field or another account's policy all fail."""
    events: list = []
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH(events))
    server_key = SigningKey.generate()
    user_id, owner_key = _owner(vault)
    forged = _policy(vault, 50, key=server_key)
    forged["signing_pk"] = bytes(server_key.verify_key).hex()  # never consulted
    tampered = _policy(vault, 50)
    tampered["epoch"] = 51
    other_user = "01JOTHER00000000000000000Z"
    foreign = {
        "user_id": other_user, "enabled": False, "epoch": 50,
        "signature": sign_policy(owner_key, other_user, False, 50),
    }
    for policy in (forged, tampered, foreign):
        poller, _ = _poller(vault, broker, policy)
        assert poller.poll_once() == "invalid"

    assert events == []
    assert ai_access.read_state(vault).enabled
    assert applied_epoch(vault) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch", "100"), ("epoch", True), ("epoch", 0), ("epoch", -1), ("epoch", 2**63),
        ("enabled", 0), ("enabled", "false"), ("signature", "ab" * 10), ("signature", None),
    ],
)
def test_malformed_policy_is_ignored(vault, field, value):
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
    policy = _policy(vault, 100)
    policy[field] = value
    poller, _ = _poller(vault, broker, policy)

    assert poller.poll_once() == "invalid"
    assert ai_access.read_state(vault).enabled


def test_locked_vault_is_not_polled_and_errors_change_nothing(vault):
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())

    def broken():
        raise RuntimeError("Server error 502: bad gateway")

    poller = RemotePolicyPoller(vault, broker, fetch=broken)
    assert poller.poll_once() == "error"
    assert ai_access.read_state(vault).enabled

    poller, box = _poller(vault, broker, None)
    assert poller.poll_once() == "none"
    vault.lock()
    assert poller.poll_once() == "locked"
    assert box["calls"] == 1


def test_brake_is_retried_when_the_off_state_cannot_be_written(vault, monkeypatch):
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
    poller, _ = _poller(vault, broker, _policy(vault, 100))

    def broken(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(ai_access, "disable", broken)
    assert poller.poll_once() == "applied"
    assert _code(lambda: broker.vault_list("")) == "ai_disabled"  # held in memory
    assert applied_epoch(vault) == 0  # so the next poll tries again

    monkeypatch.undo()
    assert poller.poll_once() == "applied"
    assert applied_epoch(vault) == 100 and not ai_access.read_state(vault).enabled


def test_poller_thread_brakes_within_seconds(vault):
    events: list = []
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH(events))
    poller = RemotePolicyPoller(vault, broker, interval=0.05, fetch=lambda: None)
    poller.start()
    try:
        time.sleep(0.1)
        assert ai_access.read_state(vault).enabled
        poller._fetch = lambda: _policy(vault, 3)
        deadline = time.monotonic() + 2
        while ai_access.read_state(vault).enabled and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        poller.stop()
    assert not ai_access.read_state(vault).enabled
    assert "close_all" in events


class _StubServer:
    """Just enough of the Sezam server: challenge auth and /api/ai-policy."""

    def __init__(self, signing_pk: bytes, username: str):
        self.policy = None
        self.verifies = 0
        self.expire_next = False
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert body["username"] == username
                if self.path == "/api/auth/challenge":
                    return self._reply(200, {"challenge": secrets.token_hex(40)})
                if self.path == "/api/auth/verify":
                    VerifyKey(signing_pk).verify(
                        b"sezam-auth-challenge-signature-v1" + bytes.fromhex(body["challenge"]),
                        bytes.fromhex(body["signature"]),
                    )
                    stub.verifies += 1
                    stub.token = f"jwt-{stub.verifies}"
                    return self._reply(200, {"token": stub.token})
                self._reply(404, {})

            def do_GET(self):
                if self.path != "/api/ai-policy":
                    return self._reply(404, {})
                if stub.expire_next or self.headers.get("Authorization") != f"Bearer {stub.token}":
                    stub.expire_next = False
                    return self._reply(401, {"detail": "expired"})
                self._reply(200, {"policy": stub.policy})

        self.token = None
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def test_end_to_end_over_http_with_the_real_fetch(vault):
    vault.db.set_meta("username", "owner")
    stub = _StubServer(bytes(vault.keypair.signing_pk), "owner")
    vault.db.set_meta("server_url", stub.url)
    try:
        broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
        poller = RemotePolicyPoller(vault, broker)

        assert poller.poll_once() == "none"
        stub.policy = _policy(vault, 1_762_500_000_123)
        assert poller.poll_once() == "applied"
        assert not ai_access.read_state(vault).enabled
        assert stub.verifies == 1  # the token is reused between polls

        stub.expire_next = True  # an expired token: authenticate again
        assert poller.poll_once() == "unchanged"
        assert stub.verifies == 2
    finally:
        stub.close()


def test_mcp_serve_runs_the_poller_and_status_reports_it(env, monkeypatch):  # noqa: F811
    seen: list = []

    def run_stdio(self):
        seen.append((self.broker.remote_policy, self.broker.status()["remote_policy"]))

    monkeypatch.setattr(SezamMCPServer, "run_stdio", run_stdio)
    env.vault.lock()

    result = _run("mcp-serve", "--transport", "stdio")

    assert result.exit_code == 0, result.output
    poller, reported = seen[0]
    assert isinstance(poller, RemotePolicyPoller)
    assert poller._stop.is_set()  # stopped on exit
    assert reported in ("not polled", "locked")
