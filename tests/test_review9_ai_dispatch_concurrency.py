"""Review 1141a20 M-AI3: the MCP dispatch lock put every call of every client in one line.

One agent's slow HTTP request or SSH command (or a Tier 1 call waiting up to
two minutes for the owner) held every other client back, even a plain
vault_list. Calls now run side by side; what they share is made safe where it
lives: the vault's one SQLite connection runs a transaction for one thread at
a time (before, another thread's statements ran inside it and were undone
with it), and the broker's brake fields change under a lock.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid

import pytest

from sezam.mcp.server import SezamMCPServer
from sezam.vault.db import VaultDB
from tests.test_ai_h1_http import https  # noqa: F401  (fixture)
from tests.test_ai_h2_http_tool import _Env

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")


def _call(handle, request_id: int, name: str, arguments: dict) -> dict:
    import win32file

    message = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    win32file.WriteFile(handle, (json.dumps(message) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        _, chunk = win32file.ReadFile(handle, 65536)
        data += chunk
    return json.loads(json.loads(data)["result"]["content"][0]["text"])


def _serve(env):
    from tests.test_review_cli_ipc import _open_client

    server = SezamMCPServer(env.vault)
    server._broker = env.broker
    name = rf"\\.\pipe\sezam_test_{uuid.uuid4().hex}"
    thread = threading.Thread(target=server.run_socket, args=(name,), daemon=True)
    thread.start()
    return server, thread, lambda: _open_client(name)


def _in_background(fn) -> tuple[threading.Thread, dict]:
    out: dict = {}
    thread = threading.Thread(target=lambda: out.update(result=fn()), daemon=True)
    thread.start()
    return thread, out


@windows_only
def test_a_slow_request_of_one_client_does_not_hold_back_another(tmp_path, https):  # noqa: F811
    env = _Env(tmp_path, https)
    server, thread, connect = _serve(env)
    slow_client, other = connect(), connect()
    try:
        slow, out = _in_background(lambda: _call(
            slow_client, 1, "http_request",
            {"path": "Sites/blog", "method": "GET", "request_path": "/wp/v2/slow"},
        ))
        deadline = time.monotonic() + 5
        while not https.seen and time.monotonic() < deadline:
            time.sleep(0.02)
        assert https.seen, "the slow request never reached the server"
        started = time.monotonic()
        listed = _call(other, 2, "vault_list", {"path": "Sites"})
        took = time.monotonic() - started
        assert [e["name"] for e in listed["entries"]] == ["blog"]
        assert took < 1.5, f"vault_list waited {took:.1f} s behind the slow request"
        slow.join(10)
        assert out["result"]["status"] == "ok" and out["result"]["body"] == "late"
    finally:
        slow_client.Close()
        other.Close()
        server.stop()
    thread.join(5)


@windows_only
def test_a_call_waiting_for_the_owner_does_not_hold_back_another(tmp_path, https):  # noqa: F811
    env = _Env(tmp_path, https, tier=1)
    asked: list = []
    env.approvals.set_on_request(asked.append)  # the owner has not answered yet
    server, thread, connect = _serve(env)
    waiting_client, other = connect(), connect()
    try:
        waiting, out = _in_background(lambda: _call(
            waiting_client, 1, "http_request",
            {"path": "Sites/blog", "method": "GET", "request_path": "/wp/v2/echo"},
        ))
        deadline = time.monotonic() + 5
        while not asked and time.monotonic() < deadline:
            time.sleep(0.02)
        assert asked, "no approval was asked"
        started = time.monotonic()
        listed = _call(other, 2, "vault_list", {"path": ""})
        assert listed["entries"] == [] and listed["nodes"] == [{"name": "Sites"}]
        assert time.monotonic() - started < 1.5
        env.approvals.approve(asked[0].request_id)
        waiting.join(10)
        assert out["result"]["status"] == "ok" and out["result"]["http_status"] == 200
    finally:
        waiting_client.Close()
        other.Close()
        server.stop()
    thread.join(5)


def test_calls_side_by_side_keep_the_audit_whole(tmp_path, https):  # noqa: F811
    env = _Env(tmp_path, https)
    errors: list = []

    def agent(n: int) -> None:
        try:
            for _ in range(4):
                result = env.broker.http_request("Sites/blog", "GET", "/wp/v2/echo", agent_name=f"a{n}")
                assert result["status"] == "ok", result
                assert env.broker.vault_list("Sites")["entries"]
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=agent, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors[:3]
    rows = env.log()
    assert [r["result"] for r in rows].count("started") == 24
    assert [r["result"] for r in rows].count("ok, HTTP 200") == 24
    env.vault.lock()
    env.vault.unlock("h2-master")  # the audit chain still verifies
    assert len(env.log()) == 48


def test_another_threads_statements_never_run_inside_a_transaction(tmp_path):
    db = VaultDB(tmp_path / "t.db", hold_in_use=False)
    db.open()
    db.create_schema()
    inside, b_waiting = threading.Event(), threading.Event()

    def first() -> None:
        try:
            with db.transaction(immediate=True):
                db.execute("INSERT INTO vault_meta (key, value) VALUES ('a', '1')")
                inside.set()
                b_waiting.wait(5)
                time.sleep(0.3)
                raise RuntimeError("undo a")
        except RuntimeError:
            pass

    def second() -> None:
        inside.wait(5)
        b_waiting.set()
        with db.transaction():
            db.execute("INSERT INTO vault_meta (key, value) VALUES ('b', '1')")

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    try:
        assert db.get_meta("a") is None
        assert db.get_meta("b") == "1", "the second thread's write was undone with the first's"
    finally:
        db.close()
