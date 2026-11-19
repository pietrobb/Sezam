"""AI broker TODO P4: a running mcp-serve locks on 'sezam lock' and when idle.

The session watcher of ``mcp-serve`` locks the vault and closes every SSH
session when the CLI session ends, and also after ``--idle-lock-minutes``
without an MCP tool call. A tool call that is still running (an approval
wait, a long command) is never treated as idle.
"""

from __future__ import annotations

import sys
import threading
import time
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.mcp.server import SezamMCPServer
from sezam.vault.crud import Vault

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "p4-master-password"


class _SSH:
    def __init__(self):
        self.closed_all = 0

    def close_all(self):
        self.closed_all += 1


@pytest.fixture
def served(tmp_path, monkeypatch):
    stored: dict = {}
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
    assert CliRunner().invoke(cli.main, ["unlock"], input=PASSWORD + "\n").exit_code == 0

    vault = Vault(Path(tmp_path))
    vault.unlock(PASSWORD)
    server = SezamMCPServer(vault)
    ssh = _SSH()
    server.broker._ssh = ssh
    stops = []

    def watch(idle_limit=None):
        stop = cli._watch_session_and_lock(
            vault,
            server.broker.close,
            interval=0.02,
            idle_seconds=server.idle_seconds,
            idle_limit=idle_limit,
        )
        stops.append(stop)

    yield types.SimpleNamespace(vault=vault, server=server, ssh=ssh, watch=watch)
    for stop in stops:
        stop.set()
    vault.lock()


def _wait_locked(vault, seconds=2.0) -> bool:
    deadline = time.monotonic() + seconds
    while vault.is_unlocked and time.monotonic() < deadline:
        time.sleep(0.02)
    return not vault.is_unlocked


def test_sezam_lock_locks_running_server_and_closes_ssh_sessions(served):
    served.watch(idle_limit=3600)
    time.sleep(0.1)
    assert served.vault.is_unlocked

    started = time.monotonic()
    assert CliRunner().invoke(cli.main, ["lock"]).exit_code == 0

    assert _wait_locked(served.vault)
    assert time.monotonic() - started < 2
    assert served.ssh.closed_all >= 1
    assert served.server.handle_tool_call("vault_list", {})["code"] == "vault_locked"


def test_idle_server_locks_after_idle_limit(served):
    served.watch(idle_limit=0.3)

    assert _wait_locked(served.vault)
    assert served.ssh.closed_all >= 1


def test_tool_calls_keep_the_server_unlocked(served):
    served.watch(idle_limit=0.3)
    deadline = time.monotonic() + 0.9
    while time.monotonic() < deadline:
        served.server.handle_tool_call("vault_list", {})
        time.sleep(0.05)
    assert served.vault.is_unlocked

    assert _wait_locked(served.vault)


def test_running_tool_call_is_never_idle(served, monkeypatch):
    release = threading.Event()

    def slow_list(path=""):
        release.wait(5)
        return {"nodes": [], "entries": []}

    monkeypatch.setattr(served.server.broker, "vault_list", slow_list)
    caller = threading.Thread(target=served.server.handle_tool_call, args=("vault_list", {}))
    caller.start()
    time.sleep(0.05)
    served.watch(idle_limit=0.2)

    time.sleep(0.6)
    assert served.vault.is_unlocked
    release.set()
    caller.join(5)

    assert _wait_locked(served.vault)


def test_idle_lock_minutes_option_is_bounded():
    result = CliRunner().invoke(cli.main, ["mcp-serve", "--idle-lock-minutes", "0"])
    assert result.exit_code != 0
    assert "idle-lock-minutes" in result.output
