"""AI broker TODO P5: mcp-serve never reads the password and follows the session.

Without a CLI session the MCP server runs locked (every tool call answers
vault_locked); a later 'sezam unlock' unlocks it, 'sezam lock' locks it, and
after an idle lock only a *new* session unlocks it again. The KEK comes only
from the OS-keyring session, never from stdin.
"""

from __future__ import annotations

import sys
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
PASSWORD = "p5-master-password"


@pytest.fixture
def env(tmp_path, monkeypatch):
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
    vault = Vault(Path(tmp_path))
    server = SezamMCPServer(vault)
    stops = []
    idle = {"limit": None}

    def watch():
        stop = cli._watch_session_and_lock(
            vault,
            server.broker.close,
            interval=0.02,
            idle_seconds=server.idle_seconds,
            idle_limit=None,
            on_unlock=server.mark_active,
        )
        stops.append(stop)

    yield types.SimpleNamespace(
        vault=vault, server=server, watch=watch, idle=idle, stored=stored, path=tmp_path
    )
    for stop in stops:
        stop.set()
    vault.lock()


def _unlock_cli() -> None:
    assert CliRunner().invoke(cli.main, ["unlock"], input=PASSWORD + "\n").exit_code == 0


def _until(predicate, seconds=2.0) -> bool:
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.02)
    return predicate()


def _code(server) -> str:
    return server.handle_tool_call("vault_list", {}).get("code", "ok")


def test_server_starts_locked_and_unlocks_on_sezam_unlock(env):
    env.watch()
    assert not env.vault.is_unlocked
    assert _code(env.server) == "vault_locked"

    _unlock_cli()
    assert _until(lambda: env.vault.is_unlocked)
    assert _code(env.server) == "ok"

    assert CliRunner().invoke(cli.main, ["lock"]).exit_code == 0
    assert _until(lambda: not env.vault.is_unlocked)
    assert _code(env.server) == "vault_locked"

    _unlock_cli()
    assert _until(lambda: env.vault.is_unlocked)


def test_existing_session_unlocks_immediately(env):
    _unlock_cli()
    env.watch()
    assert env.vault.is_unlocked


def test_idle_lock_needs_a_new_session(env, monkeypatch):
    _unlock_cli()
    stop = cli._watch_session_and_lock(
        env.vault,
        env.server.broker.close,
        interval=0.02,
        idle_seconds=env.server.idle_seconds,
        idle_limit=0.2,
        on_unlock=env.server.mark_active,
    )
    try:
        assert env.vault.is_unlocked
        assert _until(lambda: not env.vault.is_unlocked)
        # The same (still valid) session must not unlock it again.
        time.sleep(0.2)
        assert not env.vault.is_unlocked

        time.sleep(0.01)  # new session -> new expiry
        _unlock_cli()
        assert _until(lambda: env.vault.is_unlocked)
    finally:
        stop.set()


def test_stale_session_is_cleared_and_server_stays_locked(env):
    record = {
        "v": 2,
        "kek": "00" * 32,
        "expires_at": time.time() + 600,
        "vault": str(Path(env.path).resolve()),
    }
    import json

    env.stored[("sezam", "session")] = json.dumps(record)
    (Path(env.path) / ".session").write_text(cli._SESSION_MARKER, encoding="ascii")

    env.watch()

    assert not env.vault.is_unlocked
    assert ("sezam", "session") not in env.stored
    assert _code(env.server) == "vault_locked"
