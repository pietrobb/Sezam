"""Review 18c300f R16-M3 (regression of 3e17d5f, goal #451).

3e17d5f made every write of a VaultDB take the vault lock (INV-6). A push
already held that lock from start to end, so it now held every other
process's writes through all its network requests: while a push waited for
the server, 'sezam list' in another process waited too (28 s instead of 1 s),
and after 120 s it ended in VaultBusy as a raw traceback.

The lock is two locks now. The sync lock orders the operations that read,
send and rewrite the account's sync state (push, pull, key changes, team
log); the write lock orders single writes and read-then-write edits. A
thread holding the sync lock gives the write lock up while it waits for the
server (outside a transaction) and takes it back after. VaultBusy is shown as
an error message.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import urllib.request

from sezam import cli
from sezam.vault import oplock
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review6_vault_oplock import _hold_in_another_process

CLI = r"""
import sys, types
from pathlib import Path
sys.modules["keyring"] = types.SimpleNamespace(
    set_password=lambda *a: None, get_password=lambda *a: None, delete_password=lambda *a: None)
from sezam.vault import oplock
oplock.DEFAULT_TIMEOUT = float(sys.argv[1])
from sezam import cli
cli._attempt_tracker_path = lambda: Path(sys.argv[2]) / "attempts.json"
cli.main(sys.argv[3:])
"""


def _sezam(vault_dir, timeout: float, *args) -> tuple[subprocess.CompletedProcess, float]:
    """'sezam <args>' in its own process."""
    env = {**os.environ, "SEZAM_VAULT": str(vault_dir), "PYTHONIOENCODING": "utf-8"}
    started = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-c", CLI, str(timeout), str(vault_dir), *args],
        input=f"{PASSWORD}\n", capture_output=True, text=True, encoding="utf-8", env=env, timeout=120,
    )
    return done, time.monotonic() - started


def test_another_process_reads_and_writes_while_a_push_waits_for_the_server(
    server, tmp_path, monkeypatch,  # noqa: F811
):
    url, _ = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    client = _client(laptop, url)
    laptop.create_node("sent by the push")

    sent, answer = threading.Event(), threading.Event()
    real = urllib.request.urlopen

    def slow_server(req, *args, **kwargs):
        if req.get_method() == "POST" and req.full_url.endswith("/api/sync"):
            sent.set()
            answer.wait(60)
        return real(req, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", slow_server)
    pushed: dict = {}
    pusher = threading.Thread(target=lambda: pushed.update(client.push()))
    pusher.start()
    try:
        assert sent.wait(60)
        listed, took = _sezam(tmp_path / "laptop", 10, "list")
        made, _ = _sezam(tmp_path / "laptop", 10, "set", "sent by the push/meanwhile", "-f", "user", "-v", "bob")
    finally:
        answer.set()
        pusher.join(60)
    # Red on 18c300f: both waited for the push and gave up (VaultBusy).
    assert listed.returncode == 0, listed.stderr
    assert "sent by the push" in listed.stdout
    assert took < 9, took
    assert made.returncode == 0, made.stderr
    assert {acc["id"] for acc in pushed["accepted"]}
    # The entry made meanwhile is still queued and goes with the next push.
    folder = next(n["id"] for n in laptop.list_nodes() if n["name"] == "sent by the push")
    made_id = next(e["id"] for e in laptop.list_entries(folder) if e["name"] == "meanwhile")
    assert made_id in {acc["id"] for acc in client.push()["accepted"]}


def test_a_busy_vault_is_an_error_message_not_a_traceback(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    vault.lock()
    holder = _hold_in_another_process(vault.db.path, 8.0)
    try:
        done, _ = _sezam(tmp_path / "laptop", 0.5, "list")
    finally:
        holder.wait(20)
    assert done.returncode == 1
    assert "Traceback" not in done.stderr, done.stderr
    assert "Error: Another Sezam program is syncing" in done.stderr, done.stderr


def test_a_sync_holder_gives_the_write_lock_up_only_outside_a_transaction(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    try:
        path = vault.db.path
        with oplock.exclusive(path):
            assert oplock.held_here(path)
            with oplock.network(vault.db):
                assert not oplock.held_here(path)
                assert oplock.holds_sync(path)
            assert oplock.held_here(path)
            with vault.db.transaction():
                with oplock.network(vault.db):
                    assert oplock.held_here(path)
        with oplock.exclusive(path, implicit=True):  # a write alone keeps it
            with oplock.network(vault.db):
                assert oplock.held_here(path)
    finally:
        vault.lock()


def test_a_write_holder_does_not_wait_for_a_sync_holder_waiting_for_the_server(tmp_path):
    """Lock order: sync before write. A thread holding the write lock alone
    that waited for the sync lock would wait for a sync holder that waits
    for the write lock after its request (a deadlock until the timeout)."""
    vault = _vault(tmp_path / "laptop", "admin")
    path = vault.db.path
    requesting, answered = threading.Event(), threading.Event()

    def push():
        with oplock.exclusive(path), oplock.network(vault.db):
            requesting.set()
            answered.wait(30)

    pusher = threading.Thread(target=push)
    pusher.start()
    try:
        assert requesting.wait(30)
        started = time.monotonic()
        with oplock.exclusive(path, implicit=True):
            vault.db.set_meta("r16_m3_probe", "1")  # a write goes on meanwhile
            try:
                with oplock.exclusive(path):
                    raise AssertionError("took the sync lock a request holds")
            except oplock.VaultBusy:
                pass
        assert time.monotonic() - started < 5
    finally:
        answered.set()
        pusher.join(30)
        vault.lock()
