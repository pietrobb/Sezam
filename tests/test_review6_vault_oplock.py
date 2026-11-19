"""Review main@d615826 H4: nothing ordered sync and key changes across processes.

A push, pull or full resync in the GUI or 'mcp-serve' ran at the same time as
a password change or a re-key in a CLI command. Both now hold one exclusive
lock (``sezam.db.sync``); a second process waits for it or gets VaultBusy.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time

import pytest

from sezam.vault import oplock
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS

PASSWORD = "oplock-master-password"

HOLDER = r"""
import sys, time
from sezam.vault import oplock
with oplock.exclusive(sys.argv[1], timeout=5):
    print("held", flush=True)
    time.sleep(float(sys.argv[2]))
"""


def _hold_in_another_process(db_path, seconds: float) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(db_path), str(seconds)],
        stdout=subprocess.PIPE, text=True,
    )
    assert proc.stdout.readline().strip() == "held"
    return proc


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def test_a_key_change_waits_for_another_process_and_then_runs(vault):
    proc = _hold_in_another_process(vault.db.path, 1.0)
    try:
        started = time.monotonic()
        vault.change_password(PASSWORD, "oplock-new-password")
        assert time.monotonic() - started >= 0.5
    finally:
        proc.wait(10)


def test_a_key_change_gives_up_while_another_process_holds_it(vault, monkeypatch):
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            with oplock.exclusive(vault.db.path, timeout=0.3):
                pass
        with pytest.raises(oplock.VaultBusy):
            vault.change_password(PASSWORD, "oplock-new-password")
    finally:
        proc.wait(10)
    vault.change_password(PASSWORD, "oplock-new-password")


@pytest.mark.parametrize("op", ["push", "pull", "full_resync"])
def test_sync_waits_for_another_process_before_touching_anything(vault, monkeypatch, op):
    from sezam.vault import rekey_abandon
    from sezam.vault.sync_client import SyncClient

    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    client = SyncClient(vault.db, "http://127.0.0.1:9", None, "nobody")
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            getattr(client, op)()
        with pytest.raises(oplock.VaultBusy):
            rekey_abandon.abandon_pending_rekey(client)
    finally:
        proc.wait(10)


def _key_state(vault_dir):
    db = Vault(vault_dir).db
    db.open()
    try:
        return db.get_meta("key_epoch"), db.get_meta("argon2_salt")
    finally:
        db.close()


def test_shamir_recovery_waits_for_another_process(tmp_path, monkeypatch):
    """Capability review run 144: org_recovery re-wraps every DEK and raises
    key_epoch, yet never took the lock, so it ran right through a push."""
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    shares = vault.setup_org_recovery(2, 3)[:2]
    vault.lock()
    before = _key_state(tmp_path)
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            Vault(tmp_path).org_recovery(shares, "oplock-new-password")
        assert _key_state(tmp_path) == before
    finally:
        proc.wait(10)
    Vault(tmp_path).org_recovery(shares, "oplock-new-password")
    assert _key_state(tmp_path) != before


def test_adopting_an_account_kek_waits_for_another_process(vault, monkeypatch):
    """Run 144: adopt_account_kek (CLI, GUI connect dialog) re-wraps the local
    DEKs outside any SyncClient method that holds the lock."""
    import os

    before = _key_state(vault.db.path.parent)
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 0.3)
    proc = _hold_in_another_process(vault.db.path, 3.0)
    try:
        with pytest.raises(oplock.VaultBusy):
            vault.adopt_account_kek(os.urandom(32), os.urandom(16), FAST_PARAMS, key_epoch=5)
    finally:
        proc.wait(10)
    assert _key_state(vault.db.path.parent) == before


def test_nested_holds_in_one_thread_and_threads_take_turns(vault):
    path = vault.db.path
    order = []
    with oplock.exclusive(path):
        with oplock.exclusive(path):  # a push inside a re-key
            order.append("outer")

            def other():
                with oplock.exclusive(path):
                    order.append("thread")

            t = threading.Thread(target=other)
            t.start()
            time.sleep(0.2)
            order.append("still outer")
    t.join(5)
    assert order == ["outer", "still outer", "thread"]
