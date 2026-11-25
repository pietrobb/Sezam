"""Review 7c10379 (AI broker, medium): two brokers turning AI off at once - 'database is locked'.

disable() read the switch and then wrote it inside a deferred transaction.
When another broker (another process on the same vault) committed its own
'off' in between, SQLite refused the upgrade to a write at once
(SQLITE_BUSY_SNAPSHOT, which busy_timeout does not retry), so the brake
failed to persist. disable() now takes the write lock before reading.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import traceback

import pytest

from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS

PASSWORD = "r7-two-brokers"


@pytest.fixture
def vaults(tmp_path):
    first = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    second = Vault(tmp_path)  # another process: locked, short-lived connections
    yield first, second
    first.lock()


def test_a_second_ai_off_in_the_middle_of_the_first_does_not_fail(vaults, monkeypatch):
    first, second = vaults
    real_parse = ai_access._parse
    errors: list = []
    other = threading.Thread(target=lambda: _disable(second, errors))

    def parse_then_let_the_other_broker_run(enabled, epoch):
        # Between the first broker's read and its write, the second one
        # tries its own 'off' (it commits at once unless the first holds
        # the write lock, in which case it waits for it).
        if threading.current_thread() is threading.main_thread() and not other.is_alive() and not errors:
            if other.ident is None:
                other.start()
                other.join(0.5)
        return real_parse(enabled, epoch)

    monkeypatch.setattr(ai_access, "_parse", parse_then_let_the_other_broker_run)

    state = ai_access.disable(first, "cli")
    other.join(15)

    assert not other.is_alive()
    assert errors == []
    assert not state.enabled
    final = ai_access.read_state(first)
    assert not final.enabled and final.epoch == 2  # both offs counted
    # The locked broker's audit record waits for the next unlock, not lost.
    assert [r["detail"]["source"] for r in ai_access._pending(first.db)] == ["phone"]


@pytest.mark.parametrize("which", ["unlocked", "locked"])
def test_ai_off_waits_out_a_writer_holding_the_lock_past_the_busy_timeout(vaults, which):
    """R16-N7 (gate 28 on 590b00c): under load the second broker's 'off'
    failed with 'database is locked'. Another process's writer holding its
    transaction past the 5 s busy timeout failed the brake the same way."""
    first, second = vaults
    vault = first if which == "unlocked" else second
    held = threading.Event()

    def hold_the_write_lock() -> None:
        conn = sqlite3.connect(str(first.db.path), isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            held.set()
            time.sleep(6.5)  # past the 5 s busy_timeout of open()
            conn.execute("COMMIT")
        finally:
            conn.close()

    holder = threading.Thread(target=hold_the_write_lock)
    holder.start()
    assert held.wait(10)
    try:
        state = ai_access.disable(vault, "cli")
    finally:
        holder.join(30)

    assert not state.enabled and state.epoch == 1
    assert ai_access.read_state(first) == state
    # Statements other than the brake keep the ordinary wait.
    assert first.db.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def _disable(vault, errors: list) -> None:
    try:
        ai_access.disable(vault, "phone")
    except Exception as exc:  # pragma: no cover - the failure being tested
        errors.append((exc, traceback.format_exc()))
