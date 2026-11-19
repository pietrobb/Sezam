"""Review 1141a20 (R9-E, goal #361): audit generation check and record were two steps.

`_audit_log` checked the vault's identity and generation, then wrote the
record outside any transaction. Another process rebinding the vault (account
id, keys, password) in between got the record signed under the dead id; the
server refuses such records and the vault's pushes stuck on them. Now the
check and the record are one write transaction: a rebind waits for it, or
the record is refused.
"""

from __future__ import annotations

import threading

from sezam.models import new_ulid
from sezam.vault.crud import Vault
from sezam.vault.db import VaultDB
from tests.test_ai_r1_snapshots import MASTER, _make_vault


def test_a_rebind_never_lands_between_the_check_and_the_audit_record(tmp_path):
    path = tmp_path / "v"
    _make_vault(path).lock()
    vault = Vault(path)
    vault.unlock(MASTER)
    old_id = vault.db.get_meta("user_id")
    state = {"landed": False, "landed_before_record": None}

    def rebind():
        other = VaultDB(path / "sezam.db", hold_in_use=False)
        other.open()
        try:
            other.set_meta("user_id", new_ulid())  # another process binds the vault elsewhere
            state["landed"] = True
        except Exception as exc:  # locked out for longer than busy_timeout
            state["error"] = exc
        finally:
            other.close()

    original = vault._append_audit

    def racing_append(action, detail, *, strict=False):
        thread = threading.Thread(target=rebind)
        thread.start()
        thread.join(1.0)
        state["landed_before_record"] = state["landed"]
        original(action, detail, strict=strict)
        state["thread"] = thread

    vault._append_audit = racing_append
    try:
        vault._audit_log("read", strict=True)
        state["thread"].join(10)
        written = vault.db.fetchall("SELECT actor_id FROM audit_log WHERE action = 'read'")
        assert written and written[-1]["actor_id"] == old_id
        # The record was written before the rebind, never after it under the dead id.
        assert state["landed_before_record"] is False
    finally:
        vault._append_audit = original
        vault.lock()


def test_a_stale_process_writes_nothing_once_the_password_changed_elsewhere(tmp_path):
    """State machine seed 737373: the GUI stayed unlocked while the CLI changed
    the password; its new entry landed, then its audit record was refused, and
    the write was reported as failed."""
    import pytest

    from sezam.vault.db import VaultChangedElsewhere

    path = tmp_path / "v"
    _make_vault(path).lock()
    cli_process = Vault(path)
    cli_process.unlock(MASTER)
    gui = Vault(path)
    gui.unlock(MASTER)
    folder = gui.create_node("F")
    entry = gui.create_entry(folder, "E", [{"key": "password", "value": "p"}])
    cli_process.change_password(MASTER, MASTER + "-new")
    tables = ("nodes", "entries", "deks", "entry_history", "audit_log")
    before = {t: [dict(r) for r in cli_process.db.fetchall(f"SELECT * FROM {t}")] for t in tables}
    writes = {
        "create_entry": lambda: gui.create_entry(folder, "E2", [{"key": "password", "value": "q"}]),
        "update_entry": lambda: gui.update_entry(entry, name="E3"),
        "create_node": lambda: gui.create_node("F2", parent_id=folder),
        "rename_node": lambda: gui.rename_node(folder, "F3"),
        "delete_entry": lambda: gui.delete_entry(entry),
    }
    try:
        for name, write in writes.items():
            with pytest.raises(VaultChangedElsewhere):
                write()
            after = {t: [dict(r) for r in cli_process.db.fetchall(f"SELECT * FROM {t}")] for t in tables}
            assert after == before, name
    finally:
        gui.lock()
        cli_process.lock()
