"""Review c78fd19 R13-10: grant_folder_access wrote before it checked identity.

The envelope (sealed with this process's keypair) and its push mark were
written, and only the audit record after them checked that the vault was
still bound to this process's identity and key epoch. A GUI left unlocked
while the CLI changed the password or rebound the account then reported the
grant as failed, yet the envelope was in the vault and went with the next
push. The check now comes first, in the transaction of the write.
"""

from __future__ import annotations

import os

import pytest

from sezam.models import new_ulid
from sezam.vault import outbox
from sezam.vault.crud import Vault
from sezam.vault.db import VaultChangedElsewhere, VaultDB
from tests.test_ai_r1_snapshots import MASTER, _make_vault

TABLES = ("access_envelopes", "outbox", "audit_log")


def _snapshot(vault) -> dict:
    return {t: [dict(r) for r in vault.db.fetchall(f"SELECT * FROM {t}")] for t in TABLES}


def _two_processes(tmp_path):
    path = tmp_path / "v"
    _make_vault(path).lock()
    cli_process = Vault(path)
    cli_process.unlock(MASTER)
    gui = Vault(path)
    gui.unlock(MASTER)
    folder = gui.create_node("Shared")
    return path, cli_process, gui, folder


def _grant(gui, folder):
    return gui.grant_folder_access(folder, new_ulid(), os.urandom(32), "write")


def test_no_envelope_after_the_password_changed_elsewhere(tmp_path):
    _path, cli_process, gui, folder = _two_processes(tmp_path)
    try:
        cli_process.change_password(MASTER, MASTER + "-new")
        before = _snapshot(cli_process)
        with pytest.raises(VaultChangedElsewhere):
            _grant(gui, folder)
        assert _snapshot(cli_process) == before  # before: the envelope and its push mark
    finally:
        gui.lock()
        cli_process.lock()


def test_no_envelope_after_a_rebind_elsewhere(tmp_path):
    path, cli_process, gui, folder = _two_processes(tmp_path)
    try:
        other = VaultDB(path / "sezam.db", hold_in_use=False)
        other.open()
        try:
            other.set_meta("user_id", new_ulid())  # another process binds the vault elsewhere
        finally:
            other.close()
        before = _snapshot(cli_process)
        with pytest.raises(VaultChangedElsewhere):  # IdentityChangedElsewhere or its base
            _grant(gui, folder)
        assert _snapshot(cli_process) == before
    finally:
        gui.lock()
        cli_process.lock()


def test_a_current_process_still_grants(tmp_path):
    _path, cli_process, gui, folder = _two_processes(tmp_path)
    try:
        envelope_id = _grant(gui, folder)
        assert cli_process.db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (envelope_id,))
        assert outbox.has_write(cli_process.db, folder)
        assert cli_process.db.fetchone("SELECT 1 FROM audit_log WHERE action = 'grant'")
    finally:
        gui.lock()
        cli_process.lock()
