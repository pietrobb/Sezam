"""Review e443cbc R15 (goal #438 item 6): a write sealed or signed by this
process is made only while the vault is still bound to its identity.

R13-10 (0b50217) put the identity check into grant_folder_access. Its sibling,
the folder re-key after a member is removed, signs its audit record through
AuditLog.append directly and never checked: a GUI left unlocked while another
process rebound the vault re-keyed every folder of the member, sealed the new
keys with the dead keypair and signed the batch under the dead id. The server
refuses that record ('Invalid audit signature') and every push of the vault
sticks on it. The check now sits in AuditLog.append, which every signed audit
record goes through, inside the write transaction of the record.
"""

from __future__ import annotations

import os

import pytest

from sezam.models import new_ulid
from sezam.vault.audit import AuditLog
from sezam.vault.db import VaultChangedElsewhere, VaultDB
from sezam.vault.crud import Vault
from tests.test_ai_r1_snapshots import MASTER, _make_vault

TABLES = (
    "access_envelopes", "outbox", "audit_log", "deks", "dek_archive", "nodes", "vault_meta",
)


def _snapshot(vault) -> dict:
    return {t: [dict(r) for r in vault.db.fetchall(f"SELECT * FROM {t}")] for t in TABLES}


def _member_folder(tmp_path):
    path = tmp_path / "v"
    _make_vault(path).lock()
    cli_process = Vault(path)
    cli_process.unlock(MASTER)
    gui = Vault(path)
    gui.unlock(MASTER)
    folder = gui.create_node("Shared")
    member = new_ulid()
    gui.grant_folder_access(folder, member, os.urandom(32), "write")
    return path, cli_process, gui, member


def _rebind_elsewhere(path) -> None:
    other = VaultDB(path / "sezam.db", hold_in_use=False)
    other.open()
    try:
        other.set_meta("user_id", new_ulid())
    finally:
        other.close()


def test_no_rekey_after_a_rebind_elsewhere(tmp_path):
    path, cli_process, gui, member = _member_folder(tmp_path)
    try:
        _rebind_elsewhere(path)
        before = _snapshot(cli_process)
        with pytest.raises(VaultChangedElsewhere):  # IdentityChangedElsewhere
            gui.rekey_after_revocation(member)
        assert _snapshot(cli_process) == before  # e443cbc: new key + audit under the dead id
    finally:
        gui.lock()
        cli_process.lock()


def test_no_withdrawal_after_a_rebind_elsewhere(tmp_path):
    """The member's envelope on a key no folder uses any more (SM32): the
    re-key creates no key, only withdraws it and signs the batch."""
    path = tmp_path / "v"
    _make_vault(path).lock()
    cli_process = Vault(path)
    cli_process.unlock(MASTER)
    gui = Vault(path)
    gui.unlock(MASTER)
    try:
        member = new_ulid()
        dek_id = gui.db.fetchone("SELECT id FROM deks WHERE scope = 'audit'")["id"]
        gui.db.execute(
            "INSERT INTO access_envelopes "
            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) VALUES (?, ?, ?, ?, ?, ?)",
            (new_ulid(), dek_id, member, gui._user_id, "read", os.urandom(72)),
        )
        _rebind_elsewhere(path)
        before = _snapshot(cli_process)
        with pytest.raises(VaultChangedElsewhere):
            gui.rekey_after_revocation(member)
        assert _snapshot(cli_process) == before  # e443cbc: 'rekey' signed under the dead id
    finally:
        gui.lock()
        cli_process.lock()


def test_no_audit_record_under_another_identity(tmp_path):
    path, cli_process, gui, _member = _member_folder(tmp_path)
    try:
        _rebind_elsewhere(path)
        before = _snapshot(cli_process)
        with pytest.raises(VaultChangedElsewhere):
            AuditLog(gui.db).append(
                actor_id=gui._user_id, action="write",
                signing_key=gui.keypair.to_nacl_signing_key(),
            )
        assert _snapshot(cli_process) == before
    finally:
        gui.lock()
        cli_process.lock()


def test_no_rekey_after_the_password_changed_elsewhere(tmp_path):
    _path, cli_process, gui, member = _member_folder(tmp_path)
    try:
        cli_process.change_password(MASTER, MASTER + "-new")
        before = _snapshot(cli_process)
        with pytest.raises(VaultChangedElsewhere):
            gui.rekey_after_revocation(member)
        assert _snapshot(cli_process) == before
    finally:
        gui.lock()
        cli_process.lock()


def test_a_current_process_still_rekeys(tmp_path):
    _path, cli_process, gui, member = _member_folder(tmp_path)
    try:
        assert gui.rekey_after_revocation(member) == 1
        assert cli_process.db.fetchone("SELECT 1 FROM audit_log WHERE action = 'rekey'")
    finally:
        gui.lock()
        cli_process.lock()
