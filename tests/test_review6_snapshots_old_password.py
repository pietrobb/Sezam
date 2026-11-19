"""Review d615826 (desktop medium): snapshots before a password change opened
with the old password.

A password change leaves the DEKs as they are, so a snapshot from before it
opened with the old (perhaps leaked) password and its keys still decrypted
today's data; up to 20 of them were kept. After the change only the snapshot
the change itself took stays, until the new password has opened the vault.
"""

from __future__ import annotations

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault
from sezam.vault.snapshots import discard_staged, list_snapshots, stage_snapshot, take_snapshot

OLD = "old-password-1"
NEW = "new-password-2"
FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


def _opens_with(vault_dir, name: str, password: str) -> bool:
    staging = stage_snapshot(vault_dir, name)
    try:
        copy = Vault(staging)
        try:
            copy.unlock(password)
        except ValueError:
            return False
        copy.lock()
        return True
    finally:
        discard_staged(staging)


def test_no_snapshot_opens_with_the_old_password_after_the_change(tmp_path):
    vault_dir = tmp_path / "vault"
    vault = Vault.create(str(vault_dir), OLD, FAST)
    folder = vault.create_node("Ops")
    vault.create_entry(folder, "vpn", [{"key": "password", "value": "today", "sensitive": True}])
    for _ in range(3):
        take_snapshot(vault.db, "rekey")
    assert all(_opens_with(vault_dir, s.name, OLD) for s in list_snapshots(vault_dir))

    proof = vault.change_password(OLD, NEW)
    proof[:] = b"\x00" * len(proof)
    left = list_snapshots(vault_dir)
    # Only the change's own snapshot, as a way back from a mistyped password.
    assert [s.reason for s in left] == ["change-password"]
    take_snapshot(vault.db, "rekey")
    vault.lock()

    with pytest.raises(ValueError):
        Vault(vault_dir).unlock(OLD)
    reopened = Vault(vault_dir)
    reopened.unlock(NEW)
    reopened.lock()
    left = list_snapshots(vault_dir)
    assert [s.reason for s in left] == ["rekey"]
    assert not any(_opens_with(vault_dir, s.name, OLD) for s in left)
    assert all(_opens_with(vault_dir, s.name, NEW) for s in left)
