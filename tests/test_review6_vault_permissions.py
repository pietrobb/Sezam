"""Review d615826: the vault directory and sezam.db are owner-only (POSIX).

They used to be created with the umask (usually 022), so any local user could
copy the wrapped keys and guess the password offline.
"""

from __future__ import annotations

import os
import stat

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")

PASSWORD = "perm-password-1"
FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _db_files(vault_dir):
    return [p for p in vault_dir.iterdir() if p.name in ("sezam.db", "sezam.db-wal", "sezam.db-shm")]


@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def test_new_vault_is_owner_only(tmp_path, umask_022):
    vault_dir = tmp_path / "vault"
    vault = Vault.create(str(vault_dir), PASSWORD, FAST)
    vault.create_node("Ops")
    try:
        assert _mode(vault_dir) == 0o700
        files = _db_files(vault_dir)
        assert any(p.name == "sezam.db" for p in files)
        for path in files:
            assert _mode(path) == 0o600, path.name
    finally:
        vault.lock()


def test_existing_world_readable_vault_is_tightened_on_open(tmp_path, umask_022):
    vault_dir = tmp_path / "vault"
    Vault.create(str(vault_dir), PASSWORD, FAST).lock()
    vault_dir.chmod(0o755)
    for path in _db_files(vault_dir):
        path.chmod(0o644)

    vault = Vault(vault_dir)
    vault.unlock(PASSWORD)
    try:
        assert _mode(vault_dir) == 0o700
        for path in _db_files(vault_dir):
            assert _mode(path) == 0o600, path.name
    finally:
        vault.lock()
