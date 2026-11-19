"""Review 526419e N3: a backup could be made but not restored, and a vault of
a newer schema was opened (and written) as if this Sezam understood it.

'sezam export --format backup' wrote a vault copy, but no command put it back
(only snapshots from <vault>/snapshots could be restored). 'sezam restore
FILE' now does it the way 'sezam snapshot restore' does. Opening a vault, or
restoring a backup, of a newer schema version is refused before anything is
written.
"""

from __future__ import annotations

import hashlib
import sqlite3

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault import snapshots
from sezam.vault.crud import Vault
from tests.test_ai_r2_snapshot_cli import _names, _with_vault, sent, vault_dir  # noqa: F401
from tests.test_ai_r1_snapshots import MASTER


def _backup(vault_dir, dest):
    result = CliRunner().invoke(cli.main, ["export", str(dest), "--format", "backup"])
    assert result.exit_code == 0, result.output


def _add(vault_dir, title):
    _with_vault(vault_dir, lambda v: v.create_entry(
        v.create_node("More"), title, [{"key": "k", "value": "v"}]
    ))


def _restore(path, password=MASTER):
    return CliRunner().invoke(
        cli.main, ["restore", str(path), "--yes"], input=password + "\n"
    )


def _set_schema(db_path, version):
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
            (version,),
        )
        conn.commit()
    finally:
        conn.close()


def test_backup_restores_and_can_be_undone(vault_dir, tmp_path):  # noqa: F811
    backup = tmp_path / "backup.db"
    _backup(vault_dir, backup)
    _add(vault_dir, "later")
    assert _names(vault_dir) == {"web", "later"}

    result = _restore(backup)

    assert result.exit_code == 0, result.output
    assert "Vault restored" in result.output
    assert _names(vault_dir) == {"web"}
    assert [s.reason for s in snapshots.list_snapshots(vault_dir)] == ["pre-restore"]


def test_wrong_password_restores_nothing(vault_dir, tmp_path):  # noqa: F811
    backup = tmp_path / "backup.db"
    _backup(vault_dir, backup)
    _add(vault_dir, "later")

    result = _restore(backup, password="not-the-password")

    assert result.exit_code != 0
    assert _names(vault_dir) == {"web", "later"}


def test_backup_of_newer_schema_is_refused(vault_dir, tmp_path):  # noqa: F811
    backup = tmp_path / "backup.db"
    _backup(vault_dir, backup)
    _set_schema(backup, "99")
    _add(vault_dir, "later")

    result = _restore(backup)

    assert result.exit_code != 0
    assert "schema version 99" in result.output
    assert _names(vault_dir) == {"web", "later"}


def test_vault_of_newer_schema_is_not_opened_or_written(vault_dir):  # noqa: F811
    from sezam.vault.db import VaultSchemaTooNew

    db_path = vault_dir / "sezam.db"
    _set_schema(db_path, "99")
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()

    with pytest.raises(VaultSchemaTooNew):
        Vault(vault_dir).unlock(MASTER)

    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before
    assert not (vault_dir / "sezam.db-wal").exists()
