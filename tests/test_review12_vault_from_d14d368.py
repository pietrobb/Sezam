"""Review 782dde8 R12 #1: a vault the public release d14d368 wrote must unlock.

The fixture is a real vault of d14d368 (tests/fixtures/make_vault_d14d368.py),
not one assembled by hand: its triggers still read is_dirty and the
object_base_* tables, which the sync redesign dropped, so the upgrade failed
with "no such column: NEW.is_dirty" and no vault of the public release opened.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from sezam.vault import outbox
from sezam.vault.crud import Vault

FIXTURE = Path(__file__).parent / "fixtures" / "vault_d14d368"


def _copy(tmp_path) -> tuple[Path, dict]:
    path = tmp_path / "laptop"
    shutil.copytree(FIXTURE, path)
    (path / "expected.json").unlink()
    return path, json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))


def _object_names(db) -> set[str]:
    return {
        r["name"]
        for r in db.fetchall("SELECT name FROM sqlite_master WHERE type IN ('table', 'trigger')")
    }


def test_the_fixture_is_a_vault_of_the_public_release():
    import sqlite3

    conn = sqlite3.connect(FIXTURE / "sezam.db")
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    finally:
        conn.close()
    assert {"nodes_base_insert", "entries_base_clean", "base_hash_reset", "object_base_hash"} <= names


def test_a_vault_of_the_public_release_unlocks_and_keeps_its_unsent_changes(tmp_path):
    path, expected = _copy(tmp_path)
    vault = Vault(path)
    vault.unlock(expected["password"])
    try:
        db = vault.db
        names = _object_names(db)
        for gone in (
            "nodes_base_insert", "nodes_base_clean", "entries_base_insert",
            "entries_base_clean", "base_hash_reset", "object_base_version", "object_base_hash",
        ):
            assert gone not in names, gone
        for table in ("nodes", "entries"):
            columns = {r["name"] for r in db.fetchall(f"PRAGMA table_info({table})")}
            assert "is_dirty" not in columns

        # The unsent changes wait in the outbox, each on the server copy it was made on.
        assert sorted(
            r["object_id"] for r in db.fetchall("SELECT object_id FROM outbox WHERE kind = 'write'")
        ) == expected["dirty"]
        for object_id in expected["dirty"]:
            table = "entries" if object_id == expected["entry"] else "nodes"
            row = db.fetchone(f"SELECT base_version, base_hash FROM {table} WHERE id = ?", (object_id,))
            assert [row["base_version"], row["base_hash"]] == expected["base"][object_id], object_id
        assert not outbox.has_write(db, expected["servers"])

        # The data reads, and the vault still works: edit, delete.
        assert vault.get_field_value(expected["entry"], "password") == "v2 unsent"
        vault.update_entry(expected["entry"], fields=[{"key": "password", "value": "v3"}])
        row = db.fetchone("SELECT base_version, base_hash FROM entries WHERE id = ?", (expected["entry"],))
        assert [row["base_version"], row["base_hash"]] == expected["base"][expected["entry"]]
        vault.create_entry(expected["servers"], "db02", [{"key": "password", "value": "x"}])
        vault.delete_node(expected["fresh"])
    finally:
        vault.lock()

    # And it opens again.
    vault = Vault(path)
    vault.unlock(expected["password"])
    vault.lock()
