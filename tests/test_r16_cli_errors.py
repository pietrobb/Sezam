"""Review 18c300f R16-L7: raw tracebacks.

1. An unreachable sync server: push, pull, share-list, revoke-user,
   change-password, provision-device, share-revoke, org-recovery-setup and
   rotate-identity ended in a urllib URLError traceback (rotate-identity even
   without a server call: it read vault_meta before the unlock).
2. Back on d14d368 (the public release): the outbox schema dropped is_dirty
   but kept schema_version 1, so d14d368 passed its own schema check and died
   on its is_dirty triggers (sqlite3.OperationalError: no such column:
   is_dirty). The outbox schema is version 2 now; d14d368 refuses it with
   "Update Sezam to open it; nothing was changed". A vault newer than this
   Sezam is a message here, not a traceback.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys

import pytest

from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.schema import SCHEMA_VERSION
from tests.test_integration_client_server import PASSWORD, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_r16_push_lock_network import CLI
from tests.test_review12_vault_from_d14d368 import _copy

DEAD = "http://127.0.0.1:9"


def _sezam(vault_dir, *args) -> subprocess.CompletedProcess:
    env = {**os.environ, "SEZAM_VAULT": str(vault_dir), "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, "-c", CLI, "10", str(vault_dir), *args],
        input=f"{PASSWORD}\n" * 6, capture_output=True, text=True, encoding="utf-8",
        env=env, timeout=120,
    )


def _schema(db_path) -> str | None:
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute("SELECT value FROM vault_meta WHERE key = 'schema_version'").fetchone()
    finally:
        conn.close()
    return None if row is None else row[0]


def _set_schema(db_path, value: str) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?)", (value,))
        conn.commit()
    finally:
        conn.close()


def _d14d368_opens(value: str | None) -> bool:
    """d14d368's check_vault_schema (its SCHEMA_VERSION is 1)."""
    try:
        version = int(value) if value else 1
    except ValueError:
        return False
    return version <= 1


@pytest.fixture
def offline(server, tmp_path):  # noqa: F811
    """A vault connected to a server that then cannot be reached."""
    url, _ = server
    vault = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    vault.db.set_meta("server_url", DEAD)
    vault.lock()
    return tmp_path / "laptop"


@pytest.mark.parametrize("args", [
    ("push",), ("pull",), ("share-list",), ("revoke-user", "bob"), ("change-password",),
    ("rotate-identity",), ("org-recovery-setup",),
])
def test_an_unreachable_server_is_a_message(offline, args):
    done = _sezam(offline, *args)
    assert done.returncode != 0
    assert "Traceback" not in done.stderr, done.stderr
    assert "could not be reached" in done.stderr, done.stderr


def test_rotate_identity_without_a_server_is_a_message(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    vault.lock()
    done = _sezam(tmp_path / "laptop", "rotate-identity")
    assert "Traceback" not in done.stderr, done.stderr
    assert "used only with a server" in done.stderr


def test_a_new_vault_is_one_d14d368_refuses(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    vault.lock()
    assert _schema(tmp_path / "laptop" / "sezam.db") == str(SCHEMA_VERSION)
    assert not _d14d368_opens(_schema(tmp_path / "laptop" / "sezam.db"))


def test_a_vault_of_the_outbox_schema_marked_1_is_marked_2(tmp_path):
    """A vault 782dde8 (or 18c300f) made or upgraded: outbox schema, version 1."""
    vault = _vault(tmp_path / "laptop", "admin")
    vault.create_node("kept")
    vault.lock()
    db_path = tmp_path / "laptop" / "sezam.db"
    _set_schema(db_path, "1")
    vault = Vault(tmp_path / "laptop")
    vault.unlock(PASSWORD)
    assert [n["name"] for n in vault.list_nodes()] == ["kept"]
    vault.lock()
    assert _schema(db_path) == "2"
    assert not _d14d368_opens(_schema(db_path))


def test_a_vault_of_d14d368_upgraded_is_one_d14d368_refuses(tmp_path):
    path, expected = _copy(tmp_path)
    assert _d14d368_opens(_schema(path / "sezam.db"))
    vault = Vault(path)
    vault.unlock(expected["password"])
    vault.lock()
    assert not _d14d368_opens(_schema(path / "sezam.db"))


def test_a_vault_newer_than_this_sezam_is_a_message(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    vault.lock()
    _set_schema(tmp_path / "laptop" / "sezam.db", str(SCHEMA_VERSION + 1))
    done = _sezam(tmp_path / "laptop", "list")
    assert done.returncode != 0
    assert "Traceback" not in done.stderr, done.stderr
    assert "Update Sezam to open it" in done.stderr
