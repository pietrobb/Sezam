"""Regressions for follow-up review main@2052248, desktop medium findings (R-F)."""

from __future__ import annotations

import json

import pytest

from sezam.crypto.aead import BlobKind, decrypt, parse_envelope
from sezam.crypto.kdf import Argon2Params
from sezam.models import bytes_to_ulid, ulid_to_bytes
from sezam.vault.crud import Vault

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "review2-desktop-medium-pw!"


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path / "a", PASSWORD, FAST_PARAMS)
    yield v
    v.lock()


def _entry_dek(vault: Vault, entry_id: str) -> tuple[str | None, str | None, str]:
    row = vault.db.fetchone("SELECT dek_id, encrypted_data FROM entries WHERE id = ?", (entry_id,))
    header = bytes_to_ulid(parse_envelope(bytes(row["encrypted_data"])).dek_id)
    scope = vault.db.fetchone("SELECT scope FROM deks WHERE id = ?", (header,))
    return row["dek_id"], (scope["scope"] if scope else None), header


# ── D5: tier-2 entry keeps its own DEK on edit and move ──

def test_tier2_entry_keeps_own_dek_when_moved(vault):
    a = vault.create_node("A")
    b = vault.create_node("B")
    entry = vault.create_entry(a, "root-pw", [{"key": "password", "value": "s3"}], tier=2)
    dek_before, scope, _ = _entry_dek(vault, entry)
    assert scope == "tier2"

    vault.move_entry(entry, b)

    dek_after, scope, header = _entry_dek(vault, entry)
    assert dek_after == dek_before
    assert header == dek_before
    assert scope == "tier2"
    assert vault.read_entry(entry)["fields"][0]["value"] == "s3"


def test_entry_raised_to_tier2_gets_own_dek(vault):
    folder = vault.create_node("F")
    entry = vault.create_entry(folder, "db", [{"key": "password", "value": "x"}])
    assert _entry_dek(vault, entry)[0] is None

    vault.update_entry(entry, tier=2)

    dek_id, scope, header = _entry_dek(vault, entry)
    assert dek_id is not None and header == dek_id
    assert scope == "tier2"
    assert vault.read_entry(entry)["tier"] == 2


def test_tier2_entry_edit_keeps_own_dek(vault):
    folder = vault.create_node("F")
    entry = vault.create_entry(folder, "db", [{"key": "password", "value": "x"}], tier=2)
    dek_before = _entry_dek(vault, entry)[0]

    vault.update_entry(entry, fields=[{"key": "password", "value": "y"}])

    dek_after, scope, header = _entry_dek(vault, entry)
    assert dek_after == dek_before == header
    assert scope == "tier2"


# ── D8: personal folders are visible to their owner on desktop ──

def test_personal_folder_is_listed_read_and_renamed(vault):
    root = vault.db.get_meta("root_node_id")
    personal = vault.create_personal_folder("Moje")

    assert "Moje" in [n["name"] for n in vault.list_nodes(root)]
    assert vault.read_node(personal)["name"] == "Moje"

    vault.rename_node(personal, "Moje2")
    assert vault.read_node(personal)["name"] == "Moje2"
    # Still under the personal DEK, never the root DEK.
    row = vault.db.fetchone("SELECT dek_id, encrypted_meta FROM nodes WHERE id = ?", (personal,))
    assert bytes_to_ulid(parse_envelope(bytes(row["encrypted_meta"])).dek_id) == row["dek_id"]


def test_personal_folder_meta_carries_web_marker(vault):
    personal = vault.create_personal_folder("Moje")
    row = vault.db.fetchone(
        "SELECT dek_id, encrypted_meta, version FROM nodes WHERE id = ?", (personal,)
    )
    dek = vault.dek_mgr.unlock_dek(row["dek_id"])
    meta = json.loads(decrypt(
        bytes(row["encrypted_meta"]), dek, ulid_to_bytes(personal), row["version"],
        expected_blob_kind=BlobKind.NODE_META,
    ))
    assert meta["personal"] is True


def test_entry_path_and_move_of_personal_root(vault):
    personal = vault.create_personal_folder("Moje")
    other = vault.create_node("Other")
    entry = vault.create_entry(personal, "bank", [{"key": "password", "value": "p"}])
    assert vault._build_node_path(personal) == "Moje"

    vault.move_node(personal, other)

    assert vault.read_node(personal)["name"] == "Moje"
    assert [n["name"] for n in vault.list_nodes(other)] == ["Moje"]
    row = vault.db.fetchone("SELECT dek_id, encrypted_meta FROM nodes WHERE id = ?", (personal,))
    assert bytes_to_ulid(parse_envelope(bytes(row["encrypted_meta"])).dek_id) == row["dek_id"]
    assert vault.read_entry(entry)["fields"][0]["value"] == "p"


# ── rollback_warning reaches the user (CLI and GUI) ──

ROLLBACK = {
    "pulled": 0, "skipped": 0, "max_commit_seq": 9,
    "rollback_warning": "Sync rollback detected: server head commit_seq 3 < local checkpoint 9",
}


def test_cli_pull_shows_rollback_warning(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from sezam import cli
    from sezam.vault.sync_client import SyncClient

    v = Vault.create(tmp_path / "v", PASSWORD, FAST_PARAMS)
    v.db.set_meta("server_url", "https://sync.invalid")
    v.lock()
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "v"))
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(cli, "_clear_session", lambda: None)
    monkeypatch.setattr(SyncClient, "pull", lambda self: dict(ROLLBACK))

    result = CliRunner().invoke(cli.main, ["pull"], input=f"{PASSWORD}\n")
    assert result.exit_code == 0, result.output
    assert "ROLLBACK WARNING" in result.output
    assert "head commit_seq 3 < local checkpoint 9" in result.output


def test_gui_connect_message_carries_rollback_warning():
    pytest.importorskip("PySide6")
    from sezam.gui.server_connect_dialog import _with_pull_warnings

    message = _with_pull_warnings(dict(ROLLBACK), "Pripojeny k serveru.")
    assert message.startswith("ROLLBACK WARNING")
    assert message.endswith("Pripojeny k serveru.")
