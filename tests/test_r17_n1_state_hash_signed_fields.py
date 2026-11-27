"""Review c02cc47 R17-N1: the state hash covers an object's parent and its
deleted flag, not only (id, version, payload).

A server that serves a held version again with another parent or as deleted,
at the same commit_seq, gave a state the checkpoint took as unchanged. The
checkpoint of a vault from before (no ``state_v``) is still compared, by the
formula it was made with, so an upgrade neither fails its first pull nor skips
the comparison.
"""

from __future__ import annotations

import pytest

from sezam.crypto.keys import generate_keypair
from sezam.vault.db import VaultDB
from sezam.models import new_ulid
from sezam.vault.sync_client import SyncClient, SyncRollbackWarning


@pytest.fixture
def vault(tmp_path):
    db = VaultDB(tmp_path / "state_hash.db")
    db.open()
    db.create_schema()
    ids = {name: new_ulid() for name in ("dek", "dek2", "root", "node", "entry", "envelope", "archive")}
    db.execute(
        "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) VALUES (?, NULL, 'root', ?, 1)",
        (ids["dek"], b"dek"),
    )
    db.execute(
        "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
        "VALUES (?, NULL, ?, ?, 1, 0)", (ids["root"], b"root", ids["dek"]),
    )
    db.execute(
        "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
        "VALUES (?, ?, ?, ?, 2, 0)", (ids["node"], ids["root"], b"node", ids["dek"]),
    )
    db.execute(
        "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) VALUES (?, ?, 'folder', ?, 1)",
        (ids["dek2"], ids["node"], b"dek2"),
    )
    db.execute(
        "INSERT INTO entries (id, node_id, encrypted_meta, encrypted_data, dek_id, version, is_deleted) "
        "VALUES (?, ?, ?, ?, ?, 3, 0)", (ids["entry"], ids["node"], b"meta", b"data", ids["dek"]),
    )
    db.execute(
        "INSERT INTO access_envelopes (id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)", (ids["envelope"], ids["dek"], new_ulid(), new_ulid(), b"env"),
    )
    db.execute(
        "INSERT INTO dek_archive (id, replaced_by, encrypted_dek, archived_at, version) "
        "VALUES (?, ?, ?, 1, 4)", (ids["archive"], ids["dek"], b"archive"),
    )
    client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
    try:
        yield db, client, ids
    finally:
        db.close()


@pytest.mark.parametrize("change", [
    "UPDATE nodes SET parent_id = NULL WHERE id = :node",
    "UPDATE nodes SET is_deleted = 1 WHERE id = :node",
    "UPDATE entries SET node_id = :root WHERE id = :entry",
    "UPDATE entries SET is_deleted = 1 WHERE id = :entry",
    "UPDATE deks SET node_id = :root WHERE id = :dek2",
    "UPDATE access_envelopes SET dek_id = :dek2 WHERE id = :envelope",
    "UPDATE dek_archive SET replaced_by = :dek2 WHERE id = :archive",
], ids=["node parent", "node deleted", "entry folder", "entry deleted", "key folder",
        "envelope key", "archive successor"])
def test_the_state_hash_changes_with_a_signed_parent_or_deleted_flag(vault, change):
    db, client, ids = vault
    baseline = client._compute_state_hash()
    db.execute(change, ids)
    assert client._compute_state_hash() != baseline


def test_a_held_conflict_copy_counts_with_the_server_s_parent_and_flag(vault):
    db, client, ids = vault
    db.execute(
        "INSERT INTO sync_conflicts (object_id, object_type, local_version, server_version, "
        "server_payload, server_parent_ref, server_is_deleted, detected_at) "
        "VALUES (?, 'node', 3, 2, ?, ?, 0, 1)", (ids["node"], b"node", ids["root"]),
    )
    db.execute("INSERT INTO outbox (kind, object_id) VALUES ('write', ?)", (ids["node"],))
    baseline = client._compute_state_hash()
    for change in ("UPDATE sync_conflicts SET server_parent_ref = NULL WHERE object_id = ?",
                   "UPDATE sync_conflicts SET server_is_deleted = 1 WHERE object_id = ?"):
        db.execute(change, (ids["node"],))
        assert client._compute_state_hash() != baseline
        db.execute(
            "UPDATE sync_conflicts SET server_parent_ref = ?, server_is_deleted = 0 WHERE object_id = ?",
            (ids["root"], ids["node"]),
        )
        assert client._compute_state_hash() == baseline


def _checkpoint(client, monkeypatch, checkpoint):
    monkeypatch.setattr(client, "_load_sync_checkpoint", lambda: checkpoint)


def test_a_checkpoint_from_before_compares_by_its_own_formula(vault, monkeypatch):
    """An upgraded vault's first pull at an unchanged seq: the same state
    passes, a changed one is still a mismatch."""
    db, client, ids = vault
    from sezam.vault.sync_common import legacy_state_hash

    legacy = legacy_state_hash(client._local_objects())
    _checkpoint(client, monkeypatch, {"last_sync_seq": 5, "state_hash": legacy})
    client._check_rollback(5, client._compute_state_hash())
    db.execute("UPDATE entries SET encrypted_data = ? WHERE id = ?", (b"other", ids["entry"]))
    with pytest.raises(SyncRollbackWarning, match="mismatch"):
        client._check_rollback(5, client._compute_state_hash())


def test_a_new_checkpoint_names_its_formula_and_catches_a_move(vault, monkeypatch):
    db, client, ids = vault
    record = client._checkpoint_record(5, client._compute_state_hash())
    assert record["state_v"] == 2
    _checkpoint(client, monkeypatch, record)
    db.execute("UPDATE nodes SET parent_id = NULL WHERE id = ?", (ids["node"],))
    with pytest.raises(SyncRollbackWarning, match="mismatch"):
        client._check_rollback(5, client._compute_state_hash())
