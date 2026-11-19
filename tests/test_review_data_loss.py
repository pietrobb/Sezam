"""Regressions for code review HEAD 2c7e809, section 1 (data loss)."""

from __future__ import annotations

import base64
import os

import pytest

from sezam.vault import pending_states
from sezam.crypto.kdf import Argon2Params
from sezam.crypto.keys import generate_keypair
from sezam.crypto.padding import pad, unpad
from sezam.models import new_ulid
from sezam.vault import outbox
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "review-data-loss-pw!"


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path / "a", PASSWORD, FAST_PARAMS)
    yield v
    v.lock()


def _client(vault: Vault) -> SyncClient:
    client = SyncClient(vault.db, "https://sync.invalid", vault.keypair, vault._user_id)
    client.token = "test-token"
    client.set_dek_manager(vault.dek_mgr)
    return client


# ── Bod 5: pad() u16 overflow ──

@pytest.mark.parametrize("size", [131_069, 131_071, 150_000, 196_606, 196_607, 300_000])
def test_pad_roundtrips_payloads_past_u16_padding_limit(size):
    data = os.urandom(size)
    padded = pad(data)
    assert unpad(padded) == data


# ── Bod 1: server-assigned user_id must not lock the user out ──

def test_rebind_server_identity_keeps_vault_unlockable(tmp_path):
    path = tmp_path / "v"
    v = Vault.create(path, PASSWORD, FAST_PARAMS)
    node_id = v.create_node("Servers")
    entry_id = v.create_entry(node_id, "ssh", [{"key": "password", "value": "s3cret"}])
    server_user_id = new_ulid()
    v.rebind_server_identity(server_user_id)
    v.lock()

    reopened = Vault(path)
    reopened.unlock(PASSWORD)
    try:
        assert reopened.db.get_meta("user_id") == server_user_id
        assert reopened.read_entry(entry_id)["fields"][0]["value"] == "s3cret"
    finally:
        reopened.lock()


@pytest.mark.parametrize("recovery", [False, True])
def test_rebind_then_initial_push_uploads_pre_connect_audit(tmp_path, recovery):
    path = tmp_path / "v"
    Vault.create(path, PASSWORD, FAST_PARAMS).lock()
    v = Vault(path)
    v.unlock(PASSWORD)  # unlocked vaults write signed audit records
    try:
        node_id = v.create_node("Servers")
        v.create_entry(node_id, "ssh", [{"key": "password", "value": "s3cret"}])
        assert v.db.fetchone("SELECT COUNT(*) AS c FROM audit_log")["c"] >= 2
        server_user_id = new_ulid()
        v.rebind_server_identity(server_user_id, generate_keypair() if recovery else None)

        client = _client(v)
        pushed = []

        def fake_request(method, path, body=None, auth=False, extra_headers=None):
            if "/keys" in path:
                raise RuntimeError("404 unknown user")
            pushed.extend(body["objects"])
            return {"accepted": [{"id": o["id"], "commit_seq": i + 1}
                                 for i, o in enumerate(body["objects"])],
                    "conflicts": []}

        client._request = fake_request
        client.push()
        audits = [o for o in pushed if o["object_type"] == "audit"]
        assert len(audits) >= 2
        for obj in audits:
            payload = base64.b64decode(obj["payload"])
            record = client._verify_audit_payload(obj["id"], payload)
            assert record["actor_id"] == server_user_id
        assert {o["object_type"] for o in pushed} >= {"node", "entry", "dek"}
        client._validate_audit_dag()
    finally:
        v.lock()


# ── Bod 2: KDF upgrade must verify the typed password ──

def test_kdf_upgrade_with_wrong_password_changes_nothing(vault):
    salt_before = vault.db.get_meta("argon2_salt")
    epoch_before = vault.db.get_meta("key_epoch")
    stronger = Argon2Params(time_cost=2, memory_cost=8192, parallelism=1)
    with pytest.raises(ValueError, match="Wrong master password"):
        vault.change_password("typo" + PASSWORD, "typo" + PASSWORD, stronger)
    assert vault.db.get_meta("argon2_salt") == salt_before
    assert vault.db.get_meta("key_epoch") == epoch_before


def test_gui_upgrade_dialog_uses_verified_change_password():
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "sezam" / "gui" / "argon2_upgrade_dialog.py"
    ).read_text(encoding="utf-8")
    assert "change_password(" in src
    assert "rewrap_all_deks" not in src


# ── Bod 6a: revocation re-key must carry subfolders along ──

def test_rekey_after_revocation_keeps_subfolders_readable(vault):
    parent = vault.create_node("Shared")
    child = vault.create_node("Child", parent_id=parent)
    grandchild_entry = vault.create_entry(child, "db", [{"key": "password", "value": "deep"}])
    old_dek_id = vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (parent,))["dek_id"]

    remaining = generate_keypair()
    remaining_user_id = new_ulid()
    vault.db.execute(
        "INSERT INTO known_keys (user_id, signing_pk, encryption_pk, fingerprint, "
        "first_seen, last_verified) VALUES (?, ?, ?, ?, 1, 1)",
        (remaining_user_id, remaining.signing_pk, remaining.encryption_pk, remaining.fingerprint),
    )
    revoked_user_id = new_ulid()
    for user_id in (revoked_user_id, remaining_user_id):
        vault.db.execute(
            "INSERT INTO access_envelopes (id, dek_id, user_id, created_by, access_level, "
            "encrypted_dek) VALUES (?, ?, ?, ?, 'write', ?)",
            (new_ulid(), old_dek_id, user_id, vault._user_id, os.urandom(80)),
        )

    assert vault.rekey_after_revocation(revoked_user_id) == 1

    children = vault.list_nodes(parent)
    assert [c["name"] for c in children] == ["Child"]
    assert vault.read_node(child)["name"] == "Child"
    assert vault.read_entry(grandchild_entry)["fields"][0]["value"] == "deep"
    pending = (pending_states.rekey_batch(vault.db) or None)
    assert child in pending["object_ids"]


# ── Bod 6b: tier-2 DEK pull must not replace the folder DEK ──

def test_pulled_second_dek_is_tier2_not_folder_dek(vault):
    folder = vault.create_node("Folder")
    entry_id = vault.create_entry(folder, "web", [{"key": "password", "value": "plain"}])
    folder_dek = vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    tier2_dek = new_ulid()
    vault.db.execute(
        "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
        "VALUES (?, ?, 'folder', ?, 1)",
        (tier2_dek, folder, os.urandom(80)),
    )
    client = _client(vault)
    client._pulled_dek_ids = [tier2_dek]
    client._bind_pulled_deks()

    assert vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == folder_dek
    assert vault.db.fetchone("SELECT scope FROM deks WHERE id = ?", (tier2_dek,))["scope"] == "tier2"
    assert vault.read_entry(entry_id)["fields"][0]["value"] == "plain"


def test_pulled_rekey_replacement_moves_all_sharing_nodes(vault):
    folder = vault.create_node("Folder")
    old_dek = vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    new_dek = new_ulid()
    vault.db.execute(
        "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
        "VALUES (?, ?, 'folder', ?, 1)",
        (new_dek, folder, os.urandom(80)),
    )
    vault.db.execute(
        "INSERT INTO dek_archive (id, replaced_by, encrypted_dek, archived_at, version) "
        "VALUES (?, ?, ?, 1, 1)",
        (new_ulid(), new_dek, os.urandom(80)),
    )
    client = _client(vault)
    client._pulled_dek_ids = [new_dek]
    client._bind_pulled_deks()

    assert vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == new_dek
    assert vault.db.fetchone("SELECT node_id FROM deks WHERE id = ?", (old_dek,))["node_id"] is None


def test_tier2_entry_dek_is_taken_from_envelope_header(vault):
    folder = vault.create_node("Folder")
    tier2_entry = vault.create_entry(
        folder, "root-pw", [{"key": "password", "value": "t2"}], tier=2
    )
    tier2_dek = vault.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (tier2_entry,))["dek_id"]
    assert tier2_dek is not None
    # Simulate a pulled row: the sync payload carries no local dek_id.
    vault.db.execute("UPDATE entries SET dek_id = NULL WHERE id = ?", (tier2_entry,))
    outbox.drop_write(vault.db, tier2_entry)
    _client(vault)._resolve_entry_deks()
    assert vault.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (tier2_entry,))["dek_id"] == tier2_dek
    assert vault.read_entry(tier2_entry)["fields"][0]["value"] == "t2"


# ── Bod 6c: incremental pull must tolerate any object order ──

def test_order_pulled_objects_parents_first():
    objs = [
        {"id": "E", "object_type": "entry", "parent_ref": "C"},
        {"id": "C", "object_type": "node", "parent_ref": "P"},
        {"id": "P", "object_type": "node", "parent_ref": None},
        {"id": "D", "object_type": "dek", "parent_ref": "C"},
    ]
    assert [o["id"] for o in SyncClient._order_pulled_objects(objs)] == ["D", "P", "C", "E"]


def test_incremental_pull_accepts_reverse_ordered_batch(tmp_path):
    source = Vault.create(tmp_path / "src", PASSWORD, FAST_PARAMS)
    parent = source.create_node("Parent")
    child = source.create_node("Child", parent_id=parent)
    source.create_entry(child, "e", [{"key": "password", "value": "x"}])
    objects = [
        obj for obj in _client(source)._collect_dirty_objects()
        if obj["object_type"] in {"node", "entry", "dek"}
    ]
    child_dek = source.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (child,))["dek_id"]
    source.lock()

    target = Vault.create(tmp_path / "dst", PASSWORD, FAST_PARAMS)
    try:
        client = _client(target)
        client._fetch_pull_pages = lambda *a, **k: {
            "objects": list(reversed(objects)), "max_commit_seq": 7, "key_epoch": 0,
        }
        client._verify_object_signature = lambda obj: True
        client.pull()
        row = target.db.fetchone("SELECT parent_id, dek_id FROM nodes WHERE id = ?", (child,))
        assert row["parent_id"] == parent
        assert row["dek_id"] == child_dek
    finally:
        target.lock()


# ── Bod 6d: root, audit and tier-2 DEKs must be pushed ──

def test_root_audit_and_tier2_deks_are_pushed_once(vault):
    folder = vault.create_node("Folder")
    vault.create_entry(folder, "t2", [{"key": "password", "value": "x"}], tier=2)
    scopes = {
        row["id"]: row["scope"] for row in vault.db.fetchall("SELECT id, scope FROM deks")
    }
    client = _client(vault)

    def fake_request(method, path, body=None, auth=False, extra_headers=None):
        return {"accepted": [{"id": o["id"], "commit_seq": 1} for o in body["objects"]],
                "conflicts": []}

    client._request = fake_request
    pushed_deks = {
        o["id"] for o in client._collect_dirty_objects() if o["object_type"] == "dek"
    }
    assert {scopes[d] for d in pushed_deks} >= {"root", "audit", "folder", "tier2"}
    client.push()
    assert not [
        o for o in client._collect_dirty_objects() if o["object_type"] == "dek"
    ]
