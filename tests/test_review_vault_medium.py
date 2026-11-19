"""Regressions for code review HEAD 2c7e809, section 3 (vault/crypto V1-V8)."""

from __future__ import annotations

import base64
import hashlib
import os
import time

import pytest

from sezam.crypto.aead import BlobKind, decrypt, encrypt
from sezam.crypto.kdf import Argon2Params
from sezam.crypto.keys import generate_keypair
from sezam.models import new_ulid, ulid_to_bytes
from sezam.password import estimate_strength, generate_passphrase
from sezam.totp import generate_totp
from sezam.vault.crud import Vault
from sezam.vault.db import VaultDB
from sezam.vault.dek import DEKManager
from sezam.vault.sync_client import SyncClient
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    app_client,
    mock_db,
)

FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "TestHeslo123!"


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path, PASSWORD, FAST)
    yield v
    v.lock()


# ── V1: rollback detection ──


class _MetaDB:
    def __init__(self):
        self._meta: dict[str, str] = {}

    def get_meta(self, key):
        return self._meta.get(key)

    def set_meta(self, key, value):
        self._meta[key] = value

    def fetchall(self, *a, **k):
        return []

    def fetchone(self, *a, **k):
        return None

    def execute(self, *a, **k):
        return None

    def require_generation(self):
        pass

    def begin(self):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


class _AuditDEK:
    def __init__(self):
        self.dek_id = new_ulid()
        self.dek = bytearray(b"\x42" * 32)

    def get_audit_dek(self):
        return self.dek_id, self.dek

    def _wrapping_kek_id(self):
        return self.dek_id  # the fake KEK is always the vault's current one


def test_pull_flags_server_head_behind_local_checkpoint():
    client = SyncClient(_MetaDB(), "http://localhost", generate_keypair(), new_ulid())
    client.set_dek_manager(_AuditDEK())
    client._token = "tok"
    client._save_sync_checkpoint(50, "a1" * 32)
    client._db.set_meta("last_known_commit_seq", "50")
    # A restored server has nothing newer, so max_commit_seq echoes our
    # baseline; only the head reveals it went back to seq 42.
    client._request = lambda *a, **k: {
        "objects": [], "max_commit_seq": 50, "head_commit_seq": 42,
    }
    applied = []
    client._apply_pulled_object = applied.append

    result = client.pull()

    assert "rollback_warning" in result
    assert applied == []
    assert client._load_sync_checkpoint()["last_sync_seq"] == 50
    assert client._db.get_meta("last_known_commit_seq") == "50"


def _vault_object(seq: int) -> dict:
    return {
        "id": f"ROLL{seq:022d}",
        "object_type": "dek",
        "payload": b"data",
        "owner_id": "ADMIN000000000000000000001",
        "parent_ref": None,
        "target_user_id": None,
        "version": 1,
        "commit_seq": seq,
        "is_deleted": 0,
        "payload_hash": hashlib.sha256(b"data").hexdigest(),
        "client_signature": b"\x00" * 64,
        "modified_at": int(time.time() * 1000),
    }


@pytest.mark.asyncio
async def test_server_does_not_304_an_etag_ahead_of_its_head(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    token = _create_jwt("ADMIN000000000000000000001", "admin", True)
    mock_db._storage["vault_objects"].append(_vault_object(42))
    mock_db._storage["commit_counter"][0]["next_seq"] = 43

    resp = await app_client.get(
        "/api/sync?since_commit_seq=0",
        headers={"Authorization": f"Bearer {token}", "If-None-Match": '"50"'},
    )

    assert resp.status_code == 200
    assert resp.json()["head_commit_seq"] == 42


@pytest.mark.asyncio
async def test_server_head_uses_counter_after_top_row_was_collected(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    token = _create_jwt("ADMIN000000000000000000001", "admin", True)
    mock_db._storage["vault_objects"].append(_vault_object(42))
    mock_db._storage["commit_counter"][0]["next_seq"] = 60  # 43..59 GC'd

    resp = await app_client.get(
        "/api/sync?since_commit_seq=0", headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    assert resp.json()["head_commit_seq"] == 59


# ── V2: foreign DEKs are decided by our KEK, not by owner_id ──


def test_foreign_dek_classification_ignores_unsigned_owner_id(tmp_path):
    db = VaultDB(tmp_path / "v2.db")
    db.open()
    db.create_schema()
    try:
        user_id = new_ulid()
        manager = DEKManager(db, bytearray(os.urandom(32)))
        owned_id, _ = manager.create_dek("root")
        row = db.fetchone("SELECT encrypted_dek, version FROM deks WHERE id = ?", (owned_id,))
        client = SyncClient(db, "https://example.invalid", generate_keypair(), user_id)
        client.set_dek_manager(manager)

        # Server claims our own DEK belongs to someone else.
        client._apply_dek(
            owned_id, None, bytes(row["encrypted_dek"]), row["version"],
            {"owner_id": new_ulid()},
        )
        assert owned_id not in (db.get_meta_json("foreign_dek_ids") or [])

        # Server claims a wrap we cannot open is ours.
        alien_id = new_ulid()
        client._apply_dek(alien_id, None, b"opaque foreign wrap", 1, {"owner_id": user_id})
        assert alien_id in db.get_meta_json("foreign_dek_ids")
    finally:
        db.close()


# ── V3: passphrase strength ──


def test_passphrase_strength_counts_words_not_letters():
    s = estimate_strength("hell-date-boat-fear-dirt")
    assert s["entropy_bits"] < 45
    assert s["score"] <= 2


def test_default_passphrase_is_at_least_strong():
    phrase = generate_passphrase()
    assert len(phrase.split("-")) == 8
    assert estimate_strength(phrase)["score"] >= 3


# ── V4: TOTP URIs and unpadded seeds ──

_RFC_SHA1 = base64.b32encode(b"12345678901234567890").decode()
_RFC_SHA256 = base64.b32encode(b"12345678901234567890123456789012").decode()
_RFC_SHA512 = base64.b32encode(b"1234567890" * 6 + b"1234").decode()


@pytest.mark.parametrize(
    "secret, algorithm, expected",
    [
        (_RFC_SHA1, "SHA1", "94287082"),
        (_RFC_SHA256, "SHA256", "46119246"),
        (_RFC_SHA512, "SHA512", "90693936"),
    ],
)
def test_totp_otpauth_uri_matches_rfc6238_vectors(secret, algorithm, expected):
    uri = (
        f"otpauth://totp/Acme:alice?secret={secret.rstrip('=')}"
        f"&algorithm={algorithm}&digits=8&period=30&issuer=Acme"
    )
    assert generate_totp(uri, at=59) == expected


def test_totp_accepts_unpadded_and_spaced_base32():
    padded = base64.b32encode(b"abc").decode()  # "MFRGG==="
    assert generate_totp("mfrg g", at=1000) == generate_totp(padded, at=1000)


def test_totp_rejects_hotp_uri():
    with pytest.raises(ValueError):
        generate_totp("otpauth://hotp/x?secret=MFRGG&counter=1")


# ── V5: search index follows update and delete ──


def test_search_index_follows_rename_and_delete(vault):
    node = vault.create_node("Servers")
    eid = vault.create_entry(node, "Oldname", [{"key": "host", "value": "h"}])
    vault.update_entry(eid, name="Newname")

    assert vault.search("Oldname") == []
    assert [r["entry_id"] for r in vault.search("Newname")] == [eid]

    vault.delete_entry(eid)
    assert vault.search("Newname") == []


# ── V6: blob kind is checked before parsing ──


def test_decrypt_rejects_unexpected_blob_kind():
    dek, dek_id, obj_id = bytearray(os.urandom(32)), new_ulid(), new_ulid()
    blob = encrypt(
        plaintext=b"{}", dek=dek, dek_id=ulid_to_bytes(dek_id),
        object_id=ulid_to_bytes(obj_id), version=1, blob_kind=BlobKind.ENTRY_DATA,
    )
    assert decrypt(blob, dek, ulid_to_bytes(obj_id), 1) == b"{}"
    with pytest.raises(ValueError, match="blob kind"):
        decrypt(blob, dek, ulid_to_bytes(obj_id), 1, expected_blob_kind=BlobKind.ENTRY_META)


def test_read_entry_refuses_swapped_meta_and_data(vault):
    node = vault.create_node("Servers")
    eid = vault.create_entry(node, "Box", [{"key": "pw", "value": "s", "sensitive": True}])
    vault.db.execute(
        "UPDATE entries SET encrypted_meta = encrypted_data, encrypted_data = encrypted_meta "
        "WHERE id = ?",
        (eid,),
    )
    with pytest.raises(ValueError, match="blob kind"):
        vault.read_entry(eid)


# ── V8: multi-statement folder creation is atomic ──


@pytest.mark.parametrize("personal", [False, True])
def test_folder_creation_rolls_back_when_dek_creation_fails(vault, monkeypatch, personal):
    before = vault.db.fetchone("SELECT COUNT(*) AS n FROM nodes")["n"]

    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(vault.dek_mgr, "create_dek", boom)
    with pytest.raises(RuntimeError, match="disk full"):
        if personal:
            vault.create_personal_folder("Mine")
        else:
            vault.create_node("Shared")

    assert vault.db.fetchone("SELECT COUNT(*) AS n FROM nodes")["n"] == before
    assert not vault.db.conn.in_transaction


def test_transaction_nests_inside_explicit_begin(vault):
    db = vault.db
    db.begin()
    with db.transaction():
        db.set_meta("probe", "1")
    db.rollback()
    assert db.get_meta("probe") is None
