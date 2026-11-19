#!/usr/bin/env python3
"""End-to-end test of the Sezam system: clean DB, bootstrap, vault CRUD, sync, verify.

Tests the full lifecycle against the explicitly selected isolated server.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import ssl
import struct
import sys
import time
import traceback
import urllib.request
import urllib.error

from e2e_environment import E2EEnvironment
import paramiko
import nacl.bindings
from nacl.signing import SigningKey
from nacl.public import PrivateKey as X25519PrivateKey
from ulid import ULID

# Add project source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sezam.crypto.kdf import Argon2Params, derive_kek, derive_kek_and_proof, generate_salt
from sezam.crypto.keys import KeyPair, generate_keypair
from sezam.crypto.aead import (
    BlobKind, encrypt, decrypt, encrypt_dek_wrap, decrypt_dek_wrap,
    encrypt_keypair_wrap, decrypt_keypair_wrap,
)
from sezam.models import new_ulid, ulid_to_bytes, EntryData, EntryField, EntryMeta, NodeMeta
from sezam.vault.crud import Vault
from sezam.vault.db import VaultDB
from sezam.vault.dek import DEKManager

# ── Config ──
E2E_ENV = E2EEnvironment.from_environ()
SSH_HOST = E2E_ENV.ssh_host
SSH_PORT = E2E_ENV.ssh_port
SSH_USER = E2E_ENV.ssh_user
SSH_PASSWORD = E2E_ENV.ssh_password
SERVER_URL = E2E_ENV.server_url
USERNAME = os.environ.get("SEZAM_E2E_USERNAME", "peter")
PASSWORD = os.environ.get("SEZAM_E2E_PASSWORD") or secrets.token_urlsafe(24)
VAULT_PATH_1 = "/tmp/sezam_e2e"
VAULT_PATH_2 = "/tmp/sezam_e2e_2"

# Use faster Argon2 params for test speed (still Argon2id)
TEST_ARGON2 = Argon2Params(time_cost=2, memory_cost=65536, parallelism=4)

ctx = ssl.create_default_context()

results: list[tuple[str, bool, str]] = []


def report(step: str, success: bool, detail: str = ""):
    status = "PASS" if success else "FAIL"
    results.append((step, success, detail))
    print(f"  [{status}] {step}" + (f" -- {detail}" if detail else ""))


def api(method: str, path: str, body=None, token=None):
    """Make API call to the server."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(SERVER_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read())


def ulid_str_to_bytes26(ulid_str: str) -> bytes:
    """Encode ULID string as UTF-8, padded/truncated to 26 bytes.

    This matches the SERVER's encoding in _verify_sync_signature:
      obj.id.encode("utf-8").ljust(26, b"\\x00")[:26]
    """
    return ulid_str.encode("utf-8").ljust(26, b"\x00")[:26]


def build_server_canonical(
    obj_id: str,
    object_type: str,
    parent_ref: str | None,
    target_user_id: str | None,
    is_deleted: int,
    version: int,
    payload_hash: str,
) -> bytes:
    """Build canonical signed data matching the SERVER's _verify_sync_signature.

    Server format:
      id(26B UTF-8) || u8(len(object_type)) || object_type
      || parent_ref_or_zero(26B UTF-8) || target_user_id_or_zero(26B UTF-8)
      || u8(is_deleted) || u32be(version) || payload_hash(32B raw)
    """
    id_bytes = ulid_str_to_bytes26(obj_id)
    ot_bytes = object_type.encode("utf-8")
    parent_bytes = ulid_str_to_bytes26(parent_ref) if parent_ref else b"\x00" * 26
    target_bytes = ulid_str_to_bytes26(target_user_id) if target_user_id else b"\x00" * 26
    ph_bytes = bytes.fromhex(payload_hash)

    return (
        id_bytes
        + bytes([len(ot_bytes)]) + ot_bytes
        + parent_bytes
        + target_bytes
        + bytes([is_deleted])
        + version.to_bytes(4, "big")
        + ph_bytes
    )


def make_sync_object(
    obj_id: str,
    object_type: str,
    payload: bytes,
    signing_key,
    parent_ref: str | None = None,
    target_user_id: str | None = None,
    version: int = 1,
    is_deleted: int = 0,
) -> dict:
    """Create a sync object dict with server-compatible signature."""
    payload_b64 = base64.b64encode(payload).decode("ascii")
    payload_hash = hashlib.sha256(payload).hexdigest()

    canonical = build_server_canonical(
        obj_id, object_type, parent_ref, target_user_id,
        is_deleted, version, payload_hash,
    )
    signature = signing_key.sign(canonical).signature.hex()

    return {
        "id": obj_id,
        "object_type": object_type,
        "payload": payload_b64,
        "parent_ref": parent_ref,
        "target_user_id": target_user_id,
        "version": version,
        "is_deleted": is_deleted,
        "payload_hash": payload_hash,
        "signature": signature,
    }


def push_objects(objects: list[dict], token: str) -> dict:
    """Push sync objects to the server."""
    return api("POST", "/api/sync", {"objects": objects, "atomic_batch": False}, token=token)


def collect_dirty_objects(db: VaultDB, signing_key) -> list[dict]:
    """Collect dirty objects from local vault and build server-compatible sync objects."""
    objects = []

    # Dirty nodes
    rows = db.fetchall(
        "SELECT id, parent_id, encrypted_meta, dek_id, version, is_deleted "
        "FROM nodes WHERE is_dirty = 1"
    )
    for row in rows:
        obj = make_sync_object(
            obj_id=row["id"],
            object_type="node",
            payload=bytes(row["encrypted_meta"]),
            signing_key=signing_key,
            parent_ref=row["parent_id"],
            version=row["version"],
            is_deleted=row["is_deleted"],
        )
        objects.append(obj)

    # Dirty entries (length-prefixed binary format)
    rows = db.fetchall(
        "SELECT id, node_id, encrypted_meta, encrypted_data, version, is_deleted "
        "FROM entries WHERE is_dirty = 1"
    )
    for row in rows:
        meta_bytes = bytes(row["encrypted_meta"])
        data_bytes = bytes(row["encrypted_data"])
        payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + data_bytes
        obj = make_sync_object(
            obj_id=row["id"],
            object_type="entry",
            payload=payload,
            signing_key=signing_key,
            parent_ref=row["node_id"],
            version=row["version"],
            is_deleted=row["is_deleted"],
        )
        objects.append(obj)

    # DEKs
    rows = db.fetchall("SELECT id, node_id, scope, encrypted_dek, version FROM deks")
    for row in rows:
        obj = make_sync_object(
            obj_id=row["id"],
            object_type="dek",
            payload=bytes(row["encrypted_dek"]),
            signing_key=signing_key,
            parent_ref=row["node_id"],
            version=row["version"],
        )
        objects.append(obj)

    # Access envelopes
    rows = db.fetchall(
        "SELECT ae.id, ae.dek_id, ae.user_id, ae.created_by, ae.access_level, ae.encrypted_dek "
        "FROM access_envelopes ae"
    )
    for row in rows:
        obj = make_sync_object(
            obj_id=row["id"],
            object_type="envelope",
            payload=bytes(row["encrypted_dek"]),
            signing_key=signing_key,
            parent_ref=row["dek_id"],
            target_user_id=row["user_id"],
            version=1,
        )
        objects.append(obj)

    return objects


def apply_pulled_objects_to_vault2(db: VaultDB, all_objects: list[dict]) -> int:
    """Apply pulled objects to fresh vault2 DB, handling FK constraints.

    Inserts in correct order: DEKs (with node_id=NULL first) -> nodes -> entries -> envelopes.
    Then patches DEK node_id references.
    """
    # Disable FK constraints temporarily for clean bulk insert
    db.execute("PRAGMA foreign_keys=OFF")

    applied = 0
    dek_objs = [o for o in all_objects if o["object_type"] == "dek"]
    node_objs = [o for o in all_objects if o["object_type"] == "node"]
    entry_objs = [o for o in all_objects if o["object_type"] == "entry"]
    envelope_objs = [o for o in all_objects if o["object_type"] == "envelope"]

    # 1. Insert DEKs (node_id may reference nodes not yet inserted)
    for obj in dek_objs:
        obj_id = obj["id"]
        version = obj.get("version", 1)
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        parent_ref = obj.get("parent_ref")
        scope = obj.get("scope") or "folder"  # the server sends null for an unscoped key
        db.execute(
            "INSERT OR REPLACE INTO deks (id, node_id, scope, encrypted_dek, version) VALUES (?,?,?,?,?)",
            (obj_id, parent_ref, scope, payload, version),
        )
        applied += 1

    # 2. Insert nodes
    for obj in node_objs:
        obj_id = obj["id"]
        version = obj.get("version", 1)
        is_deleted = obj.get("is_deleted", 0)
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        parent_ref = obj.get("parent_ref")

        # Find dek_id: look for a DEK that references this node, or use root DEK
        dek_id = None
        for d in dek_objs:
            if d.get("parent_ref") == obj_id:
                dek_id = d["id"]
                break
        if not dek_id:
            # Use root DEK (the one with no parent_ref or scope='root')
            for d in dek_objs:
                if not d.get("parent_ref"):
                    dek_id = d["id"]
                    break
        if not dek_id and dek_objs:
            dek_id = dek_objs[0]["id"]

        db.execute(
            "INSERT OR REPLACE INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_dirty, is_deleted) VALUES (?,?,?,?,?,0,?)",
            (obj_id, parent_ref, payload, dek_id, version, is_deleted),
        )
        applied += 1

    # 3. Insert entries
    for obj in entry_objs:
        obj_id = obj["id"]
        version = obj.get("version", 1)
        is_deleted = obj.get("is_deleted", 0)
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        parent_ref = obj.get("parent_ref")  # This is node_id for entries

        if len(payload) < 4:
            continue
        meta_len = struct.unpack(">I", payload[:4])[0]
        encrypted_meta = payload[4:4 + meta_len]
        encrypted_data = payload[4 + meta_len:]

        db.execute(
            "INSERT OR REPLACE INTO entries (id, node_id, encrypted_meta, encrypted_data, version, is_dirty, is_deleted) VALUES (?,?,?,?,?,0,?)",
            (obj_id, parent_ref, encrypted_meta, encrypted_data, version, is_deleted),
        )
        applied += 1

    # 4. Insert envelopes
    for obj in envelope_objs:
        obj_id = obj["id"]
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        parent_ref = obj.get("parent_ref")
        target = obj.get("target_user_id", "")
        owner = obj.get("owner_id", "")
        db.execute(
            "INSERT OR REPLACE INTO access_envelopes (id, dek_id, user_id, created_by, access_level, encrypted_dek) VALUES (?,?,?,?,?,?)",
            (obj_id, parent_ref, target, owner, "write", payload),
        )
        applied += 1

    # Re-enable FK constraints
    db.execute("PRAGMA foreign_keys=ON")

    return applied


def authenticate(kp: KeyPair) -> str:
    """Perform challenge-response auth, return JWT."""
    ch = api("POST", "/api/auth/challenge", {"username": USERNAME})
    sig = kp.to_nacl_signing_key().sign(bytes.fromhex(ch["challenge"])).signature
    resp = api("POST", "/api/auth/verify", {
        "username": USERNAME,
        "challenge": ch["challenge"],
        "signature": sig.hex(),
    })
    return resp["token"]


# ================================================================
# STEP 1: Clean server DB
# ================================================================
print("\n" + "=" * 60)
print("STEP 1: Clean server DB completely")
print("=" * 60)
if E2E_ENV.reset_mode == "fresh":
    report("DB cleanup", True, "Skipped: caller supplied a fresh loopback stack")
else:
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        if known_hosts := os.environ.get("SEZAM_SSH_KNOWN_HOSTS"):
            ssh.load_host_keys(os.path.expanduser(known_hosts))
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        ssh.connect(
            SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD,
            timeout=15, look_for_keys=True, allow_agent=True,
        )

        clean_sql = (
            "DELETE FROM server_audit; "
            "DELETE FROM share_views; "
            "DELETE FROM shared_links; "
            "DELETE FROM write_acl; "
            "DELETE FROM sync_state; "
            "DELETE FROM spent_challenges; "
            "DELETE FROM revoked_tokens; "
            "DELETE FROM provisioning_tokens; "
            "DELETE FROM invitation_tokens; "
            "DELETE FROM vault_objects; "
            "DELETE FROM users; "
            "DELETE FROM commit_counter WHERE id > 0; "
            "INSERT INTO commit_counter (id, next_seq, gc_floor_seq) VALUES (1, 1, 0) "
            "ON DUPLICATE KEY UPDATE next_seq=1, gc_floor_seq=0;"
        )
        stdin, stdout, stderr = ssh.exec_command(
            E2E_ENV.database_reset_command(),
            timeout=30,
        )
        stdin.write(clean_sql)
        stdin.channel.shutdown_write()
        exit_status = stdout.channel.recv_exit_status()
        err_out = stderr.read().decode()
        if exit_status != 0:
            raise RuntimeError(f"MySQL cleanup failed (exit {exit_status}): {err_out}")
        report("DB cleanup", True, "All tables cleaned")

        _, stdout, stderr = ssh.exec_command(E2E_ENV.api_restart_command(), timeout=30)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise RuntimeError(f"docker restart failed: {stderr.read().decode()}")
        time.sleep(3)
        report("API restart", True)
        ssh.close()

    except Exception as e:
        report("Server DB cleanup", False, str(e))
        traceback.print_exc()
        sys.exit(1)


# ================================================================
# STEP 2: Bootstrap admin via API
# ================================================================
print("\n" + "=" * 60)
print("STEP 2: Bootstrap admin user via API")
print("=" * 60)

try:
    # 2a. Verify needs_setup
    status_resp = api("GET", "/api/bootstrap-status")
    assert status_resp["needs_setup"] is True, f"Expected needs_setup=true, got {status_resp}"
    report("Bootstrap status check", True, "needs_setup=true")

    # 2b. Generate keypair
    kp = generate_keypair()
    report("Keypair generated", True, f"fingerprint={kp.fingerprint[:16]}...")

    # 2c. Bootstrap
    bootstrap_resp = api("POST", "/api/bootstrap", {
        "username": USERNAME,
        "signing_pk": kp.signing_pk.hex(),
        "encryption_pk": kp.encryption_pk.hex(),
    })
    user_id = bootstrap_resp["user_id"]
    onboarding_jwt = bootstrap_resp["token"]
    report("Bootstrap admin", True, f"user_id={user_id}")

    # 2d. Derive KEK + auth_proof
    argon2_salt = generate_salt(16)
    auth_salt = generate_salt(16)
    kek, auth_proof = derive_kek_and_proof(PASSWORD, argon2_salt, TEST_ARGON2)
    report("KEK derived", True, f"salt={argon2_salt.hex()[:16]}...")

    # 2e. Encrypt keypair (legacy format: nonce + XChaCha20-Poly1305(data, None, nonce, kek))
    keypair_data = bytes(kp.signing_sk) + bytes(kp.encryption_sk)
    nonce = os.urandom(24)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        keypair_data, None, nonce, bytes(kek)
    )
    encrypted_keypair = nonce + ct
    report("Keypair encrypted (legacy)", True, f"{len(encrypted_keypair)} bytes")

    # 2f. Upload keypair
    upload_resp = api("PUT", "/api/me/keypair", {
        "encrypted_keypair": encrypted_keypair.hex(),
        "argon2_salt": argon2_salt.hex(),
        "auth_salt": auth_salt.hex(),
        "auth_proof": auth_proof.hex(),
        "argon2_params": TEST_ARGON2.account_dict(),
    }, token=onboarding_jwt)
    assert upload_resp.get("status") == "ok"
    report("Keypair uploaded", True)

    # 2g. Authenticate
    jwt_token = authenticate(kp)
    report("Challenge-response auth", True)

except Exception as e:
    report("Bootstrap", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# STEP 3: Create local vault with SAME credentials
# ================================================================
print("\n" + "=" * 60)
print("STEP 3: Create local vault synced with server")
print("=" * 60)

try:
    for p in [VAULT_PATH_1, VAULT_PATH_2]:
        if os.path.exists(p):
            shutil.rmtree(p)

    vault_path = VAULT_PATH_1
    os.makedirs(vault_path, exist_ok=True)

    vault = Vault(vault_path)
    vault._db.open()
    vault._db.create_schema()

    vault._db.set_meta_json("argon2_params", TEST_ARGON2.to_dict())
    vault._db.set_meta("argon2_salt", argon2_salt.hex())

    kek_dek_id = new_ulid()
    vault._db.set_meta("kek_dek_id", kek_dek_id)

    encrypted_kp_local = encrypt_keypair_wrap(
        keypair_data=kp.serialize_private(),
        kek=kek,
        kek_dek_id=ulid_to_bytes(kek_dek_id),
        user_object_id=ulid_to_bytes(user_id),
    )
    vault._db.set_meta("encrypted_keypair", encrypted_kp_local.hex())
    vault._db.set_meta("user_id", user_id)
    vault._db.set_meta("username", USERNAME)
    vault._db.set_meta("signing_pk", kp.signing_pk.hex())
    vault._db.set_meta("encryption_pk", kp.encryption_pk.hex())
    vault._db.set_meta("key_epoch", "0")

    dek_mgr = DEKManager(vault._db, kek)
    vault._dek_mgr = dek_mgr
    vault._keypair = kp
    vault._user_id = user_id
    vault._unlocked = True

    root_dek_id, root_dek = dek_mgr.create_dek("root")
    dek_mgr.create_dek("audit")

    root_node_id = new_ulid()
    root_meta = NodeMeta(name="Root")
    encrypted_root_meta = encrypt(
        plaintext=root_meta.to_json(),
        dek=root_dek,
        dek_id=ulid_to_bytes(root_dek_id),
        object_id=ulid_to_bytes(root_node_id),
        version=1,
        blob_kind=BlobKind.NODE_META,
    )
    vault._db.execute(
        "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_dirty, is_deleted) "
        "VALUES (?, NULL, ?, ?, 1, 1, 0)",
        (root_node_id, encrypted_root_meta, root_dek_id),
    )
    vault._db.set_meta("root_node_id", root_node_id)
    vault._db.conn.commit()

    report("Local vault created", True, f"path={vault_path}")

    # Quick pull test (should be empty)
    pull_resp = api("GET", "/api/sync?since_commit_seq=0", token=jwt_token)
    report("Initial pull (API)", True, f"objects={len(pull_resp.get('objects', []))}")

except Exception as e:
    report("Local vault creation", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# STEP 4: Create entries locally and push
# ================================================================
print("\n" + "=" * 60)
print("STEP 4: Create folders and entries, then push")
print("=" * 60)

try:
    folders = {}
    folder_names = ["Servery", "Databazy", "Email", "Osobne"]
    for fname in folder_names:
        fid = vault.create_node(fname)
        folders[fname] = fid
        report(f"Created folder '{fname}'", True, f"id={fid}")
    vault._db.conn.commit()

    entries_data = [
        ("Servery", "Hetzner SSH", [
            {"key": "host", "value": "192.0.2.10", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": "root", "sensitive": False, "sort_order": 1},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 2},
            {"key": "port", "value": "22", "sensitive": False, "sort_order": 3},
        ]),
        ("Servery", "DigitalOcean VPS", [
            {"key": "host", "value": "192.0.2.11", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": "root", "sensitive": False, "sort_order": 1},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 2},
            {"key": "notes", "value": "Sezam production server", "sensitive": False, "sort_order": 3},
        ]),
        ("Databazy", "MariaDB Production", [
            {"key": "host", "value": "sezam-db:3306", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": "sezam", "sensitive": False, "sort_order": 1},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 2},
            {"key": "database", "value": "sezam", "sensitive": False, "sort_order": 3},
        ]),
        ("Databazy", "Redis Cache", [
            {"key": "host", "value": "redis.internal:6379", "sensitive": False, "sort_order": 0},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
        ]),
        ("Email", "Gmail", [
            {"key": "email", "value": "jan.novak@example.com", "sensitive": False, "sort_order": 0},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
            {"key": "recovery_email", "value": "backup@example.org", "sensitive": False, "sort_order": 2},
        ]),
        ("Email", "Firma SMTP", [
            {"key": "server", "value": "smtp.firma.sk", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": "jan@firma.sk", "sensitive": False, "sort_order": 1},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 2},
            {"key": "port", "value": "587", "sensitive": False, "sort_order": 3},
        ]),
        ("Osobne", "Internet Banking", [
            {"key": "banka", "value": "Demo banka", "sensitive": False, "sort_order": 0},
            {"key": "login", "value": "jan.novak", "sensitive": False, "sort_order": 1},
            {"key": "pin", "value": "1234", "sensitive": True, "sort_order": 2},
            {"key": "iban", "value": "SK00 0000 0000 0000 0000 0000", "sensitive": True, "sort_order": 3},
        ]),
        ("Osobne", "WiFi Doma", [
            {"key": "ssid", "value": "DomacaSiet_5G", "sensitive": False, "sort_order": 0},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
        ]),
    ]

    entry_ids = []
    for folder_name, entry_name, fields in entries_data:
        eid = vault.create_entry(folders[folder_name], entry_name, fields)
        entry_ids.append(eid)
        report(f"Created entry '{entry_name}'", True, f"in {folder_name}")
    vault._db.conn.commit()

    # Collect all dirty objects with server-compatible signatures
    signing_key = kp.to_nacl_signing_key()
    sync_objects = collect_dirty_objects(vault._db, signing_key)
    report("Collected dirty objects", True, f"count={len(sync_objects)}")

    # Re-authenticate in case token expired during Argon2
    jwt_token = authenticate(kp)

    # Push to server
    push_result = push_objects(sync_objects, jwt_token)
    accepted = len(push_result.get("accepted", []))
    conflicts = push_result.get("conflicts", [])
    n_conflicts = len(conflicts)

    if n_conflicts > 0:
        print(f"    Conflicts detail: {json.dumps(conflicts[:3], indent=2)}")

    report(
        "Push to server", accepted > 0 and n_conflicts == 0,
        f"accepted={accepted}, conflicts={n_conflicts}"
    )

    # Mark all as clean locally
    if accepted > 0:
        vault._db.execute("UPDATE nodes SET is_dirty = 0")
        vault._db.execute("UPDATE entries SET is_dirty = 0")
        vault._db.conn.commit()

except Exception as e:
    report("Create & push", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# STEP 5: Pull back into second vault and verify
# ================================================================
print("\n" + "=" * 60)
print("STEP 5: Pull into second vault and verify")
print("=" * 60)

try:
    vault2_path = VAULT_PATH_2
    os.makedirs(vault2_path, exist_ok=True)

    vault2 = Vault(vault2_path)
    vault2._db.open()
    vault2._db.create_schema()

    vault2._db.set_meta_json("argon2_params", TEST_ARGON2.to_dict())
    vault2._db.set_meta("argon2_salt", argon2_salt.hex())

    kek_dek_id_2 = new_ulid()
    vault2._db.set_meta("kek_dek_id", kek_dek_id_2)
    encrypted_kp_2 = encrypt_keypair_wrap(
        keypair_data=kp.serialize_private(),
        kek=kek,
        kek_dek_id=ulid_to_bytes(kek_dek_id_2),
        user_object_id=ulid_to_bytes(user_id),
    )
    vault2._db.set_meta("encrypted_keypair", encrypted_kp_2.hex())
    vault2._db.set_meta("user_id", user_id)
    vault2._db.set_meta("username", USERNAME)
    vault2._db.set_meta("signing_pk", kp.signing_pk.hex())
    vault2._db.set_meta("encryption_pk", kp.encryption_pk.hex())
    vault2._db.set_meta("key_epoch", "0")

    dek_mgr_2 = DEKManager(vault2._db, kek)
    vault2._dek_mgr = dek_mgr_2
    vault2._keypair = kp
    vault2._user_id = user_id
    vault2._unlocked = True

    vault2._db.conn.commit()
    report("Second vault created", True, f"path={vault2_path}")

    # Authenticate vault2
    jwt2 = authenticate(kp)
    report("Vault2 authenticated", True)

    # Pull all data from server via API
    pull_resp = api("GET", "/api/sync?since_commit_seq=0", token=jwt2)
    pulled_objects = pull_resp.get("objects", [])
    max_seq = pull_resp.get("max_commit_seq", 0)
    report("Pull from server", len(pulled_objects) > 0, f"objects={len(pulled_objects)}, max_seq={max_seq}")

    # Apply all pulled objects to vault2
    applied = apply_pulled_objects_to_vault2(vault2._db, pulled_objects)
    vault2._db.conn.commit()
    report("Applied pulled objects", applied > 0, f"applied={applied}")

    # Unlock all pulled DEKs
    dek_mgr_2.unlock_all_deks()
    report("DEKs unlocked in vault2", True)

    # Verify nodes match
    v2_nodes = vault2._db.fetchall("SELECT id FROM nodes WHERE is_deleted = 0")
    v1_nodes = vault._db.fetchall("SELECT id FROM nodes WHERE is_deleted = 0")
    v2_node_ids = {r["id"] for r in v2_nodes}
    v1_node_ids = {r["id"] for r in v1_nodes}
    nodes_match = v1_node_ids == v2_node_ids
    report("Nodes match", nodes_match, f"vault1={len(v1_node_ids)}, vault2={len(v2_node_ids)}")

    # Verify entries match
    v2_entries = vault2._db.fetchall("SELECT id FROM entries WHERE is_deleted = 0")
    v1_entries = vault._db.fetchall("SELECT id FROM entries WHERE is_deleted = 0")
    v2_entry_ids = {r["id"] for r in v2_entries}
    v1_entry_ids = {r["id"] for r in v1_entries}
    entries_match = v1_entry_ids == v2_entry_ids
    report("Entries match", entries_match, f"vault1={len(v1_entry_ids)}, vault2={len(v2_entry_ids)}")

    # Decrypt and verify content
    decrypted_ok = 0
    decrypt_errors = 0
    content_match = True
    for eid in v1_entry_ids:
        try:
            e1 = vault.read_entry(eid)
            e2 = vault2.read_entry(eid)
            if e1["name"] != e2["name"]:
                content_match = False
                print(f"    Name mismatch for {eid}: '{e1['name']}' vs '{e2['name']}'")
            elif len(e1["fields"]) != len(e2["fields"]):
                content_match = False
                print(f"    Field count mismatch for {eid}")
            else:
                for f1, f2 in zip(e1["fields"], e2["fields"]):
                    if f1["key"] != f2["key"] or f1["value"] != f2["value"]:
                        content_match = False
                        print(f"    Field mismatch in {eid}: {f1['key']}!={f2['key']}")
            decrypted_ok += 1
        except Exception as ex:
            decrypt_errors += 1
            content_match = False
            print(f"    Decrypt error for {eid}: {ex}")

    report("Decrypt entries in vault2", decrypt_errors == 0, f"ok={decrypted_ok}, errors={decrypt_errors}")
    report("Entry content matches", content_match, f"compared {decrypted_ok} entries")

except Exception as e:
    report("Pull & verify", False, str(e))
    traceback.print_exc()


# ================================================================
# STEP 6: Verify on web (API pull)
# ================================================================
print("\n" + "=" * 60)
print("STEP 6: Verify data accessible via API")
print("=" * 60)

try:
    jwt3 = authenticate(kp)
    report("API re-authentication", True)

    sync_resp = api("GET", "/api/sync?since_commit_seq=0", token=jwt3)
    objects = sync_resp.get("objects", [])
    max_seq = sync_resp.get("max_commit_seq", 0)

    obj_types = {}
    for obj in objects:
        otype = obj["object_type"]
        obj_types[otype] = obj_types.get(otype, 0) + 1

    report(
        "API pull objects", len(objects) > 0,
        f"total={len(objects)}, types={obj_types}, max_seq={max_seq}"
    )

    # Verify counts
    expected_nodes = 5   # root + 4 folders
    expected_entries = 8
    actual_nodes = obj_types.get("node", 0)
    actual_entries = obj_types.get("entry", 0)
    actual_deks = obj_types.get("dek", 0)

    report("Object counts correct",
           actual_nodes == expected_nodes and actual_entries == expected_entries,
           f"nodes={actual_nodes}/{expected_nodes}, entries={actual_entries}/{expected_entries}, deks={actual_deks}")

    # Verify all have signatures
    signed = sum(1 for o in objects if o.get("client_signature"))
    report("All objects signed", signed == len(objects), f"{signed}/{len(objects)}")

    # Bootstrap status locked
    status_after = api("GET", "/api/bootstrap-status")
    report("Bootstrap locked", status_after["needs_setup"] is False, "needs_setup=false")

except Exception as e:
    report("API verification", False, str(e))
    traceback.print_exc()


# ================================================================
# STEP 7: Final report
# ================================================================
print("\n" + "=" * 60)
print("FINAL REPORT")
print("=" * 60)

passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total = len(results)

print()
for step, ok, detail in results:
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {step}" + (f" -- {detail}" if detail else ""))

print(f"\n  Total: {total} | Passed: {passed} | Failed: {failed}")

if failed > 0:
    print("\n  *** SOME TESTS FAILED ***")
    sys.exit(1)
else:
    print("\n  *** ALL TESTS PASSED ***")

# Cleanup
try:
    vault.lock()
except Exception:
    pass
try:
    vault2.lock()
except Exception:
    pass
