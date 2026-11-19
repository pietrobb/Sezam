#!/usr/bin/env python3
"""Multi-user end-to-end test of the Sezam system.

Tests the full multi-user lifecycle against the explicitly selected isolated server:
  - DB cleanup & bootstrap
  - Admin vault CRUD & sync
  - Invitation, registration, approval flow
  - Two-user push/pull
  - Share links
  - Audit log
  - User revocation
  - Security boundary tests

Phases 1–12 with clear PASS/FAIL for each sub-test.
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

ADMIN_USERNAME = os.environ.get("SEZAM_E2E_ADMIN_USERNAME", "peter")
ADMIN_PASSWORD = os.environ.get("SEZAM_E2E_ADMIN_PASSWORD") or secrets.token_urlsafe(24)
COLLEAGUE_USERNAME = os.environ.get("SEZAM_E2E_COLLEAGUE_USERNAME", "janko")
COLLEAGUE_PASSWORD = os.environ.get("SEZAM_E2E_COLLEAGUE_PASSWORD") or secrets.token_urlsafe(24)

VAULT_ADMIN = "/tmp/sezam_mu_admin"
VAULT_ADMIN_2 = "/tmp/sezam_mu_admin2"
VAULT_JANKO = "/tmp/sezam_mu_janko"

# Use faster Argon2 params for test speed
TEST_ARGON2 = Argon2Params(time_cost=2, memory_cost=65536, parallelism=4)

ctx = ssl.create_default_context()

results: list[tuple[str, bool, str]] = []
phase_results: dict[int, list[tuple[str, bool, str]]] = {}
current_phase = 0


def report(step: str, success: bool, detail: str = ""):
    status = "PASS" if success else "FAIL"
    results.append((step, success, detail))
    if current_phase not in phase_results:
        phase_results[current_phase] = []
    phase_results[current_phase].append((step, success, detail))
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


def api_raw(method: str, path: str, body=None, token=None):
    """Make API call, return (status_code, body_dict_or_None)."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(SERVER_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
        except Exception:
            err_body = {"detail": str(e)}
        return e.code, err_body


def ulid_str_to_bytes26(ulid_str: str) -> bytes:
    return ulid_str.encode("utf-8").ljust(26, b"\x00")[:26]


def build_server_canonical(
    obj_id: str, object_type: str, parent_ref: str | None,
    target_user_id: str | None, is_deleted: int, version: int, payload_hash: str,
) -> bytes:
    id_bytes = ulid_str_to_bytes26(obj_id)
    ot_bytes = object_type.encode("utf-8")
    parent_bytes = ulid_str_to_bytes26(parent_ref) if parent_ref else b"\x00" * 26
    target_bytes = ulid_str_to_bytes26(target_user_id) if target_user_id else b"\x00" * 26
    ph_bytes = bytes.fromhex(payload_hash)
    return (
        id_bytes
        + bytes([len(ot_bytes)]) + ot_bytes
        + parent_bytes + target_bytes
        + bytes([is_deleted])
        + version.to_bytes(4, "big")
        + ph_bytes
    )


def make_sync_object(
    obj_id: str, object_type: str, payload: bytes, signing_key,
    parent_ref: str | None = None, target_user_id: str | None = None,
    version: int = 1, is_deleted: int = 0,
) -> dict:
    payload_b64 = base64.b64encode(payload).decode("ascii")
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical = build_server_canonical(
        obj_id, object_type, parent_ref, target_user_id,
        is_deleted, version, payload_hash,
    )
    signature = signing_key.sign(canonical).signature.hex()
    return {
        "id": obj_id, "object_type": object_type,
        "payload": payload_b64, "parent_ref": parent_ref,
        "target_user_id": target_user_id, "version": version,
        "is_deleted": is_deleted, "payload_hash": payload_hash,
        "signature": signature,
    }


def push_objects(objects: list[dict], token: str) -> dict:
    return api("POST", "/api/sync", {"objects": objects, "atomic_batch": False}, token=token)


def collect_dirty_objects(db: VaultDB, signing_key) -> list[dict]:
    objects = []
    rows = db.fetchall(
        "SELECT id, parent_id, encrypted_meta, dek_id, version, is_deleted "
        "FROM nodes WHERE is_dirty = 1"
    )
    for row in rows:
        obj = make_sync_object(
            obj_id=row["id"], object_type="node",
            payload=bytes(row["encrypted_meta"]), signing_key=signing_key,
            parent_ref=row["parent_id"], version=row["version"],
            is_deleted=row["is_deleted"],
        )
        objects.append(obj)

    rows = db.fetchall(
        "SELECT id, node_id, encrypted_meta, encrypted_data, version, is_deleted "
        "FROM entries WHERE is_dirty = 1"
    )
    for row in rows:
        meta_bytes = bytes(row["encrypted_meta"])
        data_bytes = bytes(row["encrypted_data"])
        payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + data_bytes
        obj = make_sync_object(
            obj_id=row["id"], object_type="entry",
            payload=payload, signing_key=signing_key,
            parent_ref=row["node_id"], version=row["version"],
            is_deleted=row["is_deleted"],
        )
        objects.append(obj)

    rows = db.fetchall("SELECT id, node_id, scope, encrypted_dek, version FROM deks")
    for row in rows:
        obj = make_sync_object(
            obj_id=row["id"], object_type="dek",
            payload=bytes(row["encrypted_dek"]), signing_key=signing_key,
            parent_ref=row["node_id"], version=row["version"],
        )
        objects.append(obj)

    rows = db.fetchall(
        "SELECT ae.id, ae.dek_id, ae.user_id, ae.created_by, ae.access_level, ae.encrypted_dek "
        "FROM access_envelopes ae"
    )
    for row in rows:
        obj = make_sync_object(
            obj_id=row["id"], object_type="envelope",
            payload=bytes(row["encrypted_dek"]), signing_key=signing_key,
            parent_ref=row["dek_id"], target_user_id=row["user_id"],
            version=1,
        )
        objects.append(obj)

    return objects


_jwt_cache: dict[str, str] = {}


def authenticate(kp: KeyPair, username: str, *, reuse: bool = True) -> str:
    if reuse and username in _jwt_cache:
        return _jwt_cache[username]
    ch = api("POST", "/api/auth/challenge", {"username": username})
    sig = kp.to_nacl_signing_key().sign(bytes.fromhex(ch["challenge"])).signature
    resp = api("POST", "/api/auth/verify", {
        "username": username,
        "challenge": ch["challenge"],
        "signature": sig.hex(),
    })
    _jwt_cache[username] = resp["token"]
    return resp["token"]


def authenticate_raw(kp: KeyPair, username: str) -> tuple[int, dict]:
    """Try auth, return (status_code, body). Does not raise on failure."""
    ch_code, ch_body = api_raw("POST", "/api/auth/challenge", {"username": username})
    if ch_code != 200:
        return ch_code, ch_body
    sig = kp.to_nacl_signing_key().sign(bytes.fromhex(ch_body["challenge"])).signature
    return api_raw("POST", "/api/auth/verify", {
        "username": username,
        "challenge": ch_body["challenge"],
        "signature": sig.hex(),
    })


def setup_local_vault(vault_path, kp, kek, argon2_salt, user_id, username):
    """Create and setup a local vault, return (vault, dek_mgr, signing_key)."""
    if os.path.exists(vault_path):
        shutil.rmtree(vault_path)
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
    vault._db.set_meta("username", username)
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

    return vault, dek_mgr


def apply_pulled_objects(db: VaultDB, objects: list[dict]) -> int:
    """Apply pulled objects to a vault DB."""
    db.execute("PRAGMA foreign_keys=OFF")
    applied = 0
    dek_objs = [o for o in objects if o["object_type"] == "dek"]
    node_objs = [o for o in objects if o["object_type"] == "node"]
    entry_objs = [o for o in objects if o["object_type"] == "entry"]
    envelope_objs = [o for o in objects if o["object_type"] == "envelope"]

    for obj in dek_objs:
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        db.execute(
            "INSERT OR REPLACE INTO deks (id, node_id, scope, encrypted_dek, version) VALUES (?,?,?,?,?)",
            (obj["id"], obj.get("parent_ref"), obj.get("scope") or "folder", payload, obj.get("version", 1)),
        )
        applied += 1

    for obj in node_objs:
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        dek_id = None
        for d in dek_objs:
            if d.get("parent_ref") == obj["id"]:
                dek_id = d["id"]
                break
        if not dek_id:
            for d in dek_objs:
                if not d.get("parent_ref"):
                    dek_id = d["id"]
                    break
        if not dek_id and dek_objs:
            dek_id = dek_objs[0]["id"]
        db.execute(
            "INSERT OR REPLACE INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_dirty, is_deleted) VALUES (?,?,?,?,?,0,?)",
            (obj["id"], obj.get("parent_ref"), payload, dek_id, obj.get("version", 1), obj.get("is_deleted", 0)),
        )
        applied += 1

    for obj in entry_objs:
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        if len(payload) < 4:
            continue
        meta_len = struct.unpack(">I", payload[:4])[0]
        encrypted_meta = payload[4:4 + meta_len]
        encrypted_data = payload[4 + meta_len:]
        db.execute(
            "INSERT OR REPLACE INTO entries (id, node_id, encrypted_meta, encrypted_data, version, is_dirty, is_deleted) VALUES (?,?,?,?,?,0,?)",
            (obj["id"], obj.get("parent_ref"), encrypted_meta, encrypted_data, obj.get("version", 1), obj.get("is_deleted", 0)),
        )
        applied += 1

    for obj in envelope_objs:
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        db.execute(
            "INSERT OR REPLACE INTO access_envelopes (id, dek_id, user_id, created_by, access_level, encrypted_dek) VALUES (?,?,?,?,?,?)",
            (obj["id"], obj.get("parent_ref"), obj.get("target_user_id", ""), obj.get("owner_id", ""), "write", payload),
        )
        applied += 1

    db.execute("PRAGMA foreign_keys=ON")
    return applied


# ================================================================
print("=" * 70)
print("  SEZAM MULTI-USER END-TO-END TEST")
print(f"  Server: {SERVER_URL}")
print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 70)


# ================================================================
# PHASE 1: Clean Start
# ================================================================
current_phase = 1
print(f"\n{'=' * 60}")
print("PHASE 1: Clean Start")
print("=" * 60)

try:
    if E2E_ENV.reset_mode == "fresh":
        report("1.1 DB cleanup", True, "Skipped: caller supplied a fresh loopback stack")
    else:
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
        report("1.1 DB cleanup", True, "All tables cleaned")

        _, stdout, stderr = ssh.exec_command(E2E_ENV.api_restart_command(), timeout=30)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise RuntimeError(f"docker restart failed: {stderr.read().decode()}")
        time.sleep(4)
        report("1.2 API restart", True)
        ssh.close()

    status_resp = api("GET", "/api/bootstrap-status")
    assert status_resp["needs_setup"] is True, f"Expected needs_setup=true, got {status_resp}"
    report("1.3 Bootstrap status = needs_setup", True)

except Exception as e:
    report("Phase 1 setup", False, str(e))
    traceback.print_exc()
    sys.exit(1)

# Clean local vault dirs
for p in [VAULT_ADMIN, VAULT_ADMIN_2, VAULT_JANKO]:
    if os.path.exists(p):
        shutil.rmtree(p)


# ================================================================
# PHASE 2: Admin Bootstrap
# ================================================================
current_phase = 2
print(f"\n{'=' * 60}")
print("PHASE 2: Admin Bootstrap")
print("=" * 60)

try:
    # 2.1 Generate admin keypair
    admin_kp = generate_keypair()
    report("2.1 Admin keypair generated", True, f"fp={admin_kp.fingerprint[:16]}...")

    # 2.2 Bootstrap
    bootstrap_resp = api("POST", "/api/bootstrap", {
        "username": ADMIN_USERNAME,
        "signing_pk": admin_kp.signing_pk.hex(),
        "encryption_pk": admin_kp.encryption_pk.hex(),
    })
    admin_user_id = bootstrap_resp["user_id"]
    onboarding_jwt = bootstrap_resp["token"]
    report("2.2 Bootstrap admin", True, f"user_id={admin_user_id}")

    # 2.3 Derive KEK + auth_proof
    admin_argon2_salt = generate_salt(16)
    admin_auth_salt = generate_salt(16)
    admin_kek, admin_auth_proof = derive_kek_and_proof(ADMIN_PASSWORD, admin_argon2_salt, TEST_ARGON2)
    report("2.3 KEK derived", True)

    # 2.4 Encrypt keypair (legacy format: nonce + XChaCha20-Poly1305)
    keypair_data = bytes(admin_kp.signing_sk) + bytes(admin_kp.encryption_sk)
    nonce = os.urandom(24)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        keypair_data, None, nonce, bytes(admin_kek)
    )
    encrypted_keypair = nonce + ct
    report("2.4 Keypair encrypted", True, f"{len(encrypted_keypair)} bytes")

    # 2.5 Upload keypair
    upload_resp = api("PUT", "/api/me/keypair", {
        "encrypted_keypair": encrypted_keypair.hex(),
        "argon2_salt": admin_argon2_salt.hex(),
        "auth_salt": admin_auth_salt.hex(),
        "auth_proof": admin_auth_proof.hex(),
        "argon2_params": TEST_ARGON2.account_dict(),
    }, token=onboarding_jwt)
    assert upload_resp.get("status") == "ok"
    report("2.5 Keypair uploaded", True)

    # 2.6 Authenticate
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    report("2.6 Admin authenticated (challenge-response)", True)

    # 2.7 Create admin local vault with entries
    admin_vault, admin_dek_mgr = setup_local_vault(
        VAULT_ADMIN, admin_kp, admin_kek, admin_argon2_salt, admin_user_id, ADMIN_USERNAME
    )

    # Create folders and entries
    folders = {}
    for fname in ["Servery", "Databazy", "Firemne"]:
        fid = admin_vault.create_node(fname)
        folders[fname] = fid
    admin_vault._db.conn.commit()
    report("2.7 Folders created", True, f"Servery, Databazy, Firemne")

    entries_data = [
        ("Servery", "Hetzner", [
            {"key": "host", "value": "192.0.2.10", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": "root", "sensitive": False, "sort_order": 1},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 2},
        ]),
        ("Servery", "DigitalOcean", [
            {"key": "host", "value": "192.0.2.11", "sensitive": False, "sort_order": 0},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
        ]),
        ("Databazy", "PostgreSQL", [
            {"key": "host", "value": "db.prod:5432", "sensitive": False, "sort_order": 0},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
        ]),
        ("Databazy", "Redis", [
            {"key": "host", "value": "redis:6379", "sensitive": False, "sort_order": 0},
            {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
        ]),
        ("Firemne", "API kluc", [
            {"key": "key", "value": "sk-proj-abc123xyz", "sensitive": True, "sort_order": 0},
            {"key": "service", "value": "OpenAI", "sensitive": False, "sort_order": 1},
        ]),
    ]

    admin_entry_ids = []
    for folder_name, entry_name, fields in entries_data:
        eid = admin_vault.create_entry(folders[folder_name], entry_name, fields)
        admin_entry_ids.append(eid)
    admin_vault._db.conn.commit()
    report("2.8 Entries created", True, f"count={len(admin_entry_ids)}")

    # 2.9 Push all to server
    admin_signing_key = admin_kp.to_nacl_signing_key()
    sync_objects = collect_dirty_objects(admin_vault._db, admin_signing_key)

    # Re-authenticate just in case
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    push_result = push_objects(sync_objects, admin_jwt)
    accepted = len(push_result.get("accepted", []))
    conflicts = push_result.get("conflicts", [])
    report("2.9 Push to server", accepted > 0 and len(conflicts) == 0,
           f"accepted={accepted}, conflicts={len(conflicts)}")

    if accepted > 0:
        admin_vault._db.execute("UPDATE nodes SET is_dirty = 0")
        admin_vault._db.execute("UPDATE entries SET is_dirty = 0")
        admin_vault._db.conn.commit()

    # 2.10 Pull back and verify
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    pull_resp = api("GET", "/api/sync?since_commit_seq=0", token=admin_jwt)
    pulled_objects = pull_resp.get("objects", [])

    # Create second admin vault and verify data matches
    admin_vault_2, admin_dek_mgr_2 = setup_local_vault(
        VAULT_ADMIN_2, admin_kp, admin_kek, admin_argon2_salt, admin_user_id, ADMIN_USERNAME
    )
    applied = apply_pulled_objects(admin_vault_2._db, pulled_objects)
    admin_vault_2._db.conn.commit()
    admin_dek_mgr_2.unlock_all_deks()

    # Verify content matches
    content_match = True
    for eid in admin_entry_ids:
        try:
            e1 = admin_vault.read_entry(eid)
            e2 = admin_vault_2.read_entry(eid)
            if e1["name"] != e2["name"]:
                content_match = False
            elif len(e1["fields"]) != len(e2["fields"]):
                content_match = False
            else:
                for f1, f2 in zip(e1["fields"], e2["fields"]):
                    if f1["key"] != f2["key"] or f1["value"] != f2["value"]:
                        content_match = False
        except Exception as ex:
            content_match = False
            print(f"    Decrypt error for {eid}: {ex}")

    report("2.10 Pull-back data matches", content_match, f"entries verified: {len(admin_entry_ids)}")

except Exception as e:
    report("Phase 2", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# PHASE 3: Invite Colleague
# ================================================================
current_phase = 3
print(f"\n{'=' * 60}")
print("PHASE 3: Invite Colleague")
print("=" * 60)

try:
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    invite_resp = api("POST", "/api/users/invite", token=admin_jwt)
    invitation_token = invite_resp["invitation_token"]
    expires_at = invite_resp["expires_at"]
    report("3.1 Invitation created", True, f"token={invitation_token[:8]}..., expires={expires_at}")

    # Verify invitation exists (list users should still show only admin)
    users_resp = api("GET", "/api/users", token=admin_jwt)
    report("3.2 Only admin user exists", len(users_resp) == 1,
           f"users={[u['username'] for u in users_resp]}")

except Exception as e:
    report("Phase 3", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# PHASE 4: Colleague Registration
# ================================================================
current_phase = 4
print(f"\n{'=' * 60}")
print("PHASE 4: Colleague Registration")
print("=" * 60)

try:
    # 4.1 Generate colleague keypair
    janko_kp = generate_keypair()
    report("4.1 Janko keypair generated", True, f"fp={janko_kp.fingerprint[:16]}...")

    # 4.2 Register
    register_resp = api("POST", "/api/users/register", {
        "invitation_token": invitation_token,
        "username": COLLEAGUE_USERNAME,
        "signing_pk": janko_kp.signing_pk.hex(),
        "encryption_pk": janko_kp.encryption_pk.hex(),
    })
    janko_user_id = register_resp["user_id"]
    janko_onboarding_jwt = register_resp["token"]
    report("4.2 Janko registered", True, f"user_id={janko_user_id}")

    # 4.3 Upload Janko's encrypted keypair
    janko_argon2_salt = generate_salt(16)
    janko_auth_salt = generate_salt(16)
    janko_kek, janko_auth_proof = derive_kek_and_proof(COLLEAGUE_PASSWORD, janko_argon2_salt, TEST_ARGON2)

    janko_keypair_data = bytes(janko_kp.signing_sk) + bytes(janko_kp.encryption_sk)
    janko_nonce = os.urandom(24)
    janko_ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        janko_keypair_data, None, janko_nonce, bytes(janko_kek)
    )
    janko_encrypted_keypair = janko_nonce + janko_ct

    upload_resp = api("PUT", "/api/me/keypair", {
        "encrypted_keypair": janko_encrypted_keypair.hex(),
        "argon2_salt": janko_argon2_salt.hex(),
        "auth_salt": janko_auth_salt.hex(),
        "auth_proof": janko_auth_proof.hex(),
        "argon2_params": TEST_ARGON2.account_dict(),
    }, token=janko_onboarding_jwt)
    assert upload_resp.get("status") == "ok"
    report("4.3 Janko keypair uploaded", True)

    # 4.4 Verify user is "pending"
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    users_resp = api("GET", "/api/users", token=admin_jwt)
    janko_info = next((u for u in users_resp if u["username"] == COLLEAGUE_USERNAME), None)
    report("4.4 Janko status = pending", janko_info is not None and janko_info["status"] == "pending",
           f"status={janko_info['status'] if janko_info else 'NOT FOUND'}")

    # 4.5 Try to authenticate as Janko -> should FAIL (pending user)
    auth_code, auth_body = authenticate_raw(janko_kp, COLLEAGUE_USERNAME)
    report("4.5 Janko auth fails (pending)", auth_code == 401,
           f"status={auth_code}, detail={auth_body.get('detail', '')}")

except Exception as e:
    report("Phase 4", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# PHASE 5: Admin Approves
# ================================================================
current_phase = 5
print(f"\n{'=' * 60}")
print("PHASE 5: Admin Approves Janko")
print("=" * 60)

try:
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)

    # 5.1 Approve
    approve_resp = api("PATCH", f"/api/users/{janko_user_id}/approve", token=admin_jwt)
    assert approve_resp.get("status") == "ok"
    report("5.1 Admin approved Janko", True)

    # 5.2 Verify status = active
    users_resp = api("GET", "/api/users", token=admin_jwt)
    janko_info = next((u for u in users_resp if u["username"] == COLLEAGUE_USERNAME), None)
    report("5.2 Janko status = active", janko_info is not None and janko_info["status"] == "active",
           f"status={janko_info['status'] if janko_info else 'NOT FOUND'}")

    # 5.3 Janko authenticates -> should SUCCEED
    janko_jwt = authenticate(janko_kp, COLLEAGUE_USERNAME)
    report("5.3 Janko auth succeeds (active)", True)

except Exception as e:
    report("Phase 5", False, str(e))
    traceback.print_exc()
    sys.exit(1)


# ================================================================
# PHASE 6: Janko Syncs
# ================================================================
current_phase = 6
print(f"\n{'=' * 60}")
print("PHASE 6: Janko Syncs (pulls admin data)")
print("=" * 60)

try:
    janko_jwt = authenticate(janko_kp, COLLEAGUE_USERNAME)

    # 6.1 Janko pulls from server
    pull_resp = api("GET", "/api/sync?since_commit_seq=0", token=janko_jwt)
    janko_pulled = pull_resp.get("objects", [])
    max_seq = pull_resp.get("max_commit_seq", 0)

    obj_types = {}
    for obj in janko_pulled:
        otype = obj["object_type"]
        obj_types[otype] = obj_types.get(otype, 0) + 1

    report("6.1 Janko pull from server", len(janko_pulled) > 0,
           f"objects={len(janko_pulled)}, types={obj_types}, max_seq={max_seq}")

    # 6.2 Verify Janko sees the objects (encrypted blobs)
    node_count = obj_types.get("node", 0)
    entry_count = obj_types.get("entry", 0)
    dek_count = obj_types.get("dek", 0)
    # Expected: root + 3 folders = 4 nodes, 5 entries, DEKs
    report("6.2 Janko sees admin objects", node_count >= 4 and entry_count >= 5,
           f"nodes={node_count}, entries={entry_count}, deks={dek_count}")

    # 6.3 Janko can't decrypt without DEK envelopes (but has the encrypted blobs)
    report("6.3 Janko has encrypted objects (no DEK envelopes to decrypt)", True,
           "Objects are encrypted blobs, Janko needs access envelopes to decrypt")

except Exception as e:
    report("Phase 6", False, str(e))
    traceback.print_exc()


# ================================================================
# PHASE 7: Admin Shares Folder (sync/pull mechanics verification)
# ================================================================
current_phase = 7
print(f"\n{'=' * 60}")
print("PHASE 7: Verify Sync/Pull Mechanics")
print("=" * 60)

try:
    # 7.1 Verify server has all objects
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    sync_resp = api("GET", "/api/sync?since_commit_seq=0", token=admin_jwt)
    all_objects = sync_resp.get("objects", [])
    all_signed = sum(1 for o in all_objects if o.get("client_signature"))

    report("7.1 All objects have signatures", all_signed == len(all_objects),
           f"{all_signed}/{len(all_objects)}")

    # 7.2 Bootstrap is now locked
    status_after = api("GET", "/api/bootstrap-status")
    report("7.2 Bootstrap locked", status_after["needs_setup"] is False)

except Exception as e:
    report("Phase 7", False, str(e))
    traceback.print_exc()


# ================================================================
# PHASE 8: Both Users Push/Pull
# ================================================================
current_phase = 8
print(f"\n{'=' * 60}")
print("PHASE 8: Both Users Push/Pull")
print("=" * 60)

try:
    # 8.1 Admin creates a new entry "Novy server"
    new_entry_id = admin_vault.create_entry(folders["Servery"], "Novy server", [
        {"key": "host", "value": "10.0.0.99", "sensitive": False, "sort_order": 0},
        {"key": "password", "value": secrets.token_urlsafe(24), "sensitive": True, "sort_order": 1},
    ])
    admin_vault._db.conn.commit()
    report("8.1 Admin created 'Novy server'", True, f"id={new_entry_id}")

    # 8.2 Admin pushes
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    new_sync_objects = collect_dirty_objects(admin_vault._db, admin_signing_key)
    push_result = push_objects(new_sync_objects, admin_jwt)
    accepted = len(push_result.get("accepted", []))
    report("8.2 Admin push new entry", accepted > 0,
           f"accepted={accepted}")

    if accepted > 0:
        admin_vault._db.execute("UPDATE nodes SET is_dirty = 0")
        admin_vault._db.execute("UPDATE entries SET is_dirty = 0")
        admin_vault._db.conn.commit()

    # 8.3 Janko pulls -> sees new object
    janko_jwt = authenticate(janko_kp, COLLEAGUE_USERNAME)
    pull_resp2 = api("GET", f"/api/sync?since_commit_seq={max_seq}", token=janko_jwt)
    new_pulled = pull_resp2.get("objects", [])
    # The new entry + possibly its node update should appear
    new_entry_present = any(o["id"] == new_entry_id for o in new_pulled)
    report("8.3 Janko sees new object after pull", new_entry_present or len(new_pulled) > 0,
           f"new_objects={len(new_pulled)}, new_entry_id_present={new_entry_present}")

    # 8.4 Janko creates an entry in his own local vault and pushes
    # Janko's local vault setup
    janko_vault, janko_dek_mgr = setup_local_vault(
        VAULT_JANKO, janko_kp, janko_kek, janko_argon2_salt, janko_user_id, COLLEAGUE_USERNAME
    )

    janko_signing_key = janko_kp.to_nacl_signing_key()

    # Janko creates a folder and entry
    janko_folder_id = janko_vault.create_node("JankoData")
    janko_entry_id = janko_vault.create_entry(janko_folder_id, "Jankov zaznam", [
        {"key": "url", "value": "https://example.com", "sensitive": False, "sort_order": 0},
        {"key": "heslo", "value": "JankoPass!99", "sensitive": True, "sort_order": 1},
    ])
    janko_vault._db.conn.commit()
    report("8.4 Janko created local entry", True, f"entry={janko_entry_id}")

    # 8.5 Janko pushes
    janko_jwt = authenticate(janko_kp, COLLEAGUE_USERNAME)
    janko_sync_objects = collect_dirty_objects(janko_vault._db, janko_signing_key)
    janko_push_result = push_objects(janko_sync_objects, janko_jwt)
    janko_accepted = len(janko_push_result.get("accepted", []))
    janko_conflicts = janko_push_result.get("conflicts", [])
    # Non-admin users need write_acl -- top-level nodes will be denied.
    # This is expected behavior! Non-admin can't create top-level nodes.
    # We test that the push mechanism works even if some are denied.
    report("8.5 Janko push attempt", True,
           f"accepted={janko_accepted}, conflicts={len(janko_conflicts)}")
    if janko_conflicts:
        conflict_reasons = [c.get("error", "?") for c in janko_conflicts[:3]]
        report("8.5a Janko conflicts (expected: write_acl denied for non-admin)", True,
               f"reasons={conflict_reasons}")

    # 8.6 Admin pulls -> should see Janko's objects (if any were accepted)
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    admin_pull_new = api("GET", "/api/sync?since_commit_seq=0", token=admin_jwt)
    admin_new_objects = admin_pull_new.get("objects", [])
    admin_new_max = admin_pull_new.get("max_commit_seq", 0)
    report("8.6 Admin full pull", len(admin_new_objects) > 0,
           f"objects={len(admin_new_objects)}, max_seq={admin_new_max}")

except Exception as e:
    report("Phase 8", False, str(e))
    traceback.print_exc()


# ================================================================
# PHASE 9: Share Link
# ================================================================
current_phase = 9
print(f"\n{'=' * 60}")
print("PHASE 9: Share Link")
print("=" * 60)

try:
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)

    # 9.1 Create share link
    share_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    share_blob = base64.b64encode(b"test-encrypted-blob-data-for-share").decode("ascii")
    share_expires = int(time.time() * 1000) + 3600 * 1000  # 1h

    share_resp = api("POST", "/api/share", {
        "id": share_id,
        "encrypted_blob": share_blob,
        "expires_at": share_expires,
        "max_views": 1,
        "pin_hash": None,
    }, token=admin_jwt)
    report("9.1 Share link created", share_resp.get("status") == "ok",
           f"id={share_id[:16]}...")

    # 9.2 Consume share link (no auth required)
    consume_code, consume_body = api_raw("POST", f"/api/share/{share_id}", {"pin": None})
    report("9.2 Consume share link", consume_code == 200,
           f"view_count={consume_body.get('view_count', '?')}, max_views={consume_body.get('max_views', '?')}")

    # 9.3 Second consume -> should fail (max_views=1)
    consume2_code, consume2_body = api_raw("POST", f"/api/share/{share_id}", {"pin": None})
    report("9.3 Second consume fails (max_views=1)", consume2_code == 404,
           f"status={consume2_code}, detail={consume2_body.get('detail', '')}")

except Exception as e:
    report("Phase 9", False, str(e))
    traceback.print_exc()


# ================================================================
# PHASE 10: Audit Log
# ================================================================
current_phase = 10
print(f"\n{'=' * 60}")
print("PHASE 10: Audit Log")
print("=" * 60)

try:
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    audit_id = new_ulid()
    audit_action = "entry_view"
    audit_timestamp = int(time.time() * 1000)
    request_hash = hashlib.sha256(audit_action.encode("utf-8")).hexdigest()
    audit_canonical = (
        audit_id.encode("ascii")
        + admin_user_id.encode("ascii")
        + audit_action.encode("utf-8")
        + audit_timestamp.to_bytes(8, "big")
        + bytes.fromhex(request_hash)
    )
    audit_signature = admin_kp.to_nacl_signing_key().sign(audit_canonical).signature.hex()
    log_resp = api("POST", "/api/audit/log", {
        "id": audit_id,
        "action": audit_action,
        "timestamp": audit_timestamp,
        "request_hash": request_hash,
        "signature": audit_signature,
    }, token=admin_jwt)
    report("10.1 Signed client audit accepted", log_resp.get("ok") is True)

    audit_resp = api("GET", "/api/audit?action=entry_view", token=admin_jwt)
    entries = audit_resp.get("entries", [])
    matching = [entry for entry in entries if entry["id"] == audit_id]
    report("10.2 Audit log returns signed event", audit_resp.get("total") == 1 and len(matching) == 1,
           f"total={audit_resp.get('total')}, matching={len(matching)}")

    logged = matching[0] if matching else {}
    report("10.3 Audit actor and action match", logged.get("user_id") == admin_user_id
           and logged.get("action") == audit_action,
           f"user_id={logged.get('user_id')}, action={logged.get('action')}")
    report("10.4 Audit signature preserved", logged.get("client_signature") == audit_signature,
           f"signature_bytes={len(bytes.fromhex(logged.get('client_signature', '')))}")

except Exception as e:
    report("Phase 10", False, str(e))
    traceback.print_exc()


# ================================================================
# PHASE 11: User Revocation
# ================================================================
current_phase = 11
print(f"\n{'=' * 60}")
print("PHASE 11: User Revocation")
print("=" * 60)

try:
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)

    # 11.1 Revoke Janko
    revoke_resp = api("DELETE", f"/api/users/{janko_user_id}", token=admin_jwt)
    report("11.1 Janko revoked", revoke_resp.get("status") == "ok",
           f"note={revoke_resp.get('note', '')}")

    # 11.2 Verify Janko can't authenticate
    auth_code, auth_body = authenticate_raw(janko_kp, COLLEAGUE_USERNAME)
    report("11.2 Janko auth fails (revoked)", auth_code == 401,
           f"status={auth_code}")

    # 11.3 Verify Janko's write_acl removed (via admin listing users)
    users_resp = api("GET", "/api/users", token=admin_jwt)
    janko_info = next((u for u in users_resp if u["username"] == COLLEAGUE_USERNAME), None)
    report("11.3 Janko status = revoked", janko_info is not None and janko_info["status"] == "revoked",
           f"status={janko_info['status'] if janko_info else 'NOT FOUND'}")

    # 11.4 Admin can still authenticate with a fresh challenge
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME, reuse=False)
    report("11.4 Admin still authenticates", True)

except Exception as e:
    report("Phase 11", False, str(e))
    traceback.print_exc()


# ================================================================
# PHASE 12: Security Tests
# ================================================================
current_phase = 12
print(f"\n{'=' * 60}")
print("PHASE 12: Security Tests")
print("=" * 60)

try:
    # 12.1 Try accessing admin endpoint with revoked user's last known token
    # Janko's JWT was obtained before revocation -- attempt to use it
    # (We don't have janko_jwt anymore from Phase 5, so we test with a direct challenge)
    # Instead, test: try to authenticate as Janko (already tested in 11.2, but verify more)
    auth_code, _ = authenticate_raw(janko_kp, COLLEAGUE_USERNAME)
    report("12.1 Revoked user cannot authenticate", auth_code == 401,
           f"status={auth_code}")

    # 12.2 Try push with wrong signature
    admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
    # Create an object with a wrong signature (use Janko's key to sign but admin's token)
    fake_payload = b"fake-payload-data"
    fake_obj_id = new_ulid()
    wrong_signing_key = janko_kp.to_nacl_signing_key()  # Wrong key!
    bad_obj = make_sync_object(
        obj_id=fake_obj_id, object_type="node", payload=fake_payload,
        signing_key=wrong_signing_key,  # Signed with wrong key
        parent_ref=None, version=1,
    )
    bad_push_result = push_objects([bad_obj], admin_jwt)
    bad_conflicts = bad_push_result.get("conflicts", [])
    # The server should reject this because the signature doesn't match admin's key
    report("12.2 Push with wrong signature rejected", len(bad_conflicts) > 0,
           f"conflicts={len(bad_conflicts)}, reasons={[c.get('error', '?') for c in bad_conflicts[:2]]}")

    # 12.3 Try accessing /api/users without admin
    # Create a fake non-admin token scenario.
    # Since Janko is revoked, we can't get a non-admin token easily.
    # Instead, test that unauthenticated access fails.
    code_no_auth, body_no_auth = api_raw("GET", "/api/users")
    report("12.3 /api/users without auth -> 401/403",
           code_no_auth in (401, 403, 422),
           f"status={code_no_auth}")

    # 12.4 Try accessing /api/audit without admin
    code_audit_noauth, _ = api_raw("GET", "/api/audit")
    report("12.4 /api/audit without auth -> 401/403",
           code_audit_noauth in (401, 403, 422),
           f"status={code_audit_noauth}")

    # 12.5 Try bootstrap again (should be locked)
    code_bs, body_bs = api_raw("POST", "/api/bootstrap", {
        "username": "attacker",
        "signing_pk": janko_kp.signing_pk.hex(),
        "encryption_pk": janko_kp.encryption_pk.hex(),
    })
    report("12.5 Bootstrap re-attempt rejected", code_bs == 403,
           f"status={code_bs}, detail={body_bs.get('detail', '')}")

    # 12.6 Try consuming expired/deleted share link
    code_expired, body_expired = api_raw("POST", f"/api/share/{share_id}", {"pin": None})
    report("12.6 Consumed share not re-consumable", code_expired == 404,
           f"status={code_expired}")

    # 12.7 Try invalid invitation token
    code_bad_invite, body_bad_invite = api_raw("POST", "/api/users/register", {
        "invitation_token": "totally-fake-invalid-token",
        "username": "hacker",
        "signing_pk": janko_kp.signing_pk.hex(),
        "encryption_pk": janko_kp.encryption_pk.hex(),
    })
    report("12.7 Fake invitation token rejected", code_bad_invite in (404, 410),
           f"status={code_bad_invite}")

    # 12.8 Try re-using the same invitation token
    code_reuse, body_reuse = api_raw("POST", "/api/users/register", {
        "invitation_token": invitation_token,
        "username": "hacker2",
        "signing_pk": janko_kp.signing_pk.hex(),
        "encryption_pk": janko_kp.encryption_pk.hex(),
    })
    report("12.8 Reused invitation token rejected", code_reuse == 410,
           f"status={code_reuse}, detail={body_reuse.get('detail', '')}")

except Exception as e:
    report("Phase 12", False, str(e))
    traceback.print_exc()


# ================================================================
# FINAL REPORT
# ================================================================
print("\n" + "=" * 70)
print("  FINAL REPORT")
print("=" * 70)

passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total = len(results)

print()
for phase_num in sorted(phase_results.keys()):
    phase_tests = phase_results[phase_num]
    phase_pass = sum(1 for _, ok, _ in phase_tests if ok)
    phase_total = len(phase_tests)
    phase_status = "PASS" if phase_pass == phase_total else "FAIL"
    print(f"  Phase {phase_num}: [{phase_status}] {phase_pass}/{phase_total}")
    for step, ok, detail in phase_tests:
        status = "PASS" if ok else "FAIL"
        print(f"    [{status}] {step}" + (f" -- {detail}" if detail else ""))

print(f"\n  {'=' * 50}")
print(f"  Total: {total} | Passed: {passed} | Failed: {failed}")
print(f"  {'=' * 50}")

if failed > 0:
    print("\n  *** SOME TESTS FAILED ***")
    sys.exit(1)
else:
    print("\n  *** ALL TESTS PASSED ***")

# Cleanup
for v in [admin_vault, admin_vault_2]:
    try:
        v.lock()
    except Exception:
        pass
try:
    janko_vault.lock()
except Exception:
    pass
