#!/usr/bin/env python3
"""Stress test of the Sezam system against the live server.

Phases:
  1. Clean DB via SSH
  2. Bootstrap admin
  3. Create 30 users (invite, register, approve, verify auth)
  4. Push 1000 entries (20 folders x 50 entries each, batched)
  5. 10 users push simultaneously (100 entries)
  6. 30 users pull full vault
  7. 50 share links create + consume
  8. Audit log verification
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import secrets
import shutil
import ssl
import string
import struct
import sys
import time
import traceback
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from e2e_environment import E2EEnvironment
import paramiko
import nacl.bindings
from nacl.signing import SigningKey
from nacl.public import PrivateKey as X25519PrivateKey
from ulid import ULID

# Add project source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof, generate_salt
from sezam.crypto.keys import KeyPair, generate_keypair
from sezam.crypto.aead import BlobKind, encrypt
from sezam.models import new_ulid, ulid_to_bytes, EntryData, EntryField, EntryMeta, NodeMeta

# ── Config ──
E2E_ENV = E2EEnvironment.from_environ()
SSH_HOST = E2E_ENV.ssh_host
SSH_PORT = E2E_ENV.ssh_port
SSH_USER = E2E_ENV.ssh_user
SSH_PASSWORD = E2E_ENV.ssh_password
SERVER_URL = E2E_ENV.server_url

ADMIN_USERNAME = os.environ.get("SEZAM_STRESS_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("SEZAM_STRESS_ADMIN_PASSWORD") or secrets.token_urlsafe(24)

NUM_USERS = 30
NUM_FOLDERS = 20
ENTRIES_PER_FOLDER = 50
BATCH_SIZE = 50
NUM_CONCURRENT_USERS = 10
ENTRIES_PER_CONCURRENT_USER = 10
NUM_SHARES = 50

# Fast Argon2 params for test speed
TEST_ARGON2 = Argon2Params(time_cost=1, memory_cost=16384, parallelism=1)

ctx = ssl.create_default_context()

FOLDER_NAMES = [
    "Servery", "Databázy", "Email", "VPN", "API",
    "Cloud", "Bankovníctvo", "Sociálne siete", "Interne", "Zálohy",
    "Monitorovanie", "DNS", "SSL", "Docker", "Kubernetes",
    "GitLab", "Jenkins", "AWS", "Azure", "GCP",
]

# ── Realistic data generators ──

HOSTNAMES = [
    "web01.firma.sk", "web02.firma.sk", "web03.firma.sk",
    "db-prod-01.internal", "db-prod-02.internal", "db-prod-03.internal",
    "db-staging.internal", "db-dev.internal",
    "mail01.firma.sk", "mail02.firma.sk",
    "vpn-gw.firma.sk", "vpn-backup.firma.sk",
    "api-prod.firma.sk", "api-staging.firma.sk",
    "cloud-gw.firma.sk", "backup01.internal",
    "monitor.firma.sk", "grafana.firma.sk",
    "dns1.firma.sk", "dns2.firma.sk",
    "proxy-01.firma.sk", "proxy-02.firma.sk",
    "k8s-master.internal", "k8s-worker-01.internal",
    "k8s-worker-02.internal", "k8s-worker-03.internal",
    "gitlab.firma.sk", "jenkins.firma.sk",
    "docker-registry.firma.sk", "nexus.firma.sk",
    "redis-prod.internal", "redis-cache.internal",
    "elastic-01.internal", "elastic-02.internal",
    "kafka-01.internal", "kafka-02.internal",
    "rabbitmq.internal", "vault.firma.sk",
    "ldap.firma.sk", "sso.firma.sk",
]

FIRST_NAMES = [
    "jan", "peter", "martin", "tomas", "jozef", "juraj", "milan", "andrej",
    "marek", "stefan", "roman", "richard", "michal", "vladimir", "lukas",
    "patrik", "daniel", "filip", "adam", "matej", "samuel", "jakub",
    "simon", "ondrej", "gabriel", "dominik", "erik", "ivan", "robert", "tibor",
]

LAST_NAMES = [
    "novak", "horvath", "kovac", "varga", "toth", "szabo", "molnar", "kiss",
    "nagy", "benes", "kral", "polak", "janak", "hruska", "mraz", "sokol",
    "vlk", "urban", "cernok", "dolezal", "simko", "rusnak", "bartos", "pavelka",
    "kucera", "nemec", "vesely", "soukup", "blazek", "fiala",
]

PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9090, 9200, 27017, 1433, 5672, 15672, 2379]

DB_NAMES = [
    "production_main", "production_users", "staging_app", "analytics_dw",
    "reporting_db", "inventory_db", "crm_data", "billing_prod",
    "logs_archive", "sessions_store", "audit_trail", "config_db",
]

SMTP_SERVERS = [
    "smtp.firma.sk", "mail.firma.sk", "mx1.firma.sk", "mx2.firma.sk",
    "smtp.gmail.com", "smtp.office365.com",
]

API_ENDPOINTS = [
    "https://api.firma.sk/v1", "https://api.firma.sk/v2",
    "https://staging-api.firma.sk", "https://internal-api.firma.sk",
    "https://api.stripe.com/v1", "https://api.twilio.com",
    "https://api.sendgrid.com/v3", "https://api.cloudflare.com/client/v4",
]

DOC_URLS = [
    "https://docs.firma.sk/api", "https://wiki.firma.sk/internal",
    "https://confluence.firma.sk", "https://notion.firma.sk",
]


def random_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%&*"
    return "".join(random.choices(chars, k=length))


def random_api_key():
    return "ak_live_" + os.urandom(16).hex()


def random_secret():
    return "sk_live_" + os.urandom(20).hex()


def random_email():
    fn = random.choice(FIRST_NAMES)
    ln = random.choice(LAST_NAMES)
    return f"{fn}.{ln}@firma.sk"


def random_conn_string(host, db, user, password, port):
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def generate_entry_fields(folder_name: str, entry_idx: int) -> tuple[str, list[dict]]:
    """Generate realistic entry name + fields based on folder category."""
    idx = entry_idx
    hostname = random.choice(HOSTNAMES)
    pw = random_password()

    if folder_name in ("Servery", "Docker", "Kubernetes"):
        name = f"{hostname}-{idx:02d}"
        port = random.choice([22, 80, 443, 8080, 8443])
        fields = [
            {"key": "host", "value": hostname, "sensitive": False, "sort_order": 0},
            {"key": "port", "value": str(port), "sensitive": False, "sort_order": 1},
            {"key": "username", "value": random.choice(["root", "deploy", "admin", "sysadmin"]), "sensitive": False, "sort_order": 2},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 3},
            {"key": "notes", "value": f"Server {idx:02d} in {folder_name} cluster", "sensitive": False, "sort_order": 4},
        ]
    elif folder_name in ("Databázy",):
        db = random.choice(DB_NAMES)
        port = random.choice([3306, 5432, 27017, 1433, 6379])
        user = random.choice(["app_user", "readonly", "admin", "migration", "backup_agent"])
        name = f"{db}-{idx:02d}"
        fields = [
            {"key": "host", "value": hostname, "sensitive": False, "sort_order": 0},
            {"key": "database", "value": db, "sensitive": False, "sort_order": 1},
            {"key": "user", "value": user, "sensitive": False, "sort_order": 2},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 3},
            {"key": "connection_string", "value": random_conn_string(hostname, db, user, pw, port), "sensitive": True, "sort_order": 4},
            {"key": "port", "value": str(port), "sensitive": False, "sort_order": 5},
        ]
    elif folder_name in ("Email",):
        email = random_email()
        smtp = random.choice(SMTP_SERVERS)
        name = f"email-{email.split('@')[0]}-{idx:02d}"
        fields = [
            {"key": "address", "value": email, "sensitive": False, "sort_order": 0},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 1},
            {"key": "smtp_server", "value": smtp, "sensitive": False, "sort_order": 2},
            {"key": "smtp_port", "value": str(random.choice([25, 465, 587])), "sensitive": False, "sort_order": 3},
        ]
    elif folder_name in ("VPN",):
        name = f"vpn-config-{idx:02d}"
        fields = [
            {"key": "server", "value": f"vpn{random.randint(1,5)}.firma.sk", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": random_email().split("@")[0], "sensitive": False, "sort_order": 1},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 2},
            {"key": "protocol", "value": random.choice(["OpenVPN", "WireGuard", "IPSec"]), "sensitive": False, "sort_order": 3},
            {"key": "port", "value": str(random.choice([1194, 51820, 500])), "sensitive": False, "sort_order": 4},
        ]
    elif folder_name in ("API", "AWS", "Azure", "GCP"):
        endpoint = random.choice(API_ENDPOINTS)
        name = f"api-key-{folder_name.lower()}-{idx:02d}"
        fields = [
            {"key": "endpoint", "value": endpoint, "sensitive": False, "sort_order": 0},
            {"key": "api_key", "value": random_api_key(), "sensitive": True, "sort_order": 1},
            {"key": "secret", "value": random_secret(), "sensitive": True, "sort_order": 2},
            {"key": "documentation_url", "value": random.choice(DOC_URLS), "sensitive": False, "sort_order": 3},
        ]
    elif folder_name in ("Cloud",):
        name = f"cloud-instance-{idx:02d}"
        fields = [
            {"key": "provider", "value": random.choice(["AWS", "GCP", "Azure", "DigitalOcean", "Hetzner"]), "sensitive": False, "sort_order": 0},
            {"key": "instance_id", "value": f"i-{os.urandom(8).hex()}", "sensitive": False, "sort_order": 1},
            {"key": "api_key", "value": random_api_key(), "sensitive": True, "sort_order": 2},
            {"key": "secret", "value": random_secret(), "sensitive": True, "sort_order": 3},
            {"key": "region", "value": random.choice(["eu-central-1", "us-east-1", "eu-west-1", "ap-southeast-1"]), "sensitive": False, "sort_order": 4},
        ]
    elif folder_name in ("Bankovníctvo",):
        name = f"bank-account-{idx:02d}"
        fields = [
            {"key": "bank", "value": random.choice(["Tatra banka", "VUB", "CSOB", "Slovenská sporiteľňa", "mBank"]), "sensitive": False, "sort_order": 0},
            {"key": "iban", "value": f"SK{random.randint(10,99)}{random.randint(1000,9999)}{os.urandom(6).hex()[:12]}", "sensitive": True, "sort_order": 1},
            {"key": "login", "value": random_email().split("@")[0], "sensitive": False, "sort_order": 2},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 3},
        ]
    elif folder_name in ("Sociálne siete",):
        name = f"social-{random.choice(['twitter','facebook','linkedin','instagram','github'])}-{idx:02d}"
        fields = [
            {"key": "url", "value": f"https://{random.choice(['twitter.com','facebook.com','linkedin.com','instagram.com','github.com'])}/firma", "sensitive": False, "sort_order": 0},
            {"key": "email", "value": random_email(), "sensitive": False, "sort_order": 1},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 2},
        ]
    elif folder_name in ("Interne",):
        name = f"internal-service-{idx:02d}"
        fields = [
            {"key": "url", "value": f"https://internal-{idx:02d}.firma.sk", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": random.choice(["admin", "operator", "service-account"]), "sensitive": False, "sort_order": 1},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 2},
            {"key": "notes", "value": f"Internal service #{idx}", "sensitive": False, "sort_order": 3},
        ]
    elif folder_name in ("Zálohy",):
        name = f"backup-config-{idx:02d}"
        fields = [
            {"key": "target", "value": f"s3://backups-firma/{random.choice(['daily','weekly','monthly'])}/", "sensitive": False, "sort_order": 0},
            {"key": "access_key", "value": random_api_key(), "sensitive": True, "sort_order": 1},
            {"key": "secret_key", "value": random_secret(), "sensitive": True, "sort_order": 2},
            {"key": "schedule", "value": random.choice(["0 2 * * *", "0 3 * * 0", "0 1 1 * *"]), "sensitive": False, "sort_order": 3},
        ]
    elif folder_name in ("Monitorovanie",):
        name = f"monitoring-{random.choice(['grafana','prometheus','alertmanager','datadog','newrelic'])}-{idx:02d}"
        fields = [
            {"key": "url", "value": f"https://monitoring-{idx:02d}.firma.sk", "sensitive": False, "sort_order": 0},
            {"key": "api_key", "value": random_api_key(), "sensitive": True, "sort_order": 1},
            {"key": "username", "value": "admin", "sensitive": False, "sort_order": 2},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 3},
        ]
    elif folder_name in ("DNS",):
        name = f"dns-zone-{idx:02d}"
        fields = [
            {"key": "provider", "value": random.choice(["Cloudflare", "Route53", "Google DNS", "NS1"]), "sensitive": False, "sort_order": 0},
            {"key": "zone", "value": f"zone-{idx:02d}.firma.sk", "sensitive": False, "sort_order": 1},
            {"key": "api_token", "value": random_api_key(), "sensitive": True, "sort_order": 2},
        ]
    elif folder_name in ("SSL",):
        name = f"ssl-cert-{idx:02d}"
        fields = [
            {"key": "domain", "value": f"*.{random.choice(['firma.sk','app.firma.sk','api.firma.sk'])}", "sensitive": False, "sort_order": 0},
            {"key": "provider", "value": random.choice(["Let's Encrypt", "DigiCert", "Sectigo", "Comodo"]), "sensitive": False, "sort_order": 1},
            {"key": "private_key_passphrase", "value": pw, "sensitive": True, "sort_order": 2},
            {"key": "expiry", "value": f"2026-{random.randint(1,12):02d}-{random.randint(1,28):02d}", "sensitive": False, "sort_order": 3},
        ]
    elif folder_name in ("GitLab",):
        name = f"gitlab-token-{idx:02d}"
        fields = [
            {"key": "url", "value": "https://gitlab.firma.sk", "sensitive": False, "sort_order": 0},
            {"key": "token_name", "value": f"deploy-token-{idx:02d}", "sensitive": False, "sort_order": 1},
            {"key": "token", "value": f"glpat-{os.urandom(20).hex()}", "sensitive": True, "sort_order": 2},
            {"key": "scope", "value": random.choice(["read_api", "write_repository", "read_registry", "api"]), "sensitive": False, "sort_order": 3},
        ]
    elif folder_name in ("Jenkins",):
        name = f"jenkins-credential-{idx:02d}"
        fields = [
            {"key": "url", "value": "https://jenkins.firma.sk", "sensitive": False, "sort_order": 0},
            {"key": "username", "value": random.choice(["admin", "deployer", "ci-bot"]), "sensitive": False, "sort_order": 1},
            {"key": "api_token", "value": f"jenkins-{os.urandom(16).hex()}", "sensitive": True, "sort_order": 2},
        ]
    else:
        # Fallback: generic
        name = f"{folder_name}-entry-{idx:02d}"
        fields = [
            {"key": "host", "value": hostname, "sensitive": False, "sort_order": 0},
            {"key": "username", "value": "admin", "sensitive": False, "sort_order": 1},
            {"key": "password", "value": pw, "sensitive": True, "sort_order": 2},
        ]

    return name, fields


# ── API helpers ──

def api(method: str, path: str, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(SERVER_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        return json.loads(r.read())


def api_raw(method: str, path: str, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(SERVER_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
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


def authenticate(kp: KeyPair, username: str) -> str:
    ch = api("POST", "/api/auth/challenge", {"username": username})
    sig = kp.to_nacl_signing_key().sign(bytes.fromhex(ch["challenge"])).signature
    resp = api("POST", "/api/auth/verify", {
        "username": username,
        "challenge": ch["challenge"],
        "signature": sig.hex(),
    })
    return resp["token"]


# ── Crypto helpers for building sync objects without local vault ──

def make_dek_and_wrap(dek_key: bytes, wrapping_key: bytes, wrapping_key_id: str, dek_id: str, node_id: str | None, scope: str, signing_key) -> dict:
    """Create a DEK object that wraps dek_key with wrapping_key."""
    from sezam.crypto.aead import encrypt_dek_wrap
    encrypted_dek = encrypt_dek_wrap(
        dek_to_wrap=dek_key,
        wrapping_key=wrapping_key,
        wrapping_key_id=ulid_to_bytes(wrapping_key_id),
        dek_archive_id=ulid_to_bytes(dek_id),
    )
    return make_sync_object(
        obj_id=dek_id, object_type="dek",
        payload=encrypted_dek, signing_key=signing_key,
        parent_ref=node_id, version=1,
    )


def make_node_object(node_id: str, parent_ref: str | None, name: str, dek: bytes, dek_id: str, signing_key) -> dict:
    """Create a node sync object."""
    meta = NodeMeta(name=name)
    encrypted_meta = encrypt(
        plaintext=meta.to_json(),
        dek=dek,
        dek_id=ulid_to_bytes(dek_id),
        object_id=ulid_to_bytes(node_id),
        version=1,
        blob_kind=BlobKind.NODE_META,
    )
    return make_sync_object(
        obj_id=node_id, object_type="node",
        payload=encrypted_meta, signing_key=signing_key,
        parent_ref=parent_ref, version=1,
    )


def make_entry_object(entry_id: str, node_id: str, name: str, fields: list[dict], dek: bytes, dek_id: str, signing_key) -> dict:
    """Create an entry sync object."""
    entry_meta = EntryMeta(name=name)
    entry_data = EntryData(fields=[EntryField.from_dict(f) for f in fields])

    encrypted_meta = encrypt(
        plaintext=entry_meta.to_json(),
        dek=dek,
        dek_id=ulid_to_bytes(dek_id),
        object_id=ulid_to_bytes(entry_id),
        version=1,
        blob_kind=BlobKind.ENTRY_META,
    )
    encrypted_data = encrypt(
        plaintext=entry_data.to_json(),
        dek=dek,
        dek_id=ulid_to_bytes(dek_id),
        object_id=ulid_to_bytes(entry_id),
        version=1,
        blob_kind=BlobKind.ENTRY_DATA,
    )

    payload = struct.pack(">I", len(encrypted_meta)) + encrypted_meta + encrypted_data
    return make_sync_object(
        obj_id=entry_id, object_type="entry",
        payload=payload, signing_key=signing_key,
        parent_ref=node_id, version=1,
    )


# ── Timing helpers ──

phase_timings: dict[int, float] = {}


def timed_phase(phase_num):
    """Decorator / context for timing phases."""
    class Timer:
        def __enter__(self):
            self.start = time.perf_counter()
            return self
        def __exit__(self, *args):
            phase_timings[phase_num] = time.perf_counter() - self.start
    return Timer()


# ================================================================
print("=" * 70)
print("  SEZAM STRESS TEST")
print(f"  Server: {SERVER_URL}")
print(f"  Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  Plan: {NUM_USERS} users, {NUM_FOLDERS}x{ENTRIES_PER_FOLDER}={NUM_FOLDERS*ENTRIES_PER_FOLDER} entries, {NUM_SHARES} shares")
print("=" * 70)

total_start = time.perf_counter()

# ================================================================
# PHASE 1: Clean DB
# ================================================================
print(f"\n{'=' * 60}")
print("PHASE 1: Clean DB")
print("=" * 60)

with timed_phase(1):
    try:
        if E2E_ENV.reset_mode == "fresh":
            print("  [OK] DB cleanup skipped: caller supplied a fresh loopback stack")
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
            print("  [OK] DB cleaned")

            _, stdout, stderr = ssh.exec_command(E2E_ENV.api_restart_command(), timeout=30)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                raise RuntimeError(f"docker restart failed: {stderr.read().decode()}")
            time.sleep(4)
            print("  [OK] API restarted")
            ssh.close()

        status_resp = api("GET", "/api/bootstrap-status")
        assert status_resp["needs_setup"] is True
        print("  [OK] Bootstrap status = needs_setup")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()
        sys.exit(1)


# ================================================================
# PHASE 2: Bootstrap Admin
# ================================================================
print(f"\n{'=' * 60}")
print("PHASE 2: Bootstrap Admin")
print("=" * 60)

with timed_phase(2):
    try:
        admin_kp = generate_keypair()
        bootstrap_resp = api("POST", "/api/bootstrap", {
            "username": ADMIN_USERNAME,
            "signing_pk": admin_kp.signing_pk.hex(),
            "encryption_pk": admin_kp.encryption_pk.hex(),
        })
        admin_user_id = bootstrap_resp["user_id"]
        onboarding_jwt = bootstrap_resp["token"]
        print(f"  [OK] Admin bootstrapped, user_id={admin_user_id}")

        admin_argon2_salt = generate_salt(16)
        admin_auth_salt = generate_salt(16)
        admin_kek, admin_auth_proof = derive_kek_and_proof(ADMIN_PASSWORD, admin_argon2_salt, TEST_ARGON2)

        # Encrypt keypair (legacy: nonce + XChaCha20-Poly1305)
        keypair_data = bytes(admin_kp.signing_sk) + bytes(admin_kp.encryption_sk)
        nonce = os.urandom(24)
        ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            keypair_data, None, nonce, bytes(admin_kek)
        )
        encrypted_keypair = nonce + ct

        upload_resp = api("PUT", "/api/me/keypair", {
            "encrypted_keypair": encrypted_keypair.hex(),
            "argon2_salt": admin_argon2_salt.hex(),
            "auth_salt": admin_auth_salt.hex(),
            "auth_proof": admin_auth_proof.hex(),
        }, token=onboarding_jwt)
        assert upload_resp.get("status") == "ok"
        print("  [OK] Keypair uploaded")

        admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
        admin_signing_key = admin_kp.to_nacl_signing_key()
        print("  [OK] Admin authenticated")

        # Create root DEK for admin (needed for folder/entry encryption)
        admin_root_dek = os.urandom(32)
        admin_root_dek_id = new_ulid()
        kek_dek_id = new_ulid()

        # Wrap root DEK with KEK
        from sezam.crypto.aead import encrypt_dek_wrap
        encrypted_root_dek = encrypt_dek_wrap(
            dek_to_wrap=admin_root_dek,
            wrapping_key=admin_kek,
            wrapping_key_id=ulid_to_bytes(kek_dek_id),
            dek_archive_id=ulid_to_bytes(admin_root_dek_id),
        )

        # Create root node
        admin_root_node_id = new_ulid()
        root_node_obj = make_node_object(
            admin_root_node_id, None, "Root",
            admin_root_dek, admin_root_dek_id, admin_signing_key,
        )
        root_dek_obj = make_sync_object(
            obj_id=admin_root_dek_id, object_type="dek",
            payload=encrypted_root_dek, signing_key=admin_signing_key,
            parent_ref=None, version=1,
        )

        # Push root objects
        admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
        push_result = push_objects([root_dek_obj, root_node_obj], admin_jwt)
        accepted = len(push_result.get("accepted", []))
        conflicts = push_result.get("conflicts", [])
        print(f"  [OK] Root node pushed: accepted={accepted}, conflicts={len(conflicts)}")
        if conflicts:
            print(f"       Conflict details: {conflicts[:3]}")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()
        sys.exit(1)


# ================================================================
# PHASE 3: Create 30 Users
# ================================================================
print(f"\n{'=' * 60}")
print(f"PHASE 3: Create {NUM_USERS} Users")
print("=" * 60)

users = []  # list of (username, kp, user_id, jwt)

with timed_phase(3):
    try:
        user_start = time.perf_counter()
        for i in range(1, NUM_USERS + 1):
            uname = f"user{i:02d}"
            upass = f"UserPass{i}!2026"

            # Admin creates invitation
            admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
            invite_resp = api("POST", "/api/users/invite", token=admin_jwt)
            inv_token = invite_resp["invitation_token"]

            # Register user
            user_kp = generate_keypair()
            register_resp = api("POST", "/api/users/register", {
                "invitation_token": inv_token,
                "username": uname,
                "signing_pk": user_kp.signing_pk.hex(),
                "encryption_pk": user_kp.encryption_pk.hex(),
            })
            user_id = register_resp["user_id"]
            user_onboarding_jwt = register_resp["token"]

            # Upload keypair
            user_argon2_salt = generate_salt(16)
            user_auth_salt = generate_salt(16)
            user_kek, user_auth_proof = derive_kek_and_proof(upass, user_argon2_salt, TEST_ARGON2)

            user_keypair_data = bytes(user_kp.signing_sk) + bytes(user_kp.encryption_sk)
            user_nonce = os.urandom(24)
            user_ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                user_keypair_data, None, user_nonce, bytes(user_kek)
            )
            user_encrypted_kp = user_nonce + user_ct

            upload_resp = api("PUT", "/api/me/keypair", {
                "encrypted_keypair": user_encrypted_kp.hex(),
                "argon2_salt": user_argon2_salt.hex(),
                "auth_salt": user_auth_salt.hex(),
                "auth_proof": user_auth_proof.hex(),
            }, token=user_onboarding_jwt)
            assert upload_resp.get("status") == "ok"

            # Admin approves
            admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
            approve_resp = api("PATCH", f"/api/users/{user_id}/approve", token=admin_jwt)
            assert approve_resp.get("status") == "ok"

            # Verify user can authenticate
            user_jwt = authenticate(user_kp, uname)

            users.append((uname, user_kp, user_id, user_jwt))

            if i % 5 == 0:
                elapsed = time.perf_counter() - user_start
                print(f"  [OK] {i}/{NUM_USERS} users created ({elapsed:.1f}s)")

        elapsed = time.perf_counter() - user_start
        print(f"  [OK] All {NUM_USERS} users registered + approved + verified ({elapsed:.1f}s, {elapsed/NUM_USERS:.2f}s/user)")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()
        sys.exit(1)


# ================================================================
# PHASE 4: Push 1000+ Entries
# ================================================================
print(f"\n{'=' * 60}")
print(f"PHASE 4: Push {NUM_FOLDERS * ENTRIES_PER_FOLDER} Entries ({NUM_FOLDERS} folders x {ENTRIES_PER_FOLDER} entries)")
print("=" * 60)

folder_deks = {}  # folder_name -> (dek_id, dek_bytes, node_id)
total_entries_pushed = 0

with timed_phase(4):
    try:
        # Create all folders + their DEKs first
        folder_objects = []
        for fname in FOLDER_NAMES:
            folder_node_id = new_ulid()
            folder_dek = os.urandom(32)
            folder_dek_id = new_ulid()

            # Wrap folder DEK with root DEK
            folder_dek_obj = make_dek_and_wrap(
                folder_dek, admin_root_dek, admin_root_dek_id,
                folder_dek_id, folder_node_id, "folder", admin_signing_key,
            )

            folder_node_obj = make_node_object(
                folder_node_id, admin_root_node_id, fname,
                admin_root_dek, admin_root_dek_id, admin_signing_key,
            )

            folder_objects.append(folder_dek_obj)
            folder_objects.append(folder_node_obj)
            folder_deks[fname] = (folder_dek_id, folder_dek, folder_node_id)

        # Push all folder objects in one batch
        admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
        push_result = push_objects(folder_objects, admin_jwt)
        accepted = len(push_result.get("accepted", []))
        conflicts = push_result.get("conflicts", [])
        print(f"  [OK] {NUM_FOLDERS} folders pushed: accepted={accepted}, conflicts={len(conflicts)}")
        if conflicts:
            for c in conflicts[:5]:
                print(f"       Conflict: {c.get('id', '?')}: {c.get('error', '?')}")

        # Now create and push entries in batches
        entry_start = time.perf_counter()
        all_entry_objects = []

        for fname in FOLDER_NAMES:
            dek_id, dek, node_id = folder_deks[fname]
            for j in range(1, ENTRIES_PER_FOLDER + 1):
                entry_id = new_ulid()
                entry_name, fields = generate_entry_fields(fname, j)
                entry_obj = make_entry_object(
                    entry_id, node_id, entry_name, fields,
                    dek, dek_id, admin_signing_key,
                )
                all_entry_objects.append(entry_obj)

        # Push in batches
        total_accepted = 0
        total_conflicts = 0
        batch_count = 0
        for i in range(0, len(all_entry_objects), BATCH_SIZE):
            batch = all_entry_objects[i:i + BATCH_SIZE]
            admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
            push_result = push_objects(batch, admin_jwt)
            batch_accepted = len(push_result.get("accepted", []))
            batch_conflicts = len(push_result.get("conflicts", []))
            total_accepted += batch_accepted
            total_conflicts += batch_conflicts
            batch_count += 1

            if batch_count % 4 == 0:
                elapsed = time.perf_counter() - entry_start
                print(f"  [OK] Batch {batch_count}: {total_accepted} entries pushed ({elapsed:.1f}s)")

        total_entries_pushed = total_accepted
        elapsed = time.perf_counter() - entry_start
        entries_per_sec = total_accepted / elapsed if elapsed > 0 else 0
        print(f"  [OK] All entries pushed: accepted={total_accepted}, conflicts={total_conflicts} ({elapsed:.1f}s, {entries_per_sec:.1f} entries/sec)")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()
        sys.exit(1)


# ================================================================
# PHASE 5: Multiple Users Push Simultaneously
# ================================================================
print(f"\n{'=' * 60}")
print(f"PHASE 5: {NUM_CONCURRENT_USERS} Users Push Simultaneously ({ENTRIES_PER_CONCURRENT_USER} entries each)")
print("=" * 60)

concurrent_entries_pushed = 0

with timed_phase(5):
    try:
        def concurrent_push_task(thread_idx, uname):
            """Each thread creates a folder with entries using admin credentials (admin exempt from write_acl).

            This tests concurrent push pressure on the server from multiple threads.
            """
            # Each thread gets its own admin JWT to avoid token conflicts
            thread_jwt = authenticate(admin_kp, ADMIN_USERNAME)

            # Create user's folder DEK + node (signed by admin)
            user_folder_dek = os.urandom(32)
            user_folder_dek_id = new_ulid()
            user_folder_node_id = new_ulid()

            user_folder_dek_obj = make_dek_and_wrap(
                user_folder_dek, admin_root_dek, admin_root_dek_id,
                user_folder_dek_id, user_folder_node_id, "folder", admin_signing_key,
            )

            user_folder_node_obj = make_node_object(
                user_folder_node_id, admin_root_node_id, f"Folder-{uname}",
                admin_root_dek, admin_root_dek_id, admin_signing_key,
            )

            # Create entries
            entry_objects = []
            for j in range(1, ENTRIES_PER_CONCURRENT_USER + 1):
                eid = new_ulid()
                ename = f"{uname}-entry-{j:02d}"
                fields = [
                    {"key": "host", "value": f"{uname}-server-{j:02d}.internal", "sensitive": False, "sort_order": 0},
                    {"key": "username", "value": uname, "sensitive": False, "sort_order": 1},
                    {"key": "password", "value": random_password(), "sensitive": True, "sort_order": 2},
                ]
                entry_obj = make_entry_object(
                    eid, user_folder_node_id, ename, fields,
                    user_folder_dek, user_folder_dek_id, admin_signing_key,
                )
                entry_objects.append(entry_obj)

            # Push all in one call
            all_objects = [user_folder_dek_obj, user_folder_node_obj] + entry_objects
            result = push_objects(all_objects, thread_jwt)
            accepted = len(result.get("accepted", []))
            conflicts = result.get("conflicts", [])
            return uname, accepted, len(conflicts)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(concurrent_push_task, i, users[i][0]): users[i][0]
                       for i in range(NUM_CONCURRENT_USERS)}

            user_results = []
            for future in as_completed(futures):
                try:
                    uname, accepted, conflicts = future.result()
                    user_results.append((uname, accepted, conflicts))
                    concurrent_entries_pushed += accepted
                except Exception as ex:
                    uname = futures[future]
                    print(f"  [WARN] {uname} push failed: {ex}")
                    user_results.append((uname, 0, -1))

        ok_count = sum(1 for _, a, c in user_results if a > 0)
        total_accepted = sum(a for _, a, _ in user_results)
        total_conflicts = sum(c for _, _, c in user_results if c >= 0)
        print(f"  [OK] {ok_count}/{NUM_CONCURRENT_USERS} users pushed successfully")
        print(f"       Total accepted: {total_accepted}, Total conflicts: {total_conflicts}")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()


# ================================================================
# PHASE 6: Pull Stress
# ================================================================
print(f"\n{'=' * 60}")
print(f"PHASE 6: {NUM_USERS} Users Pull Full Vault")
print("=" * 60)

with timed_phase(6):
    try:
        pull_times = []
        pull_counts = []

        def user_pull_task(user_tuple):
            uname, user_kp, user_id, _ = user_tuple
            t0 = time.perf_counter()
            user_jwt = authenticate(user_kp, uname)
            pull_resp = api("GET", "/api/sync?since_commit_seq=0", token=user_jwt)
            t1 = time.perf_counter()
            obj_count = len(pull_resp.get("objects", []))
            return uname, t1 - t0, obj_count

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(user_pull_task, u): u[0] for u in users}

            for future in as_completed(futures):
                try:
                    uname, elapsed, obj_count = future.result()
                    pull_times.append(elapsed)
                    pull_counts.append(obj_count)
                except Exception as ex:
                    uname = futures[future]
                    print(f"  [WARN] {uname} pull failed: {ex}")

        if pull_times:
            avg_time = sum(pull_times) / len(pull_times)
            max_time = max(pull_times)
            min_time = min(pull_times)
            avg_count = sum(pull_counts) / len(pull_counts) if pull_counts else 0
            print(f"  [OK] {len(pull_times)}/{NUM_USERS} users pulled successfully")
            print(f"       Objects per pull: avg={avg_count:.0f}")
            print(f"       Pull time: avg={avg_time:.2f}s, min={min_time:.2f}s, max={max_time:.2f}s")
        else:
            print("  [FAIL] No pulls succeeded")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()


# ================================================================
# PHASE 7: Share Stress
# ================================================================
print(f"\n{'=' * 60}")
print(f"PHASE 7: {NUM_SHARES} Share Links")
print("=" * 60)

with timed_phase(7):
    try:
        shares_created = 0
        shares_consumed = 0

        admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)

        share_ids = []
        for i in range(NUM_SHARES):
            share_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
            share_blob = base64.b64encode(f"stress-test-share-{i:03d}-data".encode()).decode("ascii")
            share_expires = int(time.time() * 1000) + 3600 * 1000

            # Re-auth every 10 shares to avoid token expiry
            if i % 10 == 0 and i > 0:
                admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)

            code, resp = api_raw("POST", "/api/share", {
                "id": share_id,
                "encrypted_blob": share_blob,
                "expires_at": share_expires,
                "max_views": 1,
                "pin_hash": None,
            }, token=admin_jwt)
            if code == 200:
                shares_created += 1
                share_ids.append(share_id)

        print(f"  [OK] {shares_created}/{NUM_SHARES} shares created")

        # Consume shares
        for share_id in share_ids:
            code, resp = api_raw("POST", f"/api/share/{share_id}", {"pin": None})
            if code == 200:
                shares_consumed += 1

        print(f"  [OK] {shares_consumed}/{shares_created} shares consumed")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()


# ================================================================
# PHASE 8: Audit Stress
# ================================================================
print(f"\n{'=' * 60}")
print("PHASE 8: Audit Verification")
print("=" * 60)

audit_count = 0

with timed_phase(8):
    try:
        admin_jwt = authenticate(admin_kp, ADMIN_USERNAME)
        audit_resp = api("GET", "/api/audit", token=admin_jwt)
        entries = audit_resp.get("entries", [])
        audit_count = audit_resp.get("total", len(entries))

        actions = {}
        for e in entries:
            act = e.get("action", "unknown")
            actions[act] = actions.get(act, 0) + 1

        print(f"  [OK] Audit entries: {audit_count}")
        print(f"       Actions: {dict(sorted(actions.items()))}")

    except Exception as e:
        print(f"  [FAIL] {e}")
        traceback.print_exc()


# ================================================================
# FINAL REPORT
# ================================================================
total_elapsed = time.perf_counter() - total_start

print("\n" + "=" * 70)
print("  STRESS TEST RESULTS")
print("=" * 70)
print()

phase_names = {
    1: "Clean DB",
    2: "Bootstrap admin",
    3: f"{NUM_USERS} users registered",
    4: f"{NUM_FOLDERS * ENTRIES_PER_FOLDER} entries pushed",
    5: f"{NUM_CONCURRENT_USERS} users push",
    6: f"{NUM_USERS} users pull",
    7: f"{NUM_SHARES} shares",
    8: f"Audit entries: {audit_count}",
}

for phase_num in sorted(phase_timings.keys()):
    name = phase_names.get(phase_num, f"Phase {phase_num}")
    t = phase_timings[phase_num]
    dots = "." * (40 - len(name))
    extra = ""
    if phase_num == 3:
        extra = f" ({t / NUM_USERS:.2f}s/user avg)"
    elif phase_num == 4:
        total = NUM_FOLDERS * ENTRIES_PER_FOLDER
        eps = total / t if t > 0 else 0
        extra = f" ({eps:.1f} entries/sec)"
    elif phase_num == 6:
        extra = f" ({t / NUM_USERS:.2f}s/pull avg)" if NUM_USERS > 0 else ""
    print(f"Phase {phase_num}: {name} {dots} {t:.1f}s{extra}")

print(f"TOTAL: {total_elapsed:.1f}s")
print()

total_entries = total_entries_pushed + concurrent_entries_pushed
print(f"{total_entries} entries, {NUM_USERS} users, {NUM_SHARES} shares -- ALL OK")
print("=" * 70)
