"""T5 (code review HEAD 2c7e809): shared cross-client golden vectors.

tests/vectors/cross_client.json pins the byte formats every client must agree
on: AEAD AAD, sync-object and audit signature messages, key-rotation
certificates, an entry envelope and a DEK wrap. The desktop reference
implementation must reproduce the file exactly (test below); the web client
is checked here through node, the mobile client by
mobile/test/cross_client_vectors_test.dart. A client that drifts fails its
own suite instead of silently writing data the others cannot read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path

import nacl.bindings
import nacl.public
import nacl.signing
import pytest

from sezam.crypto.aead import (
    ALG_XCHACHA20POLY1305,
    SCHEMA_VERSION,
    BlobKind,
    build_aad,
    decrypt,
    decrypt_dek_wrap,
    decrypt_keypair_wrap,
)
from sezam.crypto.envelope_crypto import create_envelope, open_envelope
from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
from sezam.crypto.keys import KeyPair
from sezam.mcp import remote_policy
from sezam.models import ulid_to_bytes
from sezam.vault.audit import AuditLog
from sezam.vault.sync_client import SyncClient, compute_state_hash, key_rotation_message
from sezam.vault.sync_common import legacy_state_hash
from tests.node_support import node_cmd, requires_node

ROOT = Path(__file__).resolve().parents[1]
VECTORS_PATH = ROOT / "tests" / "vectors" / "cross_client.json"

DEK_ID = "01JDEK0000000000000000000A"
OBJ_ID = "01JOBJ0000000000000000000B"
KEK_ID = "01JKEK0000000000000000000C"
USER = "01JUSER000000000000000000D"
AUDIT_ID = "01JAUD0000000000000000000E"
ACCOUNT = "01JACC0000000000000000000F"  # Crockford-valid (USER is not)


def _envelope(plain, key, kind, key_id, obj_id, version, nonce, pad_len):
    # Deterministic padding bytes so the vector is reproducible.
    padded = struct.pack(">H", pad_len) + bytes((i * 37 + 11) & 0xFF for i in range(pad_len)) + plain
    aad = build_aad(
        ALG_XCHACHA20POLY1305, SCHEMA_VERSION, kind,
        ulid_to_bytes(key_id), ulid_to_bytes(obj_id), version,
    )
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(padded, aad, nonce, key)
    return bytes([ALG_XCHACHA20POLY1305, SCHEMA_VERSION, kind]) + ulid_to_bytes(key_id) + nonce + ct


def desktop_vectors() -> dict:
    vectors: dict = {
        "_comment": (
            "Cross-client golden vectors (code review T5), produced by "
            "tests/test_cross_client_vectors.py:desktop_vectors from the desktop "
            "reference code. Web and mobile tests must reproduce them byte for "
            "byte; never regenerate this file to make a client pass."
        ),
    }

    vectors["aad"] = [
        {
            "blob_kind": kind, "dek_id": dek, "object_id": obj, "version": version,
            "aad_hex": build_aad(
                ALG_XCHACHA20POLY1305, SCHEMA_VERSION, kind,
                ulid_to_bytes(dek), ulid_to_bytes(obj), version,
            ).hex(),
        }
        for kind, dek, obj, version in (
            (BlobKind.ENTRY_DATA, DEK_ID, OBJ_ID, 7),
            (BlobKind.DEK_WRAP, KEK_ID, DEK_ID, 1),
            (BlobKind.NODE_META, DEK_ID, OBJ_ID, 0xFFFFFFFF),
        )
    ]

    seed = bytes(range(32))
    signing_key = nacl.signing.SigningKey(seed)
    vectors["ed25519"] = {
        "seed_hex": seed.hex(),
        "public_key_hex": bytes(signing_key.verify_key).hex(),
    }
    vectors["sync_signature"] = []
    for args in (
        (OBJ_ID, "entry", DEK_ID, None, 0, 3, hashlib.sha256(b"payload").hexdigest()),
        (DEK_ID, "dek", None, USER, 1, 12, hashlib.sha256(b"").hexdigest()),
    ):
        message = SyncClient._build_signature_payload(*args)
        vectors["sync_signature"].append({
            "id": args[0], "object_type": args[1], "parent_ref": args[2],
            "target_user_id": args[3], "is_deleted": args[4], "version": args[5],
            "payload_hash": args[6], "message_hex": message.hex(),
            "signature_hex": signing_key.sign(message).signature.hex(),
        })

    vectors["audit_canonical"] = []
    for record_id, parents, action, timestamp, details in (
        (OBJ_ID, [], "init", 1_700_000_000_000, b""),
        (AUDIT_ID, sorted([OBJ_ID, DEK_ID]), "read", 1_762_500_000_123, bytes(range(40))),
    ):
        parents_json = json.dumps(sorted(parents), separators=(",", ":"))
        vectors["audit_canonical"].append({
            "id": record_id, "actor_id": USER, "parent_ids": parents, "action": action,
            "timestamp": timestamp, "encrypted_details_hex": details.hex(),
            "message_hex": AuditLog._build_canonical(
                record_id, USER, parents_json, action, timestamp, details
            ).hex(),
        })

    keys = [bytes([b]) * 32 for b in (1, 2, 3, 4)]
    vectors["key_rotation"] = {
        "user_id": USER,
        "old_signing_pk_hex": keys[0].hex(),
        "old_encryption_pk_hex": keys[1].hex(),
        "new_signing_pk_hex": keys[2].hex(),
        "new_encryption_pk_hex": keys[3].hex(),
        "message_hex": key_rotation_message(USER, *keys).hex(),
    }

    dek = bytes(range(100, 132))
    kek = bytes(range(200, 232))
    plain = json.dumps(
        {"fields": [{"key": "password", "value": "golden \u017elt\u00fd"}]},
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    vectors["envelope"] = {
        "dek_hex": dek.hex(), "dek_id": DEK_ID, "object_id": OBJ_ID, "version": 2,
        "blob_kind": int(BlobKind.ENTRY_DATA), "plaintext_hex": plain.hex(),
        "envelope_hex": _envelope(
            plain, dek, BlobKind.ENTRY_DATA, DEK_ID, OBJ_ID, 2, bytes([9]) * 24, 29
        ).hex(),
    }
    vectors["dek_wrap"] = {
        "kek_hex": kek.hex(), "kek_id": KEK_ID, "dek_id": DEK_ID, "version": 1,
        "dek_hex": dek.hex(),
        "envelope_hex": _envelope(
            dek, kek, BlobKind.DEK_WRAP, KEK_ID, DEK_ID, 1, bytes([5]) * 24, 30
        ).hex(),
    }

    # Account keypair as uploaded to the server. The desktop wraps
    # signing_seed || encryption_sk (64 B), web and mobile signing_sk(64) ||
    # encryption_sk (96 B); every client must open both.
    encryption_sk = bytes(range(64, 96))
    keypair = KeyPair.from_private_only(seed + encryption_sk)
    desktop_payload = bytes(keypair.serialize_private())
    full_payload = seed + keypair.signing_pk + encryption_sk
    vectors["keypair_wrap"] = {
        "kek_hex": kek.hex(), "kek_id": KEK_ID, "user_id": ACCOUNT,
        "signing_pk_hex": keypair.signing_pk.hex(),
        "encryption_pk_hex": keypair.encryption_pk.hex(),
        "keypair_hex": full_payload.hex(),
        "envelopes": [
            {
                "payload_hex": payload.hex(),
                "envelope_hex": _envelope(
                    payload, kek, BlobKind.KEYPAIR_WRAP, KEK_ID, ACCOUNT, 1,
                    bytes([nonce_byte]) * 24, 18,
                ).hex(),
            }
            for payload, nonce_byte in ((desktop_payload, 6), (full_payload, 7))
        ],
    }

    # A DEK rewrapped after key rotations: the version is part of the AAD.
    vectors["dek_wrap_v3"] = {
        "kek_hex": kek.hex(), "kek_id": KEK_ID, "dek_id": DEK_ID, "version": 3,
        "dek_hex": dek.hex(),
        "envelope_hex": _envelope(
            dek, kek, BlobKind.DEK_WRAP, KEK_ID, DEK_ID, 3, bytes([8]) * 24, 30
        ).hex(),
    }

    # One Argon2id run, 64 bytes: KEK = [0:32], auth proof = [32:64]. The
    # params are the web hard floor so no client raises them.
    password = "golden heslo \u017elt\u00fd k\u00f4\u0148"
    salt = bytes(range(16, 32))
    params = Argon2Params(time_cost=2, memory_cost=65536, parallelism=1)
    split_kek, auth_proof = derive_kek_and_proof(password, salt, params)
    vectors["argon2_split"] = {
        "password": password, "salt_hex": salt.hex(),
        "params": {"time_cost": 2, "memory_cost": 65536, "parallelism": 1},
        "kek_hex": bytes(split_kek).hex(), "auth_proof_hex": bytes(auth_proof).hex(),
    }

    # state_hash over raw sync objects, given out of order; one tombstone
    # (empty payload) and the largest version.
    objects = [
        ("01JZZZ0000000000000000000A", 4, b"zeta"),
        ("01JAAA0000000000000000000B", 0xFFFFFFFF, b""),
        ("01JMMM0000000000000000000C", 1, bytes(range(200))),
    ]
    vectors["state_hash"] = {
        "objects": [
            {"id": i, "version": v, "payload": base64.b64encode(p).decode("ascii")}
            for i, v, p in objects
        ],
        "state_hash": legacy_state_hash(objects),
    }
    # R17-N1: the state hash a checkpoint with state_v 2 holds (parent and
    # deleted flag count); "moved" / "deleted": the first object served again
    # with one of them changed.
    signed = [
        ("01JZZZ0000000000000000000A", 4, b"zeta", "01JMMM0000000000000000000C", 0),
        ("01JAAA0000000000000000000B", 0xFFFFFFFF, b"", None, 1),
        ("01JMMM0000000000000000000C", 1, bytes(range(200)), None, 0),
    ]
    vectors["state_hash_v2"] = {
        "objects": [
            {"id": i, "version": v, "payload": base64.b64encode(p).decode("ascii"),
             "parent_ref": parent, "is_deleted": deleted}
            for i, v, p, parent, deleted in signed
        ],
        "state_hash": compute_state_hash(signed),
        "moved": compute_state_hash([(*signed[0][:3], None, 0), *signed[1:]]),
        "deleted": compute_state_hash([(*signed[0][:4], 1), *signed[1:]]),
    }

    # Remote AI kill switch (AI broker S1e), signed by the account key.
    policy_epoch = 1_762_500_000_123
    policy_message = remote_policy.policy_message(ACCOUNT, False, policy_epoch)
    vectors["ai_policy"] = {
        "user_id": ACCOUNT, "enabled": False, "epoch": policy_epoch,
        "message_hex": policy_message.hex(),
        "signature_hex": signing_key.sign(policy_message).signature.hex(),
    }

    # Access envelope: nonce(24) || crypto_box(DEK), sender = granting admin.
    sender = nacl.public.PrivateKey(bytes(range(32, 64)))
    recipient = nacl.public.PrivateKey(bytes(range(96, 128)))
    box_nonce = bytes([3]) * 24
    vectors["crypto_box"] = {
        "sender_sk_hex": bytes(sender).hex(), "sender_pk_hex": bytes(sender.public_key).hex(),
        "recipient_sk_hex": bytes(recipient).hex(),
        "recipient_pk_hex": bytes(recipient.public_key).hex(),
        "dek_hex": dek.hex(),
        "payload_hex": bytes(
            nacl.public.Box(sender, recipient.public_key).encrypt(dek, box_nonce)
        ).hex(),
    }
    return vectors


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def test_desktop_reproduces_the_shared_vectors(vectors):
    assert desktop_vectors() == vectors


def test_desktop_decrypts_and_verifies_the_shared_vectors(vectors):
    env = vectors["envelope"]
    assert decrypt(
        bytes.fromhex(env["envelope_hex"]), bytes.fromhex(env["dek_hex"]),
        ulid_to_bytes(env["object_id"]), env["version"],
        expected_blob_kind=env["blob_kind"],
    ) == bytes.fromhex(env["plaintext_hex"])

    wrap = vectors["dek_wrap"]
    assert bytes(decrypt_dek_wrap(
        bytes.fromhex(wrap["envelope_hex"]), bytes.fromhex(wrap["kek_hex"]),
        ulid_to_bytes(wrap["dek_id"]), wrap["version"],
    )) == bytes.fromhex(wrap["dek_hex"])

    verify_key = nacl.signing.VerifyKey(bytes.fromhex(vectors["ed25519"]["public_key_hex"]))
    for item in vectors["sync_signature"]:
        verify_key.verify(bytes.fromhex(item["message_hex"]), bytes.fromhex(item["signature_hex"]))

    kp = vectors["keypair_wrap"]
    for item in kp["envelopes"]:
        payload = bytes(decrypt_keypair_wrap(
            bytes.fromhex(item["envelope_hex"]), bytes.fromhex(kp["kek_hex"]),
            ulid_to_bytes(kp["user_id"]),
        ))
        assert payload == bytes.fromhex(item["payload_hex"])
        keypair = KeyPair.from_private_only(payload)
        assert keypair.signing_pk.hex() == kp["signing_pk_hex"]
        assert keypair.encryption_pk.hex() == kp["encryption_pk_hex"]

    w3 = vectors["dek_wrap_v3"]
    for version in (1, 2, 3):
        open_wrap = lambda: decrypt_dek_wrap(  # noqa: E731
            bytes.fromhex(w3["envelope_hex"]), bytes.fromhex(w3["kek_hex"]),
            ulid_to_bytes(w3["dek_id"]), version,
        )
        if version == w3["version"]:
            assert bytes(open_wrap()) == bytes.fromhex(w3["dek_hex"])
        else:
            with pytest.raises(Exception):
                open_wrap()

    a = vectors["argon2_split"]
    kek, proof = derive_kek_and_proof(
        a["password"], bytes.fromhex(a["salt_hex"]), Argon2Params(**a["params"])
    )
    assert (bytes(kek).hex(), bytes(proof).hex()) == (a["kek_hex"], a["auth_proof_hex"])

    sh = vectors["state_hash"]
    objects = [(o["id"], o["version"], base64.b64decode(o["payload"])) for o in sh["objects"]]
    assert legacy_state_hash(objects) == sh["state_hash"]
    assert legacy_state_hash(list(reversed(objects))) == sh["state_hash"]
    v2 = vectors["state_hash_v2"]
    signed = [
        (o["id"], o["version"], base64.b64decode(o["payload"]), o["parent_ref"], o["is_deleted"])
        for o in v2["objects"]
    ]
    assert compute_state_hash(list(reversed(signed))) == v2["state_hash"]
    assert len({v2["state_hash"], v2["moved"], v2["deleted"], sh["state_hash"]}) == 4

    policy = vectors["ai_policy"]
    signing_pk = bytes.fromhex(vectors["ed25519"]["public_key_hex"])
    assert remote_policy.verify_policy(
        {"enabled": policy["enabled"], "epoch": policy["epoch"],
         "signature": policy["signature_hex"]},
        policy["user_id"], signing_pk,
    ) == remote_policy.RemotePolicy(False, policy["epoch"])
    from server.app.routers.ai_policy import policy_message as server_policy_message

    assert server_policy_message(
        policy["user_id"], policy["enabled"], policy["epoch"]
    ).hex() == policy["message_hex"]

    box = vectors["crypto_box"]
    assert bytes(open_envelope(
        bytes.fromhex(box["payload_hex"]), bytes.fromhex(box["recipient_sk_hex"]),
        bytes.fromhex(box["sender_pk_hex"]),
    )).hex() == box["dek_hex"]
    fresh = create_envelope(
        bytes.fromhex(box["dek_hex"]), bytes.fromhex(box["sender_sk_hex"]),
        bytes.fromhex(box["recipient_pk_hex"]),
    )
    assert len(fresh) == len(bytes.fromhex(box["payload_hex"]))


def _web_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    if source[max(0, start - 6):start] == "async ":
        start -= 6
    depth = 0
    for index in range(source.index("{", start), len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(name)


def _web_constant(source: str, name: str) -> str:
    start = source.index(f"const {name} =")
    end = source.index(";", start)
    return source[start:end + 1]


@requires_node
def test_web_client_reproduces_the_shared_vectors():
    app = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    functions = "\n".join(
        _web_function(app, name)
        for name in (
            "validateCanonicalEnvelopeHeader", "buildAAD", "idBytes26", "unpadPlaintext",
            "decryptEnvelope", "unwrapDEK", "signSyncObject", "buildAuditCanonical",
            "keyRotationMessage", "signedObjectMessage", "hexToBytes", "padPlaintext", "paddedSize", "encryptKeypairWrap", "decryptKeypairWrap",
            "expandDesktopKeypair", "base64ToBytes", "bytesToHex", "computeWebStateHash",
            "openDekEnvelope", "normalizeKdfParams", "deriveKEK", "deriveKEKViaWorker",
        )
    )
    constants = "\n".join(
        _web_constant(app, name)
        for name in (
            "ENVELOPE_ALG", "SCHEMA_VERSION", "BLOB_KIND", "ARGON2_HARD_FLOOR",
            "ARGON2_ACCOUNT_MAX",
        )
    )
    body = r"""
var state = null;
const hex = (h) => Uint8Array.from((h.match(/../g) || []).map((b) => parseInt(b, 16)));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const check = (ok, what) => { if (!ok) throw new Error('vector mismatch: ' + what); };
globalThis.__runVectors = async (V) => {
  await sodium.ready;
  await SezamSyncCore.ready;
  const s = sodium;
  for (const v of V.aad) {
    check(toHex(buildAAD(v.blob_kind, v.dek_id, v.object_id, v.version)) === v.aad_hex, 'aad ' + v.blob_kind);
  }
  const kp = s.crypto_sign_seed_keypair(hex(V.ed25519.seed_hex));
  check(toHex(kp.publicKey) === V.ed25519.public_key_hex, 'ed25519 public key');
  state = { keypair: { signingSk: kp.privateKey } };
  for (const v of V.sync_signature) {
    let message = null;
    const spy = { crypto_sign_detached: (m, sk) => { message = m; return s.crypto_sign_detached(m, sk); } };
    const sig = signSyncObject(spy, v.id, v.object_type, v.parent_ref, v.target_user_id,
      v.is_deleted, v.version, hex(v.payload_hash));
    check(toHex(message) === v.message_hex, 'sync message ' + v.object_type);
    check(toHex(sig) === v.signature_hex, 'sync signature ' + v.object_type);
  }
  for (const v of V.audit_canonical) {
    const record = {
      id: v.id, actor_id: v.actor_id, parent_ids: v.parent_ids, action: v.action,
      timestamp: v.timestamp, encrypted_details_bytes: hex(v.encrypted_details_hex),
    };
    check(toHex(buildAuditCanonical(record, s)) === v.message_hex, 'audit ' + v.action);
  }
  const r = V.key_rotation;
  check(toHex(keyRotationMessage(r.user_id, hex(r.old_signing_pk_hex), hex(r.old_encryption_pk_hex),
    hex(r.new_signing_pk_hex), hex(r.new_encryption_pk_hex))) === r.message_hex, 'key rotation');
  const e = V.envelope;
  const entry = decryptEnvelope(hex(e.envelope_hex), e.object_id, e.version, { [e.dek_id]: hex(e.dek_hex) }, s, e.blob_kind);
  check(JSON.stringify(entry) === new TextDecoder().decode(hex(e.plaintext_hex)), 'entry envelope');
  const w = V.dek_wrap;
  check(toHex(unwrapDEK(hex(w.envelope_hex), hex(w.kek_hex), w.dek_id, w.version, s)) === w.dek_hex, 'dek wrap');
  const k = V.keypair_wrap;
  for (const item of k.envelopes) {
    check(toHex(decryptKeypairWrap(hex(item.envelope_hex), hex(k.kek_hex), k.user_id, s)) === k.keypair_hex,
      'keypair wrap ' + item.payload_hex.length / 2);
  }
  const w3 = V.dek_wrap_v3;
  check(toHex(unwrapDEK(hex(w3.envelope_hex), hex(w3.kek_hex), w3.dek_id, w3.version, s)) === w3.dek_hex,
    'dek wrap v3');
  let staleVersionOpened = true;
  try { unwrapDEK(hex(w3.envelope_hex), hex(w3.kek_hex), w3.dek_id, 1, s); } catch { staleVersionOpened = false; }
  check(!staleVersionOpened, 'dek wrap v3 must not open as version 1');
  const a = V.argon2_split;
  const derived = await deriveKEK(a.password, hex(a.salt_hex), a.params);
  check(derived.length === 64, 'argon2 output length');
  check(toHex(derived.subarray(0, 32)) === a.kek_hex, 'argon2 kek half');
  check(toHex(derived.subarray(32, 64)) === a.auth_proof_hex, 'argon2 auth proof half');
  const shuffled = {};
  for (const o of V.state_hash.objects) shuffled[o.id] = { id: o.id, version: o.version, payload: o.payload };
  check(await computeWebStateHash(shuffled, s, true) === V.state_hash.state_hash, 'legacy state hash');
  const v2 = V.state_hash_v2;
  const served = {};
  for (const o of [...v2.objects].reverse()) served[o.id] = { ...o };
  check(await computeWebStateHash(served, s) === v2.state_hash, 'state hash');
  const first = v2.objects[0].id;
  check(await computeWebStateHash({ ...served, [first]: { ...served[first], parent_ref: null } }, s) === v2.moved,
    'state hash of a moved copy');
  check(await computeWebStateHash({ ...served, [first]: { ...served[first], is_deleted: 1 } }, s) === v2.deleted,
    'state hash of a deleted copy');
  const b = V.crypto_box;
  state = {
    keypair: { encryptionSk: hex(b.recipient_sk_hex) },
    userEncryptionKeys: { sender: [hex(b.sender_pk_hex)] },
  };
  const boxPayload = s.to_base64(hex(b.payload_hex), s.base64_variants.ORIGINAL);
  check(toHex(openDekEnvelope({ signature_user_id: 'sender', payload: boxPayload }, s)) === b.dek_hex,
    'crypto_box envelope');
  return JSON.stringify({
    keypair_wrap: toHex(encryptKeypairWrap(hex(k.keypair_hex), hex(k.kek_hex), k.kek_id, k.user_id, s)),
  });
};
"""
    harness = r"""
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt,
  Promise, WebAssembly, crypto: webcrypto, setTimeout, clearTimeout,
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
};
context.window = context; context.self = context; context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 5)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
vm.runInContext(fs.readFileSync(0, 'utf8'), context);
const vectors = JSON.parse(fs.readFileSync(process.argv[5], 'utf8'));
context.__runVectors(vectors)
  .then((result) => process.stdout.write(result))
  .catch((error) => { console.error(error.message); process.exit(1); });
"""
    vendor = ROOT / "web" / "static" / "js" / "vendor"
    result = subprocess.run(
        [
            node_cmd(), "-e", harness,
            str(vendor / "libsodium-sumo.min.js"),
            str(vendor / "libsodium-wrappers.min.js"),
            str(vendor / "argon2-bundled.min.js"),
            str(vendor / "sezam-sync-core.js"),
            str(VECTORS_PATH),
        ],
        input="\n".join([constants, functions, body]),
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert result.returncode == 0, result.stderr
    produced = json.loads(result.stdout)

    # The other direction: the desktop opens what the web client wrote.
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    kp = vectors["keypair_wrap"]
    assert bytes(decrypt_keypair_wrap(
        bytes.fromhex(produced["keypair_wrap"]), bytes.fromhex(kp["kek_hex"]),
        ulid_to_bytes(kp["user_id"]),
    )).hex() == kp["keypair_hex"]
