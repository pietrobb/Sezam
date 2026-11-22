"""Unit tests for the crypto layer.

Tests: key generation, Argon2id KDF, AEAD encrypt/decrypt with AAD,
envelope format, padding, KEK/DEK wrapping, zeroize.
Edge cases: wrong password, corrupted blob, AAD mismatch (swap attack detection).
"""

from __future__ import annotations

import os
import struct

import pytest
from nacl.exceptions import CryptoError

from sezam.vault import pending_states
from sezam.crypto.aead import (
    ALG_XCHACHA20POLY1305,
    HEADER_SIZE,
    SCHEMA_VERSION,
    BlobKind,
    build_aad,
    decrypt,
    decrypt_dek_wrap,
    decrypt_keypair_wrap,
    encrypt,
    encrypt_dek_wrap,
    encrypt_keypair_wrap,
    parse_envelope,
)
from sezam.crypto.kdf import Argon2Params, derive_kek, generate_salt
from sezam.crypto.keys import (
    KeyPair,
    compute_fingerprint,
    export_sezam_key,
    generate_keypair,
    import_sezam_key,
)
from sezam.crypto.padding import _next_power_of_2, pad, unpad
from sezam.models import bytes_to_ulid, new_ulid, ulid_to_bytes
from tests.node_support import node_cmd
from sezam.vault import outbox


# ── Key Generation ──


class TestKeyGeneration:
    def test_generate_keypair_sizes(self):
        kp = generate_keypair()
        assert len(kp.signing_sk) == 32
        assert len(kp.signing_pk) == 32
        assert len(kp.encryption_sk) == 32
        assert len(kp.encryption_pk) == 32

    def test_keypairs_are_unique(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.signing_pk != kp2.signing_pk
        assert kp1.encryption_pk != kp2.encryption_pk

    def test_fingerprint(self):
        kp = generate_keypair()
        fp = kp.fingerprint
        assert len(fp) == 64  # SHA-256 hex
        assert fp == compute_fingerprint(kp.signing_pk, kp.encryption_pk)

    def test_fingerprint_deterministic(self):
        kp = generate_keypair()
        assert kp.fingerprint == kp.fingerprint

    def test_fingerprint_changes_with_keys(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.fingerprint != kp2.fingerprint

    def test_zeroize(self):
        kp = generate_keypair()
        kp.zeroize()
        assert kp.signing_sk == bytearray(32)
        assert kp.encryption_sk == bytearray(32)

    def test_serialize_roundtrip(self):
        kp = generate_keypair()
        serialized = kp.serialize_private()
        assert len(serialized) == 64

        kp2 = KeyPair.from_private_bytes(
            bytes(serialized), kp.signing_pk, kp.encryption_pk
        )
        assert bytes(kp2.signing_sk) == bytes(kp.signing_sk)
        assert bytes(kp2.encryption_sk) == bytes(kp.encryption_sk)

    def test_ed25519_sign_verify(self):
        kp = generate_keypair()
        sk = kp.to_nacl_signing_key()
        vk = kp.to_nacl_verify_key()

        message = b"test message"
        signed = sk.sign(message)
        # Should not raise
        vk.verify(signed.message, signed.signature)

    def test_fingerprint_words(self):
        kp = generate_keypair()
        words = kp.fingerprint_words()
        assert len(words) == 4


class TestSezamKeyBackup:
    FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)

    def test_round_trip_uses_embedded_salt_and_kdf_params(self, tmp_path):
        password = "backup password"
        salt = b"original-salt-01"
        keypair = generate_keypair()
        kek = derive_kek(password, salt, self.FAST_PARAMS)
        backup = tmp_path / "vault.sezam-key"

        export_sezam_key(keypair, kek, backup, salt, self.FAST_PARAMS)
        kek[:] = b"\x00" * len(kek)
        recovered = import_sezam_key(backup, password)

        assert recovered.fingerprint == keypair.fingerprint
        assert recovered.serialize_private() == keypair.serialize_private()

    def test_desktop_imports_canonical_mobile_96_byte_keypair(self, tmp_path):
        password = "mobile backup password"
        salt = b"mobile-salt-0001"
        keypair = generate_keypair()
        kek = derive_kek(password, salt, self.FAST_PARAMS)
        kek_dek_id = new_ulid()
        user_object_id = new_ulid()
        mobile_private = (
            bytes(keypair.signing_sk)
            + keypair.signing_pk
            + bytes(keypair.encryption_sk)
        )
        envelope = encrypt_keypair_wrap(
            mobile_private,
            kek,
            ulid_to_bytes(kek_dek_id),
            ulid_to_bytes(user_object_id),
        )
        backup = tmp_path / "mobile.sezam-key"
        backup.write_bytes(
            struct.pack(
                ">8sHIIIH",
                b"SEZAMK02",
                len(salt),
                self.FAST_PARAMS.time_cost,
                self.FAST_PARAMS.memory_cost,
                self.FAST_PARAMS.parallelism,
                self.FAST_PARAMS.hash_len,
            )
            + salt
            + keypair.signing_pk
            + keypair.encryption_pk
            + ulid_to_bytes(kek_dek_id)
            + ulid_to_bytes(user_object_id)
            + envelope
        )
        kek[:] = b"\x00" * len(kek)

        recovered = import_sezam_key(backup, password)

        assert recovered.fingerprint == keypair.fingerprint
        assert recovered.serialize_private() == keypair.serialize_private()

    def test_rejects_unbounded_embedded_kdf_params(self, tmp_path):
        password = "backup password"
        salt = b"original-salt-01"
        keypair = generate_keypair()
        kek = derive_kek(password, salt, self.FAST_PARAMS)
        backup = tmp_path / "vault.sezam-key"
        export_sezam_key(keypair, kek, backup, salt, self.FAST_PARAMS)

        data = bytearray(backup.read_bytes())
        struct.pack_into(">I", data, 14, 262145)
        backup.write_bytes(data)

        with pytest.raises(ValueError, match="memory cost"):
            import_sezam_key(backup, password)

    def test_web_and_desktop_sezam_key_round_trip_and_tamper_rejection(self, tmp_path):
        import base64
        import json
        import subprocess
        from pathlib import Path

        password = "cross-client backup password"
        params = Argon2Params(time_cost=2, memory_cost=65536, parallelism=1)
        salt = b"web-backup-salt1"
        desktop_keypair = generate_keypair()
        kek = derive_kek(password, salt, params)
        desktop_backup = tmp_path / "desktop.sezam-key"
        export_sezam_key(desktop_keypair, kek, desktop_backup, salt, params)

        root = Path(__file__).resolve().parents[1]
        harness = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, Promise,
  WebAssembly, Blob, URL, crypto: webcrypto,
  location: { origin: 'https://sezam.invalid', search: '' },
  addEventListener() {},
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
  document: { addEventListener() {} },
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 4)) {
  vm.runInContext(fs.readFileSync(path, 'utf8'), context);
}
(async () => {
  await context.sodium.ready;
  const api = context.SezamKeyBackup;
  const kek = context.Uint8Array.from(Buffer.from(process.argv[5], 'base64'));
  const salt = context.Uint8Array.from(Buffer.from(process.argv[6], 'base64'));
  const desktopBackup = context.Uint8Array.from(Buffer.from(process.argv[4], 'base64'));
  const derive = async () => context.Uint8Array.from(kek);
  const imported = await api.parse(
    desktopBackup, 'cross-client backup password', context.sodium, derive
  );
  assert.strictEqual(imported.keypairBytes.length, 96);

  const signing = context.sodium.crypto_sign_keypair();
  const encryption = context.sodium.crypto_box_keypair();
  const privateData = new context.Uint8Array(96);
  privateData.set(signing.privateKey, 0);
  privateData.set(encryption.privateKey, 64);
  const webBackup = api.build(
    privateData,
    signing.publicKey,
    encryption.publicKey,
    kek,
    salt,
    { time_cost: 2, memory_cost: 65536, parallelism: 1, hash_len: 64 },
    context.sodium
  );
  const tampered = context.Uint8Array.from(webBackup);
  tampered[tampered.length - 1] ^= 1;
  await assert.rejects(
    api.parse(tampered, 'cross-client backup password', context.sodium, derive)
  );
  process.stdout.write(JSON.stringify({
    importedPrivate: Buffer.from(imported.keypairBytes).toString('base64'),
    webBackup: Buffer.from(webBackup).toString('base64'),
    webSigningSeed: Buffer.from(signing.privateKey.slice(0, 32)).toString('base64'),
    webEncryptionSk: Buffer.from(encryption.privateKey).toString('base64'),
  }));
})().catch((error) => { console.error(error); process.exit(1); });
"""
        vendor = root / "web" / "static" / "js" / "vendor"
        result = subprocess.run(
            [
                node_cmd(),
                "-e",
                harness,
                str(vendor / "libsodium-sumo.min.js"),
                str(vendor / "libsodium-wrappers.min.js"),
                str(root / "web" / "static" / "js" / "app.js"),
                base64.b64encode(desktop_backup.read_bytes()).decode("ascii"),
                base64.b64encode(kek).decode("ascii"),
                base64.b64encode(salt).decode("ascii"),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = json.loads(result.stdout)
        assert base64.b64decode(output["importedPrivate"]) == (
            bytes(desktop_keypair.signing_sk)
            + desktop_keypair.signing_pk
            + bytes(desktop_keypair.encryption_sk)
        )

        web_backup = tmp_path / "web.sezam-key"
        web_backup.write_bytes(base64.b64decode(output["webBackup"]))
        recovered = import_sezam_key(web_backup, password)
        assert bytes(recovered.signing_sk) == base64.b64decode(output["webSigningSeed"])
        assert bytes(recovered.encryption_sk) == base64.b64decode(output["webEncryptionSk"])
        kek[:] = b"\x00" * len(kek)


# ── Argon2id KDF ──


class TestArgon2id:
    # Use fast params for testing
    FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)

    def test_derive_kek_length(self):
        salt = generate_salt()
        kek = derive_kek("test_password", salt, self.FAST_PARAMS)
        assert len(kek) == 32
        assert isinstance(kek, bytearray)

    def test_same_password_same_salt(self):
        salt = generate_salt()
        kek1 = derive_kek("password", salt, self.FAST_PARAMS)
        kek2 = derive_kek("password", salt, self.FAST_PARAMS)
        assert kek1 == kek2

    def test_different_password_different_kek(self):
        salt = generate_salt()
        kek1 = derive_kek("password1", salt, self.FAST_PARAMS)
        kek2 = derive_kek("password2", salt, self.FAST_PARAMS)
        assert kek1 != kek2

    def test_different_salt_different_kek(self):
        kek1 = derive_kek("password", generate_salt(), self.FAST_PARAMS)
        kek2 = derive_kek("password", generate_salt(), self.FAST_PARAMS)
        assert kek1 != kek2

    def test_salt_length(self):
        salt = generate_salt()
        assert len(salt) == 16

    def test_zeroize_kek(self):
        salt = generate_salt()
        kek = derive_kek("password", salt, self.FAST_PARAMS)
        kek[:] = b"\x00" * len(kek)
        assert kek == bytearray(32)

    def test_kdf_does_not_create_immutable_raw_key(self, monkeypatch):
        def reject_immutable_api(*args, **kwargs):
            raise AssertionError("immutable Argon2 output API used")

        monkeypatch.setattr(
            "sezam.crypto.kdf.argon2.low_level.hash_secret_raw", reject_immutable_api
        )
        kek = derive_kek("password", generate_salt(), self.FAST_PARAMS)
        assert isinstance(kek, bytearray)
        assert len(kek) == 32

    def test_params_serialization(self):
        params = Argon2Params(time_cost=5, memory_cost=131072, parallelism=2)
        d = params.to_dict()
        restored = Argon2Params.from_dict(d)
        assert restored.time_cost == 5
        assert restored.memory_cost == 131072
        assert restored.parallelism == 2


# ── Padding ──


class TestPadding:
    def test_pad_minimum_32_bytes(self):
        data = b"x"
        padded = pad(data)
        assert len(padded) == 32

    def test_pad_power_of_2(self):
        data = b"x" * 50
        padded = pad(data)
        assert len(padded) == 64  # next power of 2 >= 52 (2 + 50)

    def test_pad_unpad_roundtrip(self):
        for size in [0, 1, 10, 30, 100, 500, 1000]:
            data = os.urandom(size)
            assert unpad(pad(data)) == data

    def test_padding_is_random(self):
        data = b"same_data"
        p1 = pad(data)
        p2 = pad(data)
        # Same data after unpad but padding bytes should differ (random)
        assert unpad(p1) == unpad(p2) == data
        # The padded versions might differ due to random padding
        # (but with probability 1 - 2^-n they will)

    def test_invalid_padding_length(self):
        with pytest.raises(ValueError):
            unpad(b"\x00")  # Too short

    def test_corrupted_padding(self):
        with pytest.raises(ValueError):
            unpad(b"\xff\xff" + b"\x00")  # padding_len = 65535, but only 1 byte

    def test_next_power_of_2(self):
        assert _next_power_of_2(1) == 1
        assert _next_power_of_2(2) == 2
        assert _next_power_of_2(3) == 4
        assert _next_power_of_2(5) == 8
        assert _next_power_of_2(17) == 32
        assert _next_power_of_2(32) == 32
        assert _next_power_of_2(33) == 64


# ── AEAD Encryption ──


class TestAEAD:
    @staticmethod
    def _make_ids():
        dek = os.urandom(32)
        dek_id = ulid_to_bytes(new_ulid())
        object_id = ulid_to_bytes(new_ulid())
        return dek, dek_id, object_id

    def test_encrypt_decrypt_roundtrip(self):
        dek, dek_id, object_id = self._make_ids()
        plaintext = b"Hello, Sezam!"

        blob = encrypt(
            plaintext, dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        result = decrypt(blob, dek, object_id, version=1)
        assert result == plaintext

    def test_envelope_format(self):
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"test", dek, dek_id, object_id, version=1, blob_kind=BlobKind.NODE_META
        )

        env = parse_envelope(blob)
        assert env.alg == ALG_XCHACHA20POLY1305
        assert env.schema_version == SCHEMA_VERSION
        assert env.blob_kind == BlobKind.NODE_META
        assert env.dek_id == dek_id
        assert len(env.nonce) == 24

    def test_wrong_dek_fails(self):
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"secret", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        wrong_dek = os.urandom(32)
        with pytest.raises(CryptoError):
            decrypt(blob, wrong_dek, object_id, version=1)

    def test_wrong_object_id_fails(self):
        """Swap attack detection: changing object_id should fail."""
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"secret", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        wrong_object_id = ulid_to_bytes(new_ulid())
        with pytest.raises(CryptoError):
            decrypt(blob, dek, wrong_object_id, version=1)

    def test_wrong_version_fails(self):
        """Downgrade/replay attack detection: changing version should fail."""
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"secret", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        with pytest.raises(CryptoError):
            decrypt(blob, dek, object_id, version=2)

    def test_tampered_ciphertext_fails(self):
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"secret", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        # Tamper with ciphertext
        tampered = bytearray(blob)
        tampered[-5] ^= 0xFF
        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), dek, object_id, version=1)

    def test_tampered_header_fails(self):
        """Header is authenticated via AAD — tampering should fail."""
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"secret", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        # Tamper with blob_kind in header
        tampered = bytearray(blob)
        tampered[2] = BlobKind.AUDIT_DETAILS  # Change blob_kind
        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), dek, object_id, version=1)

    def test_web_rejects_tampered_alg_schema_and_kind_headers(self):
        import subprocess
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        harness = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, Promise,
  WebAssembly, Blob, URL, crypto: webcrypto,
  location: { origin: 'https://sezam.invalid', search: '' },
  addEventListener() {},
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
  document: { addEventListener() {} },
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 4)) {
  vm.runInContext(fs.readFileSync(path, 'utf8'), context);
}
(async () => {
  await context.sodium.ready;
  const dek = context.Uint8Array.from({ length: 32 }, (_, i) => i);
  const dekId = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
  const objectId = '01ARZ3NDEKTSV4RRFFQ69G5FB0';
  const envelope = context.encryptEnvelope(
    { value: 'secret' }, 3, dekId, objectId, 1, dek, context.sodium
  );
  const roundTrip = context.decryptEnvelope(
    envelope, objectId, 1, { [dekId]: dek }, context.sodium
  );
  assert.strictEqual(roundTrip.value, 'secret');
  for (const index of [0, 1, 2]) {
    const tampered = context.Uint8Array.from(envelope);
    tampered[index] ^= 1;
    assert.throws(() => context.decryptEnvelope(
      tampered, objectId, 1, { [dekId]: dek }, context.sodium
    ));
  }
  process.stdout.write('ok');
})().catch((error) => { console.error(error); process.exit(1); });
"""
        vendor = root / "web" / "static" / "js" / "vendor"
        result = subprocess.run(
            [
                node_cmd(),
                "-e",
                harness,
                str(vendor / "libsodium-sumo.min.js"),
                str(vendor / "libsodium-wrappers.min.js"),
                str(root / "web" / "static" / "js" / "app.js"),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.stdout == "ok"

    def test_aad_is_59_bytes(self):
        dek_id = ulid_to_bytes(new_ulid())
        object_id = ulid_to_bytes(new_ulid())
        aad = build_aad(1, 1, 1, dek_id, object_id, 1)
        assert len(aad) == 59

    def test_no_padding_mode(self):
        dek, dek_id, object_id = self._make_ids()
        plaintext = b"no padding test"

        blob = encrypt(
            plaintext,
            dek,
            dek_id,
            object_id,
            version=1,
            blob_kind=BlobKind.DEK_WRAP,
            enable_padding=False,
        )

        result = decrypt(blob, dek, object_id, version=1, enable_padding=False)
        assert result == plaintext

    def test_large_plaintext(self):
        dek, dek_id, object_id = self._make_ids()
        plaintext = os.urandom(10000)

        blob = encrypt(
            plaintext, dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )
        result = decrypt(blob, dek, object_id, version=1)
        assert result == plaintext

    def test_empty_plaintext(self):
        dek, dek_id, object_id = self._make_ids()
        blob = encrypt(
            b"", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )
        result = decrypt(blob, dek, object_id, version=1)
        assert result == b""


# ── DEK Wrapping ──


class TestDEKWrapping:
    def test_dek_wrap_unwrap(self):
        kek = bytearray(os.urandom(32))
        dek = bytearray(os.urandom(32))
        kek_id = ulid_to_bytes(new_ulid())
        archive_id = ulid_to_bytes(new_ulid())

        wrapped = encrypt_dek_wrap(dek, kek, kek_id, archive_id)
        unwrapped = decrypt_dek_wrap(wrapped, kek, archive_id)

        assert unwrapped == dek

    def test_wrong_kek_fails(self):
        kek = bytearray(os.urandom(32))
        dek = bytearray(os.urandom(32))
        kek_id = ulid_to_bytes(new_ulid())
        archive_id = ulid_to_bytes(new_ulid())

        wrapped = encrypt_dek_wrap(dek, kek, kek_id, archive_id)

        wrong_kek = bytearray(os.urandom(32))
        with pytest.raises(CryptoError):
            decrypt_dek_wrap(wrapped, wrong_kek, archive_id)

    def test_keypair_wrap_unwrap(self):
        kek = bytearray(os.urandom(32))
        keypair_data = bytearray(os.urandom(64))
        kek_id = ulid_to_bytes(new_ulid())
        user_id = ulid_to_bytes(new_ulid())

        wrapped = encrypt_keypair_wrap(keypair_data, kek, kek_id, user_id)
        unwrapped = decrypt_keypair_wrap(wrapped, kek, user_id)

        assert unwrapped == keypair_data

    def test_chain_wrapping(self):
        """Old DEK wrapped by new DEK (dek_archive chain, spec 9.3)."""
        kek = bytearray(os.urandom(32))
        old_dek = bytearray(os.urandom(32))
        new_dek = bytearray(os.urandom(32))
        new_dek_id = ulid_to_bytes(new_ulid())
        archive_id = ulid_to_bytes(new_ulid())

        # Wrap old DEK with new DEK
        wrapped = encrypt_dek_wrap(old_dek, new_dek, new_dek_id, archive_id)
        # Unwrap with new DEK
        unwrapped = decrypt_dek_wrap(wrapped, new_dek, archive_id)
        assert unwrapped == old_dek

        # Cannot unwrap with KEK (it's wrapped by new DEK, not KEK)
        with pytest.raises(CryptoError):
            decrypt_dek_wrap(wrapped, kek, archive_id)


# ── Blob Kind ──


class TestBlobKind:
    def test_all_blob_kinds(self):
        dek, dek_id, object_id = os.urandom(32), ulid_to_bytes(new_ulid()), ulid_to_bytes(new_ulid())

        for kind in BlobKind:
            blob = encrypt(
                b"test", dek, dek_id, object_id, version=1, blob_kind=kind
            )
            env = parse_envelope(blob)
            assert env.blob_kind == kind
            result = decrypt(blob, dek, object_id, version=1)
            assert result == b"test"

    def test_cross_kind_swap_detection(self):
        """Swapping blob_kind in AAD must fail (swap attack)."""
        dek, dek_id, object_id = os.urandom(32), ulid_to_bytes(new_ulid()), ulid_to_bytes(new_ulid())

        blob = encrypt(
            b"test", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA
        )

        # Tamper blob_kind in header
        tampered = bytearray(blob)
        tampered[2] = BlobKind.NODE_META
        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), dek, object_id, version=1)


class TestEntryWireFormat:
    """C6 regression: the canonical cross-client entry payload is TWO envelopes
    (ENTRY_META + ENTRY_DATA) framed as u32be(meta_len) || meta_env || data_env
    (spec §4.1 + §8.2 — matches desktop sync_client and the fixed web client).

    A single merged AEAD blob (the old web format, {name,tags,fields} in one
    ENTRY_DATA envelope) is NOT a valid canonical entry payload and must be
    rejected by the length-prefix parser.
    """

    @staticmethod
    def _build_entry_payload(dek, dek_id, object_id):
        import json

        meta_json = json.dumps({"name": "gmail", "tags": ["mail"]}, separators=(",", ":")).encode()
        data_json = json.dumps(
            {"fields": [{"key": "password", "value": "s3cret", "sensitive": True}]},
            separators=(",", ":"),
        ).encode()
        meta_env = encrypt(meta_json, dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_META)
        data_env = encrypt(data_json, dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA)
        payload = struct.pack(">I", len(meta_env)) + meta_env + data_env
        return payload, meta_env, data_env

    def test_canonical_framing_roundtrip(self):
        """u32be(meta_len) prefix must locate both envelopes, each decrypting back."""
        import json

        dek = os.urandom(32)
        dek_id, object_id = ulid_to_bytes(new_ulid()), ulid_to_bytes(new_ulid())
        payload, meta_env, data_env = self._build_entry_payload(dek, dek_id, object_id)

        meta_len = struct.unpack(">I", payload[:4])[0]
        assert meta_len == len(meta_env)
        assert 4 + meta_len <= len(payload)
        parsed_meta = payload[4:4 + meta_len]
        parsed_data = payload[4 + meta_len:]
        assert parsed_meta == meta_env
        assert parsed_data == data_env

        meta = json.loads(decrypt(parsed_meta, dek, object_id, version=1))
        data = json.loads(decrypt(parsed_data, dek, object_id, version=1))
        assert meta["name"] == "gmail"
        assert meta["tags"] == ["mail"]
        assert data["fields"][0]["key"] == "password"

    def test_two_envelopes_use_distinct_blob_kinds(self):
        """Meta must be ENTRY_META(2), data must be ENTRY_DATA(3) — AI ACL separation."""
        dek = os.urandom(32)
        dek_id, object_id = ulid_to_bytes(new_ulid()), ulid_to_bytes(new_ulid())
        payload, meta_env, _ = self._build_entry_payload(dek, dek_id, object_id)
        meta_len = struct.unpack(">I", payload[:4])[0]
        assert payload[4:4 + meta_len][2] == BlobKind.ENTRY_META
        assert payload[4 + meta_len:][2] == BlobKind.ENTRY_DATA

    def test_merged_single_blob_is_not_valid_canonical_payload(self):
        """The old web format (one merged envelope) misparses under the framing:
        its first 4 bytes as u32be(meta_len) overrun the payload → rejected."""
        import json

        dek = os.urandom(32)
        dek_id, object_id = ulid_to_bytes(new_ulid()), ulid_to_bytes(new_ulid())
        merged = encrypt(
            json.dumps({"name": "gmail", "tags": [], "fields": []}).encode(),
            dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA,
        )
        # Parse as canonical entry payload: first 4 bytes = alg,schema,kind,dek_id[0].
        meta_len = struct.unpack(">I", merged[:4])[0]
        assert 4 + meta_len > len(merged)  # framing guard rejects the merged blob

    def test_both_envelopes_bind_to_entry_object_id(self):
        """C6 mobile regression: both envelopes must be AAD-bound to the SAME
        entry id. Old mobile encrypted the data envelope under a separate dataId,
        so it could not be decrypted as part of the single entry object."""
        dek = os.urandom(32)
        dek_id = ulid_to_bytes(new_ulid())
        entry_id = ulid_to_bytes(new_ulid())
        other_id = ulid_to_bytes(new_ulid())  # the old mobile per-data-object id

        _, meta_env, data_env = self._build_entry_payload(dek, dek_id, entry_id)
        # Canonical: both decrypt under the entry id (single object).
        assert decrypt(meta_env, dek, entry_id, version=1)
        assert decrypt(data_env, dek, entry_id, version=1)

        # Old mobile behaviour: data envelope bound to a different object id →
        # unreadable as part of the entry object (AAD mismatch → Poly1305 fail).
        orphan_data = encrypt(
            b'{"fields":[]}', dek, dek_id, other_id, version=1,
            blob_kind=BlobKind.ENTRY_DATA,
        )
        with pytest.raises(CryptoError):
            decrypt(orphan_data, dek, entry_id, version=1)


class TestCrossClientAADEncoding:
    """C5 regression: ULID→AAD encoding must match web/mobile (26 ASCII bytes).

    Web builds AAD ids as TextEncoder().encode(id.padEnd(26,'\\0').slice(0,26));
    mobile as utf8.encode(id.padRight(26,'\\x00').substring(0,26)). Both are the
    26-char ULID string as ASCII. Desktop previously stored the 16-byte ULID
    binary + 10 zero pad, which broke Poly1305 verification across clients.
    """

    @staticmethod
    def _js_dart_id_bytes(ulid_str: str) -> bytes:
        """Reproduce the exact web/mobile id encoding independently of models.py."""
        return ulid_str.encode("ascii").ljust(26, b"\x00")[:26]

    def test_ulid_to_bytes_is_ascii_string(self):
        uid = new_ulid()
        # Before the C5 fix this returned ULID.bytes (16B) + b"\x00"*10.
        assert ulid_to_bytes(uid) == uid.encode("ascii")
        assert len(ulid_to_bytes(uid)) == 26

    def test_ulid_bytes_roundtrip(self):
        uid = new_ulid()
        assert bytes_to_ulid(ulid_to_bytes(uid)) == uid

    def test_aad_matches_web_mobile_golden_vector(self):
        """Desktop AAD must be byte-identical to the web/mobile encoding."""
        dek_uid = new_ulid()
        obj_uid = new_ulid()
        version = 7

        desktop_aad = build_aad(
            ALG_XCHACHA20POLY1305, SCHEMA_VERSION, BlobKind.ENTRY_DATA,
            ulid_to_bytes(dek_uid), ulid_to_bytes(obj_uid), version,
        )
        # Independently assembled the way JS/Dart clients do it.
        js_dart_aad = (
            struct.pack("BBB", ALG_XCHACHA20POLY1305, SCHEMA_VERSION, BlobKind.ENTRY_DATA)
            + self._js_dart_id_bytes(dek_uid)
            + self._js_dart_id_bytes(obj_uid)
            + struct.pack(">I", version)
        )
        assert desktop_aad == js_dart_aad
        assert len(desktop_aad) == 59

    def test_envelope_header_dek_id_is_ascii_ulid(self):
        """The dek_id in the envelope header must decode as the ASCII ULID string
        (what web's decryptEnvelope reads via TextDecoder)."""
        dek = os.urandom(32)
        dek_uid = new_ulid()
        obj_uid = new_ulid()
        blob = encrypt(
            b"cross-client", dek, ulid_to_bytes(dek_uid), ulid_to_bytes(obj_uid),
            version=1, blob_kind=BlobKind.ENTRY_DATA,
        )
        header_dek_id = blob[3:29]
        assert header_dek_id.rstrip(b"\x00").decode("ascii") == dek_uid


class TestPullSignatureFailClosed:
    """C3/C4 regression: pulled objects MUST be Ed25519-verified fail-closed
    (spec §8.2 pull 3a/4), pinned against the desktop SyncClient reference
    verifier that web + mobile must now match.

    Bugs pinned:
      - C3 (web): the server serializes the signature under `client_signature`;
        the web client read only `obj.signature` (always undefined) and then
        ACCEPTED the object as "legacy/system-generated" — a fail-open hole.
      - C4 (mobile): the client discarded the boolean result of the Ed25519
        verification and applied the object regardless.
    A compliant client must read `client_signature`, and reject a missing
    signature, an unknown-owner key, or a tampered payload_hash.
    """

    def _client(self, tmp_path):
        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        kp = generate_keypair()
        db = VaultDB(tmp_path / "sezam.db")
        db.open()  # a pull always runs on an open vault (its team log decides keys)
        db.create_schema()
        return SyncClient(db, "http://localhost", kp, new_ulid())

    def _self_signed_obj(self, client):
        obj = client._make_sync_object(
            id=new_ulid(), object_type="node", payload=os.urandom(64), version=1,
        )
        obj["owner_id"] = client._user_id  # signed by us → our own key verifies it
        return obj

    def test_valid_self_signed_object_verifies(self, tmp_path):
        client = self._client(tmp_path)
        assert client._verify_object_signature(self._self_signed_obj(client)) is True

    def test_missing_signature_is_rejected(self, tmp_path):
        """C3 fail-open: an object with no signature must NOT be accepted."""
        client = self._client(tmp_path)
        obj = self._self_signed_obj(client)
        obj.pop("signature", None)
        obj.pop("client_signature", None)
        assert client._verify_object_signature(obj) is False

    def test_server_client_signature_field_is_honored(self, tmp_path):
        """C3 core: the server sends the signature under `client_signature`, not
        `signature`. A reader that only checks `signature` (the old web bug) sees
        nothing and fails open; a compliant reader honors `client_signature`."""
        client = self._client(tmp_path)
        obj = self._self_signed_obj(client)
        obj["client_signature"] = obj.pop("signature")  # exactly like the pull response
        assert obj.get("signature") is None  # what the buggy web reader saw
        assert client._verify_object_signature(obj) is True

    def test_tampered_payload_hash_is_rejected(self, tmp_path):
        """A valid signature over a swapped payload_hash must be rejected (server
        kept the signature but replaced the ciphertext)."""
        client = self._client(tmp_path)
        obj = self._self_signed_obj(client)
        tampered = bytearray(bytes.fromhex(obj["payload_hash"]))
        tampered[0] ^= 0xFF
        obj["payload_hash"] = tampered.hex()
        assert client._verify_object_signature(obj) is False

    def test_unknown_owner_key_is_rejected(self, tmp_path, monkeypatch):
        """Fail-closed: if the author's signing key cannot be resolved, reject."""
        client = self._client(tmp_path)
        obj = self._self_signed_obj(client)
        obj["owner_id"] = new_ulid()  # a different, unknown user
        monkeypatch.setattr(client, "_get_signing_pk", lambda uid: None)
        assert client._verify_object_signature(obj) is False

    def test_fresh_client_accepts_current_and_historical_owner_signatures(
        self, tmp_path, monkeypatch
    ):
        import base64
        import hashlib

        from nacl.signing import SigningKey

        client = self._client(tmp_path)
        client._db.open()
        client._db.create_schema()
        owner_id = new_ulid()
        old_keypair = generate_keypair()
        current_keypair = generate_keypair()
        unrelated_keypair = generate_keypair()
        from sezam.vault.sync_client import key_rotation_message

        # The successor (current) key certifies the archived key.
        certificate = current_keypair.to_nacl_signing_key().sign(key_rotation_message(
            owner_id,
            old_keypair.signing_pk, old_keypair.encryption_pk,
            current_keypair.signing_pk, current_keypair.encryption_pk,
        )).signature
        monkeypatch.setattr(
            client,
            "_request",
            lambda method, path, **kwargs: {
                "signing_pk": current_keypair.signing_pk.hex(),
                "encryption_pk": current_keypair.encryption_pk.hex(),
                "archived_keys": [
                    {
                        "signing_pk": old_keypair.signing_pk.hex(),
                        "encryption_pk": old_keypair.encryption_pk.hex(),
                        "key_fingerprint": old_keypair.fingerprint,
                        "archived_at": 1,
                        "successor_signing_pk": current_keypair.signing_pk.hex(),
                        "rotation_signature": certificate.hex(),
                        "retired_seq": 5,
                    }
                ],
            },
        )

        def signed_object(keypair, commit_seq=3):
            payload = os.urandom(64)
            payload_hash = hashlib.sha256(payload).hexdigest()
            obj = {
                "id": new_ulid(),
                "object_type": "node",
                "payload": base64.b64encode(payload).decode(),
                "payload_hash": payload_hash,
                "owner_id": owner_id,
                "version": 1,
                "is_deleted": 0,
                "commit_seq": commit_seq,
            }
            canonical = client._build_signature_payload(
                id=obj["id"],
                object_type=obj["object_type"],
                parent_ref=None,
                target_user_id=None,
                is_deleted=0,
                version=1,
                payload_hash=payload_hash,
            )
            obj["signature"] = SigningKey(bytes(keypair.signing_sk)).sign(
                canonical
            ).signature.hex()
            return obj

        assert client._verify_object_signature(signed_object(old_keypair)) is True
        # Review 688edcb V4: nothing committed after the rotation.
        assert client._verify_object_signature(signed_object(old_keypair, 6)) is False
        assert client._verify_object_signature(signed_object(current_keypair)) is True
        assert client._verify_object_signature(signed_object(current_keypair, 6)) is True
        assert client._verify_object_signature(signed_object(unrelated_keypair)) is False


class TestDesktopTofuRotation:
    """H10 regression: cached peer keys must be refreshed and compared per pull."""

    @staticmethod
    def _client(tmp_path):
        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "sezam.db")
        db.open()
        db.create_schema()
        return SyncClient(db, "http://localhost", generate_keypair(), new_ulid())

    @staticmethod
    def _cache_peer(client, user_id, signing_pk, encryption_pk):
        client._db.execute(
            "INSERT INTO known_keys "
            "(user_id, signing_pk, encryption_pk, fingerprint, first_seen, last_verified) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                user_id,
                signing_pk,
                encryption_pk,
                compute_fingerprint(signing_pk, encryption_pk),
                100,
                200,
            ),
        )

    def test_cached_signing_key_rotation_is_blocked_until_explicit_confirmation(
        self, tmp_path, monkeypatch
    ):
        client = self._client(tmp_path)
        user_id = new_ulid()
        old_keypair = generate_keypair()
        new_keypair = generate_keypair()
        self._cache_peer(
            client, user_id, old_keypair.signing_pk, old_keypair.encryption_pk
        )
        requests = []

        def rotated_keys(method, path, **kwargs):
            requests.append((method, path, kwargs))
            return {
                "signing_pk": new_keypair.signing_pk.hex(),
                "encryption_pk": new_keypair.encryption_pk.hex(),
            }

        monkeypatch.setattr(client, "_request", rotated_keys)

        from sezam.vault.sync_client import TofuKeyChangeError

        with pytest.raises(TofuKeyChangeError) as raised:
            client._get_signing_pk(user_id)

        assert len(requests) == 1
        assert client._tofu_warnings == [{
            "user_id": user_id,
            "old_fingerprint": old_keypair.fingerprint,
            "new_fingerprint": new_keypair.fingerprint,
        }]

        cached = client._db.fetchone(
            "SELECT signing_pk, encryption_pk, fingerprint, first_seen, last_verified "
            "FROM known_keys WHERE user_id = ?",
            (user_id,),
        )
        assert bytes(cached["signing_pk"]) == old_keypair.signing_pk
        assert bytes(cached["encryption_pk"]) == old_keypair.encryption_pk
        assert cached["fingerprint"] == old_keypair.fingerprint
        assert (cached["first_seen"], cached["last_verified"]) == (100, 200)

        with pytest.raises(ValueError, match="does not match"):
            client.confirm_tofu_key_change(raised.value, old_keypair.fingerprint)
        client.confirm_tofu_key_change(raised.value, new_keypair.fingerprint)
        assert client._get_signing_pk(user_id) == new_keypair.signing_pk

        cached = client._db.fetchone(
            "SELECT signing_pk, encryption_pk, fingerprint, first_seen, last_verified "
            "FROM known_keys WHERE user_id = ?",
            (user_id,),
        )
        assert bytes(cached["signing_pk"]) == new_keypair.signing_pk
        assert bytes(cached["encryption_pk"]) == new_keypair.encryption_pk
        assert cached["fingerprint"] == new_keypair.fingerprint
        assert cached["first_seen"] == 100
        assert cached["last_verified"] > 200

    def test_encryption_key_only_rotation_also_triggers_tofu_warning(
        self, tmp_path, monkeypatch
    ):
        client = self._client(tmp_path)
        user_id = new_ulid()
        old_keypair = generate_keypair()
        replacement_encryption_pk = generate_keypair().encryption_pk
        self._cache_peer(
            client, user_id, old_keypair.signing_pk, old_keypair.encryption_pk
        )
        new_fingerprint = compute_fingerprint(
            old_keypair.signing_pk, replacement_encryption_pk
        )
        monkeypatch.setattr(
            client,
            "_request",
            lambda method, path, **kwargs: {
                "signing_pk": old_keypair.signing_pk.hex(),
                "encryption_pk": replacement_encryption_pk.hex(),
            },
        )

        from sezam.vault.sync_client import TofuKeyChangeError

        with pytest.raises(TofuKeyChangeError):
            client._get_signing_pk(user_id)
        assert client._tofu_warnings == [{
            "user_id": user_id,
            "old_fingerprint": old_keypair.fingerprint,
            "new_fingerprint": new_fingerprint,
        }]
        cached = client._db.fetchone(
            "SELECT signing_pk, encryption_pk FROM known_keys WHERE user_id = ?",
            (user_id,),
        )
        assert bytes(cached["signing_pk"]) == old_keypair.signing_pk
        assert bytes(cached["encryption_pk"]) == old_keypair.encryption_pk


class TestDesktopAuditDagSync:
    """C5 regression: sync preserves complete, independently signed audit DAG records."""

    @staticmethod
    def _db(tmp_path, name):
        from sezam.vault.db import VaultDB

        db = VaultDB(tmp_path / name)
        db.open()
        db.create_schema()
        return db

    def test_push_includes_every_unsynced_audit_as_canonical_complete_record(
        self, tmp_path
    ):
        import base64
        import json

        from sezam.vault.audit import AuditLog
        from sezam.vault.sync_client import SyncClient

        db = self._db(tmp_path, "audit-push.db")
        keypair = generate_keypair()
        actor_id = new_ulid()
        try:
            audit_id = AuditLog(db).append(
                actor_id,
                "write",
                keypair.to_nacl_signing_key(),
                encrypted_details=b"encrypted-audit-details",
            )
            legacy_id = new_ulid()
            db.execute(
                "INSERT INTO audit_log "
                "(id, parent_ids, actor_id, action, encrypted_details, timestamp, signature) "
                "VALUES (?, '[]', ?, 'sync_pull', ?, 1, ?)",
                (legacy_id, actor_id, b"legacy-details-only", b"\x00" * 64),
            )
            client = SyncClient(db, "http://localhost", keypair, actor_id)

            audit_objects = [
                obj for obj in client._collect_dirty_objects()
                if obj["object_type"] == "audit"
            ]
            assert [obj["id"] for obj in audit_objects] == [audit_id]
            assert audit_objects[0]["version"] == 2
            assert db.fetchone(
                "SELECT state FROM outbox WHERE kind = 'audit' AND object_id = ?",
                (legacy_id,),
            )["state"] == "refused"

            payload = base64.b64decode(audit_objects[0]["payload"])
            record = json.loads(payload)
            assert payload == json.dumps(
                record, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            assert record == {
                "action": "write",
                "actor_id": actor_id,
                "encrypted_details": base64.b64encode(
                    b"encrypted-audit-details"
                ).decode("ascii"),
                "format": "sezam-audit-v1",
                "id": audit_id,
                "parent_ids": [],
                "signature": db.fetchone(
                    "SELECT hex(signature) AS signature FROM audit_log WHERE id = ?",
                    (audit_id,),
                )["signature"].lower(),
                "timestamp": db.fetchone(
                    "SELECT timestamp FROM audit_log WHERE id = ?", (audit_id,)
                )["timestamp"],
            }

            client.token = "token"
            client._request = lambda *args, **kwargs: {
                "accepted": [{"id": audit_id, "commit_seq": 1}],
                "conflicts": [],
            }
            client.push()
            assert not any(
                obj["object_type"] == "audit"
                for obj in client._collect_dirty_objects()
            )
        finally:
            db.close()

    def test_pull_rejects_tampering_and_restores_verifiable_dag_edges(self, tmp_path):
        import base64
        import json

        from sezam.vault.audit import AuditLog
        from sezam.vault.sync_client import SyncClient

        source = self._db(tmp_path, "audit-source.db")
        target = self._db(tmp_path, "audit-target.db")
        keypair = generate_keypair()
        actor_id = new_ulid()
        try:
            source_audit = AuditLog(source)
            parent_id = source_audit.append(
                actor_id,
                "write",
                keypair.to_nacl_signing_key(),
                encrypted_details=b"parent",
            )
            child_id = source_audit.append(
                actor_id,
                "delete",
                keypair.to_nacl_signing_key(),
                encrypted_details=b"child",
            )
            source_client = SyncClient(
                source, "http://localhost", keypair, actor_id
            )
            audit_objects = [
                obj for obj in source_client._collect_dirty_objects()
                if obj["object_type"] == "audit"
            ]
            target_client = SyncClient(
                target, "http://localhost", keypair, actor_id
            )
            target.execute(
                "INSERT INTO audit_log "
                "(id, parent_ids, actor_id, action, encrypted_details, timestamp, signature) "
                "VALUES (?, '[]', ?, 'sync_pull', ?, 1, ?)",
                (parent_id, actor_id, b"legacy-details-only", b"\x00" * 64),
            )

            for obj in audit_objects:
                target_client._apply_pulled_object(obj)

            target_audit = AuditLog(target)
            assert target_audit.verify_record(parent_id, keypair.signing_pk)
            assert target_audit.verify_record(child_id, keypair.signing_pk)
            assert [tuple(row) for row in target.fetchall(
                "SELECT child_id, parent_id FROM audit_dag_edges"
            )] == [(child_id, parent_id)]

            tampered = dict(audit_objects[0])
            record = json.loads(base64.b64decode(tampered["payload"]))
            record["action"] = "approve"
            tampered["payload"] = base64.b64encode(json.dumps(
                record, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")).decode("ascii")
            with pytest.raises(ValueError, match="audit signature"):
                target_client._apply_pulled_object(tampered)

            cycle_a, cycle_b = new_ulid(), new_ulid()

            def cycle_object(record_id, parent_id):
                parent_ids_json = json.dumps([parent_id], separators=(",", ":"))
                canonical = AuditLog._build_canonical(
                    record_id,
                    actor_id,
                    parent_ids_json,
                    "write",
                    2,
                    b"\x00" * 32,
                )
                signature = keypair.to_nacl_signing_key().sign(canonical).signature
                payload = json.dumps({
                    "action": "write",
                    "actor_id": actor_id,
                    "encrypted_details": "",
                    "format": "sezam-audit-v1",
                    "id": record_id,
                    "parent_ids": [parent_id],
                    "signature": signature.hex(),
                    "timestamp": 2,
                }, sort_keys=True, separators=(",", ":")).encode("utf-8")
                return source_client._make_sync_object(
                    id=record_id,
                    object_type="audit",
                    payload=payload,
                    version=2,
                )

            target.begin()
            target.execute("PRAGMA defer_foreign_keys = ON")
            try:
                target_client._apply_pulled_object(cycle_object(cycle_a, cycle_b))
                target_client._apply_pulled_object(cycle_object(cycle_b, cycle_a))
                with pytest.raises(ValueError, match="cycle"):
                    target_client._validate_audit_dag()
            finally:
                target.rollback()
        finally:
            source.close()
            target.close()


class TestClientPullSignatureSource:
    """C3/C4 cross-language source guard: web (JS) and mobile (Dart) have no
    runtime harness here, so we pin the fix in-source. These FAIL on the
    pre-fix code (web reading `obj.signature` fail-open; mobile discarding the
    verifyDetached result) and pass once the clients verify fail-closed."""

    @staticmethod
    def _repo_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[1]

    def test_web_pull_reads_client_signature_and_fails_closed(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        # Reads the server field name.
        assert "obj.client_signature || obj.signature" in src
        # Fail-closed: rejects rather than accepting unsigned objects.
        assert "REJECT object" in src
        # The old fail-open branch must be gone.
        assert "system-generated) are accepted" not in src

    def test_mobile_pull_enforces_verify_result(self):
        src = (
            self._repo_root() / "mobile" / "lib" / "services" / "sync_service.dart"
        ).read_text(encoding="utf-8")
        # The boolean result is now captured and enforced.
        assert "sigValid" in src
        assert "if (!sigValid)" in src
        # The discarded-result marker of the old fail-open code must be gone.
        assert "If we reach here, signature is valid" not in src


class TestRollbackCheckpointFailClosed:
    """H5 regression: on rollback detection the desktop sync client must NOT
    advance/overwrite the trusted checkpoint (spec §2.9 fail-closed, §8.3).

    The old `pull()` caught the SyncRollbackWarning, logged it, and then called
    `_save_sync_checkpoint(...)` unconditionally — overwriting the trusted
    baseline with the suspicious state. On the *next* pull the comparison ran
    against the tampered checkpoint and the rollback was silently accepted.
    """

    class _FakeDB:
        """Minimal VaultDB stand-in — only the meta store the checkpoint path
        touches. fetchall/fetchone return empty so _compute_state_hash (which we
        override anyway) never queries a real schema."""

        def __init__(self):
            self._meta: dict[str, str] = {}

        def get_meta(self, key):
            return self._meta.get(key)

        def set_meta(self, key, value):
            self._meta[key] = value

        def get_meta_json(self, key):
            return None

        def set_meta_json(self, key, value):
            pass

        def fetchall(self, *args, **kwargs):
            return []

        def fetchone(self, *args, **kwargs):
            return None

        def execute(self, *args, **kwargs):
            return None

        def require_generation(self):
            pass

        def begin(self):
            pass

        def commit(self):
            pass

        def rollback(self):
            pass

    class _FakeDEKManager:
        def __init__(self):
            self.dek_id = new_ulid()
            self.dek = bytearray(b"\x42" * 32)

        def get_audit_dek(self):
            return self.dek_id, self.dek

        def _wrapping_kek_id(self):
            return self.dek_id  # the fake KEK is always the vault's current one

    def _client(self):
        from sezam.vault.sync_client import SyncClient

        client = SyncClient(self._FakeDB(), "http://localhost", generate_keypair(), new_ulid())
        client.set_dek_manager(self._FakeDEKManager())
        client._token = "tok"  # skip authenticate()
        return client

    def test_checkpoint_not_advanced_on_rollback(self):
        client = self._client()
        baseline_hash = "a1" * 32
        # Trusted baseline: seq=5, hash=baseline (encrypted with audit DEK).
        client._save_sync_checkpoint(5, baseline_hash)
        client._db.set_meta("last_known_commit_seq", "5")

        # Pull returns the SAME seq but a tampered state (different hash) — the
        # "same seq, different hash" rollback trigger.
        client._request = lambda *a, **k: {"objects": [{"id": new_ulid()}], "max_commit_seq": 5}
        client._verify_object_signature = lambda obj: True
        client._apply_pulled_object = lambda obj: None
        client._compute_state_hash = lambda: "b2" * 32  # differs from baseline

        result = client.pull()

        assert "rollback_warning" in result
        # Fail-closed: the trusted checkpoint must STILL hold the original hash.
        cp = client._load_sync_checkpoint()
        assert cp["state_hash"] == baseline_hash
        assert cp["last_sync_seq"] == 5
        assert client._db.get_meta("last_known_commit_seq") == "5"

    def test_checkpoint_advances_on_clean_forward_pull(self):
        client = self._client()
        client._save_sync_checkpoint(5, "a1" * 32)
        client._db.set_meta("last_known_commit_seq", "5")

        # A legitimate forward advance: higher seq, new hash, no rollback.
        new_hash = "c3" * 32
        client._request = lambda *a, **k: {"objects": [{"id": new_ulid()}], "max_commit_seq": 6}
        client._verify_object_signature = lambda obj: True
        client._apply_pulled_object = lambda obj: None
        client._compute_state_hash = lambda: new_hash

        result = client.pull()

        assert "rollback_warning" not in result
        cp = client._load_sync_checkpoint()
        assert cp["state_hash"] == new_hash
        assert cp["last_sync_seq"] == 6

    def test_invalid_signature_rejects_entire_batch_without_advancing_sequence(self):
        client = self._client()
        client._db.set_meta("last_known_commit_seq", "5")
        applied = []
        objects = [{"id": new_ulid()}, {"id": new_ulid()}]
        client._request = lambda *a, **k: {
            "objects": objects,
            "max_commit_seq": 7,
        }
        client._verify_object_signature = lambda obj: obj is objects[0]
        client._apply_pulled_object = lambda obj: applied.append(obj["id"])

        with pytest.raises(RuntimeError, match="invalid or unverifiable signature"):
            client.pull()

        assert applied == []
        assert client._db.get_meta("last_known_commit_seq") == "5"
        assert client._db.get_meta("sync_checkpoint") is None

    def test_checkpoint_requires_audit_dek_and_rejects_legacy_plaintext(self):
        import base64
        import json

        from sezam.vault.sync_client import SyncClient, SyncRollbackWarning

        db = self._FakeDB()
        client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
        with pytest.raises(RuntimeError, match="audit DEK"):
            client._save_sync_checkpoint(1, "a1" * 32)
        assert db.get_meta("sync_checkpoint") is None

        legacy = json.dumps({"last_sync_seq": 1, "state_hash": "a1" * 32}).encode()
        db.set_meta("sync_checkpoint", "plain:" + base64.b64encode(legacy).decode())
        with pytest.raises(SyncRollbackWarning, match="plaintext"):
            client._load_sync_checkpoint()

    def test_state_hash_covers_tombstones_envelopes_archives_and_audit(self, tmp_path):
        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "state_hash.db")
        db.open()
        db.create_schema()
        try:
            dek_id = new_ulid()
            node_id = new_ulid()
            entry_id = new_ulid()
            envelope_id = new_ulid()
            archive_id = new_ulid()
            audit_id = new_ulid()

            db.execute(
                "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
                "VALUES (?, NULL, 'root', ?, 1)",
                (dek_id, b"dek"),
            )
            db.execute(
                "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
                "VALUES (?, NULL, ?, ?, 2, 1)",
                (node_id, b"deleted-node", dek_id),
            )
            db.execute(
                "INSERT INTO entries (id, node_id, encrypted_meta, encrypted_data, dek_id, version, is_deleted) "
                "VALUES (?, ?, ?, ?, ?, 3, 1)",
                (entry_id, node_id, b"deleted-meta", b"deleted-data", dek_id),
            )
            db.execute(
                "INSERT INTO access_envelopes "
                "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                "VALUES (?, ?, ?, ?, 'read', ?)",
                (envelope_id, dek_id, new_ulid(), new_ulid(), b"envelope"),
            )
            db.execute(
                "INSERT INTO dek_archive (id, replaced_by, encrypted_dek, archived_at, version) "
                "VALUES (?, ?, ?, 1, 4)",
                (archive_id, dek_id, b"archive"),
            )
            db.execute(
                "INSERT INTO audit_log "
                "(id, parent_ids, actor_id, action, encrypted_details, timestamp, signature) "
                "VALUES (?, '[]', ?, 'sync', ?, 1, ?)",
                (audit_id, new_ulid(), b"audit", b"s" * 64),
            )

            client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
            baseline = client._compute_state_hash()
            mutations = [
                ("UPDATE nodes SET encrypted_meta = ? WHERE id = ?", b"changed-node", node_id,
                 "UPDATE nodes SET encrypted_meta = ? WHERE id = ?", b"deleted-node"),
                ("UPDATE entries SET encrypted_data = ? WHERE id = ?", b"changed-data", entry_id,
                 "UPDATE entries SET encrypted_data = ? WHERE id = ?", b"deleted-data"),
                ("UPDATE access_envelopes SET encrypted_dek = ? WHERE id = ?", b"changed-envelope", envelope_id,
                 "UPDATE access_envelopes SET encrypted_dek = ? WHERE id = ?", b"envelope"),
                ("UPDATE dek_archive SET encrypted_dek = ? WHERE id = ?", b"changed-archive", archive_id,
                 "UPDATE dek_archive SET encrypted_dek = ? WHERE id = ?", b"archive"),
                ("UPDATE audit_log SET encrypted_details = ? WHERE id = ?", b"changed-audit", audit_id,
                 "UPDATE audit_log SET encrypted_details = ? WHERE id = ?", b"audit"),
            ]
            for update_sql, changed, obj_id, restore_sql, original in mutations:
                db.execute(update_sql, (changed, obj_id))
                assert client._compute_state_hash() != baseline
                db.execute(restore_sql, (original, obj_id))
                assert client._compute_state_hash() == baseline
        finally:
            db.close()


class TestDesktopPullConflicts:
    class _FakeDEKManager:
        def __init__(self, dek_id):
            self.dek_id = dek_id
            self.dek = bytearray(b"\x61" * 32)

        def get_audit_dek(self):
            return self.dek_id, self.dek

        def _wrapping_kek_id(self):
            return self.dek_id  # the fake KEK is always the vault's current one

    def test_pull_preserves_dirty_objects_and_stores_server_shadows(self, tmp_path):
        import base64

        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "pull-conflict.db")
        db.open()
        db.create_schema()
        db.execute("DROP TABLE sync_conflicts")
        db.close()
        db.open()

        dek_id = new_ulid()
        node_id = new_ulid()
        entry_id = new_ulid()
        db.execute(
            "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
            "VALUES (?, NULL, 'root', ?, 1)",
            (dek_id, b"dek"),
        )
        outbox.queue_write(db, node_id)
        outbox.queue_write(db, entry_id)
        db.execute(
            "INSERT INTO nodes "
            "(id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
            "VALUES (?, NULL, ?, ?, 2, 0)",
            (node_id, b"LOCAL_NODE", dek_id),
        )
        db.execute(
            "INSERT INTO entries "
            "(id, node_id, encrypted_meta, encrypted_data, dek_id, version, is_deleted) "
            "VALUES (?, ?, ?, ?, ?, 2, 0)",
            (entry_id, node_id, b"LOCAL_META", b"LOCAL_DATA", dek_id),
        )

        remote_entry = struct.pack(">I", len(b"REMOTE_META")) + b"REMOTE_META" + b"REMOTE_DATA"
        objects = [
            {
                "id": node_id,
                "object_type": "node",
                "payload": base64.b64encode(b"REMOTE_NODE").decode(),
                "payload_hash": "node-hash",
                "version": 2,
                "is_deleted": 0,
                "commit_seq": 8,
            },
            {
                "id": entry_id,
                "object_type": "entry",
                "parent_ref": node_id,
                "payload": base64.b64encode(remote_entry).decode(),
                "payload_hash": "entry-hash",
                "version": 3,
                "is_deleted": 0,
                "commit_seq": 9,
            },
        ]
        client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
        client.set_dek_manager(self._FakeDEKManager(dek_id))
        client.token = "token"
        client._request = lambda *args, **kwargs: {
            "objects": objects,
            "max_commit_seq": 9,
        }
        client._verify_object_signature = lambda obj: True

        try:
            result = client.pull()

            node = db.fetchone(
                "SELECT encrypted_meta, version FROM nodes WHERE id = ?",
                (node_id,),
            )
            entry = db.fetchone(
                "SELECT encrypted_meta, encrypted_data, version "
                "FROM entries WHERE id = ?",
                (entry_id,),
            )
            assert tuple(node) == (b"LOCAL_NODE", 2)
            assert tuple(entry) == (b"LOCAL_META", b"LOCAL_DATA", 2)
            assert outbox.has_write(db, node_id) and outbox.has_write(db, entry_id)

            shadows = db.fetchall(
                "SELECT object_id, local_version, server_version, server_payload "
                "FROM sync_conflicts ORDER BY object_id"
            )
            assert len(shadows) == 2
            assert {row["server_payload"] for row in shadows} == {
                b"REMOTE_NODE",
                remote_entry,
            }
            assert all(row["local_version"] == 2 for row in shadows)
            assert {row["server_version"] for row in shadows} == {2, 3}
            assert {conflict["id"] for conflict in result["conflicts"]} == {
                node_id,
                entry_id,
            }
            assert db.get_meta("last_known_commit_seq") == "9"
            restarted = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
            assert {conflict["id"] for conflict in restarted.get_pull_conflicts()} == {
                node_id,
                entry_id,
            }

            checkpoint_hash = client._compute_state_hash()
            db.execute(
                "UPDATE nodes SET encrypted_meta = ? WHERE id = ?",
                (b"CHANGED_LOCAL", node_id),
            )
            assert client._compute_state_hash() == checkpoint_hash
            outbox.drop_write(db, node_id)
            assert client._compute_state_hash() != checkpoint_hash
            outbox.queue_write(db, node_id)
            assert client._compute_state_hash() == checkpoint_hash
            db.execute(
                "UPDATE sync_conflicts SET server_payload = ? WHERE object_id = ?",
                (b"CHANGED_REMOTE", node_id),
            )
            assert client._compute_state_hash() != checkpoint_hash
        finally:
            db.close()

    def test_checkpoint_failure_rolls_back_conflict_and_sequence(self, tmp_path):
        import base64

        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "pull-conflict-rollback.db")
        db.open()
        db.create_schema()
        dek_id = new_ulid()
        node_id = new_ulid()
        db.execute(
            "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
            "VALUES (?, NULL, 'root', ?, 1)",
            (dek_id, b"dek"),
        )
        outbox.queue_write(db, node_id)
        db.execute(
            "INSERT INTO nodes "
            "(id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
            "VALUES (?, NULL, ?, ?, 2, 0)",
            (node_id, b"LOCAL", dek_id),
        )
        client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
        client.token = "token"
        client._request = lambda *args, **kwargs: {
            "objects": [
                {
                    "id": node_id,
                    "object_type": "node",
                    "payload": base64.b64encode(b"REMOTE").decode(),
                    "payload_hash": "hash",
                    "version": 3,
                    "commit_seq": 4,
                }
            ],
            "max_commit_seq": 4,
        }
        client._verify_object_signature = lambda obj: True
        client._save_sync_checkpoint = lambda *args: (_ for _ in ()).throw(
            RuntimeError("checkpoint failed")
        )

        try:
            with pytest.raises(RuntimeError, match="checkpoint failed"):
                client.pull()
            assert db.fetchall("SELECT object_id FROM sync_conflicts") == []
            assert db.get_meta("last_known_commit_seq") is None
            row = db.fetchone(
                "SELECT encrypted_meta, version FROM nodes WHERE id = ?",
                (node_id,),
            )
            assert tuple(row) == (b"LOCAL", 2)
            assert outbox.has_write(db, node_id)
        finally:
            db.close()

    def test_malformed_signed_entry_does_not_advance_pull_state(self, tmp_path):
        import base64

        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "malformed-pull.db")
        db.open()
        db.create_schema()
        client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
        client.token = "token"
        client._request = lambda *args, **kwargs: {
            "objects": [
                {
                    "id": new_ulid(),
                    "object_type": "entry",
                    "payload": base64.b64encode(b"bad").decode(),
                    "payload_hash": "hash",
                    "version": 1,
                    "commit_seq": 1,
                }
            ],
            "max_commit_seq": 1,
        }
        client._verify_object_signature = lambda obj: True

        try:
            with pytest.raises(ValueError, match="payload too short"):
                client.pull()
            assert db.fetchall("SELECT id FROM entries") == []
            assert db.get_meta("last_known_commit_seq") is None
            assert db.get_meta("sync_checkpoint") is None
        finally:
            db.close()


class TestExplicitFullResync:
    """H1 regression: tombstone-GC recovery is explicit, fail-closed and
    replaces the local snapshot only after the complete response verifies."""

    class _FakeDEKManager:
        def __init__(self, dek_id):
            self.dek_id = dek_id
            self.dek = bytearray(b"\x52" * 32)

        def get_audit_dek(self):
            return self.dek_id, self.dek

        def _wrapping_kek_id(self):
            return self.dek_id  # the fake KEK is always the vault's current one

        def can_unwrap(self, dek_id, wrapped, version):
            return False  # the fake wraps open with no KEK

    def _client_with_dirty_root(self, tmp_path):
        from sezam.vault.db import VaultDB
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "full-resync.db")
        db.open()
        db.create_schema()
        dek_id = new_ulid()
        node_id = new_ulid()
        db.execute(
            "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
            "VALUES (?, NULL, 'root', ?, 1)",
            (dek_id, b"old-dek"),
        )
        outbox.queue_write(db, node_id)
        db.execute(
            "INSERT INTO nodes "
            "(id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
            "VALUES (?, NULL, ?, ?, 1, 0)",
            (node_id, b"old-node", dek_id),
        )
        client = SyncClient(db, "http://localhost", generate_keypair(), new_ulid())
        client.set_dek_manager(self._FakeDEKManager(dek_id))
        client._token = "token"
        return client, db, node_id

    def test_confirmation_is_required_before_network_or_mutation(self, tmp_path):
        client, db, node_id = self._client_with_dirty_root(tmp_path)
        requested = []
        client._request = lambda *args, **kwargs: requested.append(args)
        try:
            with pytest.raises(RuntimeError, match="explicit confirmation"):
                client.full_resync()
            assert requested == []
            assert db.fetchone("SELECT id FROM nodes WHERE id = ?", (node_id,))
        finally:
            db.close()

    def test_invalid_snapshot_is_rejected_before_local_mutation(self, tmp_path):
        client, db, node_id = self._client_with_dirty_root(tmp_path)
        client._request = lambda *args, **kwargs: {
            "objects": [{"id": new_ulid(), "object_type": "node"}],
            "max_commit_seq": 100,
        }
        client._verify_object_signature = lambda obj: False
        try:
            with pytest.raises(RuntimeError, match="invalid signature"):
                client.full_resync(confirmed=True)
            assert outbox.has_write(db, node_id)
            assert db.get_meta("last_known_commit_seq") is None
        finally:
            db.close()

    def test_confirmed_resync_exports_dirty_and_replaces_snapshot(self, tmp_path):
        import sqlite3

        client, db, node_id = self._client_with_dirty_root(tmp_path)
        requested_paths = []

        def request(method, path, **kwargs):
            requested_paths.append(path)
            return {"objects": [], "max_commit_seq": 100}

        client._request = request
        export_path = tmp_path / "before-resync.db"
        try:
            result = client.full_resync(
                confirmed=True,
                dirty_export_path=export_path,
            )
            assert requested_paths == [
                "/api/sync?since_commit_seq=0&full_resync=true"
            ]
            # Review d150605 #6: an encrypted copy of the vault, and the unsent
            # root (with its key) is kept for the next push.
            copy = sqlite3.connect(export_path)
            assert copy.execute("SELECT id FROM nodes").fetchall() == [(node_id,)]
            copy.close()
            assert outbox.queued_ids(db, "nodes") == {node_id}
            assert len(db.fetchall("SELECT id FROM deks")) == 1
            assert db.get_meta("last_known_commit_seq") == "100"
            assert result["full_resync"] is True
            assert result["dirty_exported"] >= 1
        finally:
            db.close()

    def test_pull_pages_are_collected_before_full_resync_apply(self, tmp_path):
        client, db, _ = self._client_with_dirty_root(tmp_path)
        paths = []
        pages = iter([
            {
                "objects": [{"id": "first"}],
                "max_commit_seq": 250,
                "has_more": True,
                "next_cursor": 250,
            },
            {
                "objects": [{"id": "second"}],
                "max_commit_seq": 500,
                "has_more": False,
                "next_cursor": None,
            },
        ])

        def request(method, path, **kwargs):
            paths.append(path)
            return next(pages)

        client._request = request
        try:
            result = client._fetch_pull_pages(0, full_resync=True)
        finally:
            db.close()

        assert paths == [
            "/api/sync?since_commit_seq=0&full_resync=true",
            "/api/sync?since_commit_seq=0&full_resync=true&cursor=250",
        ]
        assert [obj["id"] for obj in result["objects"]] == ["first", "second"]
        assert result["max_commit_seq"] == 500

    def test_delta_pull_410_never_auto_resyncs(self):
        from sezam.vault.sync_client import ServerError, SyncClient

        class MetaDB:
            def require_generation(self):
                pass

            def get_meta(self, key):
                return "5" if key == "last_known_commit_seq" else None

        client = SyncClient(MetaDB(), "http://localhost", generate_keypair(), new_ulid())
        client._token = "token"
        client._request = lambda *args, **kwargs: (_ for _ in ()).throw(
            ServerError(410, "")
        )
        with pytest.raises(RuntimeError, match="explicit full resync"):
            client.pull()


class TestCrossClientExplicitFullResync:
    """H1 regressions for explicit, export-first, atomic web/mobile recovery."""

    @staticmethod
    def _repo_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[1]

    def test_web_410_requires_confirmation_export_and_explicit_flag(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        pull = src.split("async function pullAndBuildTreeLocked(", 1)[1].split(
            "async function performTOFUChecks", 1
        )[0]
        assert "await confirmWebFullResync()" in pull
        assert "since_commit_seq=0&full_resync=true" in pull
        assert "exportWebDirtyObjects(outbox)" in src
        assert "state.outbox[vaultObj.id] = vaultObj" in src
        assert "delete state.outbox[vaultObj.id]" in src
        assert src.count("apiFetch('/api/sync'") >= 2
        assert "const candidateEntries = isFullPull ? {}" in pull
        assert "await saveSyncCheckpoint(withheld" in pull
        checkpoint_pos = pull.index("await saveSyncCheckpoint(withheld")
        assert checkpoint_pos < pull.index("state.entries = candidateEntries")
        assert "if (isFullPull) state.outbox = {}" not in pull
        assert "while (data.has_more === true)" in pull
        assert "&cursor=${nextCursor}" in pull

    def test_mobile_full_resync_exports_and_atomically_replaces_snapshot(self):
        sync_src = (
            self._repo_root() / "mobile" / "lib" / "services" / "sync_service.dart"
        ).read_text(encoding="utf-8")
        db_src = (
            self._repo_root() / "mobile" / "lib" / "services" / "database_service.dart"
        ).read_text(encoding="utf-8")
        screen_src = (
            self._repo_root() / "mobile" / "lib" / "screens" / "vault_screen.dart"
        ).read_text(encoding="utf-8")

        assert "Future<FullResyncResult> fullResync({required bool confirmed})" in sync_src
        assert "since_commit_seq=0&full_resync=true" in sync_src
        assert "await _exportDirtyObjects()" in sync_src
        assert "replaceAll: fullResync" in sync_src
        assert "await _db.replaceSnapshotAndCommitCheckpoint" in sync_src
        assert "while (data['has_more'] == true)" in sync_src
        assert "&cursor=$nextCursor" in sync_src
        atomic = db_src.split("replaceSnapshotAndCommitCheckpoint", 1)[1].split(
            "// ── Settings", 1
        )[0]
        assert "db.transaction" in atomic
        assert "await txn.delete('vault_objects')" in atomic
        assert "'last_commit_seq'" in atomic
        assert "on FullResyncRequiredException" in screen_src
        assert "Export & full resync" in screen_src


class TestWebPushConflictHandling:
    """M2 regression (source guard — no JS runtime harness): the web
    `pushVaultObject` previously ignored the PushResponse body, so an HTTP 200
    carrying per-object `conflicts` looked like success — the modal closed and
    pulled, silently discarding the user's edit. A compliant client inspects
    `conflicts` and throws so the entry stays dirty (spec §8.2/§11)."""

    @staticmethod
    def _repo_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[1]

    def test_push_inspects_conflicts_and_throws(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        # The response body is now captured (was a bare `await apiFetch(...)`).
        assert "const resp = await apiFetch('/api/sync'" in src
        # Conflicts are inspected and surfaced as a distinguishable error.
        assert "resp.conflicts" in src
        assert "isSyncConflict" in src

    def test_dirty_ciphertext_survives_reload_and_overlays_server_conflict(self):
        import json
        import subprocess

        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        helpers = "function syncCoreVersion" + src.split(
            "function syncCoreVersion", 1
        )[1].split("function exportWebDirtyObjects", 1)[0]
        core_js = self._repo_root() / "web" / "static" / "js" / "vendor" / "sezam-sync-core.js"
        local = {
            "id": "OBJ", "version": 2, "payload_hash": "local",
            "signature": "local-sig", "payload": "LOCAL", "object_type": "entry",
        }
        server = {
            "id": "OBJ", "version": 3, "payload_hash": "server",
            "client_signature": "server-sig", "payload": "SERVER", "object_type": "entry",
        }
        script = f"""
globalThis.SezamSyncCore = eval(require('fs').readFileSync({json.dumps(str(core_js))}, 'utf8') + ';SezamSyncCore');
{helpers}
SezamSyncCore.ready.then(() => {{
const local = {json.dumps(local)};
const server = {json.dumps(server)};
const conflict = reconcileWebDirtyState([server], {{ OBJ: local }}, {{}});
const acceptedServer = {{ ...local, client_signature: local.signature }};
delete acceptedServer.signature;
const accepted = reconcileWebDirtyState([acceptedServer], {{ OBJ: local }}, conflict.conflicts);
console.log(JSON.stringify({{
  visible: conflict.visibleObjects[0].payload,
  shadow: conflict.conflicts.OBJ.server_object.payload,
  dirtyAfterAccepted: Object.keys(accepted.outbox).length,
  conflictsAfterAccepted: Object.keys(accepted.conflicts).length
}}));
}});
"""
        observed = json.loads(subprocess.run(
            [node_cmd(), "-e", script], check=True, capture_output=True, text=True
        ).stdout)
        assert observed == {
            "visible": "LOCAL", "shadow": "SERVER",
            "dirtyAfterAccepted": 0, "conflictsAfterAccepted": 0,
        }
        assert "encrypted_dirty_state" in src
        assert "await loadWebDirtyState(_sodium)" in src
        assert "await saveWebDirtyState(state.outbox, state.syncConflicts, _sodium)" in src
        assert "if (isFullPull) state.outbox = {}" not in src
        push = src.split("async function pushEncryptedVaultObject", 1)[1].split(
            "async function pushVaultObject", 1
        )[0]
        assert push.index("await saveWebDirtyState") < push.index("await apiFetch('/api/sync'")


class TestWebTofuFailClosed:
    """G3-02 regression: changed server keys never authenticate committed web state."""

    @staticmethod
    def _source():
        from pathlib import Path

        return (Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )

    def test_changed_pin_is_rejected_before_verification_and_checkpoint(self):
        import json
        import subprocess

        src = self._source()
        pull = src.split("async function pullAndBuildTreeLocked(", 1)[1].split(
            "async function performTOFUChecks", 1
        )[0]
        resolver = "async function getUserSigningPks" + src.split(
            "async function getUserSigningPks", 1
        )[1].split("// ── Auto-create root folder", 1)[0]
        typed_error = "class TofuKeyChangeError" + src.split(
            "class TofuKeyChangeError", 1
        )[1].split("/**\n * Show a MITM warning modal", 1)[0]

        tofu_pos = pull.index("let keys = await getUserSigningPks(signerId)")
        verify_pos = pull.index("const verifiedObjects = []")
        checkpoint_pos = pull.index("await saveSyncCheckpoint(withheld")
        assert tofu_pos < verify_pos < checkpoint_pos
        assert "state.userKeys = {};" in src

        script = f"""
let state = {{ userKeys: {{}}, userId: 'CURRENT', keypair: null }};
let warned = false;
async function apiFetch() {{
  return {{ signing_pk: '11'.repeat(32), encryption_pk: '22'.repeat(32), archived_keys: [] }};
}}
function hexToBytes(value) {{ return Uint8Array.from(Buffer.from(value, 'hex')); }}
function bytesToHex(value) {{ return Buffer.from(value).toString('hex'); }}
async function checkKnownKey() {{ return 'changed'; }}
function showMITMWarning() {{ warned = true; }}
async function displayFingerprint() {{ throw new Error('not expected'); }}
async function ensureSodium() {{ throw new Error('not expected'); }}
{typed_error}
{resolver}
(async () => {{
  let result = null;
  try {{ result = await getUserSigningPks('PEER'); }}
  catch (err) {{ if (!(err instanceof TofuKeyChangeError)) throw err; }}
  console.log(JSON.stringify({{ accepted: !!result, warned, cached: !!state.userKeys.PEER }}));
}})();
"""
        observed = json.loads(subprocess.run(
            [node_cmd(), "-e", script], check=True, capture_output=True, text=True
        ).stdout)
        assert observed == {"accepted": False, "warned": True, "cached": False}


class TestWebRevocationRekey:
    """G3-03 regressions for journaled re-key -> push -> revoke ordering."""

    @staticmethod
    def _source():
        from pathlib import Path

        return (Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )

    def test_revoke_builds_and_persists_complete_atomic_batch_before_delete(self):
        src = self._source()
        flow = src.split("async function prepareWebRekeyJournal", 1)[1].split(
            "// ── Invite token modal", 1
        )[0]
        builder = src.split("async function buildWebRekeyBatch", 1)[1].split(
            "async function pushWebRekeyBatch", 1
        )[0]

        assert flow.index("await saveWebRekeyJournal(journal, _sodium)") < flow.index(
            "await pushWebRekeyBatch(journal)"
        # rindex: the success path's clear (review d150605 S3 adds an earlier
        # one that drops a journal the server can never take).
        ) < flow.index("method: 'DELETE'") < flow.rindex("await clearWebRekeyJournal(revokedUserId, _sodium)")
        assert "await finishWebRevocation(userId, _sodium)" in flow
        assert "atomic_batch: true" in src
        assert "encrypted_journal" in src
        assert "crypto_box_easy" in builder
        assert "object_type: 'dek_archive'" in builder
        assert "is_deleted: 1" in builder
        assert "_sodium.memzero(newDek)" in builder

    def test_rekeyed_versions_verify_with_signer_without_changing_owner(self):
        src = self._source()
        desktop = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "src" / "sezam" / "vault" / "sync_client.py"
        ).read_text(encoding="utf-8")
        mobile_model = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "mobile" / "lib" / "models" / "vault_models.dart"
        ).read_text(encoding="utf-8")
        mobile_sync = (
            __import__("pathlib").Path(__file__).resolve().parents[1]
            / "mobile" / "lib" / "services" / "sync_service.dart"
        ).read_text(encoding="utf-8")

        assert "obj.signature_user_id || obj.owner_id" in src
        assert 'obj.get("signature_user_id")' in desktop
        assert "json['signature_user_id']" in mobile_model
        assert "pullObj.signatureUserId" in mobile_sync

    def test_failed_push_retries_exact_journal_before_single_delete(self):
        import json
        import subprocess

        src = self._source()
        confirm = "async function prepareWebRekeyJournal" + src.split(
            "async function prepareWebRekeyJournal", 1
        )[1].split("// ── Invite token modal", 1)[0]
        script = f"""
let journal = null;
let buildCount = 0;
let pushAttempts = [];
let deleteCount = 0;
let alerts = [];
let preparedSaved = false;
let state = {{}};
async function ensureSodium() {{ return {{}}; }}
async function pendingWebRevocations() {{ return []; }}
function webRekeyJournalRecordId(userId) {{ return `pending:${{userId}}`; }}
async function loadWebRekeyJournal() {{ return journal ? JSON.parse(JSON.stringify(journal)) : null; }}
async function pullAndBuildTree() {{}}
async function buildWebRekeyBatch() {{
  buildCount += 1;
  return {{ folders_rekeyed: 1, objects: [{{ id: 'EXACT', payload: 'nonce-ciphertext' }}] }};
}}
async function saveWebRekeyJournal(value) {{
  journal = JSON.parse(JSON.stringify(value));
  if (value.phase === 'prepared') preparedSaved = true;
}}
async function pushWebRekeyBatch(value) {{
  pushAttempts.push(JSON.stringify(value.objects));
  if (pushAttempts.length === 1) throw new Error('network down');
}}
async function apiFetch(path, options) {{
  if (options && options.method === 'DELETE') {{ deleteCount += 1; return {{ status: 'ok' }}; }}
  return [];
}}
async function clearWebRekeyJournal() {{ journal = null; }}
function closeRevokeModal() {{}}
async function renderAdminUserList() {{}}
function alert(message) {{ alerts.push(message); }}
function assertSyncUnitFits() {{}}
{confirm}
(async () => {{
  await confirmRevokeUser('USER');
  await confirmRevokeUser('USER');
  console.log(JSON.stringify({{
    buildCount,
    attempts: pushAttempts.length,
    exactRetry: pushAttempts[0] === pushAttempts[1],
    deleteCount,
    alerts: alerts.length,
    preparedSaved,
    cleared: journal === null
  }}));
}})();
"""
        observed = json.loads(subprocess.run(
            [node_cmd(), "-e", script], check=True, capture_output=True, text=True
        ).stdout)
        assert observed == {
            "buildCount": 1,
            "attempts": 2,
            "exactRetry": True,
            "deleteCount": 1,
            "alerts": 1,
            "preparedSaved": True,
            "cleared": True,
        }


class TestWebSecureShareRecipient:
    """G4-01 executable browser-wire regressions for recipient decryption."""

    def test_browser_flow_binds_id_omits_fragment_and_fails_closed(self):
        import subprocess
        from pathlib import Path

        js_root = Path(__file__).resolve().parents[1] / "web" / "static" / "js"
        i18n_script = js_root / "i18n.js"
        share_script = js_root / "share.js"
        harness = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
global.document = { addEventListener() {} };
vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'));
vm.runInThisContext(fs.readFileSync(process.argv[2], 'utf8'));

(async () => {
  const api = global.SezamShare;
  const rawId = Uint8Array.from({ length: 32 }, (_, i) => i);
  const shareId = Buffer.from(rawId).toString('base64url');
  const shareKey = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const nonce = Uint8Array.from({ length: 24 }, () => 7);
  const ciphertext = Uint8Array.from({ length: 17 }, () => 9);
  const blob = Buffer.concat([Buffer.from(nonce), Buffer.from(ciphertext)]).toString('base64');
  const plaintext = new TextEncoder().encode(JSON.stringify({ name: 'Example', fields: [{ key: 'password', value: 'secret' }] }));
  let decryptCalls = 0;
  const sodiumApi = {
    ready: Promise.resolve(),
    crypto_aead_xchacha20poly1305_ietf_decrypt(_unused, actualCiphertext, aad, actualNonce, actualKey) {
      decryptCalls += 1;
      assert.deepStrictEqual(Array.from(actualCiphertext), Array.from(ciphertext));
      assert.deepStrictEqual(Array.from(actualNonce), Array.from(nonce));
      assert.deepStrictEqual(Array.from(actualKey), Array.from(shareKey));
      assert.deepStrictEqual(Array.from(aad), [1, 1, 3, ...rawId, 0, 0, 0, 1]);
      return plaintext;
    },
  };
  const fetchFn = async (url, options) => {
    assert.strictEqual(url, `/api/share/${shareId}`);
    assert.ok(!url.includes('#'));
    assert.deepStrictEqual(JSON.parse(options.body), { pin: '123456' });
    assert.strictEqual(options.credentials, 'omit');
    assert.strictEqual(options.referrerPolicy, 'no-referrer');
    return { ok: true, status: 200, async json() { return { encrypted_blob: blob }; } };
  };

  const entry = await api.fetchAndDecryptShare({ shareId, shareKey, pin: '123456', fetchFn, sodiumApi });
  assert.strictEqual(entry.fields[0].value, 'secret');
  assert.strictEqual(decryptCalls, 1);

  for (const [status, message] of [[403, /PIN/], [410, /vypršal/]]) {
    let negativeDecrypts = 0;
    const rejectingSodium = {
      ready: Promise.resolve(),
      crypto_aead_xchacha20poly1305_ietf_decrypt() { negativeDecrypts += 1; },
    };
    await assert.rejects(
      api.fetchAndDecryptShare({
        shareId,
        shareKey,
        fetchFn: async () => ({ ok: false, status }),
        sodiumApi: rejectingSodium,
      }),
      message,
    );
    assert.strictEqual(negativeDecrypts, 0);
  }

  await assert.rejects(
    api.fetchAndDecryptShare({
      shareId,
      shareKey,
      fetchFn: async () => ({ ok: true, status: 200, async json() { return { encrypted_blob: blob }; } }),
      sodiumApi: {
        ready: Promise.resolve(),
        crypto_aead_xchacha20poly1305_ietf_decrypt() { throw new Error('bad tag'); },
      },
    }),
    /zmenené/,
  );
  process.stdout.write('ok');
})().catch((error) => { console.error(error); process.exit(1); });
"""

        result = subprocess.run(
            [node_cmd(), "-e", harness, str(i18n_script), str(share_script)],
            check=True,
            capture_output=True,
            text=True,
        )
        assert result.stdout == "ok"

    def test_vendored_browser_crypto_decrypts_python_golden(self):
        import base64
        import json
        import subprocess
        from pathlib import Path

        import nacl.bindings

        root = Path(__file__).resolve().parents[1]
        raw_share_id = bytes(range(32))
        share_id = base64.urlsafe_b64encode(raw_share_id).decode("ascii").rstrip("=")
        share_key = bytes(range(1, 33))
        nonce = bytes([7]) * 24
        aad = bytes([1, 1, 3]) + raw_share_id + struct.pack(">I", 1)
        plaintext = json.dumps(
            {"name": "Browser golden", "fields": [{"key": "password", "value": "verified"}]},
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, share_key
        )
        encrypted_blob = base64.b64encode(nonce + ciphertext).decode("ascii")
        harness = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, setTimeout, clearTimeout, TextEncoder, TextDecoder, Uint8Array,
  ArrayBuffer, DataView, Promise, WebAssembly, crypto: webcrypto,
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  document: { addEventListener() {} },
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 5)) {
  vm.runInContext(fs.readFileSync(path, 'utf8'), context);
}
(async () => {
  await context.sodium.ready;
  const entry = await context.SezamShare.fetchAndDecryptShare({
    shareId: process.argv[5],
    shareKey: context.Uint8Array.from(Buffer.from(process.argv[6], 'base64')),
    fetchFn: async () => ({
      ok: true,
      status: 200,
      async json() { return { encrypted_blob: process.argv[7] }; },
    }),
    sodiumApi: context.sodium,
  });
  const tampered = Buffer.from(process.argv[7], 'base64');
  tampered[tampered.length - 1] ^= 1;
  await assert.rejects(
    context.SezamShare.fetchAndDecryptShare({
      shareId: process.argv[5],
      shareKey: context.Uint8Array.from(Buffer.from(process.argv[6], 'base64')),
      fetchFn: async () => ({
        ok: true,
        status: 200,
        async json() { return { encrypted_blob: tampered.toString('base64') }; },
      }),
      sodiumApi: context.sodium,
    }),
    /zmenené/,
  );
  process.stdout.write(JSON.stringify(entry));
})().catch((error) => { console.error(error); process.exit(1); });
"""
        vendor = root / "web" / "static" / "js" / "vendor"
        result = subprocess.run(
            [
                node_cmd(),
                "-e",
                harness,
                str(vendor / "libsodium-sumo.min.js"),
                str(vendor / "libsodium-wrappers.min.js"),
                str(root / "web" / "static" / "js" / "i18n.js"),
                str(root / "web" / "static" / "js" / "share.js"),
                share_id,
                base64.b64encode(share_key).decode("ascii"),
                encrypted_blob,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert json.loads(result.stdout) == json.loads(plaintext)


class TestMobileSignedTombstones:
    """C8 regression: mobile deletes must persist a fresh signature over the
    incremented version and ``is_deleted=1`` before sync pushes the tombstone."""

    @staticmethod
    def _repo_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[1]

    def test_delete_resigns_entries_and_nodes(self):
        vault_src = (
            self._repo_root() / "mobile" / "lib" / "services" / "vault_service.dart"
        ).read_text(encoding="utf-8")
        delete_body = vault_src.split("Future<void> _softDeleteObject", 1)[1].split(
            "/// Soft-delete an entry", 1
        )[0]

        assert "version = (row['version'] as int) + 1" in delete_body
        assert "isDeleted: 1" in delete_body
        assert "clientSignature: signature" in delete_body
        assert "await _softDeleteObject(entryId)" in vault_src
        assert "await _softDeleteObject(nodeId)" in vault_src

    def test_database_persists_tombstone_signature(self):
        db_src = (
            self._repo_root() / "mobile" / "lib" / "services" / "database_service.dart"
        ).read_text(encoding="utf-8")
        delete_body = db_src.split("Future<void> softDelete", 1)[1].split(
            "/// Get children", 1
        )[0]

        assert "'version': version" in delete_body
        assert "'is_deleted': 1" in delete_body
        assert "'client_signature': clientSignature" in delete_body


class TestWebRollbackCheckpoint:
    """H5 web regression guards for spec §8.3.

    The pre-fix web client hashed decrypted proxy data, kept its checkpoint only
    in RAM, merely logged rollback, and advanced lastCommitSeq before validating
    or applying the complete response.
    """

    @staticmethod
    def _source():
        from pathlib import Path

        return (Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )

    def test_state_hash_uses_every_raw_ciphertext_object(self):
        src = self._source()
        body = src.split("async function computeWebStateHash", 1)[1].split(
            "async function getUserSigningPk", 1
        )[0]
        assert "Object.values(syncObjects)" in body
        assert "base64ToBytes(obj.payload" in body
        assert "objects.length * 62" in body
        assert "state.allNodes" not in body
        assert "state.allEntries" not in body
        assert "candidateSyncObjects[obj.id]" in src

    def test_checkpoint_is_persistent_authenticated_and_plaintext_is_rejected(self):
        src = self._source()
        checkpoint_code = src.split("async function loadSyncCheckpoint", 1)[1].split(
            "// ── TOFU Key Cache", 1
        )[0]
        assert "encrypted_checkpoint" in checkpoint_code
        assert "crypto_aead_xchacha20poly1305_ietf_decrypt" in checkpoint_code
        assert "crypto_aead_xchacha20poly1305_ietf_encrypt" in checkpoint_code
        assert "Refusing plaintext or malformed sync checkpoint" in checkpoint_code
        assert "sezam-sync-checkpoint-${version}:${state.userId}" in src
        assert "sync_checkpoint_key:${state.userId}" in src

    def test_pull_aborts_before_advancing_checkpoint_or_sequence(self):
        src = self._source()
        pull = src.split("async function pullAndBuildTreeLocked(", 1)[1].split(
            "async function performTOFUChecks", 1
        )[0]
        assert "payload_hash does not match ciphertext" in pull
        # Review d150605 #4: the checks live in one helper the pull calls first.
        check = src.split("function checkPulledStateAgainstCheckpoint(", 1)[1].split(
            "\nfunction ", 1
        )[0]
        assert "throw new Error(`ROLLBACK DETECTED" in check
        assert "throw new Error(\n        `STATE MISMATCH" in check
        check_pos = pull.index("checkPulledStateAgainstCheckpoint(")
        save_pos = pull.index("await saveSyncCheckpoint(withheld")
        seq_pos = pull.index("state.syncCheckpoint = nextCheckpoint")
        assert check_pos < save_pos < seq_pos
        assert "lastCommitSeq" not in src  # S2: the checkpoint is the only pull state


class TestWebClipboardSafety:
    def test_auto_clear_only_clears_the_value_written_by_sezam(self):
        import json
        import subprocess
        from pathlib import Path

        src = (
            Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js"
        ).read_text(encoding="utf-8")
        helper = "async function clearClipboardIfUnchanged" + src.split(
            "async function clearClipboardIfUnchanged", 1
        )[1].split("function copyFieldBtn", 1)[0]
        harness = helper + r"""
(async () => {
    const writes = [];
    const clipboard = {
        value: 'sezam-secret',
        async readText() { return this.value; },
        async writeText(value) { writes.push(value); this.value = value; },
    };
    const owned = () => ({ value: 'sezam-secret', focusLost: false });
    await clearClipboardIfUnchanged('sezam-secret', clipboard, owned());
    clipboard.value = 'newer-user-value';
    await clearClipboardIfUnchanged('sezam-secret', clipboard, owned());
    const denied = {
        async readText() { throw new Error('denied'); },
        async writeText(value) { writes.push('denied:' + value); },
    };
    // Page lost focus: another app may own the clipboard now.
    await clearClipboardIfUnchanged('sezam-secret', denied, { value: 'sezam-secret', focusLost: true });
    // Focus kept since the copy: the secret is still ours, clear it.
    await clearClipboardIfUnchanged('sezam-secret', denied, owned());
    // A newer Sezam copy replaced it: the old timer must not clear.
    await clearClipboardIfUnchanged('sezam-secret', denied, { value: 'other', focusLost: false });
    console.log(JSON.stringify(writes));
})().catch(error => { console.error(error); process.exit(1); });
"""

        result = subprocess.run(
            [node_cmd(), "-e", harness],
            check=True,
            capture_output=True,
            text=True,
        )

        assert json.loads(result.stdout) == ["", "denied:"]


class TestMobileRollbackCheckpoint:
    """H5 mobile regression guards for encrypted fail-closed checkpoints."""

    @staticmethod
    def _source(name):
        from pathlib import Path

        return (
            Path(__file__).resolve().parents[1]
            / "mobile"
            / "lib"
            / "services"
            / name
        ).read_text(encoding="utf-8")

    def test_state_hash_covers_every_raw_ciphertext_object(self):
        src = self._source("sync_service.dart")
        state_hash = src.split("Future<String> _computeStateHash", 1)[1].split(
            "/// Pull new objects", 1
        )[0]
        assert "_db.getAllObjects()" in state_hash
        assert "replacements" in state_hash
        assert "return computeStateHash(objects.values, _crypto);" in state_hash
        # The hashing itself is pinned byte for byte by the state_hash vector
        # (mobile/test/cross_client_vectors_test.dart).
        hashing = src.split("String computeStateHash(", 1)[1].split("\nclass ", 1)[0]
        assert "object['payload'] as Uint8List" in hashing
        assert "crypto.sha256Bytes" in hashing
        assert "Uint8List(62)" in hashing

    def test_checkpoint_is_user_bound_aead_and_committed_atomically(self):
        sync_src = self._source("sync_service.dart")
        db_src = self._source("database_service.dart")
        assert "sezam-sync-checkpoint-v1:${userId ?? _vault.userId}" in sync_src
        checkpoint_src = self._source("sync_checkpoint.dart")
        assert "decodeSyncCheckpoint(raw, kek, userId ?? _vault.userId!)" in sync_src
        assert "crypto.aeadDecrypt" in checkpoint_src
        assert "sezam-sync-checkpoint-v1:$userId" in checkpoint_src
        assert "_crypto.aeadEncrypt" in sync_src
        assert "Refusing plaintext or malformed sync checkpoint" in sync_src
        atomic = db_src.split(
            "applyPullAndCommitCheckpoint", 1
        )[1].split("// ── Settings", 1)[0]
        assert "db.transaction" in atomic
        assert "'vault_objects'" in atomic
        assert "checkpointKey" in atomic
        assert "'last_commit_seq'" in atomic

    def test_pull_aborts_before_checkpoint_and_sequence_advance(self):
        src = self._source("sync_service.dart")
        pull = src.split("Future<PullResult> pull()", 1)[1].split(
            "/// Full sync cycle", 1
        )[0]
        assert "payload_hash does not match ciphertext" in pull
        assert "final verified =" in pull
        assert "ROLLBACK DETECTED" in pull
        assert "STATE MISMATCH" in pull
        assert "final rowsToApply =" in pull
        assert "await _db.applyPullAndCommitCheckpoint" in pull
        assert "await _db.upsertObject" not in pull
        assert "await _db.setLastCommitSeq(maxSeq)" not in pull
        assert "continue;" not in pull


class TestMobileConflictPreservation:
    """C10 regression: pull must not replace dirty mobile ciphertext."""

    @staticmethod
    def _source(*parts):
        from pathlib import Path

        return (
            Path(__file__).resolve().parents[1]
            / "mobile"
            / "lib"
            / Path(*parts)
        ).read_text(encoding="utf-8")

    def test_atomic_pull_preserves_dirty_rows_and_stores_server_shadow(self):
        src = self._source("services", "database_service.dart")
        assert "version: 10" in src
        assert "CREATE TABLE IF NOT EXISTS sync_conflicts" in src
        apply_pull = src.split("applyPullAndCommitCheckpoint", 1)[1].split(
            "// ── Settings", 1
        )[0]
        # The shared sync core decides what a pulled copy does to a queued row.
        dirty_guard = apply_pull.index("syncCore('decide_pulled'")
        shadow_write = apply_pull.index("await txn.insert('sync_conflicts'")
        replace_local = apply_pull.index("'vault_objects'", shadow_write)
        assert dirty_guard < shadow_write < replace_local
        assert "'server_payload': object['payload']" in apply_pull
        assert "continue;" in apply_pull[shadow_write:replace_local]

    def test_conflict_shadow_participates_in_rollback_state_hash(self):
        src = self._source("services", "sync_service.dart")
        state_hash = src.split("Future<String> _computeStateHash", 1)[1].split(
            "/// Pull new objects", 1
        )[0]
        assert "_db.getSyncConflicts()" in state_hash
        assert "conflict['server_version']" in state_hash
        assert "conflict['server_payload']" in state_hash

    def test_pull_returns_conflict_diff_and_ui_warns_user(self):
        sync_src = self._source("services", "sync_service.dart")
        screen_src = self._source("screens", "vault_screen.dart")
        assert "final List<PullConflict> conflicts" in sync_src
        assert "localVersion" in sync_src
        assert "serverVersion" in sync_src
        assert "result.conflicts.isNotEmpty" in screen_src
        assert "Lokálna zmena zostala zachovaná" in screen_src
        assert "local v${conflict.localVersion}" in screen_src
        assert "server v${conflict.serverVersion}" in screen_src


class TestDesktopTeamDashboard:
    """G4-03 regression: desktop admin actions must use authoritative server APIs."""

    @staticmethod
    def _repo_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[1]

    def test_sync_client_admin_operations_use_authenticated_server_routes(self):
        from sezam.vault.sync_client import SyncClient

        class MetaDB:
            def get_meta(self, key):
                return "admin" if key == "username" else None

            def fetchone(self, query, params=()):
                return None

        client = SyncClient(MetaDB(), "https://sync.invalid", generate_keypair(), new_ulid())
        client.token = "test-token"
        requests = []

        def fake_request(method, path, body=None, auth=False, extra_headers=None):
            requests.append((method, path, body, auth))
            return [] if path in ("/api/users", "/api/shares") else {"status": "ok"}

        client._request = fake_request
        client.list_users()
        client.create_invitation()
        client.approve_user("user-1")
        client.revoke_user("user-1")
        client.list_shares()
        client.revoke_share("share-1")

        assert requests == [
            ("GET", "/api/users", None, True),
            ("POST", "/api/users/invite", None, True),
            ("PATCH", "/api/users/user-1/approve", None, True),
            ("DELETE", "/api/users/user-1", None, True),
            ("GET", "/api/shares", None, True),
            ("DELETE", "/api/share/share-1", None, True),
        ]

    def test_team_dialog_has_no_local_admin_fallback_or_false_success_path(self):
        src = (
            self._repo_root() / "src" / "sezam" / "gui" / "team_dialog.py"
        ).read_text(encoding="utf-8")

        for forbidden in (
            "FROM users",
            "FROM share_links",
            "INSERT INTO invitations",
            "UPDATE users SET status",
            "UPDATE share_links SET is_revoked",
            "token_urlsafe",
            "expires in 7 days",
        ):
            assert forbidden not in src

        for required in (
            ".list_users()",
            ".create_invitation()",
            ".approve_user(user_id)",
            "revoke_member(",
            ".list_shares()",
            ".revoke_share(share_id)",
            "?invite={quote(token, safe='')}",
        ):
            assert required in src

        revoke_body = src.split("def _revoke_user", 1)[1].split("def _revoke_share", 1)[0]
        # Lockout review #8: the server revocation no longer waits for the
        # re-key push (tests/test_revoke_member_review8.py drives the order).
        assert "revoke_member(vault, self._get_server_client(), user_id)" in revoke_body
        assert "Revocation was not confirmed by the server" in revoke_body

        # Server calls run on the network thread; the success message lives
        # only in the success callback, never on the error path.
        assert "run_in_background(self, revoke, revoked, failed)" in revoke_body
        assert "Access revoked for" not in revoke_body.split("def revoked(_result):", 1)[0]

        approve_body = src.split("def _approve_user", 1)[1].split("def _revoke_user", 1)[0]
        assert "has been approved" not in approve_body.split("def approved(_result):", 1)[0]
        assert ".approve_user(user_id),\n                approved," in approve_body
        assert "Approval Failed" in approve_body

        share_body = src.split("def _revoke_share", 1)[1]
        assert "has been revoked" not in share_body.split("def revoked(_result):", 1)[0]
        assert ".revoke_share(share_id),\n                revoked," in share_body
        assert "Share Revocation Failed" in share_body


class TestPasswordChangeRecovery:
    """C9 regression: password rotation must preserve Option B recovery."""

    @staticmethod
    def _repo_root():
        from pathlib import Path

        return Path(__file__).resolve().parents[1]

    def test_cli_wires_server_upload_around_local_rotation(self):
        src = (self._repo_root() / "src" / "sezam" / "cli.py").read_text(
            encoding="utf-8"
        )
        body = src.split('@main.command("change-password")', 1)[1].split(
            "# ── Key export/import", 1
        )[0]
        # Logs in and pulls first (stateful test SM15).
        authenticate = body.index("client.prepare_key_change()")
        rotate = body.index("auth_proof = vault.change_password")
        sync = body.index("client.push()")
        assert authenticate < rotate < sync
        # Review 2052248 #1: no separate keypair upload; the push carries the
        # key material so the server applies it with the epoch atomically.
        assert "upload_keypair" not in body

    def test_password_change_pushes_every_dek_as_one_key_epoch(self, tmp_path):
        from sezam.vault.crud import Vault
        from sezam.vault.sync_client import SyncClient

        vault = Vault.create(
            str(tmp_path / "epoch_sync"),
            "old-password",
            Argon2Params(time_cost=1, memory_cost=8192, parallelism=1),
        )
        vault.create_node("extra-folder")
        proof = vault.change_password("old-password", "new-password")
        try:
            requests = []
            client = SyncClient(
                vault.db,
                "https://sync.invalid",
                vault.keypair,
                vault.db.get_meta("user_id"),
            )
            client.token = "test-token"
            client.set_dek_manager(vault.dek_mgr)
            sent_rotation = {}

            def fake_request(method, path, body=None, auth=False, extra_headers=None):
                requests.append((method, path, body, auth))
                if method == "GET":
                    # Own key ring lookup while validating local audit records.
                    raise RuntimeError("offline")
                if path == "/api/auth/challenge":
                    return {"challenge": "00" * 40}
                sent_rotation.update(body.get("key_rotation") or {})
                return {
                    "accepted": [
                        {"id": obj["id"], "commit_seq": index + 1}
                        for index, obj in enumerate(body["objects"])
                    ],
                    "conflicts": [],
                    "token": "rotated-token",
                }

            client._request = fake_request
            client.push()

            method, path, body, auth = next(r for r in requests if r[1] == "/api/sync")
            assert (method, path, auth) == ("POST", "/api/sync", True)
            assert body["atomic_batch"] is True
            assert body["key_epoch"] == 1
            # Review 2052248 #1: the epoch push carries the new key material.
            assert sent_rotation["auth_proof"] == bytes(proof).hex()
            assert sent_rotation["encrypted_keypair"] == vault.db.get_meta("encrypted_keypair")
            assert sent_rotation["argon2_salt"] == vault.db.get_meta("argon2_salt")
            assert client.token == "rotated-token"
            assert (pending_states.key_change_journal(vault.db) or None) is None
            pushed_deks = {
                obj["id"] for obj in body["objects"] if obj["object_type"] == "dek"
            }
            local_deks = {
                row["id"] for row in vault.db.fetchall("SELECT id FROM deks")
            }
            # Review d615826 (E8): a folder key the server never held rides
            # with its folder in the push after the atomic change.
            unsynced_folder_deks = {
                row["id"] for row in vault.db.fetchall("SELECT id FROM deks WHERE node_id IS NOT NULL")
            }
            assert unsynced_folder_deks
            assert pushed_deks == local_deks - unsynced_folder_deks
            all_pushed = {
                obj["id"] for _m, p, b, _a in requests if p == "/api/sync"
                for obj in b["objects"] if obj["object_type"] == "dek"
            }
            assert all_pushed == local_deks
            assert vault.db.get_meta("last_pushed_key_epoch") == "1"
        finally:
            proof[:] = b"\x00" * len(proof)
            vault.lock()

    def test_pull_rejects_newer_server_key_epoch_before_local_mutation(self):
        from sezam.vault.sync_client import SyncClient

        class MetaDB:
            def require_generation(self):
                pass

            def get_meta(self, key):
                return {"key_epoch": "0", "last_known_commit_seq": "0"}.get(key)

        client = SyncClient(MetaDB(), "https://sync.invalid", generate_keypair(), new_ulid())
        client.token = "test-token"
        client._request = lambda *args, **kwargs: {
            "objects": [],
            "max_commit_seq": 0,
            "key_epoch": 1,
        }

        with pytest.raises(RuntimeError, match="key epoch is stale"):
            client.pull()

    def test_web_and_mobile_propagate_and_validate_key_epoch(self):
        web = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        mobile = (
            self._repo_root() / "mobile" / "lib" / "services" / "sync_service.dart"
        ).read_text(encoding="utf-8")

        assert "key_epoch: state.keyEpoch" in web
        assert "state.keyEpoch = responseKeyEpoch" in web
        assert "responseKeyEpoch < state.keyEpoch" in web
        assert "'key_epoch': keyEpoch" in mobile
        # A lower epoch (server restored from a backup) is taken over too, but
        # only with the server's exact keypair (review d615826).
        assert "serverKeyEpoch != localKeyEpoch" in mobile
        assert "serverKeyEpoch < localKeyEpoch &&" in mobile
        assert "throw KeyEpochStaleException(serverKeyEpoch);" in mobile

    def test_web_org_recovery_uses_single_option_b_derivation(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        body = src.split("async function handleOrgRecovery", 1)[1].split(
            "// ── Shamir Secret Sharing", 1
        )[0]
        assert body.count("deriveKEK(newPassword") == 1
        assert "const newSalt = _sodium.randombytes_buf(16)" in body
        assert "const authProof = newDerivedKey.subarray(32, 64)" in body
        assert "argon2_salt: bytesToHex(newSalt)" in body
        # Server writes happen only from the persisted journal (crash-safe).
        assert "await saveKekRotationJournal(" in body
        assert body.index("await saveKekRotationJournal(") < body.index(
            "applyKekRotationJournal("
        )
        assert "authDerivedKey" not in body
        apply_fn = src.split("async function applyKekRotationJournal", 1)[1].split(
            "async function resumeKekRotation", 1
        )[0]
        assert "auth_salt: journal.argon2_salt" in apply_fn

    def test_web_uses_current_and_historical_signing_key_rings(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        pull = src.split("async function pullAndBuildTreeLocked(", 1)[1].split(
            "async function performTOFUChecks", 1
        )[0]
        resolver = src.split("async function getUserSigningPks", 1)[1].split(
            "// ── Auto-create root folder", 1
        )[0]
        audit = src.split("async function loadAuditEntries", 1)[1]

        assert "await getUserSigningPks(signerId)" in pull
        assert "sigPks.some(sigPk => mayVouch(sigPk) && verifyObjectSignature" in pull
        assert "data.archived_keys || []" in resolver
        assert "Archived key fingerprint mismatch" in resolver
        assert "userPks.some(userPk =>" in audit

    def test_mobile_qr_provisioning_binds_and_journals_canonical_user_id(self):
        src = (
            self._repo_root() / "mobile" / "lib" / "services" / "auth_service.dart"
        ).read_text(encoding="utf-8")
        body = src.split("Future<AuthResult> provisionFromQR", 1)[1].split(
            "// ── Password Recovery", 1
        )[0]

        response_id = body.index("requireCanonicalUserObjectId(provResp)")
        unwrap = body.index("await _openAnchoredAccountKeypair(")
        identity_match = body.index("authenticatedUserId != userObjectId")
        journal = body.index("await _persistKeypairState(")
        assert response_id < unwrap < identity_match < journal
        assert "_secureStorage.write(\n        key: _encryptedKeypairKey" not in body

    def test_web_shamir_split_matches_python_for_every_threshold_combination(self):
        import itertools
        import json
        import subprocess

        from sezam.crypto.shamir import reconstruct_secret

        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        shamir = src.split("const GF_EXP", 1)[1].split(
            "// ── Org Recovery Setup", 1
        )[0]
        secret = bytes(range(32))
        script = f"""
const crypto = require('node:crypto').webcrypto;
const GF_EXP{shamir}
const secret = Uint8Array.from({list(secret)});
const shares = shamirSplit(secret, 3, 5);
console.log(JSON.stringify(shares.map(([index, bytes]) =>
    [index, Buffer.from(bytes).toString('hex')]
)));
"""
        result = subprocess.run(
            [node_cmd(), "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        shares = [(index, bytes.fromhex(value)) for index, value in json.loads(result.stdout)]

        for selected in itertools.combinations(shares, 3):
            assert reconstruct_secret(list(selected)) == secret

    def test_web_org_recovery_proves_key_knowledge_and_rewraps_all_deks(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        body = src.split("async function handleOrgRecovery", 1)[1].split(
            "// ── Start ──", 1
        )[0]
        assert "crypto_sign_seed_keypair(recoveryKey)" in body
        assert "'/api/org-recovery/challenge'" in body
        assert "signature: bytesToHex(proofSignature)" in body
        assert "blob_hash" not in body
        # Every own active DEK must be re-wrapped (tests/test_web_org_recovery_multiuser.py).
        assert "const rewrappedDeks = await rewrapOwnDeks(newKek, _sodium);" in body
        rewrap = src.split("async function rewrapOwnDeks", 1)[1].split("\n}\n", 1)[0]
        assert "ownKekDekIdsToRewrap(state.syncObjects, state.kekDekIds, state.userId)" in rewrap
        assert "for (const dekId of ownDekIds)" in rewrap
        assert "wrapDEK(dekBytes, dekId, version, kek" in rewrap
        assert "deks: rewrappedDeks," in body
        assert "wrapped_kek: bytesToHex(newWrappedRecovery)" in body
        assert "key_epoch: state.keyEpoch + 1," in body
        # One push: DEKs + epoch + key material (tests/test_review2_web_rotation.py).
        apply_fn = src.split("async function applyKekRotationJournal", 1)[1].split(
            "async function resumeKekRotation", 1
        )[0]
        assert "key_rotation: keyRotation" in apply_fn and "/api/me/keypair" not in apply_fn
        # Review 688edcb K1: the recovery key proves the reset to the server.
        assert "keyRotation.recovery_signature" in apply_fn
        assert "recoverySigningKeypair.privateKey" in body

    def test_web_dek_wrap_matches_canonical_cross_client_contract(self):
        import json
        import subprocess

        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        helpers = "function buildAAD" + src.split("function buildAAD", 1)[1].split(
            "// ── Init", 1
        )[0]
        kek_dek_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        dek_id = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
        script = f"""
const crypto = require('node:crypto').webcrypto;
const ENVELOPE_ALG = 1;
const SCHEMA_VERSION = 1;
const BLOB_KIND = {{ DEK_WRAP: 6 }};
function generateULID() {{ return '{kek_dek_id}'; }}
{helpers}
let encryptAad;
let decryptAad;
let encryptedPlaintext;
const sodium = {{
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: 24,
  randombytes_buf: n => new Uint8Array(n).fill(3),
  crypto_aead_xchacha20poly1305_ietf_encrypt: (message, aad) => {{
    encryptAad = Uint8Array.from(aad);
    encryptedPlaintext = Uint8Array.from(message);
    return Uint8Array.from(message);
  }},
  crypto_aead_xchacha20poly1305_ietf_decrypt: (_secret, ciphertext, aad) => {{
    decryptAad = Uint8Array.from(aad);
    return Uint8Array.from(ciphertext);
  }},
}};
const dek = Uint8Array.from(Array.from({{length: 32}}, (_, i) => i));
const wrapped = wrapDEK(dek, '{dek_id}', 7, new Uint8Array(32), sodium);
const unwrapped = unwrapDEK(wrapped, new Uint8Array(32), '{dek_id}', 7, sodium);
console.log(JSON.stringify({{
  headerKekId: new TextDecoder().decode(wrapped.slice(3, 29)),
  encryptAad: Buffer.from(encryptAad).toString('hex'),
  decryptAad: Buffer.from(decryptAad).toString('hex'),
  paddedLength: encryptedPlaintext.length,
  unwrapped: Array.from(unwrapped),
}}));
"""
        result = subprocess.run(
            [node_cmd(), "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        observed = json.loads(result.stdout)
        expected_aad = build_aad(
            ALG_XCHACHA20POLY1305,
            SCHEMA_VERSION,
            BlobKind.DEK_WRAP,
            ulid_to_bytes(kek_dek_id),
            ulid_to_bytes(dek_id),
            7,
        ).hex()

        assert observed["headerKekId"] == kek_dek_id
        assert observed["encryptAad"] == expected_aad
        assert observed["decryptAad"] == expected_aad
        assert observed["paddedLength"] == 64
        assert observed["unwrapped"] == list(range(32))

    def test_web_keypair_wrap_is_canonical_and_has_no_null_aad_fallback(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        recovery = src.split("async function handleOrgRecovery", 1)[1].split(
            "// ── Start ──", 1
        )[0]

        assert "function encryptKeypairWrap(" in src
        assert "buildAAD(BLOB_KIND.KEYPAIR_WRAP, kekDekId, userId, 1)" in src
        assert "encryptKeypairWrap(kpData, newKek, generateULID(), state.userId, _sodium)" in recovery
        assert ("encryptAccountKeypair(kpData, publishedGenesis, newKek, generateULID(), state.userId, _sodium,\n"
                "                publishedPreAnchor)") in recovery
        bundle_writer = src.split("function encryptAccountKeypair(", 1)[1].split("function decryptAccountKeypair(", 1)[0]
        assert "encryptKeypairWrap(payload, kek, kekDekId, userId, _sodium)" in bundle_writer
        assert "kpData, null, null, kpNonce, newKek" not in recovery
        assert "freshData.slice(nn), null, freshData.slice(0, nn), kek" not in src

    def test_web_indexeddb_and_tofu_errors_fail_closed(self):
        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        indexed_db = src.split("async function loadFromIndexedDB", 1)[1].split(
            "function syncCheckpointRecordId", 1
        )[0]
        tofu = src.split("async function saveKnownKey", 1)[1].split(
            "function showMITMWarning", 1
        )[0]
        checks = src.split("async function performTOFUChecks", 1)[1].split(
            "async function renderAdminUserList", 1
        )[0]
        pull = src.split("async function pullAndBuildTreeLocked(", 1)[1].split(
            "async function performTOFUChecks", 1
        )[0]

        assert pull.index("await performTOFUChecks()") < pull.index("renderTree(tree)")
        assert "req.onerror = () => reject(" in indexed_db
        assert "catch {\n        return null;" not in indexed_db
        assert "req.onerror = () => reject(" in tofu
        assert "return 'new'; // fail-open" not in tofu
        assert "catch {}" not in tofu
        assert "TOFU check error" not in checks
        assert "Failed to fetch user list for TOFU check" not in checks

    def test_web_kdf_material_uses_views_and_transferable_buffer(self):
        root = self._repo_root()
        app = (root / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        worker = (root / "web" / "static" / "js" / "argon2-worker.js").read_text(
            encoding="utf-8"
        )

        assert "derivedKey.slice(0, 32)" not in app
        assert "derivedKey.slice(32, 64)" not in app
        assert "newDerivedKey.slice(0, 32)" not in app
        assert "newDerivedKey.slice(32, 64)" not in app
        # Login, onboarding and bootstrap (the approval wait no
        # longer derives a key: capability review run 49).
        assert app.count("derivedKey.subarray(0, 32)") >= 3
        assert app.count("derivedKey.subarray(32, 64)") >= 3
        assert "resolve(new Uint8Array(e.data.kek))" not in app
        assert "resolve(e.data.kek)" in app
        assert "[derivedKey.buffer]" in worker

    def test_mobile_kdf_material_uses_views_and_explicit_wipe(self):
        root = self._repo_root()
        auth = (root / "mobile" / "lib" / "services" / "auth_service.dart").read_text(
            encoding="utf-8"
        )
        vault = (root / "mobile" / "lib" / "services" / "vault_service.dart").read_text(
            encoding="utf-8"
        )
        crypto = (root / "mobile" / "lib" / "services" / "crypto_service.dart").read_text(
            encoding="utf-8"
        )

        assert "Uint8List.fromList(derived.sublist" not in auth
        assert auth.count("Uint8List.sublistView(derived") >= 6
        assert "_crypto.zeroize(derived)" in auth
        assert "Uint8List.fromList(derived.sublist" not in vault
        assert "derived.fillRange(32, derived.length, 0)" in vault
        assert "return rawBytes is Uint8List ? rawBytes" in crypto

    def test_web_folder_acl_read_write_behavior(self):
        import subprocess

        src = (self._repo_root() / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        helpers = "function folderAccessLevelForObject" + src.split(
            "function folderAccessLevelForObject", 1
        )[1].split("function renderEntry", 1)[0]
        # INV-3 (review e443cbc): webIsAdmin asks whether a team log is pinned.
        helpers += "\nfunction webPinnedTeamGenesis" + src.split(
            "function webPinnedTeamGenesis", 1
        )[1].split("\n}\n", 1)[0] + "\n}\n"
        harness = f"""
let state = {{
  isAdmin: false,
  userId: 'reader',
  syncObjects: {{
    dek: {{ id: 'dek', object_type: 'dek', parent_ref: 'folder', is_deleted: 0 }},
    envelope: {{
      id: 'envelope', object_type: 'envelope', parent_ref: 'dek',
      target_user_id: 'reader', access_level: 'read', is_deleted: 0
    }}
  }}
}};
{helpers}
const entry = {{
  id: 'entry', owner_id: 'owner', write_policy: 'shared',
  parent_ref: 'folder', access_level: 'write'
}};
if (canEditObject(entry)) throw new Error('read envelope allowed edit');
state.syncObjects.envelope.access_level = 'write';
if (!canEditObject(entry)) throw new Error('write envelope denied edit');
state.syncObjects.envelope.is_deleted = 1;
if (canEditObject(entry)) throw new Error('deleted envelope allowed edit');
state.syncObjects.envelope.is_deleted = 0;
entry.owner_id = 'reader';
if (!canEditObject(entry)) throw new Error('owner denied edit');
entry.owner_id = null;
if (canEditObject(entry)) throw new Error('missing owner failed open');
entry.owner_id = 'owner';
state.isAdmin = true;
if (!canEditObject(entry)) throw new Error('admin denied edit');
"""
        subprocess.run([node_cmd(), "-e", harness], check=True, capture_output=True)

    def test_acl_guards_cover_web_mutations_and_mobile_persistence(self):
        root = self._repo_root()
        web = (root / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        mobile_db = (
            root / "mobile" / "lib" / "services" / "database_service.dart"
        ).read_text(encoding="utf-8")
        mobile_sync = (
            root / "mobile" / "lib" / "services" / "sync_service.dart"
        ).read_text(encoding="utf-8")
        mobile_vault = (
            root / "mobile" / "lib" / "services" / "vault_service.dart"
        ).read_text(encoding="utf-8")

        assert "existingEntry && !canEditObject(existingEntry)" in web
        assert "if (!canEditObject(entry))" in web
        assert "version: 10" in mobile_db
        assert "ADD COLUMN access_level TEXT" in mobile_db
        assert "'access_level': accessLevel" in mobile_db
        assert "'access_level': pullObj.accessLevel" in mobile_sync
        assert mobile_vault.count("if (!existing.canEdit(_userId, isAdmin))") == 2
        assert "folderByDek[object['parent_ref']]" in mobile_vault

    def test_web_audit_inner_signature_and_dag_fail_closed(self):
        import base64
        import subprocess

        root = self._repo_root()
        app = (root / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        helpers = "function parseCanonicalAuditRecord" + app.split(
            "function parseCanonicalAuditRecord", 1
        )[1].split("async function pullAndBuildTree", 1)[0]
        harness = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView,
  Promise, WebAssembly, Buffer, Blob, URL, crypto: webcrypto,
  location: { origin: 'https://sezam.invalid', search: '' },
  addEventListener() {},
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  btoa: value => Buffer.from(value, 'binary').toString('base64'),
  document: { addEventListener() {} },
};
context.window = context;
context.self = context;
context.globalThis = context;
context.base64ToBytes = value => context.Uint8Array.from(Buffer.from(value, 'base64'));
context.bytesToBase64 = value => Buffer.from(value).toString('base64');
context.bytesToHex = value => Buffer.from(value).toString('hex');
context.hexToBytes = value => context.Uint8Array.from(Buffer.from(value, 'hex'));
vm.createContext(context);
for (const path of process.argv.slice(1, 3)) {
  vm.runInContext(fs.readFileSync(path, 'utf8'), context);
}
vm.runInContext(Buffer.from(process.argv[3], 'base64').toString('utf8'), context);
(async () => {
  await context.sodium.ready;
  const actor = '01ARZ3NDEKTSV4RRFFQ69G5FB1';
  const rootId = '01ARZ3NDEKTSV4RRFFQ69G5FB2';
  const childId = '01ARZ3NDEKTSV4RRFFQ69G5FB3';
  const otherId = '01ARZ3NDEKTSV4RRFFQ69G5FB4';
  const keypair = context.sodium.crypto_sign_keypair();
  context.state = { userKeys: { [actor]: [keypair.publicKey] } };

  function makeAudit(id, parents, action = 'write') {
    const record = {
      action,
      actor_id: actor,
      encrypted_details: '',
      format: 'sezam-audit-v1',
      id,
      parent_ids: parents,
      signature: '00'.repeat(64),
      timestamp: 7,
    };
    const object = {
      id, object_type: 'audit', version: 2, is_deleted: 0,
      payload: Buffer.from(JSON.stringify(record)).toString('base64'),
    };
    const parsed = context.parseCanonicalAuditRecord(object);
    record.signature = context.bytesToHex(context.sodium.crypto_sign_detached(
      context.buildAuditCanonical(parsed, context.sodium), keypair.privateKey
    ));
    object.payload = Buffer.from(JSON.stringify(record)).toString('base64');
    return object;
  }

  const rootAudit = makeAudit(rootId, []);
  const childAudit = makeAudit(childId, [rootId]);
  await context.verifyAuditGraph({ rootAudit, childAudit }, context.sodium);

  const tampered = { ...childAudit };
  const tamperedRecord = JSON.parse(Buffer.from(tampered.payload, 'base64').toString());
  tamperedRecord.action = 'delete';
  tampered.payload = Buffer.from(JSON.stringify(tamperedRecord)).toString('base64');
  await assert.rejects(
    context.verifyAuditGraph({ rootAudit, tampered }, context.sodium),
    /invalid audit signature/
  );

  const missing = makeAudit(otherId, ['01ARZ3NDEKTSV4RRFFQ69G5FB5']);
  await assert.rejects(
    context.verifyAuditGraph({ missing }, context.sodium), /missing parent/
  );

  const cycleA = makeAudit(rootId, [childId]);
  const cycleB = makeAudit(childId, [rootId]);
  await assert.rejects(
    context.verifyAuditGraph({ cycleA, cycleB }, context.sodium), /cycle detected/
  );
})().catch(error => { console.error(error); process.exit(1); });
"""
        vendor = root / "web" / "static" / "js" / "vendor"
        subprocess.run(
            [
                node_cmd(),
                "-e",
                harness,
                str(vendor / "libsodium-sumo.min.js"),
                str(vendor / "libsodium-wrappers.min.js"),
                base64.b64encode(helpers.encode()).decode(),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_web_and_mobile_validate_audits_before_checkpoint(self):
        root = self._repo_root()
        web = (root / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        mobile = (
            root / "mobile" / "lib" / "services" / "sync_service.dart"
        ).read_text(encoding="utf-8")
        web_pull = web.split("async function pullAndBuildTree", 1)[1].split(
            "async function performTOFUChecks", 1
        )[0]
        mobile_pull = mobile.split("Future<PullResult> pull()", 1)[1].split(
            "/// Full sync cycle", 1
        )[0]

        assert web_pull.index("await verifyAuditGraph") < web_pull.index(
            "await computeWebStateHash"
        )
        assert mobile_pull.index("parseCanonicalAuditRecord") < mobile_pull.index(
            "final candidateStateHash"
        )
        assert mobile_pull.index("validateAuditDag") < mobile_pull.index(
            "final candidateStateHash"
        )
        assert "_crypto.verifyDetached" in mobile_pull


class TestWebPersonalDekInheritance:
    @staticmethod
    def _source():
        from pathlib import Path

        return (Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )

    def test_folder_and_entry_saves_inherit_personal_dek_recursively(self):
        src = self._source()
        save = "async function handleModalSave" + src.split(
            "async function handleModalSave", 1
        )[1].split("// ── Delete modal", 1)[0]

        assert "const folderDekId = isPersonalRoot" in save
        assert "resolveInheritedPersonalDekId(parentRef)" in save
        assert "dekId: folderDekId" in save
        assert "const isPersonal = !!resolveInheritedPersonalDekId(parentRef);" in save
        assert "const entryDekId = resolveWriteDekId(parentRef, existingEntry);" in save
        assert "const writePolicy = !isPersonal" in save
        assert "state.deks[dekId] || state.deks[state.rootDekId]" not in src

    def test_nested_personal_content_is_not_decryptable_with_shared_dek(self):
        import subprocess

        src = self._source()
        resolver = "function resolveInheritedPersonalDekId" + src.split(
            "function resolveInheritedPersonalDekId", 1
        )[1].split("// ── Modal save handler", 1)[0]
        deleter = "async function handleDeleteConfirm" + src.split(
            "async function handleDeleteConfirm", 1
        )[1].split("// ── Auto-lock", 1)[0]
        migrator = "async function migrateLegacyPersonalDescendants" + src.split(
            "async function migrateLegacyPersonalDescendants", 1
        )[1].split("/**\n * Perform TOFU", 1)[0]
        script = f"""
const assert = require('assert');
let state = {{
  userId: 'CURRENT_USER',
  rootDekId: 'ROOT_DEK',
  deks: {{ PERSONAL_DEK: new Uint8Array(32), ROOT_DEK: new Uint8Array(32) }},
  nodes: {{
    personal: {{ id: 'personal', name: 'Personal', personal: true, dekId: 'PERSONAL_DEK', parent_ref: null }},
    child: {{ id: 'child', name: 'Child', owner_id: 'CURRENT_USER', dekId: 'ROOT_DEK', parent_ref: 'personal' }},
    grandchild: {{ id: 'grandchild', name: 'Grandchild', owner_id: 'CURRENT_USER', dekId: 'ROOT_DEK', parent_ref: 'child' }},
    shared: {{ id: 'shared', name: 'Shared', owner_id: 'CURRENT_USER', dekId: 'ROOT_DEK', parent_ref: null }},
    foreignRoot: {{ id: 'foreignRoot', owner_id: 'OTHER_USER', _undecryptable: true, parent_ref: null }},
    foreignChild: {{ id: 'foreignChild', name: 'Visible legacy child', owner_id: 'OTHER_USER', dekId: 'ROOT_DEK', parent_ref: 'foreignRoot' }},
  }},
  entries: {{ secret: {{ id: 'secret', name: 'Secret', owner_id: 'CURRENT_USER', dekId: 'ROOT_DEK', parent_ref: 'grandchild', version: 1, fields: [{{ key: 'password', value: 'secret' }}] }} }},
}};
state.allNodes = Object.values(state.nodes);
state.allEntries = [
  state.entries.secret,
  {{ id: 'foreign', owner_id: 'OTHER_USER', parent_ref: 'foreignRoot' }},
  {{ id: 'opaque', _undecryptable: true, parent_ref: 'missing' }},
];
{resolver}
{deleter}
{migrator}
assert.strictEqual(resolveInheritedPersonalDekId('grandchild'), 'PERSONAL_DEK');
assert.strictEqual(resolveInheritedPersonalDekId('shared'), undefined);
let usedDekId = null;
let pushedObject = null;
const modal = {{ dataset: {{ entryId: 'secret' }}, classList: {{ add() {{}} }} }};
const button = {{ disabled: false, textContent: '' }};
const detail = {{ classList: {{ add() {{}}, remove() {{}} }} }};
globalThis.document = {{ getElementById(id) {{
  if (id === 'delete-modal') return modal;
  if (id === 'delete-confirm-btn') return button;
  return detail;
}} }};
globalThis.alert = (message) => {{ throw new Error(message); }};
const t = (key) => key;
const ensureSodium = async () => ({{}});
const canEditObject = () => true;
const MAX_OBJECT_PAYLOAD_BYTES = 1024 * 1024;
const encryptEntryPayload = (_data, dekId) => {{ usedDekId = dekId; return new Uint8Array([1]); }};
const bytesToBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const base64ToBytes = (value) => new Uint8Array(Buffer.from(value, 'base64'));
const sha256hexBytes = async () => '00'.repeat(32);
const hexToBytes = () => new Uint8Array(32);
const signSyncObject = () => new Uint8Array(64);
const bytesToHex = () => '00'.repeat(64);
const pushEncryptedVaultObject = async (obj) => {{ pushedObject = obj; }};
const migratedObjects = [];
const pushVaultObjectLocked = async (obj) => {{ migratedObjects.push(obj); }};
const closeDeleteModal = () => {{}};
const logFieldAccess = () => {{}};
const pullAndBuildTree = async () => {{}};
(async () => {{
  await handleDeleteConfirm();
  assert.strictEqual(usedDekId, 'PERSONAL_DEK');
  assert.strictEqual(pushedObject.is_deleted, 1);
  assert.strictEqual(await migrateLegacyPersonalDescendants(), true);
  assert.deepStrictEqual(migratedObjects.map((obj) => obj.id), ['child', 'grandchild', 'secret']);
  assert.ok(migratedObjects.every((obj) => obj.dekId === 'PERSONAL_DEK'));
  assert.ok(migratedObjects.every((obj) => obj.write_policy === 'owner_only'));
  state.nodes.child.parent_ref = 'grandchild';
  assert.throws(() => resolveInheritedPersonalDekId('grandchild'), /cycle/);
}})().catch((error) => {{ console.error(error); process.exit(1); }});
"""
        subprocess.run(
            [node_cmd(), "-e", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )

        personal_dek = os.urandom(32)
        shared_dek = os.urandom(32)
        dek_id = ulid_to_bytes(new_ulid())
        folder_id = ulid_to_bytes(new_ulid())
        entry_id = ulid_to_bytes(new_ulid())
        folder_blob = encrypt(
            b"private folder", personal_dek, dek_id, folder_id,
            version=1, blob_kind=BlobKind.NODE_META,
        )
        entry_blob = encrypt(
            b"private entry", personal_dek, dek_id, entry_id,
            version=1, blob_kind=BlobKind.ENTRY_DATA,
        )

        assert decrypt(folder_blob, personal_dek, folder_id, version=1) == b"private folder"
        assert decrypt(entry_blob, personal_dek, entry_id, version=1) == b"private entry"
        with pytest.raises(CryptoError):
            decrypt(folder_blob, shared_dek, folder_id, version=1)
        with pytest.raises(CryptoError):
            decrypt(entry_blob, shared_dek, entry_id, version=1)


class TestDesktopForeignPersonalDeks:
    def test_unlock_and_password_rewrap_skip_only_server_marked_foreign_deks(self, tmp_path):
        from sezam.vault.db import VaultDB
        from sezam.vault.dek import DEKManager
        from sezam.vault.sync_client import SyncClient

        db = VaultDB(tmp_path / "foreign-deks.db")
        db.open()
        db.create_schema()
        try:
            user_id = new_ulid()
            kek = bytearray(os.urandom(32))
            manager = DEKManager(db, kek)
            owned_id, _ = manager.create_dek("root")
            foreign_id = new_ulid()
            client = SyncClient(db, "https://example.invalid", generate_keypair(), user_id)
            client._apply_dek(
                foreign_id, None, b"opaque foreign KEK wrap", 1,
                {"owner_id": new_ulid()},
            )

            assert db.get_meta_json("foreign_dek_ids") == [foreign_id]
            db.execute("DELETE FROM vault_meta WHERE key = 'foreign_dek_ids'")
            manager.classify_legacy_foreign_deks()
            assert db.get_meta_json("foreign_dek_ids") == [foreign_id]
            manager.unlock_all_deks()
            owned_before = db.fetchone(
                "SELECT version FROM deks WHERE id = ?", (owned_id,)
            )["version"]
            foreign_before = bytes(db.fetchone(
                "SELECT encrypted_dek FROM deks WHERE id = ?", (foreign_id,)
            )["encrypted_dek"])

            manager.rewrap_all_deks(bytearray(os.urandom(32)))

            assert db.fetchone(
                "SELECT version FROM deks WHERE id = ?", (owned_id,)
            )["version"] == owned_before + 1
            foreign = db.fetchone(
                "SELECT encrypted_dek, version FROM deks WHERE id = ?", (foreign_id,)
            )
            assert bytes(foreign["encrypted_dek"]) == foreign_before
            assert foreign["version"] == 1

            db.set_meta("key_epoch", "1")
            db.set_meta("last_pushed_key_epoch", "0")
            collected_ids = {obj["id"] for obj in client._collect_dirty_objects()}
            assert owned_id in collected_ids
            assert foreign_id not in collected_ids

            broken_owned_id = new_ulid()
            db.execute(
                "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
                "VALUES (?, NULL, 'folder', ?, 1)",
                (broken_owned_id, b"corrupt owned wrap"),
            )
            with pytest.raises((CryptoError, ValueError)):
                manager.unlock_all_deks()
        finally:
            db.close()
