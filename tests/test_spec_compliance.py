"""Comprehensive spec-compliance tests for Sezam desktop/CLI.

Tests organized by specification section. Focuses on security invariants,
boundary conditions, negative tests, and spec-mandated behavior.

Run: pytest tests/test_spec_compliance.py -v
"""

from __future__ import annotations

import ast
import json
import math
import os
import struct
import sys
import tempfile
import threading
import types
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

from sezam import cli

from sezam.crypto.aead import (
    ALG_XCHACHA20POLY1305,
    DEK_ID_SIZE,
    HEADER_SIZE,
    NONCE_SIZE,
    SCHEMA_VERSION,
    TAG_SIZE,
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
from sezam.crypto.kdf import (
    Argon2Params,
    derive_kek,
    derive_kek_and_proof,
    generate_salt,
)
from sezam.crypto.keys import KeyPair, compute_fingerprint, generate_keypair
from sezam.crypto.padding import _next_power_of_2, pad, unpad
from sezam.mcp.approval import ApprovalManager, ApprovalRequest
from sezam.mcp.broker import MCPBroker, MCPError
from sezam.models import EntryData, EntryField, EntryMeta, NodeMeta, new_ulid, ulid_to_bytes
from sezam.password import (
    DIGITS,
    LOWERCASE,
    SYMBOLS,
    UPPERCASE,
    estimate_strength,
    generate_passphrase,
    generate_password,
)
from sezam.totp import generate_totp, time_remaining
from sezam.vault import outbox
from sezam.vault.audit import AuditLog
from sezam.vault.crud import Vault, VaultLocked
from sezam.vault.dek import DEKManager, generate_dek
from sezam.vault.search import SearchIndex


# ============================================================
# Shared test fixtures
# ============================================================

# Fast Argon2id params for testing (avoid 256MB / 3 iterations)
FAST_ARGON2 = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def tmp_vault_dir(tmp_path):
    """Provide a fresh temporary directory for vault creation."""
    return tmp_path / "test_vault"


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 + X25519 keypair."""
    return generate_keypair()


@pytest.fixture
def dek():
    """Generate a random 32-byte DEK."""
    return bytearray(os.urandom(32))


@pytest.fixture
def kek():
    """Generate a random 32-byte KEK."""
    return bytearray(os.urandom(32))


@pytest.fixture
def dek_id():
    """Generate a random ULID and return as 26-byte padded bytes."""
    return ulid_to_bytes(new_ulid())


@pytest.fixture
def object_id():
    """Generate a random ULID and return as 26-byte padded bytes."""
    return ulid_to_bytes(new_ulid())


@pytest.fixture
def vault(tmp_vault_dir):
    """Create and yield an unlocked vault with fast Argon2id params."""
    v = Vault.create(str(tmp_vault_dir), "test_password_123", argon2_params=FAST_ARGON2)
    yield v
    try:
        v.lock()
    except Exception:
        pass


@pytest.fixture
def approval_mgr():
    """Create an ApprovalManager with short TTL for testing."""
    return ApprovalManager(default_ttl=5)


@pytest.fixture
def broker(vault, approval_mgr):
    """Create an MCPBroker backed by a test vault."""
    return MCPBroker(vault, approval_mgr)


# ============================================================
# 1. CRYPTO / AEAD (Spec 2.5, 2.6)
# ============================================================


class TestEnvelopeFormat:
    """Spec 2.5: Verify the ciphertext envelope header layout."""

    def test_header_size_is_53_bytes(self):
        """Header = alg(1) + schema(1) + blob_kind(1) + dek_id(26) + nonce(24) = 53."""
        assert HEADER_SIZE == 53

    def test_envelope_header_layout(self, dek, dek_id, object_id):
        blob = encrypt(b"test", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA)
        assert blob[0] == ALG_XCHACHA20POLY1305  # alg = 1
        assert blob[1] == SCHEMA_VERSION  # schema_version = 1
        assert blob[2] == BlobKind.ENTRY_DATA  # blob_kind
        assert blob[3:29] == dek_id  # dek_id = 26 bytes
        assert len(blob[29:53]) == NONCE_SIZE  # nonce = 24 bytes

    def test_dek_id_in_header_is_26_bytes(self, dek, dek_id, object_id):
        blob = encrypt(b"x", dek, dek_id, object_id, version=1, blob_kind=BlobKind.NODE_META)
        env = parse_envelope(blob)
        assert len(env.dek_id) == DEK_ID_SIZE == 26

    def test_nonce_in_header_is_24_bytes(self, dek, dek_id, object_id):
        blob = encrypt(b"x", dek, dek_id, object_id, version=1, blob_kind=BlobKind.NODE_META)
        env = parse_envelope(blob)
        assert len(env.nonce) == NONCE_SIZE == 24

    def test_ciphertext_includes_poly1305_tag(self, dek, dek_id, object_id):
        """Ciphertext portion must include a 16-byte Poly1305 authentication tag."""
        blob = encrypt(b"", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA, enable_padding=False)
        env = parse_envelope(blob)
        # For empty plaintext (no padding), ciphertext_with_tag should be exactly TAG_SIZE
        assert len(env.ciphertext_with_tag) == TAG_SIZE

    def test_parse_too_short_blob_raises(self):
        with pytest.raises(ValueError, match="Envelope too short"):
            parse_envelope(b"\x00" * (HEADER_SIZE + TAG_SIZE - 1))

    def test_alg_constant_equals_1(self):
        assert ALG_XCHACHA20POLY1305 == 1

    def test_schema_version_equals_1(self):
        assert SCHEMA_VERSION == 1


class TestAAD:
    """Spec 2.6: AAD construction and binding."""

    def test_aad_is_exactly_59_bytes(self, dek_id, object_id):
        """AAD = alg(1) + schema(1) + blob_kind(1) + dek_id(26) + object_id(26) + version(4) = 59."""
        aad = build_aad(1, 1, 1, dek_id, object_id, 1)
        assert len(aad) == 59

    def test_aad_structure_breakdown(self, dek_id, object_id):
        aad = build_aad(ALG_XCHACHA20POLY1305, SCHEMA_VERSION, BlobKind.ENTRY_DATA,
                        dek_id, object_id, 42)
        assert aad[0:1] == bytes([ALG_XCHACHA20POLY1305])
        assert aad[1:2] == bytes([SCHEMA_VERSION])
        assert aad[2:3] == bytes([BlobKind.ENTRY_DATA])
        assert aad[3:29] == dek_id
        assert aad[29:55] == object_id
        assert struct.unpack(">I", aad[55:59])[0] == 42

    def test_different_blob_kinds_produce_different_aad(self, dek_id, object_id):
        """Spec requires cross-kind decryption to fail via different AAD."""
        aads = set()
        for kind in BlobKind:
            aad = build_aad(1, 1, kind, dek_id, object_id, 1)
            aads.add(aad)
        assert len(aads) == len(BlobKind)  # All AADs are unique

    def test_cross_kind_decryption_fails(self, dek, dek_id, object_id):
        """Encrypting as ENTRY_DATA and trying to decrypt with modified blob_kind must fail."""
        blob = encrypt(b"secret", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA)
        # Tamper: change blob_kind byte in envelope header
        tampered = bytearray(blob)
        tampered[2] = BlobKind.NODE_META
        with pytest.raises(CryptoError):
            decrypt(bytes(tampered), dek, object_id, version=1)

    def test_cross_kind_decryption_fails_all_pairs(self, dek, dek_id, object_id):
        """Every pair of different blob_kinds must fail cross-decryption."""
        for kind_enc in [BlobKind.ENTRY_DATA, BlobKind.ENTRY_META, BlobKind.NODE_META]:
            blob = encrypt(b"data", dek, dek_id, object_id, version=1, blob_kind=kind_enc)
            for kind_tamper in BlobKind:
                if kind_tamper == kind_enc:
                    continue
                tampered = bytearray(blob)
                tampered[2] = kind_tamper
                with pytest.raises(CryptoError):
                    decrypt(bytes(tampered), dek, object_id, version=1)

    def test_changing_object_id_fails(self, dek, dek_id, object_id):
        """Swap attack prevention: different object_id in AAD must cause decryption failure."""
        blob = encrypt(b"secret", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA)
        wrong_oid = ulid_to_bytes(new_ulid())
        with pytest.raises(CryptoError):
            decrypt(blob, dek, wrong_oid, version=1)

    def test_changing_version_fails(self, dek, dek_id, object_id):
        """Downgrade/replay attack prevention: wrong version must cause decryption failure."""
        blob = encrypt(b"secret", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA)
        with pytest.raises(CryptoError):
            decrypt(blob, dek, object_id, version=2)

    def test_version_0_vs_1_different_aad(self, dek_id, object_id):
        aad_v0 = build_aad(1, 1, 1, dek_id, object_id, 0)
        aad_v1 = build_aad(1, 1, 1, dek_id, object_id, 1)
        assert aad_v0 != aad_v1

    def test_dek_id_size_validation(self, object_id):
        with pytest.raises(ValueError, match="dek_id must be 26 bytes"):
            build_aad(1, 1, 1, b"\x00" * 10, object_id, 1)

    def test_object_id_size_validation(self, dek_id):
        with pytest.raises(ValueError, match="object_id must be 26 bytes"):
            build_aad(1, 1, 1, dek_id, b"\x00" * 10, 1)


class TestNonceUniqueness:
    """Spec 2.5: Nonce is random 24 bytes; uniqueness across encryptions."""

    def test_nonce_is_24_bytes(self, dek, dek_id, object_id):
        blob = encrypt(b"x", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA)
        env = parse_envelope(blob)
        assert len(env.nonce) == 24

    def test_nonce_uniqueness_across_encryptions(self, dek, dek_id, object_id):
        """Multiple encryptions of the same plaintext must produce different nonces."""
        nonces = set()
        for _ in range(100):
            blob = encrypt(b"same", dek, dek_id, object_id, version=1,
                           blob_kind=BlobKind.ENTRY_DATA)
            env = parse_envelope(blob)
            nonces.add(env.nonce)
        # All 100 nonces should be unique (collision probability negligible for 24 random bytes)
        assert len(nonces) == 100

    def test_nonce_is_not_all_zeros(self, dek, dek_id, object_id):
        blob = encrypt(b"x", dek, dek_id, object_id, version=1, blob_kind=BlobKind.ENTRY_DATA)
        env = parse_envelope(blob)
        assert env.nonce != b"\x00" * 24

    def test_different_ciphertexts_for_same_plaintext(self, dek, dek_id, object_id):
        """Due to random nonce, same plaintext produces different ciphertexts."""
        blobs = set()
        for _ in range(10):
            blob = encrypt(b"same_plaintext", dek, dek_id, object_id, version=1,
                           blob_kind=BlobKind.ENTRY_DATA)
            blobs.add(blob)
        assert len(blobs) == 10


class TestPaddingSpec:
    """Spec 2.6: min 32 bytes total, power-of-2 alignment, random fill."""

    def test_padded_minimum_32_bytes(self):
        assert len(pad(b"")) == 32
        assert len(pad(b"x")) == 32
        assert len(pad(b"x" * 29)) == 32  # 2 + 29 = 31 < 32

    def test_padded_power_of_2_alignment(self):
        for size in [0, 1, 5, 10, 29, 30, 31, 62, 100, 500, 1000]:
            padded = pad(os.urandom(size))
            length = len(padded)
            assert length >= 32
            # length must be a power of 2
            assert (length & (length - 1)) == 0, f"len={length} is not power of 2 for data size={size}"

    def test_padding_fill_is_random_not_zeros(self):
        """Padding bytes should be random (os.urandom), not zero-filled."""
        # Pad a 1-byte payload: total = 32, padding_len = 32 - 2 - 1 = 29 bytes of padding
        padded = pad(b"\x42")
        padding_len = struct.unpack(">H", padded[:2])[0]
        padding_bytes = padded[2:2 + padding_len]
        # With 29 random bytes, the probability they are all zeros is 2^-232 — effectively impossible
        if padding_len > 0:
            assert padding_bytes != b"\x00" * padding_len, "Padding should be random, not zeros"

    def test_padding_fill_is_random_statistical(self):
        """Statistical check: padding bytes should have reasonable entropy."""
        padded = pad(b"x")
        padding_len = struct.unpack(">H", padded[:2])[0]
        if padding_len >= 4:
            padding_bytes = padded[2:2 + padding_len]
            unique_bytes = len(set(padding_bytes))
            # With truly random padding of 29 bytes, we expect many unique values
            assert unique_bytes > 1, "Random padding should have more than 1 unique byte value"

    def test_pad_unpad_roundtrip_various_sizes(self):
        for size in [0, 1, 30, 100, 1000]:
            data = os.urandom(size) if size > 0 else b""
            result = unpad(pad(data))
            assert result == data, f"Roundtrip failed for size={size}"

    def test_pad_unpad_empty_data(self):
        assert unpad(pad(b"")) == b""

    def test_pad_unpad_1_byte(self):
        data = b"\xff"
        assert unpad(pad(data)) == data

    def test_pad_unpad_30_bytes(self):
        data = os.urandom(30)
        assert unpad(pad(data)) == data

    def test_pad_unpad_exactly_30_bytes_boundary(self):
        """30 bytes of data: 2 + 30 = 32, so total should be 32 with 0 padding."""
        data = os.urandom(30)
        padded = pad(data)
        assert len(padded) == 32
        padding_len = struct.unpack(">H", padded[:2])[0]
        assert padding_len == 0

    def test_pad_unpad_31_bytes_bumps_to_64(self):
        """31 bytes of data: 2 + 31 = 33, next power of 2 = 64."""
        data = os.urandom(31)
        padded = pad(data)
        assert len(padded) == 64

    def test_invalid_padding_too_short(self):
        with pytest.raises(ValueError):
            unpad(b"\x00")

    def test_invalid_padding_length_exceeds_data(self):
        # Claim 1000 bytes of padding, but only supply 5 bytes total
        bad = struct.pack(">H", 1000) + b"\x00" * 3
        with pytest.raises(ValueError):
            unpad(bad)

    def test_next_power_of_2_edge_cases(self):
        assert _next_power_of_2(0) == 1
        assert _next_power_of_2(1) == 1
        assert _next_power_of_2(2) == 2
        assert _next_power_of_2(3) == 4
        assert _next_power_of_2(32) == 32
        assert _next_power_of_2(33) == 64
        assert _next_power_of_2(1024) == 1024
        assert _next_power_of_2(1025) == 2048


class TestDEKWrapSpec:
    """Spec: DEK wrap uses blob_kind=6, roundtrip with padding enabled."""

    def test_dek_wrap_uses_blob_kind_6(self, kek, dek_id, object_id):
        raw_dek = os.urandom(32)
        wrapped = encrypt_dek_wrap(raw_dek, kek, dek_id, object_id)
        env = parse_envelope(wrapped)
        assert env.blob_kind == BlobKind.DEK_WRAP == 6

    def test_dek_wrap_roundtrip(self, kek):
        raw_dek = bytearray(os.urandom(32))
        kek_id = ulid_to_bytes(new_ulid())
        archive_id = ulid_to_bytes(new_ulid())
        wrapped = encrypt_dek_wrap(raw_dek, kek, kek_id, archive_id)
        unwrapped = decrypt_dek_wrap(wrapped, kek, archive_id)
        assert unwrapped == raw_dek
        assert isinstance(unwrapped, bytearray)  # for zeroization

    def test_dek_wrap_has_padding(self, kek):
        """DEK wrap uses padding (enable_padding=True by default)."""
        raw_dek = bytearray(os.urandom(32))
        kek_id = ulid_to_bytes(new_ulid())
        archive_id = ulid_to_bytes(new_ulid())
        wrapped = encrypt_dek_wrap(raw_dek, kek, kek_id, archive_id)
        # Without padding, ciphertext would be 32 + 16 (tag) = 48 bytes after header
        # With padding, the padded plaintext is larger (32 bytes data -> pad(32) -> 2+30+32=64 -> next_pow2=64)
        env = parse_envelope(wrapped)
        # padded size >= 32 (minimum), ciphertext should be padded_size + TAG_SIZE
        assert len(env.ciphertext_with_tag) > 32 + TAG_SIZE

    def test_dek_wrap_wrong_key_fails(self, kek):
        raw_dek = bytearray(os.urandom(32))
        kek_id = ulid_to_bytes(new_ulid())
        archive_id = ulid_to_bytes(new_ulid())
        wrapped = encrypt_dek_wrap(raw_dek, kek, kek_id, archive_id)
        wrong_kek = bytearray(os.urandom(32))
        with pytest.raises(CryptoError):
            decrypt_dek_wrap(wrapped, wrong_kek, archive_id)


class TestKeypairWrapSpec:
    """Spec: Keypair wrap uses blob_kind=7, roundtrip with padding enabled."""

    def test_keypair_wrap_uses_blob_kind_7(self, kek, dek_id, object_id):
        keypair_data = os.urandom(64)
        wrapped = encrypt_keypair_wrap(keypair_data, kek, dek_id, object_id)
        env = parse_envelope(wrapped)
        assert env.blob_kind == BlobKind.KEYPAIR_WRAP == 7

    def test_keypair_wrap_roundtrip(self, kek):
        keypair_data = bytearray(os.urandom(64))
        kek_id = ulid_to_bytes(new_ulid())
        user_id = ulid_to_bytes(new_ulid())
        wrapped = encrypt_keypair_wrap(keypair_data, kek, kek_id, user_id)
        unwrapped = decrypt_keypair_wrap(wrapped, kek, user_id)
        assert unwrapped == keypair_data
        assert isinstance(unwrapped, bytearray)  # for zeroization

    def test_keypair_wrap_has_padding(self, kek):
        keypair_data = bytearray(os.urandom(64))
        kek_id = ulid_to_bytes(new_ulid())
        user_id = ulid_to_bytes(new_ulid())
        wrapped = encrypt_keypair_wrap(keypair_data, kek, kek_id, user_id)
        env = parse_envelope(wrapped)
        # 64 bytes data -> pad(64) -> 2 + data = 66 -> next power of 2 = 128
        # ciphertext_with_tag = 128 + 16 = 144
        assert len(env.ciphertext_with_tag) > 64 + TAG_SIZE

    def test_keypair_wrap_wrong_key_fails(self, kek):
        keypair_data = bytearray(os.urandom(64))
        kek_id = ulid_to_bytes(new_ulid())
        user_id = ulid_to_bytes(new_ulid())
        wrapped = encrypt_keypair_wrap(keypair_data, kek, kek_id, user_id)
        wrong_kek = bytearray(os.urandom(32))
        with pytest.raises(CryptoError):
            decrypt_keypair_wrap(wrapped, wrong_kek, user_id)


class TestBlobKindValues:
    """Spec 2.5: blob_kind values 1-7 are assigned correctly."""

    def test_blob_kind_enum_values(self):
        assert BlobKind.NODE_META == 1
        assert BlobKind.ENTRY_META == 2
        assert BlobKind.ENTRY_DATA == 3
        assert BlobKind.HISTORY_SNAPSHOT == 4
        assert BlobKind.AUDIT_DETAILS == 5
        assert BlobKind.DEK_WRAP == 6
        assert BlobKind.KEYPAIR_WRAP == 7

    def test_blob_kind_count(self):
        assert len(BlobKind) == 7


class TestTamperDetection:
    """Additional tamper-detection tests beyond AAD binding."""

    def test_flipping_single_ciphertext_bit_fails(self, dek, dek_id, object_id):
        blob = encrypt(b"important data", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA)
        for byte_offset in [HEADER_SIZE, HEADER_SIZE + 5, len(blob) - 1]:
            tampered = bytearray(blob)
            tampered[byte_offset] ^= 0x01
            with pytest.raises(CryptoError):
                decrypt(bytes(tampered), dek, object_id, version=1)

    def test_truncated_ciphertext_fails(self, dek, dek_id, object_id):
        blob = encrypt(b"data", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA)
        truncated = blob[:HEADER_SIZE + TAG_SIZE - 1]
        with pytest.raises((CryptoError, ValueError)):
            decrypt(truncated, dek, object_id, version=1)

    def test_appended_data_fails(self, dek, dek_id, object_id):
        blob = encrypt(b"data", dek, dek_id, object_id, version=1,
                       blob_kind=BlobKind.ENTRY_DATA)
        extended = blob + b"\x00"
        with pytest.raises(CryptoError):
            decrypt(extended, dek, object_id, version=1)


# ============================================================
# 2. KEY MANAGEMENT (Spec 2.2)
# ============================================================


class TestKeyManagement:
    """Spec 2.2: Two separate key pairs, fingerprint, zeroization."""

    def test_two_separate_keypairs_ed25519_x25519(self, keypair):
        """Keypair has both Ed25519 (signing) and X25519 (encryption) keys."""
        assert len(keypair.signing_sk) == 32
        assert len(keypair.signing_pk) == 32
        assert len(keypair.encryption_sk) == 32
        assert len(keypair.encryption_pk) == 32
        # Signing and encryption keys must be different (different curves)
        assert bytes(keypair.signing_sk) != bytes(keypair.encryption_sk)
        assert keypair.signing_pk != keypair.encryption_pk

    def test_fingerprint_is_sha256_of_concatenated_pks(self, keypair):
        """Fingerprint = SHA-256(signing_pk || encryption_pk)."""
        import hashlib
        expected = hashlib.sha256(keypair.signing_pk + keypair.encryption_pk).hexdigest()
        assert keypair.fingerprint == expected

    def test_fingerprint_is_64_hex_chars(self, keypair):
        fp = keypair.fingerprint
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_bytes_is_32_bytes(self, keypair):
        assert len(keypair.fingerprint_bytes) == 32

    def test_fingerprint_words_4_words_from_2048_list(self, keypair):
        """4 words from 2048-word list (11 bits each = 44 bits)."""
        words = keypair.fingerprint_words()
        assert len(words) == 4
        # Each word should be a string
        for w in words:
            assert isinstance(w, str)
            assert len(w) > 0

    def test_fingerprint_words_deterministic(self, keypair):
        words1 = keypair.fingerprint_words()
        words2 = keypair.fingerprint_words()
        assert words1 == words2

    def test_same_keypair_same_fingerprint(self, keypair):
        assert keypair.fingerprint == keypair.fingerprint

    def test_different_keypair_different_fingerprint(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.fingerprint != kp2.fingerprint

    def test_fingerprint_via_standalone_function(self, keypair):
        fp = compute_fingerprint(keypair.signing_pk, keypair.encryption_pk)
        assert fp == keypair.fingerprint

    def test_keypair_serialization_roundtrip_64_bytes(self, keypair):
        serialized = keypair.serialize_private()
        assert len(serialized) == 64
        assert isinstance(serialized, bytearray)
        # First 32 bytes = signing_sk, next 32 = encryption_sk
        assert serialized[:32] == bytes(keypair.signing_sk)
        assert serialized[32:64] == bytes(keypair.encryption_sk)

    def test_keypair_deserialization_roundtrip(self, keypair):
        serialized = keypair.serialize_private()
        restored = KeyPair.from_private_bytes(
            bytes(serialized), keypair.signing_pk, keypair.encryption_pk
        )
        assert bytes(restored.signing_sk) == bytes(keypair.signing_sk)
        assert bytes(restored.encryption_sk) == bytes(keypair.encryption_sk)
        assert restored.signing_pk == keypair.signing_pk
        assert restored.encryption_pk == keypair.encryption_pk

    def test_keypair_deserialization_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="Invalid account keypair payload length"):
            KeyPair.from_private_bytes(b"\x00" * 63, b"\x00" * 32, b"\x00" * 32)

    def test_zeroize_clears_private_keys(self, keypair):
        """After zeroize(), private keys should be zeroed."""
        keypair.zeroize()
        assert keypair.signing_sk == bytearray(32)
        assert keypair.encryption_sk == bytearray(32)
        # Public keys remain (they are bytes, not bytearray)
        assert len(keypair.signing_pk) == 32
        assert len(keypair.encryption_pk) == 32

    def test_ed25519_sign_and_verify(self, keypair):
        sk = keypair.to_nacl_signing_key()
        vk = keypair.to_nacl_verify_key()
        msg = b"test message for signing"
        signed = sk.sign(msg)
        # Verification should succeed
        vk.verify(signed.message, signed.signature)

    def test_ed25519_tampered_signature_fails(self, keypair):
        sk = keypair.to_nacl_signing_key()
        vk = keypair.to_nacl_verify_key()
        signed = sk.sign(b"test")
        bad_sig = bytearray(signed.signature)
        bad_sig[0] ^= 0xFF
        with pytest.raises(Exception):  # nacl.exceptions.BadSignatureError
            vk.verify(signed.message, bytes(bad_sig))

    def test_x25519_nacl_key_objects(self, keypair):
        """Verify X25519 key objects can be created from keypair."""
        priv = keypair.to_nacl_private_key()
        pub = keypair.to_nacl_public_key()
        assert bytes(priv) == bytes(keypair.encryption_sk)
        assert bytes(pub) == keypair.encryption_pk


# ============================================================
# 3. KDF (Spec 2.3)
# ============================================================


class TestKDF:
    """Spec 2.3: Argon2id with correct default params."""

    def test_default_params(self):
        params = Argon2Params()
        assert params.time_cost == 3
        assert params.memory_cost == 262144  # 256 MB in KiB
        assert params.parallelism == 4
        assert params.hash_len == 64  # 32B KEK + 32B auth_proof
        assert params.salt_len == 16

    def test_argon2id_output_is_32_bytes(self):
        salt = generate_salt()
        kek = derive_kek("password", salt, FAST_ARGON2)
        assert len(kek) == 32

    def test_argon2id_returns_bytearray(self):
        salt = generate_salt()
        kek = derive_kek("password", salt, FAST_ARGON2)
        assert isinstance(kek, bytearray)

    def test_deterministic_same_password_same_salt(self):
        salt = generate_salt()
        kek1 = derive_kek("my_password", salt, FAST_ARGON2)
        kek2 = derive_kek("my_password", salt, FAST_ARGON2)
        assert kek1 == kek2

    def test_different_password_different_kek(self):
        salt = generate_salt()
        kek1 = derive_kek("password_A", salt, FAST_ARGON2)
        kek2 = derive_kek("password_B", salt, FAST_ARGON2)
        assert kek1 != kek2

    def test_different_salt_different_kek(self):
        kek1 = derive_kek("same_password", os.urandom(16), FAST_ARGON2)
        kek2 = derive_kek("same_password", os.urandom(16), FAST_ARGON2)
        assert kek1 != kek2

    def test_salt_generation_length(self):
        salt = generate_salt()
        assert len(salt) == 16

    def test_salt_is_random(self):
        salts = [generate_salt() for _ in range(20)]
        assert len(set(salts)) == 20

    def test_params_serialization_roundtrip(self):
        params = Argon2Params(time_cost=5, memory_cost=131072, parallelism=2)
        d = params.to_dict()
        restored = Argon2Params.from_dict(d)
        assert restored.time_cost == params.time_cost
        assert restored.memory_cost == params.memory_cost
        assert restored.parallelism == params.parallelism
        assert restored.hash_len == params.hash_len

    def test_empty_password_still_works(self):
        """Empty password is valid (even if weak)."""
        salt = generate_salt()
        kek = derive_kek("", salt, FAST_ARGON2)
        assert len(kek) == 32

    def test_unicode_password(self):
        """Unicode password (e.g. Slovak characters) should work."""
        salt = generate_salt()
        kek = derive_kek("heslo_ščťžý_č_ď_ľ", salt, FAST_ARGON2)
        assert len(kek) == 32

    def test_kek_can_be_zeroized(self):
        salt = generate_salt()
        kek = derive_kek("password", salt, FAST_ARGON2)
        kek[:] = b"\x00" * 32
        assert kek == bytearray(32)

    # --- auth_proof derivation (spec 2.2, note B: 64B split) ---

    def test_auth_proof_is_32_bytes_nonempty(self):
        """Regression: desktop callers used derive_kek()[32:64] which was
        empty (derive_kek returns 32B). derive_kek_and_proof must give a
        real 32-byte proof."""
        salt = generate_salt()
        _kek, auth_proof = derive_kek_and_proof("password", salt, FAST_ARGON2)
        assert isinstance(auth_proof, bytearray)
        assert len(auth_proof) == 32
        assert auth_proof != b""
        assert auth_proof != b"\x00" * 32

    def test_kek_and_proof_are_independent_halves(self):
        salt = generate_salt()
        kek, auth_proof = derive_kek_and_proof("password", salt, FAST_ARGON2)
        assert len(kek) == 32
        assert kek != auth_proof

    def test_proof_matches_full_64b_slice(self):
        """Cross-client consistency: web/mobile take sublist(32,64) of the
        raw 64B Argon2 output. derive_kek_and_proof must equal that."""
        import argon2

        salt = generate_salt()
        raw = argon2.low_level.hash_secret_raw(
            secret=b"password",
            salt=salt,
            time_cost=FAST_ARGON2.time_cost,
            memory_cost=FAST_ARGON2.memory_cost,
            parallelism=FAST_ARGON2.parallelism,
            hash_len=64,
            type=argon2.low_level.Type.ID,
        )
        kek, auth_proof = derive_kek_and_proof("password", salt, FAST_ARGON2)
        assert bytes(kek) == raw[:32]
        assert bytes(auth_proof) == raw[32:64]

    def test_derive_kek_slice_32_64_is_empty_trap(self):
        """Documents the original bug: derive_kek returns only 32B, so
        [32:64] is empty. Guards against re-introducing the trap."""
        salt = generate_salt()
        kek = derive_kek("password", salt, FAST_ARGON2)
        assert bytes(kek[32:64]) == b""

    def test_password_change_spec_uses_option_b_wide_output_split(self):
        spec = (Path(__file__).parents[1] / "SEZAM_SPEC_v15_FINAL.md").read_text(
            encoding="utf-8"
        )
        password_change = spec.split("### 9.1 Zmena master hesla", 1)[1].split(
            "### 9.2 Re-keying pri presune entry", 1
        )[0]

        assert "nový_auth_salt" not in password_change
        assert "Argon2id(nové_heslo, nový argon2_salt, hash_len=64)" in password_change
        assert "raw[0:32] = nový KEK" in password_change
        assert "raw[32:64] = nový auth_proof" in password_change

    def test_multi_client_write_policy_spec_matches_clients(self):
        spec = (Path(__file__).parents[1] / "SEZAM_SPEC_v15_FINAL.md").read_text(
            encoding="utf-8"
        )
        multi_user = spec.split("### 3.4 Multi-user prístup", 1)[1].split(
            "### 3.5 `sensitive` príznak", 1
        )[0]

        assert "Desktop pole neposiela" in multi_user
        assert "Web a mobil posielajú explicitnú policy" in multi_user
        assert "UI (web/mobil)" in multi_user
        assert "Desktop/mobil pole vynechávajú" not in multi_user


# ============================================================
# 4. KEK/DEK HIERARCHY (Spec 2.3)
# ============================================================


class TestKEKDEKHierarchy:
    """Spec 2.3: Root DEK, Audit DEK, Folder DEK, wrapping, re-wrap."""

    def test_root_dek_has_scope_root(self, vault):
        row = vault.db.fetchone("SELECT scope FROM deks WHERE scope = 'root'")
        assert row is not None
        assert row["scope"] == "root"

    def test_audit_dek_has_scope_audit(self, vault):
        row = vault.db.fetchone("SELECT scope FROM deks WHERE scope = 'audit'")
        assert row is not None
        assert row["scope"] == "audit"

    def test_folder_dek_has_scope_folder(self, vault):
        node_id = vault.create_node("TestFolder")
        row = vault.db.fetchone(
            "SELECT scope FROM deks WHERE scope = 'folder' AND node_id = ?", (node_id,)
        )
        assert row is not None
        assert row["scope"] == "folder"

    def test_dek_is_always_kek_wrapped(self, vault):
        """All DEKs must have encrypted_dek NOT NULL."""
        rows = vault.db.fetchall("SELECT encrypted_dek FROM deks")
        for row in rows:
            assert row["encrypted_dek"] is not None
            assert len(row["encrypted_dek"]) > 0

    def test_dek_can_be_unlocked_with_kek(self, vault):
        """DEK manager can unlock any DEK using the KEK."""
        rows = vault.db.fetchall("SELECT id FROM deks")
        for row in rows:
            raw_dek = vault.dek_mgr.unlock_dek(row["id"])
            assert len(raw_dek) == 32
            assert isinstance(raw_dek, bytearray)

    def test_wrong_kek_fails_unlock(self, tmp_path):
        """Wrong KEK (wrong password) must fail to unlock DEKs."""
        vault_path = tmp_path / "wrong_kek_vault"
        v = Vault.create(str(vault_path), "correct_password", argon2_params=FAST_ARGON2)
        v.lock()
        with pytest.raises(ValueError, match="Wrong master password"):
            v2 = Vault(vault_path)
            v2.unlock("wrong_password")

    def test_rewrap_all_deks_with_new_kek(self, vault):
        """After re-wrap, all DEKs should still be accessible with new KEK."""
        # Get all DEK values before re-wrap
        rows = vault.db.fetchall("SELECT id FROM deks")
        original_deks = {}
        for row in rows:
            original_deks[row["id"]] = bytes(vault.dek_mgr.unlock_dek(row["id"]))

        # Re-wrap with new KEK
        new_kek = bytearray(os.urandom(32))
        vault.dek_mgr.rewrap_all_deks(new_kek)

        # All DEKs should still decrypt to the same values
        for dek_id_str, original_dek in original_deks.items():
            # Clear cache to force re-decryption
            vault.dek_mgr._dek_cache.pop(dek_id_str, None)
            unlocked = vault.dek_mgr.unlock_dek(dek_id_str)
            assert bytes(unlocked) == original_dek

    def test_dek_archive_chain_wrapping(self, vault):
        """Old DEK wrapped by new DEK (chain wrapping) during rekey."""
        # Create a folder node (which creates a folder DEK)
        node_id = vault.create_node("RekeyTest")
        row = vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))
        old_dek_id = row["dek_id"]
        old_dek = bytes(vault.dek_mgr.unlock_dek(old_dek_id))

        # Rekey the folder
        new_dek_id, new_raw_dek = vault.dek_mgr.rekey_folder(old_dek_id, node_id)

        # Verify archive was created
        archive_row = vault.db.fetchone(
            "SELECT encrypted_dek FROM dek_archive WHERE replaced_by = ?", (new_dek_id,)
        )
        assert archive_row is not None

        # Verify old DEK can be recovered from archive using new DEK
        recovered = decrypt_dek_wrap(
            archive_row["encrypted_dek"],
            new_raw_dek,
            ulid_to_bytes(vault.db.fetchone(
                "SELECT id FROM dek_archive WHERE replaced_by = ?", (new_dek_id,)
            )["id"]),
        )
        assert bytes(recovered) == old_dek

    def test_generate_dek_is_32_bytes(self):
        d = generate_dek()
        assert len(d) == 32
        assert isinstance(d, bytearray)

    def test_generate_dek_is_random(self):
        deks = [generate_dek() for _ in range(20)]
        assert len(set(bytes(d) for d in deks)) == 20


# ============================================================
# 5. VAULT CRUD
# ============================================================


class TestVaultCRUD:
    """Vault CRUD operations: create, read, update, delete, search."""

    def test_create_node_stores_encrypted_meta(self, vault):
        node_id = vault.create_node("MyFolder")
        row = vault.db.fetchone("SELECT encrypted_meta FROM nodes WHERE id = ?", (node_id,))
        assert row is not None
        assert row["encrypted_meta"] is not None
        assert len(row["encrypted_meta"]) > 0

    def test_create_node_queues_a_write(self, vault):
        node_id = vault.create_node("DirtyFolder")
        assert outbox.has_write(vault.db, node_id)

    def test_create_entry_stores_encrypted_meta_and_data(self, vault):
        node_id = vault.create_node("Entries")
        entry_id = vault.create_entry(
            node_id, "GitHub",
            [{"key": "username", "value": "user"}, {"key": "password", "value": "pass123"}],
        )
        row = vault.db.fetchone(
            "SELECT encrypted_meta, encrypted_data FROM entries WHERE id = ?", (entry_id,)
        )
        assert row["encrypted_meta"] is not None
        assert row["encrypted_data"] is not None
        assert len(row["encrypted_meta"]) > 0
        assert len(row["encrypted_data"]) > 0

    def test_read_entry_decrypts_correctly(self, vault):
        node_id = vault.create_node("ReadTest")
        entry_id = vault.create_entry(
            node_id, "MyEntry",
            [{"key": "url", "value": "https://example.com"},
             {"key": "password", "value": "s3cr3t", "sensitive": True}],
            tags=["web", "test"],
        )
        result = vault.read_entry(entry_id)
        assert result["name"] == "MyEntry"
        assert result["tags"] == ["web", "test"]
        assert len(result["fields"]) == 2
        assert result["fields"][0]["key"] == "url"
        assert result["fields"][0]["value"] == "https://example.com"
        assert result["fields"][1]["key"] == "password"
        assert result["fields"][1]["value"] == "s3cr3t"
        assert result["fields"][1]["sensitive"] is True

    def test_update_entry_increments_version(self, vault):
        node_id = vault.create_node("UpdateTest")
        entry_id = vault.create_entry(
            node_id, "Original",
            [{"key": "user", "value": "old_user"}],
        )
        assert vault.read_entry(entry_id)["version"] == 1

        vault.update_entry(entry_id, name="Updated")
        updated = vault.read_entry(entry_id)
        assert updated["name"] == "Updated"
        assert updated["version"] == 2

    def test_update_entry_creates_history_snapshot(self, vault):
        node_id = vault.create_node("HistoryTest")
        entry_id = vault.create_entry(
            node_id, "WithHistory",
            [{"key": "pw", "value": "old_password"}],
        )

        vault.update_entry(entry_id, fields=[{"key": "pw", "value": "new_password"}])

        # Check history was created
        history_rows = vault.db.fetchall(
            "SELECT * FROM entry_history WHERE entry_id = ?", (entry_id,)
        )
        assert len(history_rows) == 1

    def test_update_entry_history_uses_blob_kind_4(self, vault):
        """History snapshots should be encrypted with blob_kind=HISTORY_SNAPSHOT(4)."""
        node_id = vault.create_node("HistBlobKind")
        entry_id = vault.create_entry(
            node_id, "Entry",
            [{"key": "data", "value": "v1"}],
        )
        vault.update_entry(entry_id, fields=[{"key": "data", "value": "v2"}])

        history_row = vault.db.fetchone(
            "SELECT encrypted_snapshot FROM entry_history WHERE entry_id = ?", (entry_id,)
        )
        env = parse_envelope(history_row["encrypted_snapshot"])
        assert env.blob_kind == BlobKind.HISTORY_SNAPSHOT

    def test_delete_entry_creates_signed_new_version_tombstone(self, vault):
        from sezam.vault.sync_client import SyncClient

        node_id = vault.create_node("DeleteTest")
        entry_id = vault.create_entry(
            node_id, "ToDelete",
            [{"key": "k", "value": "v"}],
        )
        client = SyncClient(
            vault.db, "http://localhost", vault.keypair, vault._user_id
        )

        initial = next(
            obj for obj in client._collect_dirty_objects() if obj["id"] == entry_id
        )
        assert initial["version"] == 1
        assert initial["is_deleted"] == 0

        vault.delete_entry(entry_id)

        row = vault.db.fetchone(
            "SELECT version, is_deleted FROM entries WHERE id = ?", (entry_id,)
        )
        assert row["version"] == 2
        assert row["is_deleted"] == 1

        tombstone = next(
            obj for obj in client._collect_dirty_objects() if obj["id"] == entry_id
        )
        assert tombstone["version"] == 2
        assert tombstone["is_deleted"] == 1
        assert tombstone["signature"] != initial["signature"]
        assert client._verify_object_signature(tombstone) is True

    def test_deleted_entry_not_found_on_read(self, vault):
        node_id = vault.create_node("DeleteReadTest")
        entry_id = vault.create_entry(
            node_id, "Gone",
            [{"key": "k", "value": "v"}],
        )
        vault.delete_entry(entry_id)
        with pytest.raises(KeyError):
            vault.read_entry(entry_id)

    def test_deleted_entry_not_in_list(self, vault):
        node_id = vault.create_node("DeleteListTest")
        entry_id = vault.create_entry(
            node_id, "Gone",
            [{"key": "k", "value": "v"}],
        )
        vault.create_entry(
            node_id, "Remaining",
            [{"key": "k", "value": "v"}],
        )
        vault.delete_entry(entry_id)
        entries = vault.list_entries(node_id)
        assert all(e["name"] != "Gone" for e in entries)
        assert any(e["name"] == "Remaining" for e in entries)

    def test_vault_locked_raises_on_operations(self, tmp_path):
        vault_path = tmp_path / "locked_vault"
        v = Vault.create(str(vault_path), "pw", argon2_params=FAST_ARGON2)
        v.lock()
        with pytest.raises(VaultLocked):
            v.create_node("ShouldFail")

    def test_vault_unlock_then_crud(self, tmp_path):
        """Create vault, lock, unlock, then perform CRUD."""
        vault_path = tmp_path / "unlock_test"
        v = Vault.create(str(vault_path), "my_pass", argon2_params=FAST_ARGON2)
        v.lock()

        v2 = Vault(vault_path)
        v2.unlock("my_pass")
        node_id = v2.create_node("AfterUnlock")
        entry_id = v2.create_entry(node_id, "Test", [{"key": "k", "value": "v"}])
        result = v2.read_entry(entry_id)
        assert result["name"] == "Test"
        v2.lock()


class TestVaultSearch:
    """Spec 5.2: Search finds by name, field keys, tags — NOT values by default."""

    def test_search_by_name(self, vault):
        node_id = vault.create_node("SearchNode")
        vault.create_entry(node_id, "GitHub Login", [{"key": "user", "value": "me"}])
        results = vault.search("GitHub")
        assert len(results) >= 1
        assert any(r["name"] == "GitHub Login" for r in results)

    def test_search_by_field_key(self, vault):
        node_id = vault.create_node("FieldKeySearch")
        vault.create_entry(
            node_id, "SomeEntry",
            [{"key": "api_token", "value": "secret123"}],
        )
        results = vault.search("api_token")
        assert len(results) >= 1

    def test_search_by_tag(self, vault):
        node_id = vault.create_node("TagSearch")
        vault.create_entry(
            node_id, "Tagged",
            [{"key": "k", "value": "v"}],
            tags=["production", "critical"],
        )
        results = vault.search("production")
        assert len(results) >= 1

    def test_search_does_not_find_by_value(self, vault):
        """Standard search must NOT search field values."""
        node_id = vault.create_node("ValueSearch")
        vault.create_entry(
            node_id, "SecretEntry",
            [{"key": "password", "value": "xyzzy_unique_secret_12345"}],
        )
        results = vault.search("xyzzy_unique_secret_12345")
        assert len(results) == 0

    def test_search_empty_query_returns_nothing(self, vault):
        results = vault.search("")
        assert len(results) == 0


class TestChangePassword:
    """Spec 9.1: Change master password re-derives KEK, re-wraps all DEKs."""

    def test_change_password_and_unlock_with_new(self, tmp_path):
        vault_path = tmp_path / "change_pw"
        v = Vault.create(str(vault_path), "old_pw", argon2_params=FAST_ARGON2)
        node_id = v.create_node("BeforeChange")
        entry_id = v.create_entry(node_id, "Entry1", [{"key": "k", "value": "v"}])
        v.change_password("old_pw", "new_pw")
        v.lock()

        # Old password should fail
        v2 = Vault(vault_path)
        with pytest.raises(ValueError, match="Wrong master password"):
            v2.unlock("old_pw")

        # New password should work, and data should be intact
        v3 = Vault(vault_path)
        v3.unlock("new_pw")
        result = v3.read_entry(entry_id)
        assert result["name"] == "Entry1"
        assert result["fields"][0]["value"] == "v"
        v3.lock()

    def test_change_password_rewraps_org_recovery_kek(self, tmp_path):
        vault_path = tmp_path / "change_pw_org_recovery"
        v = Vault.create(str(vault_path), "old_pw", argon2_params=FAST_ARGON2)
        shares = v.setup_org_recovery(threshold=2, shares=3)
        wrapped_before = v.db.get_meta("org_recovery_wrapped_kek")

        v.change_password("old_pw", "new_pw")

        wrapped_after = v.db.get_meta("org_recovery_wrapped_kek")
        assert wrapped_after
        assert wrapped_after != wrapped_before
        assert v.db.get_meta("org_recovery_stale") != "1"
        v.lock()

        recovered = Vault(vault_path)
        recovered.org_recovery(shares[:2], "recovered_pw")
        recovered.lock()

        reopened = Vault(vault_path)
        reopened.unlock("recovered_pw")
        reopened.lock()


# ============================================================
# 6. AUDIT LOG (Spec 4.3)
# ============================================================


class TestAuditLog:
    """Spec 4.3: Ed25519 signed records with Merkle DAG."""

    @pytest.fixture
    def audit(self, vault):
        return AuditLog(vault.db)

    @pytest.fixture
    def signing_key(self, keypair):
        return keypair.to_nacl_signing_key()

    @pytest.fixture
    def verify_key_bytes(self, keypair):
        return keypair.signing_pk

    @pytest.fixture
    def actor_id(self):
        return new_ulid()

    def test_ed25519_signed_record(self, audit, signing_key, verify_key_bytes, actor_id):
        record_id = audit.append(
            actor_id=actor_id,
            action="read",
            signing_key=signing_key,
        )
        assert audit.verify_record(record_id, verify_key_bytes) is True

    def test_merkle_dag_parent_ids_json_array(self, audit, signing_key, actor_id):
        """parent_ids should be stored as a JSON array."""
        r1 = audit.append(actor_id=actor_id, action="write", signing_key=signing_key)
        row = audit._db.fetchone("SELECT parent_ids FROM audit_log WHERE id = ?", (r1,))
        parents = json.loads(row["parent_ids"])
        assert isinstance(parents, list)

    def test_merkle_dag_chain(self, audit, signing_key, verify_key_bytes, actor_id):
        """Second record should reference first as parent."""
        r1 = audit.append(actor_id=actor_id, action="write", signing_key=signing_key)
        r2 = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)

        row2 = audit._db.fetchone("SELECT parent_ids FROM audit_log WHERE id = ?", (r2,))
        parents = json.loads(row2["parent_ids"])
        assert r1 in parents

        # Both should verify
        assert audit.verify_record(r1, verify_key_bytes)
        assert audit.verify_record(r2, verify_key_bytes)

    def test_signature_verification_valid(self, audit, signing_key, verify_key_bytes, actor_id):
        record_id = audit.append(actor_id=actor_id, action="approve", signing_key=signing_key)
        assert audit.verify_record(record_id, verify_key_bytes) is True

    def test_tampered_record_fails_verification(self, audit, signing_key, verify_key_bytes, actor_id):
        """Modifying any field after signing must cause verification failure."""
        record_id = audit.append(actor_id=actor_id, action="write", signing_key=signing_key)

        # Tamper with the action field in the database
        audit._db.execute(
            "UPDATE audit_log SET action = 'delete' WHERE id = ?", (record_id,)
        )

        assert audit.verify_record(record_id, verify_key_bytes) is False

    def test_wrong_verify_key_fails(self, audit, signing_key, actor_id):
        record_id = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)
        wrong_kp = generate_keypair()
        assert audit.verify_record(record_id, wrong_kp.signing_pk) is False

    def test_tampered_signature_fails(self, audit, signing_key, verify_key_bytes, actor_id):
        record_id = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)
        # Tamper with signature
        row = audit._db.fetchone("SELECT signature FROM audit_log WHERE id = ?", (record_id,))
        bad_sig = bytearray(row["signature"])
        bad_sig[0] ^= 0xFF
        audit._db.execute(
            "UPDATE audit_log SET signature = ? WHERE id = ?", (bytes(bad_sig), record_id)
        )
        assert audit.verify_record(record_id, verify_key_bytes) is False

    def test_tampered_timestamp_fails(self, audit, signing_key, verify_key_bytes, actor_id):
        record_id = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)
        row = audit._db.fetchone("SELECT timestamp FROM audit_log WHERE id = ?", (record_id,))
        audit._db.execute(
            "UPDATE audit_log SET timestamp = ? WHERE id = ?",
            (row["timestamp"] + 1, record_id),
        )
        assert audit.verify_record(record_id, verify_key_bytes) is False

    def test_tampered_actor_id_fails(self, audit, signing_key, verify_key_bytes, actor_id):
        record_id = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)
        fake_actor = new_ulid()
        audit._db.execute(
            "UPDATE audit_log SET actor_id = ? WHERE id = ?", (fake_actor, record_id)
        )
        assert audit.verify_record(record_id, verify_key_bytes) is False

    def test_tampered_parent_ids_fails(self, audit, signing_key, verify_key_bytes, actor_id):
        r1 = audit.append(actor_id=actor_id, action="write", signing_key=signing_key)
        r2 = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)
        # Remove parent reference
        audit._db.execute(
            "UPDATE audit_log SET parent_ids = '[]' WHERE id = ?", (r2,)
        )
        assert audit.verify_record(r2, verify_key_bytes) is False

    def test_multiple_parents_fork_handling(self, audit, signing_key, verify_key_bytes, actor_id):
        """DAG can have multiple leaf nodes; next record references all of them."""
        # Create two records at the same "level" by inserting manually
        r1 = audit.append(actor_id=actor_id, action="write", signing_key=signing_key)

        # Insert a second record that also has no children (another leaf)
        # We do this by creating it referencing r1 as parent
        r2 = audit.append(actor_id=actor_id, action="read", signing_key=signing_key)

        # r2 should reference r1 as parent
        row = audit._db.fetchone("SELECT parent_ids FROM audit_log WHERE id = ?", (r2,))
        parents = json.loads(row["parent_ids"])
        assert r1 in parents

    def test_nonexistent_record_verify_returns_false(self, audit, keypair):
        assert audit.verify_record("nonexistent_ulid_12345678", keypair.signing_pk) is False

    def test_audit_with_encrypted_details(self, vault, keypair):
        audit = AuditLog(vault.db)
        sk = keypair.to_nacl_signing_key()
        actor_id = new_ulid()
        audit_dek_id, audit_dek = vault.dek_mgr.get_audit_dek()

        record_id = audit.append(
            actor_id=actor_id,
            action="write",
            signing_key=sk,
            detail_plaintext=b'{"entry_id":"test"}',
            audit_dek=audit_dek,
            audit_dek_id=audit_dek_id,
        )

        assert audit.verify_record(record_id, keypair.signing_pk) is True
        # Verify encrypted_details is stored
        row = vault.db.fetchone(
            "SELECT encrypted_details FROM audit_log WHERE id = ?", (record_id,)
        )
        assert row["encrypted_details"] is not None
        assert len(row["encrypted_details"]) > 0


# ============================================================
# 7. MCP BROKER (Spec 7.3)
# ============================================================


class TestMCPBroker:
    """Spec 7.3: Tier enforcement, approval flow, vault_list filtering."""

    def _create_tiered_entries(self, vault):
        """Helper: create entries with tiers 0, 1, and 2."""
        node_id = vault.create_node("MCP")
        # Tier 0 entry (without ai_read_secret)
        t0_id = vault.create_entry(
            node_id, "Tier0Entry",
            [{"key": "api_key", "value": "tier0_secret"}],
            tier=0,
        )
        # Tier 1 entry
        t1_id = vault.create_entry(
            node_id, "Tier1Entry",
            [{"key": "password", "value": "tier1_secret"}],
            tier=1,
            ai_read_secret=True,
        )
        # Tier 2 entry
        t2_id = vault.create_entry(
            node_id, "Tier2Entry",
            [{"key": "master_key", "value": "tier2_secret"}],
            tier=2,
        )
        return node_id, t0_id, t1_id, t2_id

    def test_tier0_without_ai_read_secret_denied(self, vault, broker):
        """Tier 0 without ai_read_secret flag should deny read_secret."""
        node_id, t0_id, _, _ = self._create_tiered_entries(vault)
        result = broker.vault_read("MCP/Tier0Entry", field="api_key")
        assert result["status"] == "denied"

    def test_tier0_with_ai_read_secret_returns_value(self, vault, broker):
        """Tier 0 with ai_read_secret=true should return the secret value."""
        node_id = vault.create_node("MCPAiRead")
        entry_id = vault.create_entry(
            node_id, "ReadableEntry",
            [{"key": "token", "value": "the_real_token"}],
            tier=0,
        )
        # Manually set ai_read_secret in the entry data
        # Since the broker reads from the entry dict, we patch the find_entry_by_path
        entry = vault.read_entry(entry_id)
        entry["ai_read_secret"] = True
        with patch.object(vault, "find_entry_by_path", return_value=entry):
            result = broker.vault_read("MCPAiRead/ReadableEntry", field="token")
        assert result["status"] == "ok"
        assert result["value"] == "the_real_token"

    def test_tier1_needs_approval(self, vault, broker, approval_mgr):
        """Tier 1 entry read should require approval (returns pending/timeout)."""
        node_id, _, t1_id, _ = self._create_tiered_entries(vault)
        # Run in thread with very short timeout to avoid blocking test
        import sezam.mcp.broker as broker_mod
        original_timeout = broker_mod.APPROVAL_TIMEOUT
        broker_mod.APPROVAL_TIMEOUT = 1  # 1 second timeout
        try:
            result = broker.vault_read("MCP/Tier1Entry", field="password")
            assert result["status"] == "timeout"
        finally:
            broker_mod.APPROVAL_TIMEOUT = original_timeout

    def test_tier1_approved_returns_value(self, vault, broker, approval_mgr):
        """Tier 1 entry read with approval should return the value."""
        node_id, _, t1_id, _ = self._create_tiered_entries(vault)
        import sezam.mcp.broker as broker_mod
        original_timeout = broker_mod.APPROVAL_TIMEOUT
        broker_mod.APPROVAL_TIMEOUT = 5
        try:
            # Auto-approve in a separate thread
            def auto_approve():
                time.sleep(0.3)
                pending = approval_mgr.get_pending()
                for req in pending:
                    approval_mgr.approve(req.request_id)

            t = threading.Thread(target=auto_approve)
            t.start()
            result = broker.vault_read("MCP/Tier1Entry", field="password")
            t.join(timeout=6)
            assert result["status"] == "ok"
            assert result["value"] == "tier1_secret"
        finally:
            broker_mod.APPROVAL_TIMEOUT = original_timeout

    def test_tier2_returns_not_found(self, vault, broker):
        """Tier 2 entries should pretend they don't exist."""
        node_id, _, _, t2_id = self._create_tiered_entries(vault)
        result = broker.vault_read("MCP/Tier2Entry", field="master_key")
        assert result["status"] == "not_found"

    def test_vault_list_tier2_invisible(self, vault, broker):
        """Tier 2 entries must not appear in vault_list results."""
        node_id, _, _, _ = self._create_tiered_entries(vault)
        listing = broker.vault_list("MCP")
        entry_names = [e["name"] for e in listing["entries"]]
        assert "Tier2Entry" not in entry_names
        # Tier 0 and 1 should be visible
        assert "Tier0Entry" in entry_names
        assert "Tier1Entry" in entry_names

    def test_vault_locked_raises_mcp_error(self, tmp_path):
        vault_path = tmp_path / "locked_mcp"
        v = Vault.create(str(vault_path), "pw", argon2_params=FAST_ARGON2)
        v.lock()
        broker = MCPBroker(v, ApprovalManager())
        with pytest.raises(MCPError):
            broker.vault_list()

    def test_vault_read_nonexistent_path(self, broker):
        result = broker.vault_read("nonexistent/path")
        assert result["status"] == "not_found"

    def test_vault_read_metadata_only(self, vault, broker):
        """Reading without field should return metadata (field keys, not values)."""
        node_id = vault.create_node("MetaOnly")
        vault.create_entry(
            node_id, "MetaEntry",
            [{"key": "username", "value": "secret_user"},
             {"key": "password", "value": "secret_pass"}],
            tier=0,
        )
        result = broker.vault_read("MetaOnly/MetaEntry")
        assert result["status"] == "ok"
        assert result["name"] == "MetaEntry"
        assert "username" in result["fields"]
        assert "password" in result["fields"]
        # Values should NOT be in the metadata response
        assert "secret_user" not in str(result)
        assert "secret_pass" not in str(result)

    def test_vault_read_nonexistent_field(self, vault, broker):
        node_id = vault.create_node("FieldNotFound")
        vault.create_entry(
            node_id, "FieldEntry",
            [{"key": "existing_key", "value": "val"}],
            tier=0,
        )
        entry = vault.read_entry(
            vault.list_entries(node_id)[0]["id"]
        )
        entry["ai_read_secret"] = True
        with patch.object(vault, "find_entry_by_path", return_value=entry):
            result = broker.vault_read("FieldNotFound/FieldEntry", field="missing_key")
        assert result["status"] == "not_found"


# ============================================================
# 8. APPROVAL MANAGER
# ============================================================


class TestApprovalManager:
    """Spec 7.3: Single-use, TTL, in-memory only."""

    def test_approval_single_use(self, approval_mgr):
        """Once consumed, approval cannot be used again."""
        req = approval_mgr.request_approval("req1", "/test", "read_secret")
        approval_mgr.approve("req1")
        # First consume
        assert approval_mgr.check_and_consume("req1") == "approved"
        # Second consume — should be not_found (already consumed)
        assert approval_mgr.check_and_consume("req1") == "not_found"

    def test_approval_expires_after_ttl(self):
        mgr = ApprovalManager(default_ttl=1)  # 1 second TTL
        mgr.request_approval("expiring", "/test", "read_secret")
        time.sleep(1.5)
        result = mgr.check_and_consume("expiring")
        assert result == "expired"

    def test_deny_request(self, approval_mgr):
        approval_mgr.request_approval("deny_me", "/test", "read_secret")
        approval_mgr.deny("deny_me")
        assert approval_mgr.check_and_consume("deny_me") == "denied"

    def test_pending_status(self, approval_mgr):
        approval_mgr.request_approval("pending_req", "/test", "read_secret")
        assert approval_mgr.check_and_consume("pending_req") == "pending"

    def test_not_found_request(self, approval_mgr):
        assert approval_mgr.check_and_consume("nonexistent") == "not_found"

    def test_approve_expired_request_fails(self):
        mgr = ApprovalManager(default_ttl=1)
        mgr.request_approval("expire_before_approve", "/test", "read_secret")
        time.sleep(1.5)
        assert mgr.approve("expire_before_approve") is False

    def test_approve_already_approved_fails(self, approval_mgr):
        approval_mgr.request_approval("double_approve", "/test", "read_secret")
        assert approval_mgr.approve("double_approve") is True
        # Second approve should fail (status is no longer "pending")
        assert approval_mgr.approve("double_approve") is False

    def test_get_pending_excludes_expired(self):
        mgr = ApprovalManager(default_ttl=1)
        mgr.request_approval("expire_soon", "/test", "read_secret")
        assert len(mgr.get_pending()) == 1
        time.sleep(1.5)
        assert len(mgr.get_pending()) == 0

    def test_clear_all(self, approval_mgr):
        approval_mgr.request_approval("r1", "/a", "read_secret")
        approval_mgr.request_approval("r2", "/b", "read_secret")
        approval_mgr.clear_all()
        assert len(approval_mgr.get_pending()) == 0

    def test_thread_safety(self, approval_mgr):
        """Concurrent approvals should not corrupt state."""
        errors = []

        def create_and_approve(i):
            try:
                rid = f"thread_{i}"
                approval_mgr.request_approval(rid, f"/path/{i}", "read_secret")
                approval_mgr.approve(rid)
                result = approval_mgr.check_and_consume(rid)
                if result != "approved":
                    errors.append(f"Thread {i}: expected 'approved', got '{result}'")
            except Exception as e:
                errors.append(f"Thread {i}: {e}")

        threads = [threading.Thread(target=create_and_approve, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == [], f"Thread safety errors: {errors}"


# ============================================================
# 9. PASSWORD GENERATION
# ============================================================


class TestPasswordGeneration:
    """Password generator: length, character classes, strength estimation."""

    def test_generated_password_has_requested_length(self):
        for length in [8, 12, 20, 30, 50]:
            pw = generate_password(length=length)
            assert len(pw) == length

    def test_generated_password_includes_lowercase(self):
        pw = generate_password(length=30, lowercase=True, uppercase=False, digits=False, symbols=False)
        assert all(c in LOWERCASE for c in pw)

    def test_generated_password_includes_uppercase(self):
        pw = generate_password(length=30, lowercase=False, uppercase=True, digits=False, symbols=False)
        assert all(c in UPPERCASE for c in pw)

    def test_generated_password_includes_digits(self):
        pw = generate_password(length=30, lowercase=False, uppercase=False, digits=True, symbols=False)
        assert all(c in DIGITS for c in pw)

    def test_generated_password_includes_symbols(self):
        pw = generate_password(length=30, lowercase=False, uppercase=False, digits=False, symbols=True)
        assert all(c in SYMBOLS for c in pw)

    def test_generated_password_includes_all_classes(self):
        pw = generate_password(length=20)
        assert any(c in LOWERCASE for c in pw)
        assert any(c in UPPERCASE for c in pw)
        assert any(c in DIGITS for c in pw)
        assert any(c in SYMBOLS for c in pw)

    def test_exclude_ambiguous(self):
        from sezam.password import AMBIGUOUS
        pw = generate_password(length=100, exclude_ambiguous=True)
        assert not any(c in AMBIGUOUS for c in pw)

    def test_no_charset_raises(self):
        with pytest.raises(ValueError):
            generate_password(lowercase=False, uppercase=False, digits=False, symbols=False)

    def test_strength_weak_password(self):
        result = estimate_strength("abc")
        assert result["score"] <= 1
        assert result["label"] in ("Very Weak", "Weak")

    def test_strength_strong_password(self):
        result = estimate_strength("Tr0ub4dor&3!@#LongP@ss")
        assert result["score"] >= 3
        assert "Strong" in result["label"]

    def test_strength_returns_entropy(self):
        result = estimate_strength("test")
        assert "entropy_bits" in result
        assert result["entropy_bits"] > 0

    def test_strength_empty_password(self):
        result = estimate_strength("")
        assert result["score"] == 0
        assert result["entropy_bits"] == 0

    def test_password_randomness(self):
        """Multiple generated passwords should differ."""
        passwords = set()
        for _ in range(50):
            passwords.add(generate_password(length=20))
        assert len(passwords) == 50

    def test_passphrase_generation(self):
        phrase = generate_passphrase(word_count=5, separator="-")
        words = phrase.split("-")
        assert len(words) == 5

    def test_passphrase_randomness(self):
        phrases = set()
        for _ in range(20):
            phrases.add(generate_passphrase(word_count=5))
        assert len(phrases) == 20

    def test_minimum_length_adjusted(self):
        """If length < required character classes, length should be adjusted up."""
        pw = generate_password(length=1)
        # With 4 required classes, length should be at least 4
        assert len(pw) >= 4


# ============================================================
# 10. TOTP
# ============================================================


class TestTOTP:
    """Spec 10.2: TOTP generation from base32-encoded seeds."""

    # RFC 6238 test vector (SHA1, base32 of "12345678901234567890")
    TEST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_totp_generates_6_digits(self):
        code = generate_totp(self.TEST_SECRET)
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_deterministic_for_same_time(self):
        """Same secret at the same time should give the same code."""
        code1 = generate_totp(self.TEST_SECRET)
        code2 = generate_totp(self.TEST_SECRET)
        # Within the same 30s window, both should match
        assert code1 == code2

    def test_time_remaining_in_range(self):
        remaining = time_remaining()
        assert 0 < remaining <= 30

    def test_totp_with_spaces_in_secret(self):
        """Secrets with spaces should be handled (stripped)."""
        code = generate_totp("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ")
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_lowercase_secret(self):
        """Lowercase secrets should work (case-insensitive base32)."""
        code = generate_totp("gezdgnbvgy3tqojqgezdgnbvgy3tqojq")
        assert len(code) == 6

    def test_totp_sha256(self):
        code = generate_totp(self.TEST_SECRET, algorithm="sha256")
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_sha512(self):
        code = generate_totp(self.TEST_SECRET, algorithm="sha512")
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_unsupported_algorithm(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            generate_totp(self.TEST_SECRET, algorithm="md5")


# ============================================================
# 11. MODELS
# ============================================================


class TestModels:
    """Data models: ULID, serialization, roundtrip."""

    def test_ulid_to_bytes_is_26_bytes(self):
        uid = new_ulid()
        b = ulid_to_bytes(uid)
        assert len(b) == 26

    def test_ulid_generation_uniqueness(self):
        ulids = [new_ulid() for _ in range(100)]
        assert len(set(ulids)) == 100

    def test_node_meta_json_roundtrip(self):
        meta = NodeMeta(name="TestNode", tier=1)
        data = meta.to_json()
        restored = NodeMeta.from_json(data)
        assert restored.name == "TestNode"
        assert restored.tier == 1

    def test_entry_meta_json_roundtrip(self):
        meta = EntryMeta(name="TestEntry", tier=0, tags=["prod", "critical"])
        data = meta.to_json()
        restored = EntryMeta.from_json(data)
        assert restored.name == "TestEntry"
        assert restored.tier == 0
        assert restored.tags == ["prod", "critical"]

    def test_entry_data_json_roundtrip(self):
        field = EntryField(key="password", value="secret", sensitive=True, sort_order=1)
        data = EntryData(fields=[field])
        serialized = data.to_json()
        restored = EntryData.from_json(serialized)
        assert len(restored.fields) == 1
        assert restored.fields[0].key == "password"
        assert restored.fields[0].value == "secret"
        assert restored.fields[0].sensitive is True

    def test_entry_data_get_field(self):
        data = EntryData(fields=[
            EntryField(key="user", value="admin"),
            EntryField(key="pass", value="secret"),
        ])
        assert data.get_field("user").value == "admin"
        assert data.get_field("pass").value == "secret"
        assert data.get_field("nonexistent") is None

    def test_node_meta_auto_timestamps(self):
        meta = NodeMeta(name="AutoTS")
        assert meta.created_at > 0
        assert meta.modified_at > 0

    def test_entry_meta_auto_timestamps(self):
        meta = EntryMeta(name="AutoTS")
        assert meta.created_at > 0
        assert meta.modified_at > 0


# ============================================================
# 12. ENVELOPE CRYPTO (NaCl crypto_box)
# ============================================================


class TestEnvelopeCrypto:
    """Spec 2.4: NaCl crypto_box for DEK sharing between users."""

    def test_create_and_open_envelope(self):
        from sezam.crypto.envelope_crypto import create_envelope, open_envelope
        sender = generate_keypair()
        recipient = generate_keypair()
        dek = os.urandom(32)

        envelope = create_envelope(dek, sender.encryption_sk, recipient.encryption_pk)
        recovered = open_envelope(envelope, recipient.encryption_sk, sender.encryption_pk)
        assert bytes(recovered) == dek

    def test_wrong_recipient_fails(self):
        from sezam.crypto.envelope_crypto import create_envelope, open_envelope
        sender = generate_keypair()
        recipient = generate_keypair()
        wrong_recipient = generate_keypair()
        dek = os.urandom(32)

        envelope = create_envelope(dek, sender.encryption_sk, recipient.encryption_pk)
        with pytest.raises(Exception):  # CryptoError
            open_envelope(envelope, wrong_recipient.encryption_sk, sender.encryption_pk)

    def test_wrong_sender_pk_fails(self):
        from sezam.crypto.envelope_crypto import create_envelope, open_envelope
        sender = generate_keypair()
        recipient = generate_keypair()
        fake_sender = generate_keypair()
        dek = os.urandom(32)

        envelope = create_envelope(dek, sender.encryption_sk, recipient.encryption_pk)
        with pytest.raises(Exception):  # CryptoError
            open_envelope(envelope, recipient.encryption_sk, fake_sender.encryption_pk)

    def test_envelope_returns_bytearray_for_zeroization(self):
        from sezam.crypto.envelope_crypto import create_envelope, open_envelope
        sender = generate_keypair()
        recipient = generate_keypair()
        dek = os.urandom(32)

        envelope = create_envelope(dek, sender.encryption_sk, recipient.encryption_pk)
        recovered = open_envelope(envelope, recipient.encryption_sk, sender.encryption_pk)
        assert isinstance(recovered, bytearray)

    def test_envelope_crypto_fingerprint(self):
        from sezam.crypto.envelope_crypto import compute_fingerprint as ec_fp
        kp = generate_keypair()
        assert ec_fp(kp.signing_pk, kp.encryption_pk) == kp.fingerprint


# ============================================================
# 13. SEARCH INDEX
# ============================================================


class TestSearchIndex:
    """Spec 5.2: In-memory FTS5, unicode61 with diacritics removal."""

    def test_search_finds_by_name(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "GitHub Login", ["user", "pass"], [])
        results = idx.search("GitHub")
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_search_finds_by_field_key(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "Entry", ["api_token"], [])
        results = idx.search("api_token")
        assert len(results) == 1

    def test_search_finds_by_tag(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "Entry", [], ["production"])
        results = idx.search("production")
        assert len(results) == 1

    def test_search_prefix_matching(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "GitHub Login", [], [])
        results = idx.search("Git")
        assert len(results) == 1

    def test_search_multi_token_and(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "GitHub Personal", [], [])
        idx.add_entry("e2", "n1", "path", "GitHub Work", [], [])
        idx.add_entry("e3", "n1", "path", "BitBucket Personal", [], [])
        results = idx.search("GitHub Personal")
        assert len(results) == 1
        assert results[0].entry_id == "e1"

    def test_search_empty_query(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "Entry", [], [])
        results = idx.search("")
        assert len(results) == 0

    def test_clear_destroys_index(self):
        idx = SearchIndex()
        idx.build()
        idx.add_entry("e1", "n1", "path", "Entry", [], [])
        idx.clear()
        results = idx.search("Entry")
        assert len(results) == 0


# ============================================================
# 14. SCHEMA INTEGRITY
# ============================================================


class TestSchemaIntegrity:
    """Verify SQLite schema matches spec expectations."""

    def test_schema_version_is_1(self):
        from sezam.vault.schema import SCHEMA_VERSION
        assert SCHEMA_VERSION == 1

    def test_all_tables_created(self, vault):
        tables = vault.db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        table_names = sorted([r["name"] for r in tables])
        expected = sorted([
            "access_envelopes", "audit_dag_edges", "audit_log",
            "dek_archive", "deks", "entries", "entry_history",
            "known_keys", "nodes", "vault_meta",
        ])
        for expected_table in expected:
            assert expected_table in table_names, f"Missing table: {expected_table}"

    def test_dek_scope_constraint(self, vault):
        """DEK scope must be one of: root, folder, tier2, share, audit."""
        with pytest.raises(Exception):
            vault.db.execute(
                "INSERT INTO deks (id, scope, encrypted_dek, version) VALUES (?, ?, ?, ?)",
                ("test_id", "invalid_scope", b"\x00", 1),
            )

    def test_nodes_have_dek_id_fk(self, vault):
        """nodes.dek_id should reference deks table."""
        # This is implicitly tested by the FK constraint being ON
        fk = vault.db.fetchone("PRAGMA foreign_keys")
        # foreign_keys pragma returns the current setting
        # Just verify we have DEKs linked to nodes
        rows = vault.db.fetchall("SELECT dek_id FROM nodes")
        for row in rows:
            assert row["dek_id"] is not None


# ============================================================
# 15. CROSS-CUTTING SECURITY INVARIANTS
# ============================================================


class TestSecurityInvariants:
    """Cross-cutting security checks across the system."""

    def test_no_plaintext_in_database(self, vault):
        """After creating an entry, no plaintext values should appear in raw DB."""
        node_id = vault.create_node("SecCheck")
        vault.create_entry(
            node_id, "SecretEntry",
            [{"key": "password", "value": "SUPER_SECRET_VALUE_12345"}],
        )
        # Read raw database content
        rows = vault.db.fetchall("SELECT encrypted_meta, encrypted_data FROM entries")
        for row in rows:
            raw_meta = row["encrypted_meta"]
            raw_data = row["encrypted_data"]
            # The plaintext should NOT appear in the raw blobs
            assert b"SUPER_SECRET_VALUE_12345" not in raw_meta
            assert b"SUPER_SECRET_VALUE_12345" not in raw_data

    def test_no_plaintext_name_in_node_meta(self, vault):
        node_id = vault.create_node("TopSecret_Node_Name_XYZ")
        row = vault.db.fetchone("SELECT encrypted_meta FROM nodes WHERE id = ?", (node_id,))
        assert b"TopSecret_Node_Name_XYZ" not in row["encrypted_meta"]

    def test_dek_never_stored_in_plaintext(self, vault):
        """Raw DEK values should never appear in the deks table."""
        rows = vault.db.fetchall("SELECT encrypted_dek FROM deks")
        for row in rows:
            blob = row["encrypted_dek"]
            # The blob is an AEAD envelope, not a raw 32-byte key
            assert len(blob) > 32 + TAG_SIZE  # Must be padded + encrypted

    def test_version_pinning_prevents_downgrade(self, vault):
        """Entry at version 2 should not decrypt with version 1 AAD."""
        node_id = vault.create_node("Downgrade")
        entry_id = vault.create_entry(
            node_id, "Versioned",
            [{"key": "k", "value": "v1"}],
        )
        vault.update_entry(entry_id, fields=[{"key": "k", "value": "v2"}])

        # Read the current encrypted blob at version 2
        row = vault.db.fetchone(
            "SELECT encrypted_data, version FROM entries WHERE id = ?", (entry_id,)
        )
        assert row["version"] == 2
        dek_id_str, dek_raw = vault.dek_mgr.get_dek_for_node(node_id)

        # Trying to decrypt v2 blob with version=1 should fail
        with pytest.raises(CryptoError):
            decrypt(row["encrypted_data"], dek_raw, ulid_to_bytes(entry_id), version=1)

    def test_lock_zeroizes_all_keys(self, tmp_path):
        """After lock(), all key material should be zeroed."""
        vault_path = tmp_path / "zeroize_vault"
        v = Vault.create(str(vault_path), "pw", argon2_params=FAST_ARGON2)

        # Get references before lock
        kp = v._keypair
        dek_mgr = v._dek_mgr
        kek_ref = dek_mgr._kek
        cached_deks = list(dek_mgr._dek_cache.values())

        v.lock()

        # KEK should be zeroed
        assert kek_ref == bytearray(32)
        # All cached DEKs should be zeroed
        for cached in cached_deks:
            assert cached == bytearray(32)
        # Keypair should be zeroed
        assert kp.signing_sk == bytearray(32)
        assert kp.encryption_sk == bytearray(32)


class TestCliSessionSecurity:
    """Spec §2.9: session secrets must use an OS credential store and fail closed."""

    @staticmethod
    def _fake_keyring(monkeypatch):
        stored = {}
        fake_keyring = types.SimpleNamespace(
            set_password=lambda service, account, password: stored.update(
                {(service, account): password}
            ),
            get_password=lambda service, account: stored.get((service, account)),
            delete_password=lambda service, account: stored.pop((service, account), None),
        )
        monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
        return stored

    def test_session_stores_only_expiring_kek_in_keyring(self, tmp_path, monkeypatch):
        stored = self._fake_keyring(monkeypatch)
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
        kek = bytearray(range(32))

        cli._save_session(kek, ttl_minutes=5)

        marker = cli._session_path().read_text(encoding="ascii")
        assert marker == "__keyring_v2__"
        record = json.loads(stored[("sezam", "session")])
        assert record["kek"] == kek.hex()
        assert record["expires_at"] <= time.time() + 5 * 60 + 1
        assert "password" not in record
        assert cli._load_session() == kek

    def test_expired_session_is_refused_and_wiped(self, tmp_path, monkeypatch):
        stored = self._fake_keyring(monkeypatch)
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
        cli._save_session(bytearray(32), ttl_minutes=1)
        record = json.loads(stored[("sezam", "session")])
        record["expires_at"] = time.time() - 1
        stored[("sezam", "session")] = json.dumps(record)

        assert cli._load_session() is None
        assert not cli._session_path().exists()
        assert ("sezam", "session") not in stored

    def test_legacy_raw_password_session_is_refused_and_wiped(self, tmp_path, monkeypatch):
        stored = self._fake_keyring(monkeypatch)
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
        stored[("sezam", "session")] = "correct horse battery staple"
        cli._session_path().write_text("__keyring__", encoding="ascii")

        assert cli._load_session() is None
        assert not cli._session_path().exists()
        assert ("sezam", "session") not in stored

    def test_session_for_other_vault_is_refused(self, tmp_path, monkeypatch):
        self._fake_keyring(monkeypatch)
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "a"))
        (tmp_path / "a").mkdir()
        cli._save_session(bytearray(32))
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / ".session").write_text("__keyring_v2__", encoding="ascii")
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "b"))

        assert cli._load_session() is None

    def test_keyring_failure_does_not_write_reversible_fallback(self, tmp_path, monkeypatch):
        def fail_to_store(*_args):
            raise RuntimeError("credential store unavailable")

        monkeypatch.setitem(
            sys.modules,
            "keyring",
            types.SimpleNamespace(set_password=fail_to_store),
        )
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
        cli._session_path().write_text("legacy-session-data")

        with pytest.raises(cli.click.ClickException, match="keyring is unavailable"):
            cli._save_session(bytearray(32))

        assert not cli._session_path().exists()

    def test_legacy_xor_session_is_rejected_and_removed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SEZAM_VAULT", str(tmp_path))
        cli._session_path().write_text("legacy-session-data")

        assert cli._load_session() is None
        assert not cli._session_path().exists()


class TestDeploymentScriptSecurity:
    """Tracked operational scripts must not embed credentials or trust unknown SSH hosts."""

    SCRIPTS = (
        "deploy_audit_rebuild.py",
        "deploy_shamir.py",
        "setup_demo.py",
        "test_e2e_real.py",
        "test_multiuser_e2e.py",
        "test_stress.py",
    )

    def test_tracked_scripts_require_known_ssh_hosts_and_external_credentials(self):
        scripts_dir = Path(__file__).parents[1] / "scripts"

        for script_name in self.SCRIPTS:
            tree = ast.parse((scripts_dir / script_name).read_text(encoding="utf-8"))
            attributes = {
                node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
            }

            assert "AutoAddPolicy" not in attributes, script_name
            assert "RejectPolicy" in attributes, script_name
            assert "load_system_host_keys" in attributes, script_name

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and (
                            target.id == "PASSWORD"
                            or target.id.endswith("_PASSWORD")
                            or target.id.endswith("_PASS")
                        ):
                            assert not isinstance(node.value.value, str) or not node.value.value, (
                                script_name,
                                target.id,
                            )

                if isinstance(node, ast.Dict):
                    fields = {
                        key.value: value
                        for key, value in zip(node.keys, node.values)
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                    }
                    if (
                        isinstance(fields.get("key"), ast.Constant)
                        and fields["key"].value == "password"
                        and isinstance(fields.get("value"), ast.Constant)
                    ):
                        pytest.fail(f"{script_name} embeds credential-like demo data")

                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and "mysql" in node.value
                    and "-p" in node.value
                ):
                    assert "$MYSQL_PASSWORD" in node.value, script_name


class TestImplementationChecklist:
    """Spec §13 must remain evidence-based release-readiness state."""

    @staticmethod
    def _checklist_section() -> str:
        spec = (Path(__file__).parents[1] / "SEZAM_SPEC_v15_FINAL.md").read_text(encoding="utf-8")
        return spec.split("## 13. Fázy implementácie", 1)[1].split("## 14.", 1)[0]

    def test_checklist_uses_verified_complete_partial_and_open_states(self):
        section = self._checklist_section()

        assert "Stav overený proti repozitáru 2026-07-22" in section
        assert section.count("- [x]") == 54
        assert section.count("- [~]") == 4
        assert section.count("- [ ]") == 4

        for completed in (
            "PySide6: systray, hotkey, tree, search, detail, clipboard countdown",
            "FastAPI + MariaDB (content-blind blob store)",
            "Flutter projekt (Android + iOS)",
            "MCP broker (žiadny raw DEK pre MCP)",
            "Watchtower (slabé/duplicitné heslá)",
        ):
            assert f"- [x] {completed}" in section

        for partial in (
            "TOTP: seed v `encrypted_data`",
            "Secure Share: vytváranie je zapojené v UI",
            "`vault_use`: TOTP + whitelist + approval sú hotové",
            "Accessibility: čiastkové ARIA/semantické prvky existujú",
        ):
            assert f"- [~] {partial}" in section

        for unfinished in (
            "Push notifikácie pre approval requesty (MCP tier 1)",
            "MCP audit",
            "Biometria desktop/web (Windows Hello, Web Authentication API)",
            "Attachments (SSH kľúče, certifikáty ako súbory)",
        ):
            assert f"- [ ] {unfinished}" in section

    def test_every_phase_has_repository_evidence_and_no_stale_test_total(self):
        section = self._checklist_section()
        assert section.count("Dôkazy:") + section.count("Dôkazy hotových bodov:") == 6
        assert "68 testov" not in section
