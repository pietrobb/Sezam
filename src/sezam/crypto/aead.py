"""AEAD encryption using libsodium crypto_aead_xchacha20poly1305_ietf.

Spec 2.5/2.6: Ciphertext envelope format with native AAD support.

Envelope layout:
┌─────────────────────────────────────────────────────┐
│ HEADER (plain text, authenticated via AAD)           │
│   alg: u8              (1 = xchacha20poly1305_ietf)  │
│   schema_version: u8                                 │
│   blob_kind: u8        (1–7)                         │
│   dek_id: 26 bytes     (ULID)                        │
│   nonce: 24 bytes      (os.urandom(24))              │
├─────────────────────────────────────────────────────┤
│ AEAD OUTPUT                                          │
│   ciphertext + tag (16 bytes Poly1305 appended)      │
│   (plaintext = padding_len:u16 + padding + data)     │
└─────────────────────────────────────────────────────┘

AAD = alg(1B) || schema_version(1B) || blob_kind(1B) || dek_id(26B)
      || object_id(26B) || u32be(version)(4B)
    = 59 bytes fixed

blob_kind values:
  1 = node_meta
  2 = entry_meta
  3 = entry_data
  4 = history_snapshot
  5 = audit_details
  6 = dek_wrap
  7 = keypair_wrap
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

import nacl.bindings

from .padding import pad, unpad


class BlobKind(IntEnum):
    NODE_META = 1
    ENTRY_META = 2
    ENTRY_DATA = 3
    HISTORY_SNAPSHOT = 4
    AUDIT_DETAILS = 5
    DEK_WRAP = 6
    KEYPAIR_WRAP = 7


ALG_XCHACHA20POLY1305 = 1
SCHEMA_VERSION = 1
HEADER_SIZE = 1 + 1 + 1 + 26 + 24  # 53 bytes
NONCE_SIZE = 24
TAG_SIZE = 16
DEK_ID_SIZE = 26


@dataclass
class Envelope:
    """Parsed ciphertext envelope."""

    alg: int
    schema_version: int
    blob_kind: int
    dek_id: bytes  # 26 bytes (ULID as raw bytes)
    nonce: bytes  # 24 bytes
    ciphertext_with_tag: bytes  # variable + 16 bytes tag


def build_aad(
    alg: int,
    schema_version: int,
    blob_kind: int,
    dek_id: bytes,
    object_id: bytes,
    version: int,
) -> bytes:
    """Canonical AAD (59 bytes, spec 2.6) from the core (docs/CORE_UNIFICATION.md
    U6): alg || schema_version || blob_kind || dek_id(26) || object_id(26) ||
    u32be(version). A version the u32 does not hold exactly is refused.
    """
    from ..vault import sync_core

    for name, raw in (("dek_id", dek_id), ("object_id", object_id)):
        if len(raw) != DEK_ID_SIZE:
            raise ValueError(f"{name} must be {DEK_ID_SIZE} bytes, got {len(raw)}")
    return bytes.fromhex(sync_core.call(
        "aad", alg=alg, schema_version=schema_version, blob_kind=int(blob_kind), dek_id=_id_text(dek_id),
        object_id=_id_text(object_id), version=version,
    ))


def _id_text(raw: bytes) -> str:
    """A 26-byte NUL-padded id as the core takes it; the core refuses one it
    would not write back byte for byte (a NUL inside)."""
    try:
        return bytes(raw).rstrip(b"\x00").decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("an id is ASCII") from None


def encrypt(
    plaintext: bytes,
    dek: bytes | bytearray,
    dek_id: bytes,
    object_id: bytes,
    version: int,
    blob_kind: BlobKind,
    enable_padding: bool = True,
) -> bytes:
    """Encrypt plaintext into a complete envelope blob.

    Args:
        plaintext: Data to encrypt.
        dek: 32-byte DEK.
        dek_id: 26-byte ULID of the DEK.
        object_id: 26-byte ULID of the object being encrypted.
        version: Object version (for AAD binding).
        blob_kind: Type of blob (1-7).
        enable_padding: Whether to pad plaintext (default True).

    Returns:
        Complete envelope: header + ciphertext_with_tag.
    """
    nonce = os.urandom(NONCE_SIZE)
    aad = build_aad(
        ALG_XCHACHA20POLY1305, SCHEMA_VERSION, blob_kind, dek_id, object_id, version
    )

    if enable_padding:
        padded = pad(plaintext)
    else:
        padded = plaintext

    ciphertext_with_tag = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        padded, aad, nonce, bytes(dek)
    )

    # Build envelope: header + ciphertext
    header = (
        struct.pack("BBB", ALG_XCHACHA20POLY1305, SCHEMA_VERSION, blob_kind)
        + dek_id
        + nonce
    )
    return header + ciphertext_with_tag


def decrypt(
    envelope_blob: bytes,
    dek: bytes | bytearray,
    object_id: bytes,
    version: int,
    enable_padding: bool = True,
    expected_blob_kind: Optional[int] = None,
) -> bytes:
    """Decrypt an envelope blob.

    Args:
        envelope_blob: Complete envelope (header + ciphertext_with_tag).
        dek: 32-byte DEK.
        object_id: 26-byte ULID from DB record (not from envelope).
        version: Object version from DB record (not from envelope).
        enable_padding: Whether plaintext was padded.
        expected_blob_kind: Kind the caller is about to parse. The header
            kind is authenticated, but blobs of one object (meta vs data)
            share object_id/version/DEK, so a swap is only caught here.

    Returns:
        Decrypted plaintext.

    Raises:
        nacl.exceptions.CryptoError: If AAD mismatch or tampered data.
        ValueError: If the blob is not of the expected kind.
    """
    env = parse_envelope(envelope_blob)
    if expected_blob_kind is not None and env.blob_kind != int(expected_blob_kind):
        raise ValueError(
            f"Unexpected blob kind {env.blob_kind} (expected {int(expected_blob_kind)})"
        )

    aad = build_aad(
        env.alg, env.schema_version, env.blob_kind, env.dek_id, object_id, version
    )

    padded = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        env.ciphertext_with_tag, aad, env.nonce, bytes(dek)
    )

    if enable_padding:
        return unpad(padded)
    return padded


def parse_envelope(blob: bytes) -> Envelope:
    """Parse envelope header from blob."""
    if len(blob) < HEADER_SIZE + TAG_SIZE:
        raise ValueError(
            f"Envelope too short: {len(blob)} bytes, "
            f"minimum {HEADER_SIZE + TAG_SIZE}"
        )
    alg, schema_version, blob_kind = struct.unpack("BBB", blob[:3])
    dek_id = blob[3:29]
    nonce = blob[29:53]
    ciphertext_with_tag = blob[53:]
    return Envelope(
        alg=alg,
        schema_version=schema_version,
        blob_kind=blob_kind,
        dek_id=dek_id,
        nonce=nonce,
        ciphertext_with_tag=ciphertext_with_tag,
    )


def encrypt_dek_wrap(
    dek_to_wrap: bytes | bytearray,
    wrapping_key: bytes | bytearray,
    wrapping_key_id: bytes,
    dek_archive_id: bytes,
    version: int = 1,
) -> bytes:
    """Wrap a DEK with another key (KEK or new DEK for archive).

    Uses blob_kind=6 (dek_wrap).
    """
    return encrypt(
        plaintext=bytes(dek_to_wrap),
        dek=wrapping_key,
        dek_id=wrapping_key_id,
        object_id=dek_archive_id,
        version=version,
        blob_kind=BlobKind.DEK_WRAP,
        enable_padding=True,  # Spec: padding default ON for all blob kinds
    )


def decrypt_dek_wrap(
    envelope_blob: bytes,
    wrapping_key: bytes | bytearray,
    dek_archive_id: bytes,
    version: int = 1,
) -> bytearray:
    """Unwrap a DEK from an envelope.

    Returns bytearray for zeroization.
    """
    raw = decrypt(
        envelope_blob=envelope_blob,
        dek=wrapping_key,
        object_id=dek_archive_id,
        version=version,
        enable_padding=True,
        expected_blob_kind=BlobKind.DEK_WRAP,
    )
    return bytearray(raw)


# Capability run 269: the keypair wrap binds no epoch, so every pre-anchor
# bundle a server kept opens again under a password that opened it then. The
# anchored bundle records each such password state as salt + Argon2 params +
# a hash of its KEK; no client may move the account back to one of them.
PRE_ANCHOR_ENTRY_LEN = 60  # salt(16) || time u32be || memory u32be || lanes u32be || check(32)
PRE_ANCHOR_MAX = 8
_PRE_ANCHOR_LABEL = b"sezam-pre-anchor-kek-v1"


def pre_anchor_check(kek: bytes | bytearray) -> bytes:
    import hashlib

    return hashlib.sha256(_PRE_ANCHOR_LABEL + bytes(kek)).digest()


def _core(op: str, **args):
    from ..vault import sync_core

    return sync_core.call(op, **args)


def parse_pre_anchor(blob: bytes) -> list[tuple[bytes, int, int, int, bytes]]:
    """``count u8 || entries`` -> [(salt, time_cost, memory_cost, parallelism, check)]
    (the core's rule, docs/CORE_UNIFICATION.md U6)."""
    return [
        (bytes.fromhex(e["salt"]), e["time_cost"], e["memory_cost"], e["parallelism"],
         bytes.fromhex(e["check"]))
        for e in _core("pre_anchor_parse", blob=bytes(blob).hex())
    ]


def merge_pre_anchor(kept: bytes, other: bytes) -> bytes:
    """``kept`` plus the states only ``other`` records, newest last, at most PRE_ANCHOR_MAX."""
    merged = _core("pre_anchor_merge", kept=bytes(kept).hex(), other=bytes(other).hex())
    return bytes.fromhex(merged) if merged else b""


def add_pre_anchor(blob: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int,
                   kek: bytes | bytearray) -> bytes:
    """``blob`` plus the password state (salt, params, KEK)."""
    return bytes.fromhex(_core(
        "pre_anchor_add", blob=bytes(blob).hex(), salt=bytes(salt).hex(), time_cost=time_cost,
        memory_cost=memory_cost, parallelism=parallelism, check=pre_anchor_check(kek).hex(),
    ))


def password_reopens_pre_anchor(password: str, blob: bytes) -> bool:
    """Does ``password`` (any of its KDF forms) derive a recorded pre-anchor KEK?"""
    from hmac import compare_digest

    from .kdf import Argon2Params, derive_kek, password_forms

    for salt, time_cost, memory_cost, parallelism, check in parse_pre_anchor(blob):
        params = Argon2Params(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)
        for form in password_forms(password):
            kek = derive_kek(form, salt, params, exact=True)
            try:
                if compare_digest(pre_anchor_check(kek), check):
                    return True
            finally:
                kek[:] = bytes(len(kek))
    return False


def encode_account_keypair(keypair_data: bytes | bytearray, confirmed_genesis: str,
                           pre_anchor: bytes = b"") -> bytearray:
    """SZACCT01 || signing_seed(32) || encryption_sk(32) || confirmed genesis(32).

    With recorded pre-anchor password states: SZACCT02 || the same || states.
    Callers must establish trust independently before publishing this bundle.
    The outer KEYPAIR_WRAP authenticates the canonical account ID and KEK.
    """
    if len(keypair_data) not in (64, 96):
        raise ValueError("Invalid account keypair private keys")
    if not isinstance(confirmed_genesis, str):
        raise ValueError("Invalid account keypair confirmed genesis")
    parts = _core("account_bundle_encode", confirmed_genesis=confirmed_genesis,
                  pre_anchor=bytes(pre_anchor).hex())
    keys, _ = decode_account_keypair(keypair_data)
    try:
        return bytearray.fromhex(parts["version"]) + keys + bytes.fromhex(parts["tail"])
    finally:
        keys[:] = bytes(len(keys))


def decode_account_bundle(payload: bytes | bytearray) -> tuple[bytearray, Optional[str], bytes]:
    """(keys, genesis, pre-anchor states). Legacy keys are explicitly unanchored;
    unknown bundles never downgrade (the core's rule; the keys stay here)."""
    whole = len(payload) >= 104
    kind = _core(
        "account_bundle_decode", length=len(payload),
        version=bytes(payload[:8]).hex() if whole else None,
        tail=bytes(payload[72:]).hex() if whole else None,
    )
    states = bytes.fromhex(kind["pre_anchor"]) if kind["pre_anchor"] else b""
    if kind["kind"] in ("anchored", "v1"):
        return bytearray(payload[8:72]), kind["confirmed_genesis"], states
    if kind["kind"] == "legacy64":
        return bytearray(payload), None, b""
    from nacl.signing import SigningKey

    if bytes(SigningKey(bytes(payload[:32])).verify_key) != payload[32:64]:
        raise ValueError("Invalid account keypair public key")
    return bytearray(payload[:32] + payload[64:]), None, b""


def decode_account_keypair(payload: bytes | bytearray) -> tuple[bytearray, Optional[str]]:
    keys, genesis, _ = decode_account_bundle(payload)
    return keys, genesis


def encrypt_account_keypair(keypair_data, confirmed_genesis, kek, kek_dek_id, user_object_id,
                            pre_anchor: bytes = b"") -> bytes:
    if any(not re.fullmatch(rb"[0-9A-HJKMNP-TV-Z]{26}", value) for value in (kek_dek_id, user_object_id)):
        raise ValueError("Invalid account keypair ID")
    payload = encode_account_keypair(keypair_data, confirmed_genesis, pre_anchor)
    try:
        return encrypt_keypair_wrap(payload, kek, kek_dek_id, user_object_id)
    finally:
        payload[:] = bytes(len(payload))


def decrypt_account_keypair(envelope_blob, kek, user_object_id) -> tuple[bytearray, Optional[str]]:
    keys, genesis, _ = decrypt_account_bundle(envelope_blob, kek, user_object_id)
    return keys, genesis


def decrypt_account_bundle(envelope_blob, kek, user_object_id) -> tuple[bytearray, Optional[str], bytes]:
    env = parse_envelope(envelope_blob)
    if (env.alg != ALG_XCHACHA20POLY1305 or env.schema_version != SCHEMA_VERSION
            or env.blob_kind != BlobKind.KEYPAIR_WRAP
            or any(not re.fullmatch(rb"[0-9A-HJKMNP-TV-Z]{26}", value)
                   for value in (env.dek_id, user_object_id))):
        raise ValueError("Invalid account keypair envelope")
    payload = decrypt_keypair_wrap(envelope_blob, kek, user_object_id)
    try:
        return decode_account_bundle(payload)
    finally:
        payload[:] = bytes(len(payload))


def encrypt_keypair_wrap(
    keypair_data: bytes | bytearray,
    kek: bytes | bytearray,
    kek_dek_id: bytes,
    user_object_id: bytes,
    version: int = 1,
) -> bytes:
    """Wrap keypair (signing_sk + encryption_sk = 64 bytes) with KEK.

    Uses blob_kind=7 (keypair_wrap).
    """
    return encrypt(
        plaintext=bytes(keypair_data),
        dek=kek,
        dek_id=kek_dek_id,
        object_id=user_object_id,
        version=version,
        blob_kind=BlobKind.KEYPAIR_WRAP,
        enable_padding=True,  # Spec: padding default ON for all blob kinds
    )


def decrypt_keypair_wrap(
    envelope_blob: bytes,
    kek: bytes | bytearray,
    user_object_id: bytes,
    version: int = 1,
) -> bytearray:
    """Unwrap keypair from envelope. Returns bytearray for zeroization."""
    raw = decrypt(
        envelope_blob=envelope_blob,
        dek=kek,
        object_id=user_object_id,
        version=version,
        enable_padding=True,
        expected_blob_kind=BlobKind.KEYPAIR_WRAP,
    )
    return bytearray(raw)
