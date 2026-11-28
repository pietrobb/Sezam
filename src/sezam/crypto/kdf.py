"""Argon2id Key Derivation Function for master password → KEK.

Spec 2.3/2.5: Argon2id with configurable params.
Default: time=3, mem=256MB, par=4, salt=16B, output=32B (256-bit KEK).
"""

from __future__ import annotations

import os
import time
import unicodedata
from dataclasses import dataclass

import argon2
from argon2.exceptions import HashingError


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id parameters (stored in vault_meta, plain text — needed before unlock)."""

    time_cost: int = 3
    memory_cost: int = 262144  # 256 MB in KiB
    parallelism: int = 4
    salt_len: int = 16
    hash_len: int = 64  # 32B KEK + 32B auth_proof

    def to_dict(self) -> dict:
        return {
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "salt_len": self.salt_len,
            "hash_len": self.hash_len,
        }

    def account_dict(self) -> dict:
        """Per-account params sent to the server with the keypair upload."""
        return {
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": 64,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Argon2Params:
        return cls(
            time_cost=d["time_cost"],
            memory_cost=d["memory_cost"],
            parallelism=d["parallelism"],
            salt_len=d.get("salt_len", 16),
            hash_len=64,  # Always 64B for server/web compatibility
        )

    # Mobile fallback profile
    MOBILE_PROFILE = None  # Will be set below


Argon2Params.MOBILE_PROFILE = Argon2Params(time_cost=2, memory_cost=131072)  # 128MB


def _derive_material(password: str, salt: bytes, params: Argon2Params) -> bytearray:
    """Derive directly into mutable memory so no immutable key copy is created."""
    output = bytearray(64)
    password_buffer = bytearray(password, "utf-8")
    ffi = argon2.low_level.ffi
    lib = argon2.low_level.lib
    output_ptr = ffi.from_buffer("uint8_t[]", output)
    password_ptr = (
        ffi.from_buffer("uint8_t[]", password_buffer) if password_buffer else ffi.NULL
    )
    salt_ptr = ffi.new("uint8_t[]", salt)
    context = ffi.new(
        "argon2_context *",
        {
            "out": output_ptr,
            "outlen": len(output),
            "pwd": password_ptr,
            "pwdlen": len(password_buffer),
            "salt": salt_ptr,
            "saltlen": len(salt),
            "secret": ffi.NULL,
            "secretlen": 0,
            "ad": ffi.NULL,
            "adlen": 0,
            "t_cost": params.time_cost,
            "m_cost": params.memory_cost,
            "lanes": params.parallelism,
            "threads": params.parallelism,
            "version": argon2.low_level.ARGON2_VERSION,
            "allocate_cbk": ffi.NULL,
            "free_cbk": ffi.NULL,
            "flags": lib.ARGON2_FLAG_CLEAR_PASSWORD,
        },
    )
    try:
        result = argon2.low_level.core(context, argon2.low_level.Type.ID.value)
        if result != lib.ARGON2_OK:
            raise HashingError(argon2.low_level.error_to_str(result))
        return output
    except Exception:
        output[:] = b"\x00" * len(output)
        raise
    finally:
        password_buffer[:] = b"\x00" * len(password_buffer)


def canonical_password(password: str) -> str:
    """The KDF input for a master password: Unicode NFC (lockout review M8).

    The same visible password can arrive as different code points (an
    accented letter precomposed or as letter + combining mark, depending on
    keyboard, OS or paste). Desktop, web and mobile all derive from NFC so
    the password opens the account on every client.
    """
    return unicodedata.normalize("NFC", password)


def password_forms(password: str) -> list[str]:
    """KDF inputs to try for an EXISTING password, canonical first.

    An account or vault created before normalization derived from the
    password exactly as typed then; it may also have been typed decomposed.
    Verification therefore falls back to the typed and the NFD form when
    they differ from NFC. New passwords use canonical_password only.
    """
    forms: list[str] = []
    for form in (canonical_password(password), password, unicodedata.normalize("NFD", password)):
        if form not in forms:
            forms.append(form)
    return forms


def derive_kek(
    password: str, salt: bytes, params: Argon2Params, *, exact: bool = False
) -> bytearray:
    """Derive a mutable 32-byte KEK from one 64-byte Argon2id run.

    The password is normalized to NFC unless ``exact`` (one of
    password_forms, for accounts from before normalization).
    """
    if not exact:
        password = canonical_password(password)
    material = _derive_material(password, salt, params)
    try:
        return material[:32]
    finally:
        material[:] = b"\x00" * len(material)


def derive_kek_and_proof(
    password: str, salt: bytes, params: Argon2Params, *, exact: bool = False
) -> tuple[bytearray, bytearray]:
    """Derive mutable KEK and auth-proof buffers from one Argon2id run (NFC, see derive_kek)."""
    if not exact:
        password = canonical_password(password)
    material = _derive_material(password, salt, params)
    try:
        return material[:32], material[32:]
    finally:
        material[:] = b"\x00" * len(material)


def generate_salt(length: int = 16) -> bytes:
    """Generate cryptographically random salt."""
    return os.urandom(length)


def benchmark_argon2(
    target_seconds: float = 1.0,
    parallelism: int = 4,
) -> Argon2Params:
    """Benchmark Argon2id to find parameters that take ~target_seconds on this HW.

    Starts with mem=256MB, time=3 and adjusts.
    """
    test_password = "benchmark_test_password"
    test_salt = os.urandom(16)

    # Try default params first
    params = Argon2Params(time_cost=3, memory_cost=262144, parallelism=parallelism)
    elapsed = _time_kdf(test_password, test_salt, params)

    if elapsed < target_seconds * 0.5:
        # Too fast — increase time_cost
        while elapsed < target_seconds * 0.8:
            params = Argon2Params(
                time_cost=params.time_cost + 1,
                memory_cost=params.memory_cost,
                parallelism=parallelism,
            )
            elapsed = _time_kdf(test_password, test_salt, params)
            if params.time_cost >= 20:
                break
    elif elapsed > target_seconds * 2.0:
        # Too slow — decrease memory
        while elapsed > target_seconds * 1.5 and params.memory_cost > 65536:
            params = Argon2Params(
                time_cost=params.time_cost,
                memory_cost=params.memory_cost // 2,
                parallelism=parallelism,
            )
            elapsed = _time_kdf(test_password, test_salt, params)

    return params


def _time_kdf(password: str, salt: bytes, params: Argon2Params) -> float:
    """Time a single KDF derivation."""
    start = time.perf_counter()
    derive_kek(password, salt, params)
    return time.perf_counter() - start
