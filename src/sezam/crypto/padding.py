"""Padding utilities for ciphertext size obfuscation.

Spec 2.6: min 32B, rounded to next power of 2, fill = os.urandom() (random, not zero).
padding_length is stored as u16be prefix inside plaintext (before encryption).
"""

from __future__ import annotations

import os
import struct

def padded_size(n: int) -> int:
    """Size a padded blob of n bytes takes (spec 2.6, review 18c300f R16-L3):
    the core's rule (docs/CORE_UNIFICATION.md U6)."""
    from ..vault import sync_core

    return sync_core.call("padded_size", n=n)


def pad_json(data: bytes) -> bytes:
    """A JSON text padded with trailing spaces to padded_size: for blobs read
    as JSON without the u16 prefix (share links), which every JSON parser
    reads as before."""
    return data + b" " * (padded_size(len(data)) - len(data))


def pad(data: bytes) -> bytes:
    """Pad data before encryption.

    Format: u16be(padding_len) + random_padding_bytes + actual_data
    Total padded size is padded_size(2 + len(data)).
    """
    raw_total = 2 + len(data)
    padding_len = padded_size(raw_total) - raw_total

    padding_bytes = os.urandom(padding_len) if padding_len > 0 else b""
    return struct.pack(">H", padding_len) + padding_bytes + data


def unpad(padded: bytes) -> bytes:
    """Remove padding after decryption.

    Reads u16be padding_len prefix, skips padding, returns actual data.
    """
    if len(padded) < 2:
        raise ValueError("Padded data too short")
    padding_len = struct.unpack(">H", padded[:2])[0]
    data_start = 2 + padding_len
    if data_start > len(padded):
        raise ValueError("Invalid padding length")
    return padded[data_start:]
