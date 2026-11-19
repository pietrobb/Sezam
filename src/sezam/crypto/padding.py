"""Padding utilities for ciphertext size obfuscation.

Spec 2.6: min 32B, rounded to next power of 2, fill = os.urandom() (random, not zero).
padding_length is stored as u16be prefix inside plaintext (before encryption).
"""

from __future__ import annotations

import os
import struct

MAX_PADDING = 0xFFFF


def pad(data: bytes) -> bytes:
    """Pad data before encryption.

    Format: u16be(padding_len) + random_padding_bytes + actual_data
    Total padded size is rounded up to next power of 2, minimum 32 bytes.
    """
    # Minimum total size = 32 bytes (including the 2-byte length prefix)
    min_total = 32
    # Calculate minimum required: 2 (length prefix) + data
    raw_total = 2 + len(data)

    # Round up to next power of 2, minimum 32
    target = max(min_total, _next_power_of_2(raw_total))

    # The u16 prefix caps padding at 0xFFFF; above that the target is no
    # longer a power of two, but the format stays readable by every client.
    padding_len = min(max(target - 2 - len(data), 0), MAX_PADDING)

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


def _next_power_of_2(n: int) -> int:
    """Return the smallest power of 2 >= n."""
    if n <= 0:
        return 1
    n -= 1
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    n |= n >> 32
    return n + 1
