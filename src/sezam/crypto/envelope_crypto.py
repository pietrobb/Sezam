"""Envelope encryption — NaCl crypto_box for multi-user DEK sharing.

Spec 2.4: crypto_box (authenticated, not crypto_box_seal).
Admin is always sender. Recipient's encryption_pk is used.

Also includes TOFU key cache management.
"""

from __future__ import annotations

import hashlib

from nacl.public import Box, PrivateKey, PublicKey



def create_envelope(
    dek: bytes | bytearray,
    sender_sk: bytes | bytearray,
    recipient_pk: bytes,
) -> bytes:
    """Wrap a DEK for a recipient using NaCl crypto_box (authenticated).

    Args:
        dek: 32-byte DEK to share.
        sender_sk: Sender's X25519 private key (admin).
        recipient_pk: Recipient's X25519 public key.

    Returns:
        Encrypted envelope (nonce + ciphertext).
    """
    box = Box(PrivateKey(bytes(sender_sk)), PublicKey(recipient_pk))
    return box.encrypt(bytes(dek))  # Returns nonce + ciphertext


def open_envelope(
    encrypted_dek: bytes,
    recipient_sk: bytes | bytearray,
    sender_pk: bytes,
) -> bytearray:
    """Open an envelope to get the DEK.

    Args:
        encrypted_dek: Encrypted envelope (nonce + ciphertext).
        recipient_sk: Recipient's X25519 private key.
        sender_pk: Sender's X25519 public key (for authentication).

    Returns:
        Decrypted DEK as bytearray (for zeroization).
    """
    box = Box(PrivateKey(bytes(recipient_sk)), PublicKey(sender_pk))
    return bytearray(box.decrypt(encrypted_dek))


def compute_fingerprint(signing_pk: bytes, encryption_pk: bytes) -> str:
    """Compute key fingerprint: SHA-256(signing_pk || encryption_pk)."""
    return hashlib.sha256(signing_pk + encryption_pk).hexdigest()
