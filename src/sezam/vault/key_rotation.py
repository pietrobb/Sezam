"""Pending key-rotation journal (review 2052248, finding 1).

A password/KEK rotation reaches the server as ONE push: the DEK rewrap batch,
the key_epoch advance and the new key material (encrypted keypair, salts, KDF
params, auth proof) are applied in a single server transaction. The local
change commits first, so until that push is accepted the vault keeps a journal
with what the push needs and cannot recompute: the auth proof, which only the
password yields. It is stored sealed under the new KEK (whoever holds the KEK
already holds everything the proof protects).
"""

from __future__ import annotations

import hashlib
import hmac
import os

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

_KEY_CONTEXT = b"sezam/pending-key-rotation/v1"
_NONCE_LEN = 24


def _journal_key(kek: bytes) -> bytes:
    return hmac.new(bytes(kek), _KEY_CONTEXT, hashlib.sha256).digest()


def _aad(user_id: str, epoch: int) -> bytes:
    return _KEY_CONTEXT + user_id.encode("utf-8") + epoch.to_bytes(8, "big")


def _seal(kek: bytes, aad: bytes, secret: bytes) -> str:
    nonce = os.urandom(_NONCE_LEN)
    sealed = crypto_aead_xchacha20poly1305_ietf_encrypt(
        bytes(secret), aad, nonce, _journal_key(kek)
    )
    return (nonce + sealed).hex()


def _open(kek: bytes, aad: bytes, sealed_hex: str) -> bytearray:
    blob = bytes.fromhex(sealed_hex)
    return bytearray(crypto_aead_xchacha20poly1305_ietf_decrypt(
        blob[_NONCE_LEN:], aad, blob[:_NONCE_LEN], _journal_key(kek),
    ))


_ORG_RECOVERY_AAD = b"sezam-org-recovery-v1"


def org_recovery_server_wrap(kek: bytes, recovery_secret: bytes) -> bytes:
    """The server's org recovery blob in the web format: nonce(24) ||
    XChaCha20-Poly1305(KEK) under the 32-byte Shamir recovery secret, so the
    same shares work in the web vault (review e4cd15a #1)."""
    nonce = os.urandom(_NONCE_LEN)
    return nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(
        bytes(kek), _ORG_RECOVERY_AAD, nonce, bytes(recovery_secret)
    )


def org_recovery_signing_key(recovery_secret: bytes):
    """Ed25519 key the server knows the recovery by; the web derives the same
    one (crypto_sign_seed_keypair of the recovery secret)."""
    from nacl.signing import SigningKey

    return SigningKey(bytes(recovery_secret))


def org_recovery_rewrap_message(
    user_id: str, key_epoch: int, threshold: int, total_shares: int, wrapped_kek: bytes,
) -> bytes:
    """Signed by the recovery key to re-store its server blob without the
    password (review d615826; server: routers.recovery, same bytes)."""
    import hashlib

    return (
        b"sezam-org-recovery-rewrap-v1\x00"
        + user_id.encode("ascii")
        + int(key_epoch).to_bytes(8, "big")
        + bytes([threshold, total_shares])
        + hashlib.sha256(wrapped_kek).digest()
    )


def make_journal(
    kek: bytes,
    auth_proof: bytes,
    user_id: str,
    epoch: int,
    identity: dict | None = None,
    old_keypair_private: bytes | None = None,
    current_auth_proof: bytes | None = None,
    recovery_secret: bytes | None = None,
    old_kek: bytes | None = None,
) -> dict:
    """``identity`` (public rotation fields) with ``old_keypair_private``: the
    rotation also replaces the identity keypair. Until the server takes it,
    the server still knows only the old key, so login needs the old private
    keys; they stay sealed here, like the auth proof.

    ``current_auth_proof``: the proof of the password the server still has,
    which it requires before replacing key material (review 688edcb K1).
    Absent after an org recovery, which has no old password: the server then
    needs an admin's key-reset grant or ``recovery_secret``: the org recovery
    key rebuilt from the shares, which signs the server's recovery challenge
    and re-wraps the server blob once the change landed (review e4cd15a #1)."""
    journal = {"epoch": epoch, "auth_proof": _seal(kek, _aad(user_id, epoch), auth_proof)}
    if old_kek is not None:
        # Stateful test SM31: a DEK another device makes while this change
        # waits is wrapped under the KEK the server still has. It is opened
        # with it and re-wrapped under ``kek`` into this change's batch.
        journal["old_kek"] = _seal(kek, _aad(user_id, epoch) + b"/old-kek", old_kek)
    if recovery_secret is not None:
        journal["recovery_secret"] = _seal(
            kek, _aad(user_id, epoch) + b"/recovery-secret", recovery_secret
        )
    if current_auth_proof is not None:
        journal["current_auth_proof"] = _seal(
            kek, _aad(user_id, epoch) + b"/current-proof", current_auth_proof
        )
    if identity is not None:
        journal["identity"] = dict(identity)
        journal["old_keypair"] = _seal(
            kek, _aad(user_id, epoch) + b"/old-keypair", old_keypair_private
        )
    return journal


def open_auth_proof(journal: dict, kek: bytes, user_id: str) -> bytearray:
    return _open(kek, _aad(user_id, int(journal["epoch"])), journal["auth_proof"])


def with_current_auth_proof(journal: dict, kek: bytes, user_id: str, proof: bytes) -> dict:
    """``journal`` with the proof of the server's password added (a journal
    written before the server asked for it, review 4acfdde R11)."""
    return {**journal, "current_auth_proof": _seal(
        kek, _aad(user_id, int(journal["epoch"])) + b"/current-proof", proof
    )}


def open_current_auth_proof(journal: dict, kek: bytes, user_id: str) -> bytearray | None:
    if "current_auth_proof" not in journal:
        return None
    return _open(
        kek, _aad(user_id, int(journal["epoch"])) + b"/current-proof",
        journal["current_auth_proof"],
    )


def open_recovery_secret(journal: dict, kek: bytes, user_id: str) -> bytearray | None:
    if "recovery_secret" not in journal:
        return None
    return _open(
        kek, _aad(user_id, int(journal["epoch"])) + b"/recovery-secret",
        journal["recovery_secret"],
    )


def open_old_kek(journal: dict, kek: bytes, user_id: str) -> bytearray | None:
    """The KEK the server still wraps DEKs under while the change waits."""
    if "old_kek" not in journal:
        return None
    return _open(kek, _aad(user_id, int(journal["epoch"])) + b"/old-kek", journal["old_kek"])


def open_old_keypair(journal: dict, kek: bytes, user_id: str) -> bytearray | None:
    """Private bytes of the identity keypair a pending rotation replaces."""
    if "old_keypair" not in journal:
        return None
    return _open(
        kek, _aad(user_id, int(journal["epoch"])) + b"/old-keypair", journal["old_keypair"]
    )
