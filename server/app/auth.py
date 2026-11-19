"""Authentication utilities — JWT (EdDSA) + challenge-response.

Spec 2.7: Ed25519 challenge-response.
Spec 8.6: JWT with alg=EdDSA, crv=Ed25519, expiry=1h.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import hmac
import logging
import os
import re
import time
from typing import Literal, Optional

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


JWT_ALGORITHM = "EdDSA"

logger = logging.getLogger(__name__)


def generate_challenge() -> tuple[bytes, int]:
    """Generate challenge = random(32B) + server_timestamp.

    Returns (challenge_bytes, timestamp_ms).
    """
    timestamp_ms = int(time.time() * 1000)
    random_part = os.urandom(32)
    return random_part + timestamp_ms.to_bytes(8, "big"), timestamp_ms


_BOUND_CHALLENGE_CONTEXT = b"sezam-auth-challenge-v1"

# One independent key per purpose, derived from HMAC_SERVER_SECRET. With a
# shared key, the public fake-salt oracle (/api/meta) returned exactly the MAC
# of a chosen login challenge; separate keys make outputs of one purpose
# useless for every other.
_KEY_FAKE_SALT = b"sezam/server-key/fake-salt/v1"
_KEY_CHALLENGE = b"sezam/server-key/auth-challenge/v1"
_KEY_IP = b"sezam/server-key/ip-hmac/v1"
_KEY_UNKNOWN_NAME = b"sezam/server-key/unknown-name/v1"


@functools.lru_cache(maxsize=16)
def _purpose_key(secret: str, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=purpose
    ).derive(secret.encode("utf-8"))


def _bound_challenge_mac(secret: str, nonce: bytes, ts_bytes: bytes, username: str) -> bytes:
    return hmac.new(
        _purpose_key(secret, _KEY_CHALLENGE),
        _BOUND_CHALLENGE_CONTEXT + nonce + ts_bytes + username.encode("utf-8"),
        hashlib.sha256,
    ).digest()[:16]


def generate_bound_challenge(secret: str, username: str) -> tuple[bytes, int]:
    """Stateless login challenge: nonce(16) || HMAC(16) || ts(8).

    Same 40-byte layout as generate_challenge(), so clients are unaffected,
    but issuing it needs no database write. Nobody can exhaust a victim's
    challenge budget, and verification only records challenges once used.
    """
    timestamp_ms = int(time.time() * 1000)
    ts_bytes = timestamp_ms.to_bytes(8, "big")
    nonce = os.urandom(16)
    return nonce + _bound_challenge_mac(secret, nonce, ts_bytes, username) + ts_bytes, timestamp_ms


def bound_challenge_is_authentic(challenge: bytes, secret: str, username: str) -> bool:
    if len(challenge) != 40:
        return False
    nonce, mac, ts_bytes = challenge[:16], challenge[16:32], challenge[32:]
    return hmac.compare_digest(mac, _bound_challenge_mac(secret, nonce, ts_bytes, username))


KEY_ROTATION_CONTEXT = b"sezam-key-rotation-v1"


def key_rotation_message(
    user_id: str,
    old_signing_pk: bytes,
    old_encryption_pk: bytes,
    new_signing_pk: bytes,
    new_encryption_pk: bytes,
) -> bytes:
    """Canonical bytes the NEW signing key signs to vouch for the old key."""
    return (
        KEY_ROTATION_CONTEXT
        + user_id.encode("utf-8").ljust(26, b"\x00")[:26]
        + bytes(old_signing_pk)
        + bytes(old_encryption_pk)
        + bytes(new_signing_pk)
        + bytes(new_encryption_pk)
    )


RESEED_CONTEXT = b"sezam-reseed-v1"
REJOIN_CONTEXT = b"sezam-rejoin-v1"


def reseed_message(
    challenge: bytes,
    user_id: str,
    username: str,
    signing_pk: bytes,
    encryption_pk: bytes,
    key_epoch: int,
    context: bytes = RESEED_CONTEXT,
) -> bytes:
    """Canonical bytes the identity key signs to bootstrap an empty server
    with an existing account (`sezam server reseed`), or, with
    REJOIN_CONTEXT, to bring back a member account a restore lost
    (`sezam server rejoin`).

    Domain-separated from login (AUTH_SIGNATURE_CONTEXT || challenge; older
    clients the bare challenge), so neither signature can stand in for the other.
    """
    name = username.encode("utf-8")
    return (
        context
        + bytes(challenge)
        + user_id.encode("ascii").ljust(26, b"\x00")[:26]
        + len(name).to_bytes(2, "big")
        + name
        + bytes(signing_pk)
        + bytes(encryption_pk)
        + int(key_epoch).to_bytes(8, "big")
    )


# Workers behind one load balancer may disagree on the clock by a little.
CHALLENGE_CLOCK_SKEW_MS = 5_000


def verify_challenge_signature(
    challenge: bytes,
    signature: bytes,
    signing_pk: bytes,
    max_age_seconds: int = 30,
) -> bool:
    """Verify Ed25519 signature on challenge.

    Also checks that challenge timestamp is not older than max_age_seconds,
    and not in the future: a future-stamped challenge would stay "fresh" long
    after its spent_challenges row is cleaned up, so one signature would be a
    login that never expires.
    """
    if not _challenge_is_fresh(challenge, max_age_seconds):
        return False
    # Clients sign AUTH_SIGNATURE_CONTEXT || challenge, so a server can never
    # make them sign its chosen bytes (a sync object, a policy) as a "login".
    if _signature_ok(auth_challenge_message(challenge), signature, signing_pk):
        return True
    # Bare signatures of clients released before that verify only until
    # legacy_bare_signature_until() (review 688edcb, low): the challenge is
    # this server's own fresh random MAC'd value, so nothing signed for any
    # other purpose can pass as one, but the old form must not live forever.
    if not _signature_ok(challenge, signature, signing_pk):
        return False
    until = legacy_bare_signature_until()
    key_id = bytes(signing_pk).hex()[:16]
    if datetime.datetime.now(datetime.timezone.utc).date() >= until:
        logger.warning(
            "Refused a bare challenge signature (no %s context) from key %s: "
            "the old form ended on %s; the client must be updated.",
            AUTH_SIGNATURE_CONTEXT.decode(), key_id, until.isoformat(),
        )
        raise OutdatedClientSignature()
    logger.warning(
        "Accepted a bare challenge signature (no %s context) from key %s; "
        "this old form is refused from %s on (SEZAM_LEGACY_BARE_SIGNATURE_UNTIL), "
        "update that client.",
        AUTH_SIGNATURE_CONTEXT.decode(), key_id, until.isoformat(),
    )
    return True


OUTDATED_CLIENT_SIGNATURE = (
    "This app version signs logins in a form the server no longer accepts. "
    "Update the Sezam app."
)


class OutdatedClientSignature(Exception):
    """A valid bare challenge signature past the grace period.

    Review e4cd15a (low): it was answered like a wrong signature (401), so a
    client released before the signature context showed "authentication
    failed" instead of asking for an update. main.py answers it with 426.
    """


# Last day (exclusive) a bare, context-less challenge signature still verifies.
LEGACY_BARE_SIGNATURE_DEFAULT_END = datetime.date(2027, 5, 1)


def legacy_bare_signature_until() -> datetime.date:
    """End of the bare-signature grace period; SEZAM_LEGACY_BARE_SIGNATURE_UNTIL
    (YYYY-MM-DD) overrides the default, a past date refuses them now."""
    raw = os.getenv("SEZAM_LEGACY_BARE_SIGNATURE_UNTIL", "").strip()
    return datetime.date.fromisoformat(raw) if raw else LEGACY_BARE_SIGNATURE_DEFAULT_END


AUTH_SIGNATURE_CONTEXT = b"sezam-auth-challenge-signature-v1"
AUTH_CHALLENGE_LENGTH = 40


def auth_challenge_message(challenge: bytes) -> bytes:
    """Bytes a client signs to answer a login challenge."""
    return AUTH_SIGNATURE_CONTEXT + bytes(challenge)


# Capability run 300: a login with a key the team log retired (a restore from
# before the rotation) proves the log's current key over the same challenge.
CURRENT_KEY_PROOF_CONTEXT = b"sezam-current-key-proof-v1"


def verify_current_key_proof(challenge: bytes, signature: bytes, signing_pk: bytes) -> bool:
    try:
        VerifyKey(bytes(signing_pk)).verify(CURRENT_KEY_PROOF_CONTEXT + bytes(challenge), bytes(signature))
    except Exception:
        return False
    return True


def verify_reseed_signature(
    challenge: bytes,
    message: bytes,
    signature: bytes,
    signing_pk: bytes,
    max_age_seconds: int = 30,
) -> bool:
    """Same freshness rule as login, signature over reseed_message()."""
    return _challenge_is_fresh(challenge, max_age_seconds) and _signature_ok(
        message, signature, signing_pk
    )


def _challenge_is_fresh(challenge: bytes, max_age_seconds: int) -> bool:
    # Extract timestamp from challenge (last 8 bytes)
    if len(challenge) < 40:
        return False
    timestamp_ms = int.from_bytes(challenge[-8:], "big")
    now_ms = int(time.time() * 1000)

    if now_ms - timestamp_ms > max_age_seconds * 1000:
        return False
    if timestamp_ms - now_ms > CHALLENGE_CLOCK_SKEW_MS:
        return False
    return True


def _signature_ok(message: bytes, signature: bytes, signing_pk: bytes) -> bool:
    try:
        vk = VerifyKey(signing_pk)
        vk.verify(message, signature)
        return True
    except (BadSignatureError, Exception):
        return False


def challenge_hash(challenge: bytes, username: str) -> str:
    """Hash challenge for spent tracking: SHA-256(challenge || username)."""
    return hashlib.sha256(challenge + username.encode("utf-8")).hexdigest()


def create_jwt(
    signing_key: SigningKey,
    user_id: str,
    username: str,
    is_admin: bool,
    expiry_seconds: int = 3600,
    scope: Optional[str] = None,
    token_epoch: int = 0,
    current_key: Optional[str] = None,
) -> str:
    """Create an EdDSA JWT token.

    ``tep`` binds the token to users.token_epoch; bumping the epoch (key or
    password rotation) invalidates every token issued before it.
    """
    now = int(time.time())
    payload = {
        "sub": user_id,
        "username": username,
        "is_admin": is_admin,
        "iat": now,
        "exp": now + expiry_seconds,
        "tep": int(token_epoch or 0),
        # Review 7c10379: Ed25519 is deterministic, so two tokens for one
        # account in one second were the same string, and revoking one (a
        # refresh revokes the old token) revoked the other one too.
        "jti": os.urandom(16).hex(),
    }
    if scope:
        payload["scope"] = scope
    if current_key:
        payload["kcur"] = current_key  # the log's current signing key this login proved

    # PyJWT with cryptography backend expects Ed25519PrivateKey object
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key_bytes = bytes(signing_key)  # 32-byte seed
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    token = jwt.encode(
        payload,
        private_key,
        algorithm=JWT_ALGORITHM,
    )
    return token


def verify_jwt(
    token: str,
    verify_key_bytes: bytes,
) -> dict:
    """Verify and decode a JWT token.

    Raises jwt.InvalidTokenError on failure.

    Review c78fd19 (GHSA-hxm8-2xgr-2p9m): only the canonical compact form is
    accepted, three unpadded Base64URL segments; PyJWT up to 2.13.0 took a
    signature with a trailing '=' or '!!!!' as the same token.
    """
    if not _COMPACT_JWS.fullmatch(token):
        raise jwt.InvalidTokenError("non-canonical token encoding")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    public_key = Ed25519PublicKey.from_public_bytes(verify_key_bytes)
    return jwt.decode(
        token,
        public_key,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub", "jti"]},
    )


_COMPACT_JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def token_revocation_key(payload: dict) -> str:
    """The revoked_tokens key of a verified token: its jti, never the raw
    string, which more than one serialization can carry (review c78fd19)."""
    return hashlib.sha256(b"jti:" + str(payload["jti"]).encode("utf-8")).hexdigest()


def compute_auth_proof_hash(verify_salt: bytes, auth_proof: bytes) -> str:
    """HMAC-SHA256(verify_salt, auth_proof) — server-side computation.

    auth_proof is already 32B high-entropy Argon2id output.
    No second Argon2id needed (spec 4.2 users table comments).
    """
    return hmac.new(verify_salt, auth_proof, hashlib.sha256).hexdigest()


def unlock_code_hash(code: str) -> str:
    """Stored form of an admin's one-time recovery unlock code (80 random bits)."""
    return hashlib.sha256(b"sezam-recovery-unlock-v1:" + code.lower().encode()).hexdigest()


def generate_fake_salt(
    server_secret: str, username: str, kind: Literal["argon2", "auth"] = "argon2"
) -> bytes:
    """Deterministic fake salt for non-existent users (user enumeration protection).

    HMAC(fake-salt key, kind || 0 || username) — consistent per username. The
    kind prefix keeps "bob"'s auth salt from equalling "bob_auth"'s argon2 salt.
    """
    return hmac.new(
        _purpose_key(server_secret, _KEY_FAKE_SALT),
        kind.encode("ascii") + b"\x00" + username.encode("utf-8"),
        hashlib.sha256,
    ).digest()[:16]


def unknown_name_mac(server_secret: str, username: str) -> bytes:
    """Stable per-name secret for answering about a name that has no account.

    Picks the fake KDF params and keys the recovery rate limit of unknown
    names, so they behave like a real account (user enumeration protection).
    """
    return hmac.new(
        _purpose_key(server_secret, _KEY_UNKNOWN_NAME),
        username.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def compute_ip_hmac(server_secret: str, ip: str) -> str:
    """HMAC(ip key, IP) — not plain hash (dictionary resistant)."""
    return hmac.new(
        _purpose_key(server_secret, _KEY_IP),
        ip.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
