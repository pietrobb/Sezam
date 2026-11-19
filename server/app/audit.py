"""Verified, client-signed server audit records (spec §4.2)."""

from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


def canonical_server_audit_data(
    audit_id: str,
    user_id: str,
    action: str,
    timestamp: int,
    request_hash: str,
) -> bytes:
    """Build the exact §4.2 byte sequence covered by Ed25519."""
    if len(audit_id.encode("ascii")) != 26 or len(user_id.encode("ascii")) != 26:
        raise ValueError("audit and user IDs must be 26-byte ULIDs")
    if timestamp < 0 or timestamp >= 2**64:
        raise ValueError("audit timestamp must fit u64")
    hash_bytes = bytes.fromhex(request_hash)
    if len(hash_bytes) != 32:
        raise ValueError("request_hash must be a SHA-256 hex digest")
    return (
        audit_id.encode("ascii")
        + user_id.encode("ascii")
        + action.encode("utf-8")
        + timestamp.to_bytes(8, "big")
        + hash_bytes
    )


def verify_server_audit_signature(
    audit_id: str,
    user_id: str,
    action: str,
    timestamp: int,
    request_hash: str,
    signature: bytes,
    signing_pk: bytes,
) -> bool:
    """Verify a dedicated audit signature; unrelated request signatures fail."""
    try:
        canonical = canonical_server_audit_data(
            audit_id, user_id, action, timestamp, request_hash
        )
        VerifyKey(signing_pk).verify(canonical, signature)
        return True
    except (BadSignatureError, TypeError, ValueError):
        return False


async def log_server_audit(
    db,
    *,
    audit_id: str,
    user_id: str,
    action: str,
    timestamp: int,
    request_hash: str,
    signature: bytes,
    signing_pk: bytes,
    commit_seq_range: str | None = None,
    client_ip: str | None = None,
) -> None:
    """Insert only an audit record carrying its own valid client signature."""
    if not verify_server_audit_signature(
        audit_id,
        user_id,
        action,
        timestamp,
        request_hash,
        signature,
        signing_pk,
    ):
        raise ValueError("invalid server audit signature")

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO server_audit "
                "(id, user_id, action, timestamp, request_hash, commit_seq_range, client_signature, client_ip) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    audit_id,
                    user_id,
                    action,
                    timestamp,
                    request_hash,
                    commit_seq_range,
                    signature,
                    client_ip,
                ),
            )
        await conn.commit()
