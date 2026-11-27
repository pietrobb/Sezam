"""Org recovery endpoints — store/retrieve Shamir-wrapped KEK blob.

The server is content-blind: it stores the wrapped KEK blob without
being able to decrypt it. The actual Shamir splitting and
reconstruction happens entirely on the client side.

Endpoints:
  POST /api/org-recovery/store   — admin stores wrapped KEK blob
  GET  /api/org-recovery/blob    — returns the wrapped KEK blob (public)
  GET  /api/org-recovery/status  — returns whether org recovery is configured
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional

import pymysql
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from .. import team_log
from ..auth import (
    challenge_hash,
    compute_auth_proof_hash,
    compute_ip_hmac,
    generate_challenge,
    verify_challenge_signature,
)
from ..config import ServerConfig
from ..database import Database, run_transaction
from ..dependencies import get_config, get_current_user, get_db, get_optional_reader
from ..errors import ORG_RECOVERY_SUPERSEDED, WRONG_CURRENT_PASSWORD, ApiError
from ..models.schemas import (
    ChallengeResponse,
    OrgRecoveryBlobResponse,
    OrgRecoveryKeypairRequest,
    OrgRecoveryKeypairResponse,
    OrgRecoveryStatusResponse,
    OrgRecoveryStoreRequest,
)
from .auth import key_gate_wait_s, record_wrong_account_proof

router = APIRouter(prefix="/api/org-recovery", tags=["org-recovery"])


@router.post("/store")
async def store_recovery_blob(
    req: OrgRecoveryStoreRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(get_current_user),
    config: ServerConfig = Depends(get_config),
):
    """Store wrapped KEK blob for organizational recovery. Admin only."""
    if not user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can configure org recovery",
        )

    if req.total_shares < req.threshold:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="total_shares must be >= threshold",
        )

    try:
        wrapped_kek_bytes = bytes.fromhex(req.wrapped_kek)
        recovery_signing_pk = bytes.fromhex(req.recovery_signing_pk)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid recovery key encoding",
        ) from exc
    if len(recovery_signing_pk) != 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recovery signing public key must be 32 bytes",
        )
    now_ms = int(time.time() * 1000)
    try:
        await _store_recovery_blob(
            db, config, req, user, wrapped_kek_bytes, recovery_signing_pk, now_ms
        )
    except _WrongStoreProof:
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                locked = await record_wrong_account_proof(cur, config, user["sub"])
        if locked:
            raise HTTPException(status_code=423, detail="Recovery locked. Contact admin.")
        raise ApiError(status.HTTP_403_FORBIDDEN, WRONG_CURRENT_PASSWORD,
                       "Wrong current account password")
    return {"status": "ok"}


class _WrongStoreProof(Exception):
    pass


def org_recovery_rewrap_message(
    user_id: str, key_epoch: int, threshold: int, total_shares: int, wrapped_kek: bytes,
) -> bytes:
    """What the recovery key signs to re-store its blob without the password."""
    return (
        b"sezam-org-recovery-rewrap-v1\x00"
        + user_id.encode("ascii")
        + int(key_epoch).to_bytes(8, "big")
        + bytes([threshold, total_shares])
        + hashlib.sha256(wrapped_kek).digest()
    )


def _rewrap_signature_ok(
    req: OrgRecoveryStoreRequest, user_id: str, wrapped_kek: bytes, recovery_pk: bytes,
) -> bool:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    if req.key_epoch is None:
        return False
    message = org_recovery_rewrap_message(
        user_id, req.key_epoch, req.threshold, req.total_shares, wrapped_kek
    )
    try:
        VerifyKey(recovery_pk).verify(message, bytes.fromhex(req.recovery_signature))
    except (BadSignatureError, ValueError):
        return False
    return True


async def _require_current_password(
    cur, config: ServerConfig, user_id: str, proof_hex: str | None,
) -> None:
    """Review e4cd15a #1: a NEW recovery key can replace the account's key
    material (it signs the reset of a recovery admin who lost the password),
    so planting one needs what replacing the key material needs: the current
    password. A JWT from a stolen identity key would otherwise be enough to
    register the thief's own recovery key and then reset the password with it.
    """
    await cur.execute(
        "SELECT verify_salt, auth_proof_hash, recovery_locked, last_recovery_attempt "
        "FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    row = await cur.fetchone()
    if not row or not row[0] or not row[1]:
        return  # the account has no password on the server yet
    if proof_hex is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setting up org recovery needs the current account password",
        )
    # Review 526419e V6: the same one-proof-per-window gate as replacing the
    # key material (K1). Here every proof was verified, so a locked name
    # stayed an unlimited password oracle for the identity key's holder.
    wait_s = await key_gate_wait_s(
        cur, config, user_id, int(time.time() * 1000), row[2], row[3]
    )
    if wait_s:
        raise HTTPException(
            status_code=429,
            detail="The account is locked after wrong passwords; the current password "
            f"is checked again in {wait_s} s.",
            headers={"Retry-After": str(wait_s)},
        )
    computed = compute_auth_proof_hash(bytes(row[0]), bytes.fromhex(proof_hex))
    if not hmac.compare_digest(computed, row[1]):
        raise _WrongStoreProof()


async def _store_recovery_blob(
    db: Database, config: ServerConfig, req: OrgRecoveryStoreRequest, user: dict,
    wrapped_kek_bytes: bytes, recovery_signing_pk: bytes, now_ms: int,
) -> None:
    # Review 8595ec1: run_transaction, because MariaDB 11.6+ (compose) aborts
    # a racing store with 1020 at the locking read below.
    await run_transaction(db, lambda conn: _store_recovery_blob_in(
        conn, config, req, user, wrapped_kek_bytes, recovery_signing_pk, now_ms
    ))


async def _store_recovery_blob_in(
    conn, config: ServerConfig, req: OrgRecoveryStoreRequest, user: dict,
    wrapped_kek_bytes: bytes, recovery_signing_pk: bytes, now_ms: int,
) -> None:
    async with conn.cursor() as cur:
        # Review e443cbc, goal #440: the lock a team log append takes, before
        # any read. The blob ranks by the log head read below (log_seq); an
        # org.recovery append committing after this store's snapshot left the
        # blob one record short, so the log's key, with no blob, was current.
        await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
        await cur.fetchone()
        # Review 7c10379 (R7-H): a locking read of the blob before the
        # first setup found no row and took a gap lock; admins storing at
        # once then deadlocked on the INSERT (MariaDB: 5 of 6 parallel
        # first stores, 500). Only an existing blob is locked; a first
        # setup is decided by the primary key of the INSERT below.
        await cur.execute("SELECT 1 FROM org_recovery_blobs WHERE id = 1")
        existing = None
        if await cur.fetchone():
            await cur.execute(
                "SELECT created_by, recovery_signing_pk FROM org_recovery_blobs "
                "WHERE id = 1 FOR UPDATE"
            )
            existing = await cur.fetchone()
        if existing and existing[0] != user["sub"] and not req.replace_other_admin:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Org recovery was set up by another admin; replacing it "
                    "voids every share they handed out"
                ),
            )
        if "expected_signing_pk" in req.model_fields_set:
            # Review c78fd19 R13-10: an older setup saved on a desktop replaced
            # the newer one set up on the web meanwhile, voiding its shares.
            current = await _current_blob(cur)
            current_pk = current["recovery_signing_pk"] if current else None
            expected = (req.expected_signing_pk or "").lower() or None
            if current_pk not in (None, expected, recovery_signing_pk.hex()):
                raise ApiError(
                    status.HTTP_409_CONFLICT, ORG_RECOVERY_SUPERSEDED,
                    "A newer org recovery was set up after this one (on the web or "
                    "another device); it is kept",
                )
        # Re-storing the same recovery key (the KEK it wraps after a
        # recovery changed the password) grants no new key, but the blob
        # it replaces is what the shares open: a stolen identity key alone
        # swapped it for garbage, so recovery failed when it was needed
        # (review d615826). Without the password it must be signed by the
        # recovery key itself, which only the shares' holders have.
        # Review 8595ec1 #4: on a server restored from before the
        # registration that is the key the team log names. Review e443cbc
        # #438 (INV-2): only the current org recovery's key (_current_recovery),
        # not an older one the log still names; its shares were voided.
        _stored, current, _state = await _current_recovery(cur)
        same_key = current is not None and current["created_by"] == user["sub"] and (
            current["recovery_signing_pk"] == recovery_signing_pk.hex()
        )
        signed_by_recovery_key = same_key and req.recovery_signature is not None and (
            _rewrap_signature_ok(req, user["sub"], wrapped_kek_bytes, recovery_signing_pk)
        )
        if not signed_by_recovery_key:
            await _require_current_password(
                cur, config, user["sub"], req.current_auth_proof
            )
        # The blob wraps the KEK of the epoch the client says it wrapped;
        # a later password change makes it stale (lockout review #3).
        # Taking the server's epoch instead stored a blob wrapping an
        # older KEK as current (review 688edcb #3b).
        await cur.execute(
            "SELECT key_epoch FROM sync_state WHERE user_id = %s", (user["sub"],)
        )
        epoch_row = await cur.fetchone()
        account_epoch = int(epoch_row[0]) if epoch_row else 0
        if req.key_epoch is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "This client does not report which key epoch it wrapped; "
                    "update it to set up org recovery"
                ),
            )
        if req.key_epoch != account_epoch:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"The wrapped key is from key epoch {req.key_epoch}, but the "
                    f"account is at {account_epoch}: the password was changed "
                    "elsewhere. Sign in again and set up org recovery once more"
                ),
            )
        if existing:
            await cur.execute("DELETE FROM org_recovery_blobs WHERE id = 1")
        # Review 4acfdde R11 #2: newer than every team-log record so far
        # (_current_recovery).
        state = await team_log.load_state(cur)
        log_seq = state.head_seq if state is not None else -1
        try:
            await cur.execute(
                "INSERT INTO org_recovery_blobs "
                "(id, wrapped_kek, recovery_signing_pk, threshold, total_shares, "
                "created_by, created_at, key_epoch, log_seq) "
                "VALUES (1, %s, %s, %s, %s, %s, %s, %s, %s)",
                (wrapped_kek_bytes, recovery_signing_pk, req.threshold,
                 req.total_shares, user["sub"], now_ms, req.key_epoch, log_seq),
            )
        except pymysql.err.IntegrityError as exc:
            if existing or not exc.args or exc.args[0] != 1062:
                raise
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Org recovery was set up by another request at the same "
                "time; check its status and try again",
            ) from exc


async def _blob_is_stale(cur, created_by: str, blob_epoch) -> bool:
    """True when the owner's KEK changed after the blob was stored.

    Blobs from before the epoch column count as epoch 0.
    """
    await cur.execute(
        "SELECT key_epoch FROM sync_state WHERE user_id = %s", (created_by,)
    )
    row = await cur.fetchone()
    owner_epoch = int(row[0]) if row else 0
    return owner_epoch != int(blob_epoch or 0)


async def _stored_blob(cur) -> dict | None:
    await cur.execute(
        "SELECT wrapped_kek, created_by, key_epoch, recovery_signing_pk, threshold, "
        "total_shares, created_at, log_seq FROM org_recovery_blobs WHERE id = 1"
    )
    row = await cur.fetchone()
    return None if not row else {
        "wrapped_kek": bytes(row[0]), "created_by": row[1], "key_epoch": row[2],
        "recovery_signing_pk": bytes(row[3]).hex() if row[3] is not None else None,
        "threshold": row[4], "total_shares": row[5], "created_at": row[6],
        "log_seq": -1 if row[7] is None else int(row[7]),
    }


async def _current_recovery(cur) -> tuple[dict | None, dict | None, object]:
    """(stored blob, the current org recovery, team state).

    Only one org recovery is valid at a time: a new setup voids every share of
    the one before (review 4acfdde R11 #2). The candidates are the stored blob
    and each key the team log names for an active admin; the newest counts.
    The blob is as new as the log head when it was stored (``log_seq``), a
    log key as its last org.recovery record. So a setup the log never heard
    of (web anchor failed, desktop push still queued) outranks the older key
    the log names, another admin's setup outranks the replaced admin's key,
    and (review 8595ec1, capability run 316) the key a log the devices put
    back names outranks the blob of a backup from before it.

    The current one is ``{"created_by", "recovery_signing_pk", "blob"}``;
    ``blob`` is None for a log key without an org.recovery.wrap.
    """
    stored = await _stored_blob(cur)
    state, recovery_seq = await team_log.load_recovery_seqs(cur)
    candidates = []  # (rank, admin, key, blob)
    if stored is not None and stored["recovery_signing_pk"]:
        # Stored after the records up to log_seq: on a tie the blob is newer.
        candidates.append(((stored["log_seq"], 1), stored["created_by"], stored["recovery_signing_pk"], stored))
    for admin in sorted(state.org_recovery) if state is not None else []:
        pk = team_log.core.recovery_key(state, admin)
        if stored is not None and (stored["created_by"], stored["recovery_signing_pk"]) == (admin, pk):
            blob = stored  # the stored blob of the key the log names
        else:
            wrap = team_log.core.recovery_wrap(state, admin)
            blob = None if wrap is None else {
                "wrapped_kek": bytes.fromhex(wrap["wrapped_kek"]), "created_by": admin,
                "key_epoch": wrap["key_epoch"], "recovery_signing_pk": pk,
                "threshold": wrap["threshold"], "total_shares": wrap["total_shares"],
                "created_at": None,
            }
        candidates.append(((recovery_seq.get(admin, 0), 0), admin, pk, blob))
    if not candidates:
        return stored, None, state
    _rank, admin, pk, blob = max(candidates, key=lambda c: c[0])
    return stored, {"created_by": admin, "recovery_signing_pk": pk, "blob": blob}, state


async def _current_blob(cur, recovery_signing_pk: str | None = None) -> dict | None:
    """The blob the shares of the current org recovery open (_current_recovery).

    ``recovery_signing_pk`` (the key the shares derive) gets it only when that
    key is the current one: older shares were voided. A current log key
    without a wrap leaves the stored blob to report.
    """
    stored, current, _state = await _current_recovery(cur)
    if current is None:
        return None
    if recovery_signing_pk is not None:
        return current["blob"] if current["recovery_signing_pk"] == recovery_signing_pk else None
    return current["blob"] or stored


@router.get("/status", response_model=OrgRecoveryStatusResponse)
async def recovery_status(
    db: Database = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_reader),
):
    """Check whether org recovery is configured.

    Without a session (the share holders, before any sign-in) only what the
    recovery asks for: configured, the shares and stale. Who set it up, when
    and its key go to a signed-in account (review c02cc47 R17-R9s V5)."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            blob = await _current_blob(cur)
            if blob is None:
                return OrgRecoveryStatusResponse(configured=False)
            stale = await _blob_is_stale(cur, blob["created_by"], blob["key_epoch"])

    if user is None:
        return OrgRecoveryStatusResponse(
            configured=True, threshold=blob["threshold"], total_shares=blob["total_shares"], stale=stale,
        )
    return OrgRecoveryStatusResponse(
        configured=True,
        threshold=blob["threshold"],
        total_shares=blob["total_shares"],
        created_at=blob["created_at"],
        created_by=blob["created_by"],
        stale=stale,
        recovery_signing_pk=blob["recovery_signing_pk"],
    )


@router.get("/blob", response_model=OrgRecoveryBlobResponse)
async def get_recovery_blob(
    recovery_signing_pk: str | None = Query(None, pattern="^[0-9a-f]{64}$"),
    db: Database = Depends(get_db),
):
    """Return the wrapped KEK blob. No auth required (blob is encrypted)."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            blob = await _current_blob(cur, recovery_signing_pk)
            if blob is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Org recovery not configured",
                )
            stale = await _blob_is_stale(cur, blob["created_by"], blob["key_epoch"])

    return OrgRecoveryBlobResponse(wrapped_kek=blob["wrapped_kek"].hex(), stale=stale)


@router.post("/challenge", response_model=ChallengeResponse)
async def recovery_challenge(
    request: Request,
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Issue a one-time challenge for proof of recovery-key reconstruction."""
    # Each challenge is a DB row; an anonymous caller must not mint unbounded ones.
    client_ip = request.client.host if request.client else "unknown"
    budget_key = compute_ip_hmac(
        config.hmac_server_secret, f"org-recovery-challenge|{client_ip}"
    )
    if not await _consume_recovery_budget(
        db, budget_key, int(time.time() * 1000), _CHALLENGE_MAX_PER_HOUR
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many recovery attempts. Try again later.",
        )
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            admins = sorted({admin for admin, _pk in await _recovery_keys(cur)})

    if not admins:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Org recovery not configured",
        )

    challenge_bytes, timestamp_ms = generate_challenge()
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            # One per admin with a recovery key; the proof spends its own.
            for admin in admins:
                await cur.execute(
                    "INSERT IGNORE INTO spent_challenges (challenge_hash, used_at) "
                    "VALUES (%s, %s)",
                    (challenge_hash(challenge_bytes, f"org-recovery:{admin}"),
                     int(time.time() * 1000)),
                )
        await conn.commit()

    return ChallengeResponse(challenge=challenge_bytes.hex(), timestamp=timestamp_ms)


# ── Durable per-IP keypair rate limiting shared by all workers ──
_KEYPAIR_WINDOW_MS = 60 * 60 * 1000
_KEYPAIR_MAX_PER_HOUR = 5
_CHALLENGE_MAX_PER_HOUR = 20


async def _consume_keypair_attempt(db: Database, ip_hmac: str, now_ms: int) -> bool:
    return await _consume_recovery_budget(db, ip_hmac, now_ms, _KEYPAIR_MAX_PER_HOUR)


async def _consume_recovery_budget(
    db: Database, ip_hmac: str, now_ms: int, max_per_hour: int
) -> bool:
    """Atomically reserve one recovery attempt in the server-wide DB budget."""
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO org_recovery_rate_limits "
                "(ip_hmac, window_started_at, attempt_count) VALUES (%s, %s, 0) "
                "ON DUPLICATE KEY UPDATE ip_hmac = ip_hmac",
                (ip_hmac, now_ms),
            )
            await cur.execute(
                "SELECT window_started_at, attempt_count "
                "FROM org_recovery_rate_limits WHERE ip_hmac = %s FOR UPDATE",
                (ip_hmac,),
            )
            window_started_at, attempt_count = await cur.fetchone()
            if window_started_at <= now_ms - _KEYPAIR_WINDOW_MS:
                await cur.execute(
                    "UPDATE org_recovery_rate_limits "
                    "SET window_started_at = %s, attempt_count = 0 WHERE ip_hmac = %s",
                    (now_ms, ip_hmac),
                )
                attempt_count = 0
            if attempt_count >= max_per_hour:
                return False
            await cur.execute(
                "UPDATE org_recovery_rate_limits "
                "SET attempt_count = attempt_count + 1 WHERE ip_hmac = %s",
                (ip_hmac,),
            )
    return True


async def _recovery_keys(cur) -> list[tuple[str, bytes]]:
    """(admin id, recovery signing key) pairs a recovery proof may be for.

    The current org recovery only (_current_recovery): the registered blob's
    key or (review 8595ec1 #4) a key the team log names, for a server
    restored from a backup older than the registration. Review 4acfdde R11 #2:
    every key either had named was taken, so the shares of a replaced setup
    (or of the admin another one replaced) still reset the account.
    """
    _stored, current, _state = await _current_recovery(cur)
    if current is None:
        return []
    return [(current["created_by"], bytes.fromhex(current["recovery_signing_pk"]))]


async def consume_org_recovery_proof(
    cur, challenge_bytes: bytes, signature_bytes: bytes
) -> str | None:
    """Verify and spend a /challenge signed by the recovery key.

    A signature can only be produced from the private key deterministically
    derived from the reconstructed Shamir recovery key. Returns the id of the
    account whose org recovery it is, or None.
    """
    for admin_user_id, recovery_signing_pk in await _recovery_keys(cur):
        challenge_digest = challenge_hash(challenge_bytes, f"org-recovery:{admin_user_id}")
        await cur.execute(
            "SELECT used_at FROM spent_challenges WHERE challenge_hash = %s FOR UPDATE",
            (challenge_digest,),
        )
        if not await cur.fetchone() or not verify_challenge_signature(
            challenge_bytes, signature_bytes, recovery_signing_pk
        ):
            continue
        await cur.execute(
            "DELETE FROM spent_challenges WHERE challenge_hash = %s", (challenge_digest,)
        )
        return admin_user_id
    return None


@router.post("/keypair", response_model=OrgRecoveryKeypairResponse)
async def get_recovery_keypair(
    req: OrgRecoveryKeypairRequest,
    request: Request,
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Return the admin encrypted_keypair after a one-time recovery-key proof."""
    client_ip = request.client.host if request.client else "unknown"
    ip_hmac = compute_ip_hmac(config.hmac_server_secret, client_ip)
    if not await _consume_keypair_attempt(db, ip_hmac, int(time.time() * 1000)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many recovery attempts. Try again later.",
        )

    try:
        challenge_bytes = bytes.fromhex(req.challenge)
        signature_bytes = bytes.fromhex(req.signature)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid recovery proof",
        ) from exc

    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            if not await _recovery_keys(cur):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Org recovery not configured",
                )
            admin_user_id = await consume_org_recovery_proof(
                cur, challenge_bytes, signature_bytes
            )
            if admin_user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid recovery proof",
                )
            await cur.execute(
                "SELECT id, username, encrypted_keypair, argon2_salt, signing_pk "
                "FROM users WHERE id = %s",
                (admin_user_id,),
            )
            user_row = await cur.fetchone()

    if not user_row or not user_row[2]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Admin keypair not found",
        )

    return OrgRecoveryKeypairResponse(
        encrypted_keypair=user_row[2].hex(),
        argon2_salt=user_row[3].hex() if user_row[3] else "",
        user_id=user_row[0],
        username=user_row[1],
        signing_pk=user_row[4].hex() if user_row[4] else "",
    )
