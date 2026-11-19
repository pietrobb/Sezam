"""Auth endpoints — challenge-response, JWT, provision, recover.

Spec 2.7, 8.6:
  POST /api/auth/challenge
  POST /api/auth/verify
  POST /api/auth/refresh
  POST /api/auth/logout
  POST /api/auth/provision
  POST /api/auth/recover
  PUT  /api/me/keypair
  PUT  /api/me/kdf-params
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth import (
    bound_challenge_is_authentic,
    challenge_hash,
    compute_auth_proof_hash,
    compute_ip_hmac,
    create_jwt,
    generate_bound_challenge,
    token_revocation_key,
    REJOIN_CONTEXT,
    reseed_message,
    unknown_name_mac,
    unlock_code_hash,
    verify_challenge_signature,
    verify_current_key_proof,
    verify_reseed_signature,
)
from .. import team_log
from ..config import JWTKeyManager, ServerConfig
from ..database import Database
from ..errors import (
    ACCOUNT_EXISTS, IDENTITY_KEY_ROTATED, USERNAME_TAKEN, WRONG_CURRENT_PASSWORD, ApiError,
)
from ..dependencies import (
    get_config,
    get_current_user,
    get_db,
    get_jwt_manager,
    get_keypair_upload_user,
    require_full_jwt,
)
from ..models.schemas import (
    BootstrapRequest,
    BootstrapResponse,
    BootstrapStatusResponse,
    ChallengeRequest,
    ChallengeResponse,
    KdfParamsBackfillRequest,
    KeyMaterialArchiveRequest,
    KeypairUploadRequest,
    ProvisionRequest,
    ProvisionResponse,
    ProvisioningTokenResponse,
    RecoverRequest,
    RefreshRequest,
    RecoverResponse,
    RejoinRequest,
    VerifyRequest,
    VerifyResponse,
    account_kdf_params,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)

# Review 688edcb N2: clients from before per-account params send key material
# without them. The server must refuse it (N2: nothing may guess an account's
# KDF), but with a reason the user can act on, not a bare 422 field error.
OUTDATED_CLIENT_KDF = (
    "This Sezam app is too old for this server: it does not send the password "
    "settings (KDF parameters) of the key material. Nothing was changed. "
    "Update the app and try again."
)


def require_kdf_params_json(params) -> str:
    """The stored form of the KDF params; 426 Upgrade Required without them."""
    if params is None:
        raise HTTPException(status_code=426, detail=OUTDATED_CLIENT_KDF)
    return json.dumps(params.model_dump(), sort_keys=True)

# ── Bootstrap router (separate prefix /api) ──

bootstrap_router = APIRouter(prefix="/api", tags=["bootstrap"])


# Tables whose rows show that an account was used for something; such an
# account is never dropped as abandoned.
_ACCOUNT_TRACES = (
    ("vault_objects", "owner_id"),
    # Review 7c10379 (R7-H): an object granted to the account; dropping it
    # cascaded into vault_objects and deleted that signed object unseen.
    ("vault_objects", "target_user_id"),
    ("shared_links", "created_by"),
    ("server_audit", "user_id"),
    ("invitation_tokens", "created_by"),
    ("provisioning_tokens", "user_id"),
)


async def keyless_account_left_no_trace(cur, user_id: str) -> bool:
    # Locking reads: they see what a push committed while the caller waited
    # for the users row lock (a plain read sees the transaction's snapshot).
    for table, column in _ACCOUNT_TRACES:
        await cur.execute(
            f"SELECT 1 FROM {table} WHERE {column} = %s LOCK IN SHARE MODE", (user_id,)
        )
        if await cur.fetchone():
            return False
    return True


async def drop_keyless_account(cur, user_id: str) -> None:
    """Delete an account that never got key material (lockout review #10).

    The caller holds the users row lock and has checked that the account has
    no encrypted_keypair and left no trace (keyless_account_left_no_trace).
    """
    await cur.execute("DELETE FROM sync_state WHERE user_id = %s", (user_id,))
    await cur.execute("DELETE FROM users WHERE id = %s", (user_id,))


def _request_network_mac(request: Request, config: ServerConfig) -> str:
    client_ip = request.client.host if request.client else "unknown"
    return compute_ip_hmac(config.hmac_server_secret, _client_network(client_ip))


_UNFINISHED_SETUP_ELSEWHERE = (
    "The first admin setup on this server was never finished (its key upload "
    "did not happen), and it can only be redone from the network it was started "
    "from. To redo it from here, the server operator sets "
    "SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1, restarts the server, and unsets it after."
)


async def _abandoned_bootstrap_id(
    cur, config: ServerConfig, network_mac: str, *, lock: bool, warn: Optional[bool] = None
) -> tuple[Optional[str], bool]:
    """Lockout review #10: the first admin is created before its keypair is
    uploaded. When that upload never happened (web keeps the private key only
    in memory until then) the server refused every later bootstrap forever.
    A lone keyless admin past ``abandoned_bootstrap_seconds`` that left no
    trace is treated as no admin at all; a device that still holds the key
    can finish its upload any time before that (full JWT via challenge).

    Review 688edcb #10: but only for a bootstrap from the network the first
    one came from (stored in recovery_trusted_nets at bootstrap). Before, an
    hour after an unfinished setup anyone on the internet could make himself
    the admin of a server its operator believed set up. From elsewhere (or
    for a setup made before this fix) the operator allows it explicitly with
    SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1; the refusal is logged with that hint.

    Returns (replaceable admin id, True when such a setup exists but this
    network may not replace it). Review e4cd15a (low): the second value lets
    bootstrap-status and the refused bootstrap explain it (web showed only a
    login nobody could pass, the hint was in the server log alone).
    """
    await cur.execute(
        "SELECT id, is_admin, encrypted_keypair, created_at, recovery_trusted_nets FROM users"
        + (" FOR UPDATE" if lock else "")
    )
    rows = list(await cur.fetchall())
    if len(rows) != 1:
        return None, False
    user_id, is_admin, encrypted_keypair, created_at, nets = rows[0]
    cutoff_ms = int(time.time() * 1000) - config.abandoned_bootstrap_seconds * 1000
    if not is_admin or encrypted_keypair or (created_at or 0) > cutoff_ms:
        return None, False
    if not await keyless_account_left_no_trace(cur, user_id):
        return None, False
    if network_mac not in _trusted_nets(nets) and not config.bootstrap_reset_any_network:
        if lock if warn is None else warn:  # a refused POST /bootstrap, not every status poll
            logger.warning(
                "Unfinished first-admin setup %s (no key material) not replaced: the "
                "new bootstrap comes from another network. To allow it from anywhere, "
                "set SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1 and restart, then unset it.",
                user_id,
            )
        return None, True
    return user_id, False


@bootstrap_router.get("/bootstrap-status", response_model=BootstrapStatusResponse)
async def bootstrap_status(
    request: Request,
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Check if the server needs initial admin setup (no usable admin yet)."""
    network_mac = _request_network_mac(request, config)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT COUNT(*) FROM users")
            row = await cur.fetchone()
            count = row[0] if row else 0
            abandoned, elsewhere = (
                await _abandoned_bootstrap_id(cur, config, network_mac, lock=False)
                if count == 1 else (None, False)
            )
    return BootstrapStatusResponse(
        needs_setup=count == 0 or bool(abandoned),
        unfinished_setup=_UNFINISHED_SETUP_ELSEWHERE if elsewhere else None,
    )


@bootstrap_router.post("/bootstrap", response_model=BootstrapResponse)
async def bootstrap(
    req: BootstrapRequest,
    request: Request,
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
    config: ServerConfig = Depends(get_config),
):
    """Create the first admin user. Only works when users table is empty.

    With ``user_id`` (reseed) the admin keeps an existing identity: the
    request must carry a fresh /auth/challenge for this username, signed by
    the identity key over reseed_message(), and sets the account key epoch.
    """
    if config.bootstrap_disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bootstrap is disabled on this server (SEZAM_BOOTSTRAP_DISABLED).",
        )
    # Validate inputs
    if not req.username.strip():
        raise HTTPException(status_code=400, detail="Username is required")
    network_mac = _request_network_mac(request, config)
    # Review a159e97 H6: anyone may call this. On a set-up server the answer
    # is 403 from a plain read, before any lock: the locking check below
    # waited behind every push on commit_counter, so a wave of anonymous
    # bootstraps during a long push held the pool's connections until the
    # health check failed and the worker was killed.
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT COUNT(*) FROM users")
            row = await cur.fetchone()
            if row and row[0] > 0:
                abandoned, elsewhere = await _abandoned_bootstrap_id(
                    cur, config, network_mac, lock=False, warn=True
                )
                if abandoned is None:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=_UNFINISHED_SETUP_ELSEWHERE if elsewhere
                        else "Server already has users. Bootstrap not allowed.",
                    )

    from ulid import ULID

    signing_pk = bytes.fromhex(req.signing_pk)
    encryption_pk = bytes.fromhex(req.encryption_pk)
    reseed = req.user_id is not None
    if not reseed:
        if req.challenge or req.signature or req.key_epoch:
            raise HTTPException(
                status_code=400, detail="challenge, signature and key_epoch need user_id"
            )
        user_id = str(ULID())
    else:
        if not req.challenge or not req.signature:
            raise HTTPException(
                status_code=401, detail="Reseed requires a signed challenge"
            )
        user_id = req.user_id
        challenge_bytes = bytes.fromhex(req.challenge)
        if not bound_challenge_is_authentic(
            challenge_bytes, config.hmac_server_secret, req.username.strip()
        ) or not verify_reseed_signature(
            challenge_bytes,
            reseed_message(
                challenge_bytes, user_id, req.username.strip(),
                signing_pk, encryption_pk, req.key_epoch,
            ),
            bytes.fromhex(req.signature),
            signing_pk,
        ):
            raise HTTPException(status_code=401, detail="Reseed proof rejected")

    import hashlib as _hashlib

    fingerprint = _hashlib.sha256(signing_pk + encryption_pk).hexdigest()
    now_ms = int(time.time() * 1000)
    signing_key = jwt_mgr.signing_key

    # Atomic check + insert in a single transaction with row-level lock
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            # Review 7c10379 (R7-H): on an empty server the locking COUNT took
            # only a gap lock, which every parallel bootstrap shared; their
            # INSERTs then deadlocked (MariaDB: 1 of 8 parallel bootstraps a
            # 500, not 403). The commit_counter row, present in every
            # database and taken before users by pushes too, orders them.
            await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
            await cur.execute("SELECT COUNT(*) FROM users FOR UPDATE")
            row = await cur.fetchone()
            if row and row[0] > 0:
                abandoned, elsewhere = await _abandoned_bootstrap_id(
                    cur, config, network_mac, lock=True
                )
                if abandoned is None:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=_UNFINISHED_SETUP_ELSEWHERE if elsewhere
                        else "Server already has users. Bootstrap not allowed.",
                    )
                await drop_keyless_account(cur, abandoned)
            # The network of the first admin: only a bootstrap from there may
            # replace this one if its key upload never happens (#10).
            await cur.execute(
                "INSERT INTO users (id, username, signing_pk, encryption_pk, "
                "key_fingerprint, status, is_admin, created_at, recovery_trusted_nets) "
                "VALUES (%s, %s, %s, %s, %s, 'active', 1, %s, %s)",
                (user_id, req.username.strip(), signing_pk, encryption_pk,
                 fingerprint, now_ms, json.dumps([network_mac])),
            )
            if reseed:
                await cur.execute(
                    "INSERT IGNORE INTO spent_challenges (challenge_hash, used_at) "
                    "VALUES (%s, %s)",
                    (challenge_hash(challenge_bytes, req.username.strip()), now_ms),
                )
                if cur.rowcount != 1:
                    raise HTTPException(status_code=401, detail="Reseed proof rejected")
                # The local key material is at this epoch; the next push
                # continues from it instead of having to "advance" from 0.
                await cur.execute(
                    "INSERT INTO sync_state "
                    "(user_id, last_push_seq, last_pull_seq, last_activity, key_epoch) "
                    "VALUES (%s, 0, 0, %s, %s)",
                    (user_id, now_ms, req.key_epoch),
                )

        # Issue onboarding JWT before committing the user insert.
        token = create_jwt(
            signing_key,
            user_id,
            req.username.strip(),
            is_admin=True,
            expiry_seconds=config.jwt_onboarding_expiry_seconds,
            scope="keypair_upload",
        )

    return BootstrapResponse(user_id=user_id, token=token)


def _rejoin_name_taken(username: str) -> ApiError:
    """Review 4acfdde R11 (low): an account registered after the backup took
    the name; the log names the member by id, so it rejoins under another."""
    return ApiError(
        409, USERNAME_TAKEN,
        f"Username already exists: another account took '{username}'; rejoin under another name",
    )


def _rejoin_keys_logged(state, req: RejoinRequest) -> bool:
    member = state.members.get(req.user_id) if state is not None else None
    return (
        member is not None and member.active
        and member.signing_pk == req.signing_pk
        and member.encryption_pk == req.encryption_pk
    )


@router.post("/rejoin", response_model=BootstrapResponse)
async def rejoin(
    req: RejoinRequest,
    request: Request,
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
    config: ServerConfig = Depends(get_config),
):
    """Bring back an account a restored backup lost, under the id the team
    log names (review 8595ec1 #1).

    The backup was older than the member's registration: the devices put the
    log back, but the server assigns ids, so the member could never sign in
    again. The admin-signed log is the authority: the account comes back only
    with the keys the log holds for that id as current, proven by those keys
    over a fresh challenge, and only while no account has the id. The key
    material follows with the usual first upload (PUT /api/me/keypair).
    """
    username = req.username.strip()
    signing_pk = bytes.fromhex(req.signing_pk)
    encryption_pk = bytes.fromhex(req.encryption_pk)
    challenge_bytes = bytes.fromhex(req.challenge)
    refused = HTTPException(status_code=401, detail="Rejoin proof rejected")
    if not bound_challenge_is_authentic(
        challenge_bytes, config.hmac_server_secret, username
    ) or not verify_reseed_signature(
        challenge_bytes,
        reseed_message(challenge_bytes, req.user_id, username, signing_pk,
                       encryption_pk, req.key_epoch, REJOIN_CONTEXT),
        bytes.fromhex(req.signature),
        signing_pk,
    ):
        raise refused
    # Review c78fd19 (medium): anyone can sign a challenge with keys of their
    # own, and each such call took the lock every push waits on. Keys the
    # log does not hold for this id, or an id that has an account, are
    # refused from a plain read; the locked check below decides the rest.
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            if not _rejoin_keys_logged(await team_log.load_state(cur), req):
                raise refused
            await cur.execute("SELECT id FROM users WHERE id = %s", (req.user_id,))
            if await cur.fetchone():
                raise ApiError(409, ACCOUNT_EXISTS, "The account exists; sign in")
    now_ms = int(time.time() * 1000)
    try:
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                # Ordered with pushes and team-log appends (they lock it first).
                await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
                state = await team_log.load_state(cur)
                if not _rejoin_keys_logged(state, req):
                    raise refused
                await cur.execute("SELECT id FROM users WHERE id = %s", (req.user_id,))
                if await cur.fetchone():
                    raise ApiError(409, ACCOUNT_EXISTS, "The account exists; sign in")
                await cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                if await cur.fetchone():
                    raise _rejoin_name_taken(username)
                await cur.execute(
                    "INSERT INTO users (id, username, signing_pk, encryption_pk, "
                    "key_fingerprint, status, is_admin, created_at, recovery_trusted_nets) "
                    "VALUES (%s, %s, %s, %s, %s, 'active', %s, %s, %s)",
                    (req.user_id, username, signing_pk, encryption_pk,
                     hashlib.sha256(signing_pk + encryption_pk).hexdigest(),
                     1 if team_log.core.is_admin(state, req.user_id) else 0, now_ms,
                     json.dumps([_request_network_mac(request, config)])),
                )
                await cur.execute(
                    "INSERT IGNORE INTO spent_challenges (challenge_hash, used_at) VALUES (%s, %s)",
                    (challenge_hash(challenge_bytes, username), now_ms),
                )
                if cur.rowcount != 1:
                    raise refused
                # The device's key material is at this epoch (as for a reseed).
                await cur.execute(
                    "INSERT INTO sync_state "
                    "(user_id, last_push_seq, last_pull_seq, last_activity, key_epoch) "
                    "VALUES (%s, 0, 0, %s, %s)",
                    (req.user_id, now_ms, req.key_epoch),
                )
    except HTTPException:
        raise
    except Exception as e:
        if "Duplicate entry" in str(e) or "UNIQUE" in str(e) or "Duplicate key" in str(e):
            raise _rejoin_name_taken(username) from e
        raise
    token = create_jwt(
        jwt_mgr.signing_key, req.user_id, username,
        is_admin=bool(team_log.core.is_admin(state, req.user_id)),
        expiry_seconds=config.jwt_onboarding_expiry_seconds,
        scope="keypair_upload",
    )
    return BootstrapResponse(user_id=req.user_id, token=token)


@router.post("/challenge", response_model=ChallengeResponse)
async def auth_challenge(
    req: ChallengeRequest,
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Step 1: return a stateless, username-bound challenge.

    Issuing writes nothing and has no per-user budget, so anonymous traffic
    can neither amplify DB writes nor exhaust a victim's login challenges.
    Single use is enforced when the signed challenge is consumed.
    """
    challenge_bytes, ts = generate_bound_challenge(config.hmac_server_secret, req.username)
    return ChallengeResponse(challenge=challenge_bytes.hex(), timestamp=ts)


async def consume_signed_challenge(
    cur,
    config: ServerConfig,
    username: str,
    challenge_hex: str,
    signature_hex: str,
    signing_pk: bytes,
    error: str = "Authentication failed",
) -> None:
    """Verify a bound challenge signed by ``signing_pk`` and mark it spent."""
    try:
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature_bytes = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail=error)
    if not bound_challenge_is_authentic(
        challenge_bytes, config.hmac_server_secret, username
    ):
        raise HTTPException(status_code=401, detail="Challenge not found or expired")
    # 30 s freshness < spent_challenges TTL, so a replay is always caught.
    if not verify_challenge_signature(challenge_bytes, signature_bytes, signing_pk):
        raise HTTPException(status_code=401, detail=error)
    await cur.execute(
        "INSERT IGNORE INTO spent_challenges (challenge_hash, used_at) VALUES (%s, %s)",
        (challenge_hash(challenge_bytes, username), int(time.time() * 1000)),
    )
    if cur.rowcount != 1:
        raise HTTPException(status_code=401, detail="Challenge not found or expired")


async def _signed_by_rotated_key(
    db: Database, user_id: str, challenge_hex: str, signature_hex: str
) -> bool:
    """True if the challenge is signed by one of the user's certified archived keys."""
    try:
        challenge_bytes = bytes.fromhex(challenge_hex)
        signature_bytes = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        return False
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT signing_pk, successor_signing_pk, rotation_signature "
                "FROM user_key_archives WHERE user_id = %s "
                "ORDER BY archived_at DESC LIMIT 64",
                (user_id,),
            )
            rows = list(await cur.fetchall())
    return any(
        successor and certificate
        and verify_challenge_signature(challenge_bytes, signature_bytes, bytes(archived_pk))
        for archived_pk, successor, certificate in rows
    )


async def _login_renamed_account(db: Database, config: ServerConfig, req, request: Request):
    """The account the name migration moved off ``req.username``, when its
    identity key signed this login (review e4cd15a, low): its devices still
    sign in with the old name, which now belongs to another account. Only
    that account's key can pass, so the old name opens nothing else.

    Review 526419e N8: a device of such an account whose identity key another
    device rotated got 401, not the 409 that makes it take the new keypair
    over - and it would have taken it over under the old name, i.e. from the
    account that holds that name now. The 409 names the account's current
    name; only the account's own certified retired key gets it."""
    rotated_candidates = []
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, username, signing_pk, is_admin, status, token_epoch, "
                "encrypted_keypair FROM users WHERE renamed_from = %s",
                (req.username,),
            )
            for row in list(await cur.fetchall()):
                if row[4] != "active":
                    continue
                try:
                    await consume_signed_challenge(
                        cur, config, req.username, req.challenge, req.signature,
                        bytes(row[2]),
                    )
                except HTTPException as exc:
                    if exc.detail == "Authentication failed":
                        rotated_candidates.append((row[0], row[1]))
                        continue
                    raise
                await remember_owner_network(
                    cur, row[0], _request_network_mac(request, config), config
                )
                return row[0], row[1], row[3], row[5], row[6]
    for user_id, username in rotated_candidates:
        if await _signed_by_rotated_key(db, user_id, req.challenge, req.signature):
            raise ApiError(
                409, IDENTITY_KEY_ROTATED,
                {"error": "Identity key rotated", "username": username},
            )
    return None


@router.post("/registration-resume")
async def registration_resume(
    req: VerifyRequest,
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
    config: ServerConfig = Depends(get_config),
):
    """Recover onboarding after a lost response; never grant an active session."""
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, username, signing_pk, is_admin, status, token_epoch, "
                "encrypted_keypair FROM users WHERE username = %s FOR UPDATE",
                (req.username,),
            )
            row = await cur.fetchone()
            if not row or row[1] != req.username or row[4] not in ("pending", "active"):
                raise HTTPException(status_code=401, detail="Registration recovery failed")
            await consume_signed_challenge(
                cur, config, req.username, req.challenge, req.signature, row[2]
            )
            token = create_jwt(
                jwt_mgr.signing_key, row[0], row[1], bool(row[3]),
                config.jwt_onboarding_expiry_seconds,
                scope="keypair_upload", token_epoch=row[5] or 0,
            )
            return {
                "user_id": row[0], "token": token,
                "key_material_hash": hashlib.sha256(bytes(row[6])).hexdigest() if row[6] else None,
            }


@router.post("/verify", response_model=VerifyResponse)
async def auth_verify(
    req: VerifyRequest,
    request: Request,
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
    config: ServerConfig = Depends(get_config),
):
    """Step 2: Client sends challenge + signature, server verifies and returns JWT."""
    # Review d615826: the challenge's MAC was checked only for a real
    # account, so a forged one told real names from unknown ones.
    try:
        challenge_bytes = bytes.fromhex(req.challenge)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Authentication failed")
    if not bound_challenge_is_authentic(
        challenge_bytes, config.hmac_server_secret, req.username
    ):
        raise HTTPException(status_code=401, detail="Challenge not found or expired")
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, username, signing_pk, is_admin, status, token_epoch, "
                "encrypted_keypair FROM users WHERE username = %s",
                (req.username,),
            )
            row = await cur.fetchone()

    # Exact match only: the case-insensitive collation must not alias names.
    if not row or row[1] != req.username or row[4] != "active":
        renamed = await _login_renamed_account(db, config, req, request)
        if renamed is None:
            raise HTTPException(status_code=401, detail="Authentication failed")
        user_id, username, is_admin, token_epoch, encrypted_keypair = renamed
        return await _issue_login(db, jwt_mgr, config, user_id, username, is_admin,
                                  token_epoch, encrypted_keypair)

    user_id, username, signing_pk, is_admin, _, token_epoch, encrypted_keypair = row
    current_key = None

    try:
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                await consume_signed_challenge(
                    cur, config, req.username, req.challenge, req.signature, signing_pk
                )
                await remember_owner_network(
                    cur, user_id, _request_network_mac(request, config), config
                )
                if req.current_key_signature:
                    member = (getattr(await team_log.load_state(cur), "members", None) or {}).get(user_id)
                    if member is not None and verify_current_key_proof(
                        challenge_bytes, bytes.fromhex(req.current_key_signature),
                        bytes.fromhex(member.signing_pk),
                    ):
                        current_key = member.signing_pk
    except HTTPException as exc:
        if exc.detail != "Authentication failed":
            raise
        renamed = await _login_renamed_account(db, config, req, request)
        if renamed is not None:
            user_id, username, is_admin, token_epoch, encrypted_keypair = renamed
        elif await _signed_by_rotated_key(db, user_id, req.challenge, req.signature):
            # Another device of this account rotated the identity key: this
            # one has to take the new keypair over with the password (no token).
            raise ApiError(409, IDENTITY_KEY_ROTATED, "Identity key rotated") from exc
        else:
            raise

    return await _issue_login(db, jwt_mgr, config, user_id, username, is_admin,
                              token_epoch, encrypted_keypair, current_key)


async def _issue_login(db, jwt_mgr, config, user_id, username, is_admin,
                       token_epoch, encrypted_keypair, current_key=None) -> VerifyResponse:
    now_ms = int(time.time() * 1000)

    # Create JWT
    token = create_jwt(
        jwt_mgr.signing_key,
        user_id,
        username,
        bool(is_admin),
        config.jwt_expiry_seconds,
        token_epoch=token_epoch or 0,
        current_key=current_key,
    )

    # Update sync_state activity
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO sync_state (user_id, last_activity) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE last_activity = VALUES(last_activity)",
                (user_id, now_ms),
            )
        await conn.commit()

    return VerifyResponse(
        token=token,
        user_id=user_id,
        username=username,
        is_admin=bool(is_admin),
        key_material_hash=(
            hashlib.sha256(bytes(encrypted_keypair)).hexdigest()
            if encrypted_keypair is not None else None
        ),
    )


@router.post("/refresh")
async def auth_refresh(
    req: RefreshRequest,
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
    config: ServerConfig = Depends(get_config),
    user: dict = Depends(get_current_user),
):
    """Refresh JWT after a fresh, one-time Ed25519 challenge proof."""
    if user.get("scope"):
        raise HTTPException(status_code=403, detail="Scoped tokens cannot be refreshed")

    now_ms = int(time.time() * 1000)

    # Consume the challenge in the same transaction that revokes the old
    # token. A concurrent replay hits the spent_challenges primary key.
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT signing_pk, username, is_admin, status, token_epoch "
                "FROM users WHERE id = %s",
                (user["sub"],),
            )
            current_user = await cur.fetchone()
            if not current_user or current_user[3] != "active":
                raise HTTPException(status_code=401, detail="User is not active")
            await consume_signed_challenge(
                cur, config, current_user[1], req.challenge, req.signature,
                current_user[0], error="Refresh authentication failed",
            )
            await cur.execute(
                "INSERT IGNORE INTO revoked_tokens (token_hash, revoked_at, expires_at) "
                "VALUES (%s, %s, %s)",
                (token_revocation_key(user), now_ms, user["exp"] * 1000),
            )

    new_token = create_jwt(
        jwt_mgr.signing_key,
        user["sub"],
        current_user[1],
        bool(current_user[2]),
        config.jwt_expiry_seconds,
        token_epoch=current_user[4] or 0,
    )
    return {"token": new_token}


@router.post("/logout")
async def auth_logout(
    db: Database = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Invalidate the current JWT — add its jti to revoked_tokens."""
    # Revoke the token from the Authorization header (not a body token)
    token_h = token_revocation_key(user)
    exp = user.get("exp", int(time.time()) + 3600)
    now_ms = int(time.time() * 1000)

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT IGNORE INTO revoked_tokens (token_hash, revoked_at, expires_at) "
                "VALUES (%s, %s, %s)",
                (token_h, now_ms, exp * 1000),
            )
        await conn.commit()

    return {"status": "ok"}


PROVISIONING_TOKEN_TTL_MS = 10 * 60 * 1000


@router.post("/provisioning-token", response_model=ProvisioningTokenResponse)
async def create_provisioning_token(
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
):
    """Mint the one-time token a new device scans (QR) to fetch its keypair.

    The keypair stays wrapped by the master password, so the token alone only
    saves typing the username; it is single use and lives 10 minutes.
    """
    token = secrets.token_urlsafe(32)
    now_ms = int(time.time() * 1000)
    expires_at = now_ms + PROVISIONING_TOKEN_TTL_MS
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO provisioning_tokens "
                "(token_hash, user_id, created_at, expires_at, is_used) "
                "VALUES (%s, %s, %s, %s, 0)",
                (hashlib.sha256(token.encode("utf-8")).hexdigest(), user["sub"],
                 now_ms, expires_at),
            )
        await conn.commit()
    return ProvisioningTokenResponse(
        token=token, username=user["username"], expires_at=expires_at
    )


@router.post("/provision", response_model=ProvisionResponse)
async def auth_provision(
    req: ProvisionRequest,
    db: Database = Depends(get_db),
):
    """Device provisioning: exchange token for encrypted_keypair + salt.

    No JWT required — token is one-time, 10min expiry.
    """
    token_h = hashlib.sha256(req.token.encode("utf-8")).hexdigest()
    now_ms = int(time.time() * 1000)

    # H6: single locked transaction — read token FOR UPDATE, verify username
    # BEFORE consuming (so a wrong-username attempt does not burn the token),
    # then atomically consume with an is_used=0 predicate + rowcount guard so
    # two concurrent redemptions cannot both succeed.
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT user_id, expires_at, is_used FROM provisioning_tokens "
                "WHERE token_hash = %s FOR UPDATE",
                (token_h,),
            )
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Invalid token")

            user_id, expires_at, is_used = row
            if is_used:
                raise HTTPException(status_code=410, detail="Token already used")
            if now_ms > expires_at:
                raise HTTPException(status_code=410, detail="Token expired")

            # Verify the target user BEFORE consuming the one-time token.
            await cur.execute(
                "SELECT username, encrypted_keypair, argon2_salt, argon2_params FROM users "
                "WHERE id = %s AND status = 'active'",
                (user_id,),
            )
            urow = await cur.fetchone()
            if not urow or urow[0] != req.username:
                raise HTTPException(status_code=404, detail="User not found")

            # Atomic single-use consume.
            await cur.execute(
                "UPDATE provisioning_tokens SET is_used = 1 "
                "WHERE token_hash = %s AND is_used = 0",
                (token_h,),
            )
            if cur.rowcount != 1:
                raise HTTPException(status_code=410, detail="Token already used")

    return ProvisionResponse(
        encrypted_keypair=urow[1].hex() if urow[1] else "",
        argon2_salt=urow[2].hex() if urow[2] else "",
        user_id=user_id,
        argon2_params=account_kdf_params(urow[3]),
    )


_TRUSTED_NETS_KEPT = 16


def _client_network(client_ip: str) -> str:
    """The unit the address limits count: an IPv6 client by its /64 (one
    host picks addresses from it freely), an IPv4 client by its address."""
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return client_ip
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


_UNLOCK_HINT = (
    "Or log in from a network this account used before, or with a one-time unlock "
    "code: any admin issues one with 'sezam unlock-recovery <user-id>' (a lone admin "
    "for their own account from a device that is still signed in)."
)


def _trusted_entries(raw) -> list[dict]:
    """Owner networks as {"n": net HMAC, "d": days seen, "t": last seen ms,
    "s": wrong proofs on the locked name since its last correct one (if any)}.
    The older format (a list of HMACs, most recent first) reads as one day each."""
    try:
        items = json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return []
    if not isinstance(items, list):
        return []
    entries = []
    for item in items:
        if isinstance(item, str):
            entries.append({"n": item, "d": 1, "t": 0})
        elif isinstance(item, dict) and isinstance(item.get("n"), str):
            entry = {"n": item["n"], "d": int(item.get("d") or 1), "t": int(item.get("t") or 0)}
            if item.get("s"):
                entry["s"] = int(item["s"])
            entries.append(entry)
    return entries


def _trusted_nets(raw) -> list[str]:
    return [e["n"] for e in _trusted_entries(raw)]


_DAY_MS = 86_400_000
_TRUSTED_NET_IDLE_MS = 180 * _DAY_MS


def _touch_trusted_net(raw, net_mac: str, now_ms: int) -> Optional[str]:
    """The list with ``net_mac`` seen now; None when nothing changes (seen today).

    Review e4cd15a (low): only the 8 most recent networks were kept, so a
    phone on mobile data (a new /64 every few hours) pushed the owner's home
    and office networks out within a day. Each network now counts the days it
    was seen; a full list drops a network idle for 180 days first, then the
    one seen on the fewest days (the oldest among those)."""
    entries = _trusted_entries(raw)
    entry = next((e for e in entries if e["n"] == net_mac), None)
    if entry is not None:
        if now_ms - entry["t"] < _DAY_MS / 2:
            return None
        entry["d"] += 1
        entry["t"] = now_ms
    else:
        entries.append({"n": net_mac, "d": 1, "t": now_ms})
        while len(entries) > _TRUSTED_NETS_KEPT:
            entries.remove(min(
                (e for e in entries if e["n"] != net_mac),
                key=lambda e: (now_ms - e["t"] < _TRUSTED_NET_IDLE_MS, e["d"], e["t"]),
            ))
    return json.dumps(entries)


_TRUSTED_NET_STRIKES = 3


def _strike_trusted_net(raw, net_mac: str) -> str:
    """A wrong proof on a locked name from an owner network.

    Review e4cd15a (low) took the trust at the first one, so during an attack
    the owner's single typo at home cost home its trust, and the attackers'
    ration then refused the owner there too (review 526419e N4). A network
    keeps it until _TRUSTED_NET_STRIKES wrong proofs with no correct one in
    between; a key thief there gets no more checked guesses than that.
    """
    entries = []
    for entry in _trusted_entries(raw):
        if entry["n"] == net_mac:
            entry["s"] = entry.get("s", 0) + 1
            if entry["s"] >= _TRUSTED_NET_STRIKES:
                continue
        entries.append(entry)
    return json.dumps(entries)


def _clear_strikes(raw, net_mac: str) -> Optional[str]:
    """The list without ``net_mac``'s wrong proofs; None if it had none."""
    entries = _trusted_entries(raw)
    entry = next((e for e in entries if e["n"] == net_mac), None)
    if entry is None or "s" not in entry:
        return None
    del entry["s"]
    return json.dumps(entries)


async def remember_owner_network(
    cur, user_id: str, net_mac: str, config: Optional[ServerConfig] = None
) -> None:
    """Capability run 88: a network the owner proved itself from (signed
    device login, registration, recovery) skips the locked-name ration, so
    attackers filling it cannot refuse the owner there. Most recent first.

    Review e4cd15a (low): a signed login proves the identity key only, which
    a key thief has too. With ``config`` (the signed login) a name locked by
    wrong passwords gains no network, so the thief cannot re-add networks the
    lock took away (see auth_recover)."""
    await cur.execute(
        "SELECT recovery_trusted_nets, recovery_locked, last_recovery_attempt "
        "FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    row = await cur.fetchone()
    if row and config is not None and row[1] and not (
        row[2] and int(time.time() * 1000) - row[2] >= config.recovery_lock_seconds * 1000
    ):
        return
    stored = _touch_trusted_net(row[0] if row else None, net_mac, int(time.time() * 1000))
    if stored is None:
        return
    await cur.execute(
        "UPDATE users SET recovery_trusted_nets = %s WHERE id = %s", (stored, user_id)
    )


def next_failure_state(
    config: ServerConfig, now_ms: int, recovery_locked, recovery_attempts,
    last_recovery_attempt, recovery_attempts_hour,
) -> tuple[int, int, Optional[int], int]:
    """Per-name counters after one wrong password proof.

    The name lock expires on its own (admins can also clear it immediately);
    while it holds, failures do not extend it. Review d615826: failures a
    quiet lock period old are forgotten whether or not they locked the name,
    as the cleanup forgets an unknown name's shadow counters by then;
    otherwise the next wrong proof locked only real names.
    """
    if last_recovery_attempt and (
        now_ms - last_recovery_attempt >= config.recovery_lock_seconds * 1000
    ):
        recovery_locked = 0
        recovery_attempts = 0
    if not last_recovery_attempt or last_recovery_attempt <= now_ms - 3600 * 1000:
        recovery_attempts_hour = 0
    if recovery_locked:
        return (
            recovery_attempts or 0, recovery_attempts_hour or 0, last_recovery_attempt, 1
        )
    total = (recovery_attempts or 0) + 1
    return (
        total, (recovery_attempts_hour or 0) + 1, now_ms,
        1 if total >= config.recovery_max_total else 0,
    )


async def record_wrong_account_proof(cur, config: ServerConfig, user_id: str) -> bool:
    """Count a wrong current-password proof against the account (review
    688edcb K1: replacing key material proves the password, and guessing it
    there is bounded like /recover). Returns True when the name is locked."""
    now_ms = int(time.time() * 1000)
    await cur.execute(
        "SELECT recovery_locked, recovery_attempts, last_recovery_attempt, "
        "recovery_attempts_hour FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    row = await cur.fetchone()
    if not row:
        return False
    total, hour, attempt_at, locked = next_failure_state(config, now_ms, *row)
    await cur.execute(
        "UPDATE users SET recovery_attempts = %s, recovery_attempts_hour = %s, "
        "last_recovery_attempt = %s, recovery_locked = %s WHERE id = %s",
        (total, hour, attempt_at, locked, user_id),
    )
    if locked:
        # Review e4cd15a (low): a locked name verifies one proof per window
        # here too; before, the identity key holder kept guessing unlimited.
        slot_key = key_gate_slot_key(user_id)
        await cur.execute(
            "INSERT INTO recovery_probe_slots (slot_key, probe_at) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE probe_at = VALUES(probe_at)",
            (slot_key, now_ms),
        )
    return bool(locked)


def key_gate_slot_key(user_id: str) -> str:
    return hashlib.sha256(f"key-material-gate:{user_id}".encode()).hexdigest()


async def key_gate_wait_s(cur, config: ServerConfig, user_id: str, now_ms: int,
                          recovery_locked, last_recovery_attempt) -> int:
    """Seconds until a locked name's K1 gate verifies its next proof (0: now)."""
    lock_live = bool(recovery_locked) and not (
        last_recovery_attempt
        and now_ms - last_recovery_attempt >= config.recovery_lock_seconds * 1000
    )
    if not lock_live:
        return 0
    await cur.execute(
        "SELECT probe_at FROM recovery_probe_slots WHERE slot_key = %s",
        (key_gate_slot_key(user_id),),
    )
    slot = await cur.fetchone()
    window_ms = config.recovery_locked_probe_seconds * 1000
    if not slot or now_ms - slot[0] >= window_ms:
        return 0
    return max(1, (slot[0] + window_ms - now_ms + 999) // 1000)


@router.post("/recover", response_model=RecoverResponse)
async def auth_recover(
    req: RecoverRequest,
    request: Request,
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Password-based recovery (Cesta B).

    Lockout review #7: the per-name limits (3/h, 10 total → locked) used to be
    checked BEFORE the proof, so anyone who knew a username locked its owner
    out for a day with ten random proofs. The proof is now verified first.

    Review 688edcb V2: the address limit refused even a correct proof, which
    locked out everyone behind one NAT or proxy, while the name lock no
    longer bounded guessing from many addresses. Now the address limit only
    shapes the answer to wrong proofs (429), and a locked name verifies per
    ``recovery_locked_probe_seconds`` window one proof from each network and
    at most ``recovery_locked_probes_per_window`` from all networks together
    (429 with Retry-After beyond that, nothing verified). The owner's own
    networks (registration, signed device logins, past recoveries) are not
    rationed; from any other network, that many attacking networks can make
    the owner wait for an admin unlock (capability run 88).
    """
    now_ms = int(time.time() * 1000)
    one_hour_ago_ms = now_ms - 3600 * 1000
    client_ip = request.client.host if request.client else "unknown"
    ip_hmac = compute_ip_hmac(config.hmac_server_secret, _client_network(client_ip))

    # H6: hold row locks (SELECT ... FOR UPDATE) for the whole
    # read-modify-write so concurrent recovery attempts cannot both slip past
    # the per-address and 10-total limits. Counter mutations are committed
    # explicitly so a failed attempt still counts even though we then return
    # an HTTP error (the transaction is NOT rolled back in that case).
    # Lock order is always address row, then name row.
    async with db.acquire() as conn:
        await conn.begin()
        committed = False
        try:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO recovery_ip_limits "
                    "(ip_hmac, window_started_at, failure_count) VALUES (%s, %s, 0) "
                    "ON DUPLICATE KEY UPDATE ip_hmac = ip_hmac",
                    (ip_hmac, now_ms),
                )
                await cur.execute(
                    "SELECT window_started_at, failure_count FROM recovery_ip_limits "
                    "WHERE ip_hmac = %s FOR UPDATE",
                    (ip_hmac,),
                )
                ip_window_started_at, ip_failures = await cur.fetchone()
                if ip_window_started_at <= one_hour_ago_ms:
                    ip_window_started_at, ip_failures = now_ms, 0
                ip_exhausted = ip_failures >= config.recovery_ip_max_failures_per_hour

                await cur.execute(
                    "SELECT id, verify_salt, auth_proof_hash, encrypted_keypair, argon2_salt, "
                    "recovery_locked, recovery_attempts, last_recovery_attempt, recovery_attempts_hour, "
                    "argon2_params, username, status, recovery_trusted_nets, "
                    "recovery_unlock_hash, recovery_unlock_until "
                    "FROM users WHERE username = %s FOR UPDATE",
                    (req.username,),
                )
                row = await cur.fetchone()

                # Exact match only (case-insensitive collation aliases names).
                if row and row[10] != req.username:
                    row = None
                inactive = None
                if row and row[11] != "active":
                    inactive, row = row, None
                # Review 2052248: a name without a usable account used to
                # answer 401 forever while a real one escalated to 429/423 —
                # an enumeration oracle. It now runs the same counters on a
                # shadow row keyed by a MAC of the name, and never verifies.
                unlock_pass = False
                if row and row[1] and row[2]:
                    user_id, verify_salt, stored_hash, encrypted_keypair, argon2_salt, \
                        recovery_locked, recovery_attempts, last_recovery_attempt, \
                        recovery_attempts_hour, stored_kdf, _, _, trusted_raw, \
                        unlock_hash, unlock_until = row
                    limit_table, limit_key, limit_id = "users", "id", user_id
                    trusted_nets = _trusted_nets(trusted_raw)
                    unlock_pass = bool(
                        req.unlock_code and unlock_hash and unlock_until
                        and unlock_until > now_ms
                        and hmac.compare_digest(
                            unlock_code_hash(req.unlock_code), unlock_hash
                        )
                    )
                else:
                    trusted_nets = []
                    stored_hash = None
                    verify_salt = os.urandom(32)
                    limit_table, limit_key = "recovery_name_limits", "name_hmac"
                    limit_id = unknown_name_mac(
                        config.hmac_server_secret, req.username
                    ).hex()
                    await cur.execute(
                        "INSERT INTO recovery_name_limits "
                        "(name_hmac, recovery_attempts, recovery_attempts_hour, "
                        "last_recovery_attempt, recovery_locked) VALUES (%s, %s, %s, %s, %s) "
                        "ON DUPLICATE KEY UPDATE name_hmac = name_hmac",
                        (limit_id, 0, 0, None, 0),
                    )
                    await cur.execute(
                        "SELECT recovery_locked, recovery_attempts, last_recovery_attempt, "
                        "recovery_attempts_hour FROM recovery_name_limits "
                        "WHERE name_hmac = %s FOR UPDATE",
                        (limit_id,),
                    )
                    recovery_locked, recovery_attempts, last_recovery_attempt, \
                        recovery_attempts_hour = await cur.fetchone()

                # Review 688edcb V2: a correct proof is never refused for its
                # address, so the name brakes guessing from many addresses: a
                # locked name verifies one proof per window from each network
                # and a few from all networks together.
                # Capability run 83: the window used to be one slot shared by
                # every network, so an attacker taking it the moment it opened
                # refused the owner's correct proof from any other network.
                # Its owner's own networks (remember_owner_network) skip the
                # window, unless that address is guessing itself.
                lock_live = bool(recovery_locked) and not (
                    last_recovery_attempt
                    and now_ms - last_recovery_attempt >= config.recovery_lock_seconds * 1000
                )
                trusted = ip_hmac in trusted_nets and not ip_exhausted
                # Review e4cd15a: the admin's one-time unlock code skips the
                # name's shared ration, which attackers from a few networks
                # use up again right after the admin unlock; the code holder's
                # own network keeps its one-proof-per-window slot.
                rationed = lock_live and not trusted and not unlock_pass
                window_ms = config.recovery_locked_probe_seconds * 1000
                slot_key = hashlib.sha256(f"{limit_id}:{ip_hmac}".encode()).hexdigest()
                if lock_live and not trusted:
                    slot = await _lock_probe_slot(cur, slot_key)
                    if slot and now_ms - slot[0] < window_ms:
                        await conn.commit()
                        committed = True
                        wait_s = max(1, (slot[0] + window_ms - now_ms + 999) // 1000)
                        raise HTTPException(
                            status_code=429,
                            detail="Too many recovery attempts for this account from "
                            f"this network. Try again in {wait_s} s. {_UNLOCK_HINT}",
                            headers={"Retry-After": str(wait_s)},
                        )
                    # Capability run 85: per-network slots alone let N networks
                    # make N checked guesses per window. All untrusted networks
                    # together get at most recovery_locked_probes_per_window:
                    # fewer attacking networks (each bound to its own slot)
                    # cannot take the owner's turn; that many can (run 88), and
                    # then only the owner's own networks or an admin get in.
                if rationed:
                    await cur.execute(
                        "INSERT INTO recovery_name_rations "
                        "(limit_id, window_started_at, checked_count) VALUES (%s, %s, 0) "
                        "ON DUPLICATE KEY UPDATE limit_id = limit_id",
                        (limit_id, now_ms),
                    )
                    await cur.execute(
                        "SELECT window_started_at, checked_count FROM recovery_name_rations "
                        "WHERE limit_id = %s FOR UPDATE",
                        (limit_id,),
                    )
                    ration_started_at, ration_checked = await cur.fetchone()
                    if now_ms - ration_started_at >= window_ms:
                        ration_started_at, ration_checked = now_ms, 0
                    if ration_checked >= config.recovery_locked_probes_per_window:
                        await conn.commit()
                        committed = True
                        wait_s = max(1, (ration_started_at + window_ms - now_ms + 999) // 1000)
                        raise HTTPException(
                            status_code=429,
                            detail="Too many recovery attempts for this account. Try again "
                            f"in {wait_s} s. {_UNLOCK_HINT}",
                            headers={"Retry-After": str(wait_s)},
                        )

                # The proof is verified before the name lock applies, so the
                # lock never refuses the owner's correct proof (lockout
                # review #7); only the rations above can delay it.
                auth_proof_bytes = bytes.fromhex(req.auth_proof)
                computed_hash = compute_auth_proof_hash(verify_salt, auth_proof_bytes)

                # A pending (not yet approved) account polled with its own
                # correct proof is not a guess: answer the same 401 but count
                # nothing, or the owner's approval wait exhausts the address
                # limit and keeps them (and their NAT) out once approved.
                if inactive and inactive[1] and inactive[2] and hmac.compare_digest(
                    compute_auth_proof_hash(inactive[1], auth_proof_bytes), inactive[2]
                ):
                    await conn.commit()
                    committed = True
                    raise HTTPException(status_code=401, detail="Recovery failed")

                if stored_hash is None or not hmac.compare_digest(computed_hash, stored_hash):
                    new_total, new_hour, attempt_at, locked = next_failure_state(
                        config, now_ms, recovery_locked, recovery_attempts,
                        last_recovery_attempt, recovery_attempts_hour,
                    )
                    await cur.execute(
                        f"UPDATE {limit_table} SET recovery_attempts = %s, "
                        f"recovery_attempts_hour = %s, last_recovery_attempt = %s, "
                        f"recovery_locked = %s WHERE {limit_key} = %s",
                        (new_total, new_hour, attempt_at, locked, limit_id),
                    )
                    if locked:  # this network waits a window for its next proof
                        await cur.execute(
                            "INSERT INTO recovery_probe_slots (slot_key, probe_at) "
                            "VALUES (%s, %s) ON DUPLICATE KEY UPDATE probe_at = VALUES(probe_at)",
                            (slot_key, now_ms),
                        )
                    if locked and ip_hmac in trusted_nets:
                        # Review e4cd15a (low): a network that keeps guessing
                        # a locked name is not the owner's (a key thief's
                        # signed login made it trusted): it loses the trust,
                        # but not at the owner's first typo (526419e N4).
                        await cur.execute(
                            "UPDATE users SET recovery_trusted_nets = %s WHERE id = %s",
                            (_strike_trusted_net(trusted_raw, ip_hmac), user_id),
                        )
                    if rationed:
                        await cur.execute(
                            "UPDATE recovery_name_rations SET window_started_at = %s, "
                            "checked_count = %s WHERE limit_id = %s",
                            (ration_started_at, ration_checked + 1, limit_id),
                        )
                    await cur.execute(
                        "UPDATE recovery_ip_limits SET window_started_at = %s, "
                        "failure_count = %s WHERE ip_hmac = %s",
                        (ip_window_started_at, ip_failures + 1, ip_hmac),
                    )
                    await conn.commit()
                    committed = True
                    if locked:
                        raise HTTPException(status_code=423, detail="Recovery locked. Contact admin.")
                    if ip_exhausted:
                        raise HTTPException(
                            status_code=429,
                            detail="Too many recovery attempts from this address. Try again later.",
                        )
                    raise HTTPException(status_code=401, detail="Recovery failed")

                # Success — the owner proved the password: reset the name
                # counters and any lock a stranger's wrong proofs set.
                touched = _touch_trusted_net(trusted_raw, ip_hmac, now_ms)
                touched = _clear_strikes(touched or trusted_raw, ip_hmac) or touched
                await cur.execute(
                    "UPDATE users SET recovery_attempts = 0, recovery_attempts_hour = 0, "
                    "recovery_locked = 0, last_recovery_attempt = %s, "
                    "recovery_trusted_nets = %s, recovery_unlock_hash = %s, "
                    "recovery_unlock_until = %s WHERE id = %s",
                    (now_ms, touched or trusted_raw, None, None, user_id),
                )
                # Lockout review N2: an account stored without params adopts
                # the ones this matching proof was derived with, so every
                # other device stops guessing (once; stored params never move;
                # the row is locked FOR UPDATE since it was read).
                if not stored_kdf and req.argon2_params is not None:
                    stored_kdf = json.dumps(req.argon2_params.model_dump(), sort_keys=True)
                    await cur.execute(
                        "UPDATE users SET argon2_params = %s WHERE id = %s",
                        (stored_kdf, user_id),
                    )
                # Read under the users row lock: a rotation push also locks
                # it, so this epoch belongs to the keypair returned below.
                await cur.execute(
                    "SELECT key_epoch FROM sync_state WHERE user_id = %s", (user_id,)
                )
                epoch_row = await cur.fetchone()
                key_epoch = int(epoch_row[0]) if epoch_row else 0
                await conn.commit()
                committed = True
        except BaseException:
            if not committed:
                await conn.rollback()
            raise

    return RecoverResponse(
        encrypted_keypair=encrypted_keypair.hex() if encrypted_keypair else "",
        argon2_salt=argon2_salt.hex() if argon2_salt else "",
        user_id=user_id,
        argon2_params=account_kdf_params(stored_kdf),
        key_epoch=key_epoch,
    )


# ── Keypair upload (separate router prefix) ──

keypair_router = APIRouter(prefix="/api/me", tags=["auth"])


@keypair_router.put("/keypair")
async def upload_keypair(
    req: KeypairUploadRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(get_keypair_upload_user),
    config: ServerConfig = Depends(get_config),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
):
    """Upload encrypted keypair + salts + auth_proof.

    Onboarding JWT (scope=keypair_upload): only the FIRST upload.
    Full JWT: also only when the account has no key material yet (finishing
    an interrupted onboarding), with a fresh challenge signed by the
    account's signing key; every older token is then revoked via token_epoch
    and a fresh token is returned. Replacing key material (password change,
    recovery) goes through the key_rotation of an epoch-advancing sync push.
    Server computes auth_proof_hash = HMAC-SHA256(verify_salt, auth_proof).
    """
    user_id = user["sub"]
    kdf_json = require_kdf_params_json(req.argon2_params)

    # Scoped JWT: only keypair_upload scope allowed
    scope = user.get("scope")
    if scope and scope != "keypair_upload":
        raise HTTPException(status_code=403, detail="Invalid token scope")

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT username, signing_pk, encrypted_keypair, is_admin, token_epoch "
                "FROM users WHERE id = %s",
                (user_id,),
            )
            account = await cur.fetchone()
    if not account:
        raise HTTPException(status_code=401, detail="User is not active")
    username, signing_pk, existing_keypair, is_admin, token_epoch = account
    if scope:
        if existing_keypair:
            raise HTTPException(
                status_code=403, detail="Onboarding token cannot replace key material"
            )
    elif not req.challenge or not req.signature:
        raise HTTPException(
            status_code=401, detail="Signed challenge required to replace key material"
        )
    elif existing_keypair:
        # Review 2052248 #1: existing key material changes only together with
        # the DEK rewrap and a key_epoch advance (POST /api/sync key_rotation),
        # otherwise other devices never notice and DEKs stay under a key the
        # server no longer vouches for.
        raise HTTPException(
            status_code=409,
            detail="Key material changes only with a key-epoch advancing sync push",
        )

    # Generate server-side verify_salt
    verify_salt = os.urandom(32)
    auth_proof_bytes = bytes.fromhex(req.auth_proof)
    auth_proof_hash = compute_auth_proof_hash(verify_salt, auth_proof_bytes)

    new_epoch = int(token_epoch or 0) + (0 if scope else 1)
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT encrypted_keypair, signing_pk, status, token_epoch FROM users WHERE id = %s FOR UPDATE",
                (user_id,),
            )
            current = await cur.fetchone()
            if (not current or current[2] == "revoked" or current[1] != signing_pk
                    or int(current[3] or 0) != int(token_epoch or 0)):
                raise HTTPException(status_code=401, detail="Account changed during keypair upload")
            if current[0]:
                raise HTTPException(status_code=409, detail="Key material already uploaded")
            if not scope:
                await consume_signed_challenge(
                    cur, config, username, req.challenge, req.signature, signing_pk
                )
            await cur.execute(
                "UPDATE users SET "
                "encrypted_keypair = %s, argon2_salt = %s, auth_salt = %s, "
                "verify_salt = %s, auth_proof_hash = %s, argon2_params = %s, "
                "token_epoch = %s "
                "WHERE id = %s",
                (
                    bytes.fromhex(req.encrypted_keypair),
                    bytes.fromhex(req.argon2_salt),
                    bytes.fromhex(req.auth_salt),
                    verify_salt,
                    auth_proof_hash,
                    kdf_json,
                    new_epoch,
                    user_id,
                ),
            )

    if scope:
        return {"status": "ok"}
    token = create_jwt(
        jwt_mgr.signing_key,
        user_id,
        username,
        bool(is_admin),
        config.jwt_expiry_seconds,
        token_epoch=new_epoch,
    )
    return {"status": "ok", "token": token}


@keypair_router.put("/kdf-params")
async def backfill_kdf_params(
    req: KdfParamsBackfillRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
    config: ServerConfig = Depends(get_config),
):
    """Store the KDF params of an account kept without them (lockout review N2).

    Accounts created before per-account params have NULL and are reported
    with the 128 MiB default, which opens nothing for an account created with
    other params. A device that unlocks the key material locally knows the
    real ones; a signed challenge proves it holds the account keypair. The
    salt must be the current one, and params once stored never change here
    (only a key rotation replaces them).
    """
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT username, signing_pk, argon2_salt, argon2_params, status "
                "FROM users WHERE id = %s FOR UPDATE",
                (user["sub"],),
            )
            row = await cur.fetchone()
            if not row or row[4] != "active":
                raise HTTPException(status_code=401, detail="User is not active")
            username, signing_pk, argon2_salt, stored_kdf, _ = row
            await consume_signed_challenge(
                cur, config, username, req.challenge, req.signature, signing_pk
            )
            if not argon2_salt or bytes(argon2_salt) != bytes.fromhex(req.argon2_salt):
                raise HTTPException(
                    status_code=409, detail="KDF params belong to other key material"
                )
            kdf_json = json.dumps(req.argon2_params.model_dump(), sort_keys=True)
            if stored_kdf:
                if account_kdf_params(stored_kdf) != json.loads(kdf_json):
                    raise HTTPException(
                        status_code=409, detail="The account already has other KDF params"
                    )
                return {"status": "ok", "argon2_params": account_kdf_params(stored_kdf)}
            await cur.execute(
                "UPDATE users SET argon2_params = %s WHERE id = %s", (kdf_json, user["sub"])
            )
    return {"status": "ok", "argon2_params": json.loads(kdf_json)}


async def _lock_probe_slot(cur, slot_key: str):
    """The slot row, locked; None when it never held a probe.

    Review 7c10379 (R7-H): SELECT ... FOR UPDATE of a slot that did not exist
    took a gap lock, and two names' first probes in the same gap deadlocked
    on their INSERTs (MariaDB: 12 of 20 parallel archive probes, 500). The
    row is created first, with an exclusive lock, as the limiters do (398b8fa);
    probe_at 0 is a window long past.
    """
    await cur.execute(
        "INSERT INTO recovery_probe_slots (slot_key, probe_at) VALUES (%s, 0) "
        "ON DUPLICATE KEY UPDATE slot_key = slot_key",
        (slot_key,),
    )
    await cur.execute(
        "SELECT probe_at FROM recovery_probe_slots WHERE slot_key = %s FOR UPDATE", (slot_key,)
    )
    slot = await cur.fetchone()
    return slot if slot and slot[0] else None


async def _take_archive_probe_slot(cur, conn, config: ServerConfig, user_id: str, now_ms: int):
    window_ms = config.recovery_locked_probe_seconds * 1000
    slot_key = hashlib.sha256(f"key-material-archive:{user_id}".encode()).hexdigest()
    slot = await _lock_probe_slot(cur, slot_key)
    if slot and now_ms - slot[0] < window_ms:
        await conn.commit()
        wait_s = max(1, (slot[0] + window_ms - now_ms + 999) // 1000)
        raise HTTPException(
            status_code=429,
            detail=f"The account is locked after wrong passwords; try again in {wait_s} s.",
            headers={"Retry-After": str(wait_s)},
        )
    await cur.execute(
        "INSERT INTO recovery_probe_slots (slot_key, probe_at) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE probe_at = VALUES(probe_at)",
        (slot_key, now_ms),
    )


async def _key_material_archive_op(
    db: Database, config: ServerConfig, user_id: str, auth_proof_hex: str, purge: bool
) -> list[dict]:
    """Review 688edcb: the archive (lockout review #11) keeps the account
    keypair wrapped under OLD passwords - after a password change because the
    old one leaked, a leaked database still opens with it. The owner proves
    the CURRENT password to read the generations (fallback when the current
    material cannot be opened) or to delete them all. A wrong proof counts
    like a wrong /recover proof, so this is no cheaper guessing oracle."""
    now_ms = int(time.time() * 1000)
    cutoff_ms = now_ms - config.key_material_archive_days * 86_400_000
    async with db.acquire() as conn:
        await conn.begin()
        try:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT verify_salt, auth_proof_hash, recovery_locked, recovery_attempts, "
                    "last_recovery_attempt, recovery_attempts_hour, status "
                    "FROM users WHERE id = %s FOR UPDATE",
                    (user_id,),
                )
                row = await cur.fetchone()
                if not row or row[6] != "active" or not row[0] or not row[1]:
                    raise HTTPException(status_code=403, detail="No account password to prove")
                verify_salt, stored_hash, locked, attempts, last_attempt, attempts_hour, _ = row
                lock_live = bool(locked) and not (
                    last_attempt
                    and now_ms - last_attempt >= config.recovery_lock_seconds * 1000
                )
                if lock_live:
                    # Review e4cd15a: a stranger's /recover guesses lock the
                    # name, which used to refuse the owner's correct proof
                    # here, so the generations under a leaked password stayed.
                    # A locked name now verifies one proof per window on this
                    # endpoint (reached only with the account's own token).
                    await _take_archive_probe_slot(cur, conn, config, user_id, now_ms)
                computed = compute_auth_proof_hash(
                    bytes(verify_salt), bytes.fromhex(auth_proof_hex)
                )
                if not hmac.compare_digest(computed, stored_hash):
                    new_total, new_hour, attempt_at, new_locked = next_failure_state(
                        config, now_ms, locked, attempts, last_attempt, attempts_hour
                    )
                    await cur.execute(
                        "UPDATE users SET recovery_attempts = %s, recovery_attempts_hour = %s, "
                        "last_recovery_attempt = %s, recovery_locked = %s WHERE id = %s",
                        (new_total, new_hour, attempt_at, new_locked, user_id),
                    )
                    await conn.commit()
                    if lock_live:
                        raise HTTPException(
                            status_code=423, detail="Recovery locked. Contact admin."
                        )
                    raise ApiError(403, WRONG_CURRENT_PASSWORD, "Wrong current account password")
                await cur.execute(
                    "SELECT id, key_epoch, encrypted_keypair, argon2_salt, argon2_params, "
                    "auth_salt, archived_at FROM user_key_material_archive WHERE user_id = %s",
                    (user_id,),
                )
                rows = sorted(await cur.fetchall(), key=lambda r: (r[6], r[0]), reverse=True)
                if purge:
                    for archive_id, *_ in rows:
                        await cur.execute(
                            "DELETE FROM user_key_material_archive WHERE id = %s",
                            (archive_id,),
                        )
                    await conn.commit()
                    return [{"key_epoch": r[1], "archived_at": r[6]} for r in rows]
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise
    return [
        {
            "key_epoch": r[1],
            "encrypted_keypair": bytes(r[2]).hex(),
            "argon2_salt": bytes(r[3]).hex() if r[3] else "",
            "argon2_params": account_kdf_params(r[4]),
            "auth_salt": bytes(r[5]).hex() if r[5] else "",
            "archived_at": r[6],
        }
        for r in rows
        if r[6] >= cutoff_ms  # past retention: awaiting the cleanup, not served
    ]


@keypair_router.post("/key-material-archive")
async def read_key_material_archive(
    req: KeyMaterialArchiveRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
    config: ServerConfig = Depends(get_config),
):
    """The account's archived key material, newest first: each generation
    opens with the password it was wrapped under (obnova, review 688edcb)."""
    generations = await _key_material_archive_op(
        db, config, user["sub"], req.auth_proof, purge=False
    )
    return {"generations": generations}


@keypair_router.post("/key-material-archive/purge")
async def purge_key_material_archive(
    req: KeyMaterialArchiveRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
    config: ServerConfig = Depends(get_config),
):
    """Delete every archived generation (after changing a leaked password)."""
    purged = await _key_material_archive_op(
        db, config, user["sub"], req.auth_proof, purge=True
    )
    logger.info("User %s purged %d archived key material generations", user["sub"], len(purged))
    return {"status": "ok", "purged": len(purged)}
