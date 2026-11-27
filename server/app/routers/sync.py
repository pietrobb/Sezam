"""Sync endpoints — delta push/pull with server-assigned commit_seq.

Spec 8.2, 8.6:
  POST /api/sync       (delta push)
  GET  /api/sync       (delta pull)
  GET  /api/meta       (public metadata)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import weakref
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..auth import (
    compute_auth_proof_hash,
    create_jwt,
    generate_fake_salt,
    key_rotation_message,
    unknown_name_mac,
)
from .. import key_vouchers, personal_tree, team_log
from ..config import JWTKeyManager, ServerConfig
from ..database import Database, run_transaction
from ..dependencies import get_config, get_db, get_jwt_manager, get_rotation_user
from ..errors import (
    ATOMIC_BATCH_CONFLICT,
    COLLECTED_OBJECT,
    FOLDER_MOVE_CYCLE,
    FOLDER_KEY_MOVED,
    HISTORY_CHANGED,
    IDENTITY_KEY_RETIRED,
    IDENTITY_ROTATION_NEEDS_NEW_KEYS,
    KEY_CHANGE_MISSES_DEKS,
    KEY_CHANGE_NEEDS_PROOF,
    KEY_VOUCHERS_INCOMPLETE,
    REVOKED_ENVELOPE,
    TEAM_LOG_ENVELOPE,
    STALE_KEY_EPOCH,
    WRONG_CURRENT_PASSWORD,
    ApiError,
)
from .auth import (
    consume_signed_challenge,
    key_gate_wait_s,
    record_wrong_account_proof,
    require_kdf_params_json,
)
from .recovery import consume_org_recovery_proof
from ..models.schemas import (
    normalize_username,
    CLIENT_DEFAULT_ACCOUNT_KDFS,
    DEFAULT_ACCOUNT_KDF,
    MAX_STAGED_BYTES,
    MAX_STAGED_OBJECTS,
    StageRequest,
    StageResponse,
    MetaResponse,
    account_kdf_params,
    PullObject,
    PullResponse,
    PushObjectResult,
    PushRequest,
    PushResponse,
    SyncObject,
)

router = APIRouter(prefix="/api", tags=["sync"])


def _is_duplicate_key(exc: Exception) -> bool:
    """MariaDB ER_DUP_ENTRY (1062), or the test double's equivalent."""
    return (bool(exc.args) and exc.args[0] == 1062) or "Duplicate" in str(exc)


def _builds_on(obj: SyncObject, stored_type: str, version: int, payload_hash: str) -> bool:
    """The write names the server copy (version, payload_hash) as its base.

    docs/SYNC_SINGLE_SOURCE.md point 1: a folder or entry change must name
    both; without them it would overwrite whatever the server holds. Other
    objects keep the optional base.
    """
    if stored_type in ("node", "entry"):
        return obj.base_version == version and obj.base_payload_hash == payload_hash
    return (obj.base_version is None or obj.base_version == version) and (
        obj.base_payload_hash is None or obj.base_payload_hash == payload_hash
    )


OUTDATED_CLIENT_BASE = (
    "This app version sends changes in a form the server no longer accepts. "
    "Update the Sezam app."
)


def _refuse_base_by_version_only(objects) -> None:
    """Review 18c300f R16-M2: a folder or entry change naming its base by
    version only comes from an app before the base hash (d14d368, after
    "keep mine"). _builds_on refuses it, so the old app got 'conflict' on
    every push and showed nothing: 426, update the app. Current clients send
    both or none (a new object)."""
    for obj in objects:
        if (
            obj.object_type in ("node", "entry")
            and obj.base_version is not None
            and not obj.base_payload_hash
        ):
            raise HTTPException(status_code=426, detail=OUTDATED_CLIENT_BASE)


def _verify_sync_signature(
    obj: SyncObject, signature_bytes: bytes, signing_pk: bytes
) -> bool:
    """Verify Ed25519 signature on a sync object.

    Canonical signed data (spec 8.2):
      id(26B) || u8(len(object_type)) || object_type
      || parent_ref_or_zero(26B) || target_user_id_or_zero(26B)
      || u8(is_deleted) || u32be(version) || payload_hash(32B)
    """
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    # Build canonical signed data
    id_bytes = obj.id.encode("utf-8").ljust(26, b"\x00")[:26]
    ot_bytes = obj.object_type.encode("utf-8")
    parent_bytes = obj.parent_ref.encode("utf-8").ljust(26, b"\x00")[:26] if obj.parent_ref else b"\x00" * 26
    target_bytes = obj.target_user_id.encode("utf-8").ljust(26, b"\x00")[:26] if obj.target_user_id else b"\x00" * 26
    payload_hash_bytes = bytes.fromhex(obj.payload_hash)

    canonical = (
        id_bytes
        + bytes([len(ot_bytes)]) + ot_bytes
        + parent_bytes
        + target_bytes
        + bytes([obj.is_deleted])
        + obj.version.to_bytes(4, "big")
        + payload_hash_bytes
    )

    try:
        vk = VerifyKey(signing_pk)
        vk.verify(canonical, signature_bytes)
        return True
    except (BadSignatureError, Exception):
        return False


@dataclass
class _CheckedObject:
    payload: bytes = b""
    signature: bytes = b""
    error: Optional[str] = None
    verified: dict[bytes, bool] = field(default_factory=dict)


def _check_objects(
    objects: list[SyncObject], signing_pks: tuple[bytes, ...],
) -> dict[int, _CheckedObject]:
    """Decode, hash and verify each object against every candidate key.

    Runs before the push takes the global commit_counter lock (review
    d615826): verifying a large batch under it stalled every other push.
    Keyed by id(obj); the locked pass re-verifies only under a key that
    changed in between.
    """
    checked: dict[int, _CheckedObject] = {}
    for obj in objects:
        try:
            payload = base64.b64decode(obj.payload, validate=True)
            signature = bytes.fromhex(obj.signature)
        except (ValueError, TypeError):
            checked[id(obj)] = _CheckedObject(error="invalid payload or signature encoding")
            continue
        if hashlib.sha256(payload).hexdigest() != obj.payload_hash.lower():
            checked[id(obj)] = _CheckedObject(error="payload hash mismatch")
            continue
        checked[id(obj)] = _CheckedObject(
            payload=payload,
            signature=signature,
            verified={pk: _verify_sync_signature(obj, signature, pk) for pk in signing_pks},
        )
    return checked


async def _with_staged_objects(
    cur, user_id: str, req: PushRequest, staged: list[SyncObject],
) -> list[SyncObject]:
    """The staged parts of this atomic batch, then its own objects.

    The staged rows are deleted in the push's transaction: applied together
    with it, or kept for a resend when it rolls back. ``staged`` was read
    before the lock under this account's push claim, which no stage request
    of the account passes, so only the row numbers are read again here (the
    hourly GC may have dropped rows meanwhile).
    """
    if req.staged_batch_id is None:
        if req.staged_count:
            raise HTTPException(status_code=400, detail="staged_count needs staged_batch_id")
        return list(req.objects)
    if not req.atomic_batch:
        raise HTTPException(status_code=400, detail="Only an atomic batch can be staged")
    await cur.execute(
        "SELECT idx FROM sync_staged_objects "
        "WHERE user_id = %s AND batch_id = %s ORDER BY idx",
        (user_id, req.staged_batch_id),
    )
    rows = await cur.fetchall()
    if [row[0] for row in rows] != list(range(req.staged_count)) or len(staged) != req.staged_count:
        raise HTTPException(
            status_code=409,
            detail="Staged batch incomplete; stage it again before the push",
        )
    if len(staged) + len(req.objects) > MAX_STAGED_OBJECTS:
        raise HTTPException(status_code=413, detail="Staged batch too large")
    await cur.execute(
        "DELETE FROM sync_staged_objects WHERE user_id = %s AND batch_id = %s",
        (user_id, req.staged_batch_id),
    )
    return staged + list(req.objects)


# Review 7c10379 H7: a staged batch (up to MAX_STAGED_BYTES) was read and
# parsed by every push naming it, before any lock, so four 200-byte pushes
# of one account took 3.2 GB and the container was killed. Each account's
# stage requests and staged pushes now run one at a time, across workers
# (sync_push_claims); a claim left by a dead worker expires after the TTL.
PUSH_CLAIM_TTL_MS = 10 * 60 * 1000
PUSH_CLAIM_WAIT_S = 120.0
STAGED_READ_CHUNK = 500


_push_gates: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = (
    weakref.WeakKeyDictionary()
)


def _push_gate() -> asyncio.Lock:
    """One push transaction at a time per worker (and event loop)."""
    loop = asyncio.get_running_loop()
    gate = _push_gates.get(loop)
    if gate is None:
        gate = _push_gates[loop] = asyncio.Lock()
    return gate


_ACCOUNT_CLAIMS = ("sync_push_claims", "user_id")
# Review a159e97 (medium): the account claims kept one staged push per
# account, not per server; four workers each held a batch parsed (~770 MB
# for the largest), ~3 GB. One staged batch is held server-wide at a time.
_STAGED_GATE = ("sync_staged_gate", "id")


async def _try_claim(cur, claims, key, claim_id: str, now_ms: int) -> bool:
    """One attempt at a claim row: free, or held past its TTL (a dead worker)."""
    table, key_col = claims
    try:
        await cur.execute(
            f"INSERT INTO {table} ({key_col}, claim_id, claimed_at) VALUES (%s, %s, %s)",
            (key, claim_id, now_ms),
        )
        return True
    except Exception as exc:
        if not _is_duplicate_key(exc):
            raise
    await cur.execute(f"SELECT claim_id, claimed_at FROM {table} WHERE {key_col} = %s", (key,))
    row = await cur.fetchone()
    if row is None or int(row[1]) >= now_ms - PUSH_CLAIM_TTL_MS:
        return False
    await cur.execute(
        f"UPDATE {table} SET claim_id = %s, claimed_at = %s WHERE {key_col} = %s AND claim_id = %s",
        (claim_id, now_ms, key, row[0]),
    )
    return cur.rowcount == 1


def _claim_timeout() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="Another push of this account is in progress; retry later",
        headers={"Retry-After": "5"},
    )


async def _claim_account_push(db: Database, user_id: str, claims=_ACCOUNT_CLAIMS) -> str:
    """Take this account's push claim, waiting for the one holding it."""
    claim_id = secrets.token_hex(16)
    deadline = time.monotonic() + PUSH_CLAIM_WAIT_S
    delay = 0.02
    while True:
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                if await _try_claim(cur, claims, user_id, claim_id, int(time.time() * 1000)):
                    return claim_id
        if time.monotonic() >= deadline:
            raise _claim_timeout()
        await asyncio.sleep(delay)
        delay = min(delay * 2, 0.5)


# A waiter polls at least every 0.5 s; one silent this long has died.
STAGED_QUEUE_STALE_MS = 30_000


async def _claim_staged_gate(db: Database, user_id: str) -> str:
    """The server-wide staged gate, in order of arrival.

    Review 1141a20 R9-F: whoever polled first took the gate, so the account
    that had just released it took it straight back while the others slept
    in their backoff. Each waiter now queues (sync_staged_queue, one row per
    account: the account claim is held) and only the oldest live one takes it.
    """
    claim_id = secrets.token_hex(16)
    queued_at = int(time.time() * 1000)
    deadline = time.monotonic() + PUSH_CLAIM_WAIT_S
    delay = 0.02

    async def _enqueue(cur, now_ms: int) -> None:
        await cur.execute("DELETE FROM sync_staged_queue WHERE user_id = %s", (user_id,))
        await cur.execute(
            "INSERT INTO sync_staged_queue (user_id, claim_id, queued_at, seen_at) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, claim_id, queued_at, now_ms),
        )

    try:
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                await _enqueue(cur, queued_at)
        while True:
            now_ms = int(time.time() * 1000)
            async with db.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE sync_staged_queue SET seen_at = %s WHERE user_id = %s AND claim_id = %s",
                        (now_ms, user_id, claim_id),
                    )
                    if cur.rowcount != 1:  # dropped as stale (this loop stalled): same place
                        await _enqueue(cur, now_ms)
                    await cur.execute(
                        "DELETE FROM sync_staged_queue WHERE seen_at < %s",
                        (now_ms - STAGED_QUEUE_STALE_MS,),
                    )
                    await cur.execute("SELECT user_id, claim_id, queued_at FROM sync_staged_queue")
                    head = min(await cur.fetchall(), key=lambda r: (int(r[2]), r[1]), default=None)
                    if head is not None and head[1] == claim_id and await _try_claim(
                        cur, _STAGED_GATE, 1, claim_id, now_ms
                    ):
                        await cur.execute(
                            "DELETE FROM sync_staged_queue WHERE user_id = %s AND claim_id = %s",
                            (user_id, claim_id),
                        )
                        return claim_id
            if time.monotonic() >= deadline:
                raise _claim_timeout()
            await asyncio.sleep(delay)
            delay = min(delay * 2, 0.5)
    except BaseException:
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM sync_staged_queue WHERE user_id = %s AND claim_id = %s",
                    (user_id, claim_id),
                )
        raise


async def _drop_staged_batch(db: Database, user_id: str, batch_id: str) -> None:
    """A push naming a batch uses it up, applied or not (review 1141a20 R9-F):
    left behind, a refused batch let a tiny POST make the server read and
    parse all of it again under the staged gate. Clients stage anew per try."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM sync_staged_objects WHERE user_id = %s AND batch_id = %s",
                (user_id, batch_id),
            )


async def _release_account_push(
    db: Database, user_id: str, claim_id: str, claims=_ACCOUNT_CLAIMS
) -> None:
    table, key_col = claims
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                f"DELETE FROM {table} WHERE {key_col} = %s AND claim_id = %s",
                (user_id, claim_id),
            )


async def _read_staged_objects(cur, user_id: str, batch_id: str, count: int) -> list[SyncObject]:
    """The staged objects, parsed a chunk of rows at a time (never all raw rows at once)."""
    staged: list[SyncObject] = []
    for start in range(0, count, STAGED_READ_CHUNK):
        await cur.execute(
            "SELECT idx, object_json FROM sync_staged_objects "
            "WHERE user_id = %s AND batch_id = %s AND idx > %s AND idx <= %s ORDER BY idx",
            (user_id, batch_id, start - 1, min(start + STAGED_READ_CHUNK, count) - 1),
        )
        for row in await cur.fetchall():
            if row[0] != len(staged):
                return staged  # a gap: the locked pass refuses the push (409)
            staged.append(SyncObject.model_validate_json(row[1]))
    return staged


def _refuse_oversized_member_push(user: dict, config: ServerConfig, count: int) -> None:
    """Review a159e97 H7: a read-only member's 50k-object push held the global
    lock for minutes. A non-admin's push carries at most
    ``member_push_max_objects`` (SEZAM_MEMBER_PUSH_MAX_OBJECTS)."""
    if not user.get("is_admin") and count > config.member_push_max_objects:
        raise HTTPException(
            status_code=413,
            detail=f"A member's push carries at most {config.member_push_max_objects} objects",
        )


@router.post("/sync/stage", response_model=StageResponse)
async def sync_stage(
    req: StageRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(get_rotation_user),
    config: ServerConfig = Depends(get_config),
):
    """Stage part of an all-or-nothing push too big for one request.

    Review d150605 #3: a key epoch advance must carry every DEK and a member
    re-key every object of the folder, at once; over 1000 objects (or 16 MiB)
    neither could ever reach the server. Nothing staged is applied before the
    push naming the batch; staging a new batch drops the user's older one.

    Review 7c10379 H7: each object's encoding and payload hash are checked
    here, so nothing malformed is stored. Its signature is checked by the
    push: an identity rotation's batch is signed by the new key, which the
    server learns only with the push.
    """
    user_id = user["sub"]
    now_ms = int(time.time() * 1000)
    if req.start + len(req.objects) > MAX_STAGED_OBJECTS:
        raise HTTPException(status_code=413, detail="Staged batch too large")
    _refuse_oversized_member_push(user, config, req.start + len(req.objects))
    checked = await asyncio.to_thread(_check_objects, list(req.objects), ())
    for obj in req.objects:
        if checked[id(obj)].error:
            raise HTTPException(status_code=400, detail=f"{obj.id}: {checked[id(obj)].error}")
    claim_id = await _claim_account_push(db, user_id)
    try:
        staged = await run_transaction(db, lambda conn: _stage_rows(conn, user_id, req, now_ms))
        return StageResponse(staged=staged)
    finally:
        await _release_account_push(db, user_id, claim_id)


async def _stage_rows(conn, user_id: str, req: StageRequest, now_ms: int) -> int:
    async with conn.cursor() as cur:
        await cur.execute(
            "SELECT batch_id, idx, size_bytes FROM sync_staged_objects WHERE user_id = %s",
            (user_id,),
        )
        sizes: dict[int, int] = {}
        stale_batches = set()
        for batch_id, idx, size in await cur.fetchall():
            if batch_id == req.batch_id:
                sizes[idx] = size
            else:
                stale_batches.add(batch_id)
        for batch_id in stale_batches:
            await cur.execute(
                "DELETE FROM sync_staged_objects WHERE user_id = %s AND batch_id = %s",
                (user_id, batch_id),
            )
        for offset, obj in enumerate(req.objects):
            idx = req.start + offset
            text = obj.model_dump_json()
            sizes[idx] = len(text)
            await cur.execute(
                "DELETE FROM sync_staged_objects "
                "WHERE user_id = %s AND batch_id = %s AND idx = %s",
                (user_id, req.batch_id, idx),
            )
            await cur.execute(
                "INSERT INTO sync_staged_objects "
                "(user_id, batch_id, idx, object_json, size_bytes, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, req.batch_id, idx, text, len(text), now_ms),
            )
        if sum(sizes.values()) > MAX_STAGED_BYTES:
            raise HTTPException(status_code=413, detail="Staged batch too large")
        return len(sizes)


@router.post("/sync", response_model=PushResponse)
async def sync_push(
    req: PushRequest,
    request: Request,
    db: Database = Depends(get_db),
    user: dict = Depends(get_rotation_user),
    config: ServerConfig = Depends(get_config),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
):
    """Delta push — dirty objects from client.

    Server assigns commit_seq, checks write_acl, verifies Ed25519 signatures.
    Atomic batch for re-key operations; a key epoch advance also carries the
    rotated key material (key_rotation), applied in the same transaction.
    A push naming a staged batch holds the account's push claim (review
    7c10379 H7) and the server's staged gate for its whole run.
    """
    if req.key_rotation is not None:
        require_kdf_params_json(req.key_rotation.argon2_params)  # N2: 426, not 422
    _refuse_oversized_member_push(user, config, req.staged_count + len(req.objects))
    if req.staged_batch_id is None:
        return await _sync_push(req, request, db, user, config, jwt_mgr)
    user_id = user["sub"]
    claim_id = await _claim_account_push(db, user_id)
    try:
        gate_id = await _claim_staged_gate(db, user_id)
        try:
            return await _sync_push(req, request, db, user, config, jwt_mgr)
        finally:
            await _release_account_push(db, 1, gate_id, _STAGED_GATE)
            await _drop_staged_batch(db, user_id, req.staged_batch_id)
    finally:
        await _release_account_push(db, user_id, claim_id)


async def _sync_push(
    req: PushRequest,
    request: Request,
    db: Database,
    user: dict,
    config: ServerConfig,
    jwt_mgr: JWTKeyManager,
) -> PushResponse:
    user_id = user["sub"]
    is_admin = user.get("is_admin", False)
    now_ms = int(time.time() * 1000)

    staged: list[SyncObject] = []
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT username, signing_pk FROM users WHERE id = %s", (user_id,)
            )
            name_row = await cur.fetchone()
            if name_row and req.staged_batch_id is not None:
                staged = await _read_staged_objects(
                    cur, user_id, req.staged_batch_id, req.staged_count
                )
    if not name_row:
        raise HTTPException(status_code=401, detail="User not found")
    username = name_row[0]
    _refuse_base_by_version_only(staged + list(req.objects))

    # Everything CPU-bound is checked before the global lock, off the event
    # loop, against the keys the locked pass will most likely use.
    candidate_pks = [bytes(name_row[1])] if name_row[1] else []
    identity_pre = req.key_rotation.identity if req.key_rotation is not None else None
    if identity_pre is not None:
        try:
            candidate_pks.append(bytes.fromhex(identity_pre.new_signing_pk))
        except ValueError:
            pass
    prechecked = await asyncio.to_thread(
        _check_objects,
        staged + list(req.objects),
        tuple(candidate_pks),
    )
    # R17-N10: a rotation's voucher lists are checked here too, not under the lock.
    # An unreadable key leaves them to the locked pass, which refuses it.
    vouchers_pre = None
    if identity_pre is not None and candidate_pks and candidate_pks[-1].hex() == identity_pre.new_signing_pk:
        vouchers_pre = await key_vouchers.checked(
            user_id, candidate_pks[-1], [vl.model_dump() for vl in identity_pre.key_vouchers]
        )

    # Lock order for every push: commit_counter → sync_state → vault_objects.
    # Taking the single commit_counter row first serializes pushes, so two of
    # them never hold the same vault_objects gap lock (from FOR UPDATE on a
    # not-yet-existing id) while waiting for each other's insert. It also makes
    # commit_seq order equal commit order. Anything InnoDB still aborts
    # (1213/1205) is retried from scratch by run_transaction.
    async def _apply(conn) -> PushResponse:
        accepted = []
        conflicts = []
        async with conn.cursor() as cur:
            await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
            counter_row = await cur.fetchone()
            if req.check_token and await _commit_token(cur, req.check_seq or 0) != req.check_token:
                # Stateful test SM7: this server lost a commit the device saw
                # (restored from a backup). What the device sends now may build
                # on it (an audit record naming a lost parent), so it first runs
                # a full resync, which keeps and resends what was lost.
                raise ApiError(
                    409, HISTORY_CHANGED,
                    "Server history changed (restored from a backup?): "
                    "full resync required before pushing.",
                )
            objects = await _with_staged_objects(cur, user_id, req, staged)
            # Team log records land first, onto the head, in this transaction:
            # a refused record or a moved head refuses the whole push.
            # The objects below are then checked against the log as it stands
            # after these records (None: no log yet, the old rules apply).
            if req.team_log:
                identity_keys = (
                    (identity_pre.new_signing_pk, identity_pre.new_encryption_pk)
                    if identity_pre is not None else None
                )
                team_state = await team_log.append(
                    cur, [r.model_dump() for r in req.team_log], user_id,
                    pending_identity=identity_keys,
                )
            else:
                team_state = await team_log.load_state(cur)
            # Everything an identity rotated by this push could still have
            # signed carries a commit_seq up to here (review 688edcb V4).
            seq_before_push = int(counter_row[0]) - 1 if counter_row else 0
            # Review 7c10379: the commit_seq of each object is counted here and
            # written once at the end, under the same row lock; two statements
            # per object kept the global lock 67 s for a 100k-object push.
            next_seq = seq_before_push + 1
            # Review e4cd15a (low): the identity key as of this lock. Read
            # before it, a rotation another device committed meanwhile left
            # the retired key verifying this batch, which then landed behind
            # retired_seq where every other client refuses its signatures.
            await cur.execute("SELECT signing_pk FROM users WHERE id = %s", (user_id,))
            key_row = await cur.fetchone()
            if not key_row:
                raise HTTPException(status_code=401, detail="User not found")
            current_pk = bytes(key_row[0])
            await cur.execute(
                "INSERT INTO sync_state "
                "(user_id, last_push_seq, last_pull_seq, last_activity, key_epoch) "
                "VALUES (%s, 0, 0, %s, 0) "
                "ON DUPLICATE KEY UPDATE user_id = user_id",
                (user_id, now_ms),
            )
            await cur.execute(
                "SELECT key_epoch FROM sync_state WHERE user_id = %s FOR UPDATE",
                (user_id,),
            )
            epoch_row = await cur.fetchone()
            server_key_epoch = epoch_row[0] if epoch_row else 0
            if req.key_epoch < server_key_epoch:
                raise ApiError(
                    409, STALE_KEY_EPOCH,
                    "Stale key epoch; pull and recover current key material before push.",
                )
            rotation = req.key_rotation
            if rotation is not None and (not rotation.challenge or not rotation.signature):
                raise HTTPException(
                    status_code=401, detail="Signed challenge required to replace key material"
                )
            if rotation is not None and not _is_keypair_envelope(rotation.encrypted_keypair):
                raise HTTPException(status_code=400, detail="Invalid encrypted_keypair envelope")
            if rotation is not None and req.key_epoch == server_key_epoch:
                # Not an advance: either the resend of a rotation this server
                # already applied (same keypair) or a rival rotation another
                # device pushed first from the same epoch. The rival loses and
                # must take the server's key material over, before any object
                # of its batch is even compared.
                await cur.execute(
                    "SELECT encrypted_keypair FROM users WHERE id = %s", (user_id,)
                )
                current = await cur.fetchone()
                try:
                    pushed_keypair = bytes.fromhex(rotation.encrypted_keypair)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid encrypted_keypair")
                if not current or current[0] is None or bytes(current[0]) != pushed_keypair:
                    raise ApiError(
                        409, STALE_KEY_EPOCH,
                        "Stale key epoch; another device changed the key material "
                        "first. Recover with the current password before push.",
                    )
            if req.key_epoch > server_key_epoch:
                if not req.atomic_batch:
                    raise HTTPException(
                        status_code=409,
                        detail="A key epoch advance requires an atomic DEK rewrap batch.",
                    )
                requested_dek_ids = {
                    obj.id
                    for obj in objects
                    if obj.object_type == "dek" and not obj.is_deleted
                }
                await cur.execute(
                    "SELECT id FROM vault_objects "
                    "WHERE owner_id = %s AND object_type = 'dek' AND is_deleted = 0",
                    (user_id,),
                )
                server_dek_ids = {row[0] for row in await cur.fetchall()}
                missing_dek_ids = server_dek_ids - requested_dek_ids
                # An account without any own DEK (a member who only reads
                # shared folders) has nothing to rewrap; review 1141a20 H2:
                # its anchor publication must still advance the epoch.
                if missing_dek_ids or (server_dek_ids and not requested_dek_ids):
                    raise ApiError(
                        409, KEY_CHANGE_MISSES_DEKS,
                        "Key epoch advance must include every active DEK.",
                    )
                if rotation is None:
                    raise HTTPException(
                        status_code=409,
                        detail="A key epoch advance must carry the rotated key material.",
                    )
            identity = rotation.identity if rotation is not None else None
            if identity is not None and team_state is not None:
                member = team_state.members.get(user_id)
                if member is not None and (
                    not member.active or (member.signing_pk, member.encryption_pk) != (
                        identity.new_signing_pk, identity.new_encryption_pk
                    )
                ) and not (
                    req.key_epoch > server_key_epoch
                    and await _readmission_rotation(cur, team_state, user_id, current_pk, identity)
                ):
                    raise ApiError(400, team_log.TEAM_LOG_REFUSED, {
                        "message": "An identity rotation requires matching member.keys in the same push",
                    })
            # An identity rotation's batch is signed by the new key (idea #11).
            object_signing_pk = (
                bytes.fromhex(identity.new_signing_pk)
                if identity is not None and req.key_epoch > server_key_epoch
                else current_pk
            )
            if team_log.key_retired(team_state, user_id, current_pk) and not (
                identity is not None and req.key_epoch > server_key_epoch
            ):
                # Capability run 294: a restore left the account on the key
                # its member.keys retired; its holder sends only the rotation.
                raise ApiError(
                    403, IDENTITY_KEY_RETIRED,
                    "The team log retired this account's key; only its identity rotation is accepted.",
                )

            batch_dek_ids = (
                frozenset() if is_admin
                else await _own_batch_dek_ids(cur, user_id, objects, prechecked)
            )
            if req.atomic_batch and req.check_token:
                conflicts.extend(await _sibling_folder_keys(cur, objects, req.check_seq or 0))
            authority_cache: dict = {}
            written_node = None
            removed_here = {obj.id for obj in objects if obj.is_deleted}
            live_before = await _live_envelopes(cur, objects) if team_state is not None else frozenset()
            cleared_folders: set[str] = set()
            cleared_moves: set[str] = set()
            for obj in objects:
                # Review a159e97 H7: an atomic batch is refused whole on its
                # first conflict; checking the rest held the global lock for
                # nothing.
                if req.atomic_batch and conflicts:
                    break
                if written_node is not None:
                    _forget_written(authority_cache, *written_node)
                written_node = (obj.id, obj.object_type)
                checked = prechecked[id(obj)]
                if checked.error:
                    conflicts.append(PushObjectResult(id=obj.id, error=checked.error))
                    continue
                payload_bytes, signature_bytes = checked.payload, checked.signature

                # Verify Ed25519 signature (spec 8.2)
                verified = checked.verified.get(object_signing_pk)
                if verified is None:  # the identity key changed after the pre-read
                    verified = _verify_sync_signature(obj, signature_bytes, object_signing_pk)
                if not verified:
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="invalid signature"
                    ))
                    continue

                await cur.execute(
                    "SELECT version, payload_hash, owner_id, write_policy, object_type, "
                    "parent_ref, target_user_id, access_level, is_deleted, dek_scope "
                    "FROM vault_objects WHERE id = %s FOR UPDATE",
                    (obj.id,),
                )
                existing = await cur.fetchone()
                stored_type = existing[4] if existing else obj.object_type

                if existing and stored_type != obj.object_type:
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="object_type is immutable"
                    ))
                    continue

                # Review d615826: a target user the server does not know broke
                # the vault_objects foreign key and failed the whole push (500).
                # Review 7c10379 (R7-H): the row is share-locked until commit,
                # or a registration dropping that keyless account in between
                # failed the push the same way (MariaDB: 39 of 40 races).
                # Review a159e97 H7: only an admin names a target user (an
                # envelope). A member's object naming one share-locked that
                # users row to commit, and the admin's login waited (500).
                if obj.target_user_id is not None and not is_admin:
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="target_user_id is admin only"
                    ))
                    continue
                if obj.target_user_id is not None and (
                    existing is None or existing[0] < obj.version
                ):
                    await cur.execute(
                        "SELECT 1 FROM users WHERE id = %s LOCK IN SHARE MODE",
                        (obj.target_user_id,),
                    )
                    if not await cur.fetchone():
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="unknown target user"
                        ))
                        continue

                # Non-admins may manage only their own metadata-free personal DEKs.
                # Shared envelopes, archives and audit records remain admin-only.
                if not is_admin and stored_type in ("dek_archive", "envelope", "audit"):
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="admin only"
                    ))
                    continue
                if not is_admin and stored_type == "dek":
                    invalid_personal_dek = (
                        obj.parent_ref is not None
                        or obj.target_user_id is not None
                        or obj.access_level is not None
                        or obj.write_policy == "shared"
                    )
                    if invalid_personal_dek:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="invalid personal DEK metadata"
                        ))
                        continue
                    if existing and existing[2] != user_id:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="not owner (read-only)"
                        ))
                        continue

                envelope_acl_node = None
                if stored_type == "envelope":
                    if not obj.target_user_id or not obj.parent_ref or obj.access_level is None:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="envelope ACL metadata required"
                        ))
                        continue
                    # Envelope parent_ref identifies its DEK. Resolve the folder node
                    # from that DEK instead of granting ACL against the DEK ID itself.
                    await cur.execute(
                        "SELECT parent_ref FROM vault_objects "
                        "WHERE id = %s AND object_type = 'dek'",
                        (obj.parent_ref,),
                    )
                    dek_row = await cur.fetchone()
                    if obj.is_deleted and not (dek_row and dek_row[0]):
                        # Stateful test SM35: a re-key withdrew an envelope this
                        # server has no live copy of, under a key that no longer
                        # names a folder: never sent (a grant made offline, then
                        # the member was revoked), or a resent batch whose reply
                        # was lost while the old key was re-wrapped without its
                        # folder. There is no access to take away; the tombstone
                        # grants none. SM48: the same for a live envelope another
                        # device sealed under that key before the re-key (pulled
                        # afterwards): withdrawing it is how a revocation ends.
                        pass
                    elif not dek_row or not dek_row[0]:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="envelope references unknown DEK"
                        ))
                        continue
                    else:
                        envelope_acl_node = dek_row[0]
                    # Review d150605 S5: no live access for a removed member. An
                    # outdated device resent a revoked member's envelope after its
                    # tombstone was collected, and it came back as a new object
                    # with write_acl. Stateful test R10-G (seed 377002): also when
                    # the server holds a newer copy. A lost-reply resend of an
                    # identity rotation re-sealed a grant another admin revoked
                    # since; as a plain version conflict it named no way out and
                    # refused the device's whole batch on every push.
                    if not obj.is_deleted:
                        await cur.execute(
                            "SELECT status FROM users WHERE id = %s", (obj.target_user_id,)
                        )
                        target = await cur.fetchone()
                        if target and target[0] == "revoked":
                            conflicts.append(PushObjectResult(
                                id=obj.id, error="envelope for a revoked user",
                                code=REVOKED_ENVELOPE,
                            ))
                            continue
                    if not obj.is_deleted and (existing is None or existing[0] < obj.version):
                        if team_state is not None:
                            regrant = False
                            if (obj.parent_ref not in team_state.dek_index
                                    and obj.target_user_id != user_id):
                                # Review c78fd19 R13-10: a key outside the log
                                # goes to another account only as a re-seal of
                                # this sender's own earlier grant (identity
                                # rotation sends it with a new id, the old
                                # one's tombstone in the same batch).
                                # Review e443cbc R15 (goal #438 item 5): the
                                # earlier grant must still stand when the batch
                                # comes; a grant withdrawn before (its member's
                                # access taken away) let the sender give the key
                                # again without an access.set.
                                await cur.execute(
                                    "SELECT id, is_deleted FROM vault_objects "
                                    "WHERE object_type = 'envelope' "
                                    "AND parent_ref = %s AND target_user_id = %s "
                                    "AND access_level = %s AND owner_id = %s",
                                    (obj.parent_ref, obj.target_user_id, obj.access_level,
                                     user_id),
                                )
                                regrant = any(
                                    not row[1] or row[0] in live_before
                                    for row in await cur.fetchall()
                                )
                            refusal = team_log.envelope_refusal(
                                team_state, user_id, obj.target_user_id, obj.parent_ref,
                                envelope_acl_node, obj.access_level, regrant=regrant,
                            )
                            if refusal:
                                conflicts.append(PushObjectResult(
                                    id=obj.id, error=refusal, code=TEAM_LOG_ENVELOPE,
                                ))
                                continue
                elif obj.access_level is not None:
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="access_level is only valid for envelopes"
                    ))
                    continue

                writes = existing is None or existing[0] < obj.version
                # Team log (§4.3.4): admins included - rights and the current
                # key come from the log, not from the JWT or write_acl, and it
                # decides before the older write_acl check below (finding 204).
                if team_state is not None and writes:
                    refusal = await _team_log_refusal(
                        cur, team_state, user_id, obj, stored_type, existing,
                        payload_bytes, batch_dek_ids, authority_cache,
                    )
                    if refusal:
                        conflicts.append(PushObjectResult(id=obj.id, error=refusal))
                        continue

                # Review 1141a20 (R9-F): a personal tree (TL7) is its owner's
                # alone, admin included. A member hung a folder of their own
                # key below a colleague's personal root, and the owner could
                # delete neither it nor the root; the owner now may.
                own_cleanup = False
                if writes and stored_type in ("node", "entry"):
                    places = {obj.parent_ref, existing[5] if existing else None}
                    if existing is not None and existing[5] is None:
                        places.add(obj.id)  # a top-level node is its own tree
                    owners = {
                        await personal_tree.tree_owner(cur, place, authority_cache)
                        for place in places if place is not None
                    } - {None}
                    if owners - {user_id}:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="another account's personal tree"
                        ))
                        continue
                    # Review c78fd19 (#1): only where the object is stored. A
                    # tombstone naming the member's own personal root as its
                    # parent made a team folder (no personal owner) drop out of
                    # the owners and skipped every write check; a tombstone that
                    # also moves the object is checked as a move, both parents.
                    own_cleanup = bool(
                        obj.is_deleted and existing is not None and existing[2] != user_id
                        and obj.parent_ref == existing[5] and owners == {user_id}
                    )

                # Check parent write authority (admin exempt). Folder owners can
                # write below their own personal tree without a share envelope;
                # everyone else still needs explicit write_acl. Existing parent is
                # always checked, and a move also checks the destination parent.
                if not is_admin and stored_type in ("node", "entry") and not own_cleanup:
                    acl_parents = [existing[5] if existing else obj.parent_ref]
                    if existing and obj.parent_ref != existing[5]:
                        acl_parents.append(obj.parent_ref)
                        # TL7: one's own personal object may leave its folder
                        # for the personal root (move_refusal decided the log).
                        if not existing[8] and await _own_personal_object(
                            cur, team_state, user_id, existing, obj.id
                        ):
                            acl_parents.remove(existing[5])

                    async def own_seal(obj=obj, existing=existing, payload=payload_bytes) -> bool:
                        if obj.is_deleted:  # removing a personal folder of their own
                            return bool(existing) and existing[2] == user_id
                        return await _sealed_with_own_dek(cur, user_id, payload, batch_dek_ids)

                    # TL7: a member's personal root is a top-level folder of
                    # their own key; nothing else of theirs is top-level.
                    if None in acl_parents and not (stored_type == "node" and await own_seal()):
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="write_acl denied (top-level)"
                        ))
                        continue
                    acl_parents = [parent for parent in acl_parents if parent is not None]
                    acl_denied = False

                    for parent in set(acl_parents):
                        if not await _has_write_authority(
                            cur, user_id, parent, stored_type, own_seal, authority_cache,
                            batch_dek_ids,
                        ):
                            acl_denied = True
                            break
                    if acl_denied:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="write_acl denied"
                        ))
                        continue

                # Review d150605 #1: nothing live may hang below a missing or
                # deleted folder, admin included. Such an object outlived the
                # folder's tombstone GC and broke every new device's sync.
                if (
                    writes
                    and stored_type in ("node", "entry")
                    and not obj.is_deleted
                    and obj.parent_ref is not None
                ):
                    await cur.execute(
                        "SELECT 1 FROM vault_objects "
                        "WHERE id = %s AND object_type = 'node' AND is_deleted = 0",
                        (obj.parent_ref,),
                    )
                    if not await cur.fetchone():
                        conflicts.append(PushObjectResult(
                            id=obj.id,
                            error="parent folder is deleted or missing; restore the "
                                  "folder or move the item",
                        ))
                        continue
                # R16-Z SM22: two devices each moved a folder below the other
                # before seeing the other's move; both landed and every device
                # held a parent cycle (unlock walked it forever). Pushes are
                # serialized (commit_counter), so the stored chain is current.
                # R17-N11: a new folder has nothing below it.
                if (
                    writes and stored_type == "node" and obj.parent_ref is not None and existing
                    and obj.parent_ref != existing[5]
                    and await _is_below(cur, obj.parent_ref, obj.id, authority_cache)
                ):
                    conflicts.append(PushObjectResult(
                        id=obj.id, code=FOLDER_MOVE_CYCLE,
                        error="the new parent is inside this folder (moved there "
                              "elsewhere); the folder stays where it is",
                        server_version=existing[0] if existing else None,
                        server_payload_hash=existing[1] if existing else None,
                        stored_object=await _stored_object(cur, obj.id) if existing else None,
                    ))
                    continue
                # Review a159e97 H8: a member's folder tombstone buried what
                # others keep in it (the folder gone, their items unreachable
                # on every device). Refused while another account's item lives
                # anywhere below it.
                if (
                    writes and not is_admin and stored_type == "node" and obj.is_deleted
                    and existing is not None and not existing[8]
                    and await _buries_others(cur, user_id, obj.id, removed_here, cleared_folders)
                ):
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="folder holds items of others; they go first",
                    ))
                    continue
                # Review 1141a20 (R9-F): a move took others' items along, out
                # of a shared or team folder (an admin's item left it).
                if (
                    writes and not is_admin and stored_type == "node" and not obj.is_deleted
                    and existing is not None and not existing[8] and obj.parent_ref != existing[5]
                    and await _buries_others(cur, user_id, obj.id, None, cleared_moves)
                ):
                    conflicts.append(PushObjectResult(
                        id=obj.id, error="folder holds items of others; it stays with them",
                    ))
                    continue

                # Normalize write policy (ownership ACL). Distinguish an explicit
                # value from "not provided" (None) so clients that omit the field
                # (desktop/mobile) preserve the existing policy instead of clobbering it.
                provided_policy = obj.write_policy if obj.write_policy in ("owner_only", "shared") else None
                # DEK type label (root/audit/tier2/...): stored for full resync,
                # kept when a client omits it.
                if stored_type != "dek":
                    dek_scope = None
                elif obj.scope is not None:
                    dek_scope = obj.scope
                else:
                    dek_scope = existing[9] if existing else None

                if existing is None:
                    if stored_type in ("node", "entry"):
                        # Tombstone GC kept the collected copy's (version, hash):
                        # a write to that id builds on it, at a higher version.
                        await cur.execute(
                            "SELECT version, payload_hash FROM collected_objects "
                            "WHERE id = %s FOR UPDATE",
                            (obj.id,),
                        )
                        collected = await cur.fetchone()
                        if collected is not None:
                            if not (
                                obj.version > collected[0]
                                and _builds_on(obj, stored_type, collected[0], collected[1])
                            ):
                                conflicts.append(PushObjectResult(
                                    id=obj.id, error="conflict", code=COLLECTED_OBJECT,
                                    server_version=collected[0],
                                    server_payload_hash=collected[1],
                                ))
                                continue
                            await cur.execute(
                                "DELETE FROM collected_objects WHERE id = %s", (obj.id,)
                            )
                    # New object — assign commit_seq
                    commit_seq = next_seq
                    next_seq += 1

                    # Not IGNORE: that also turns a too-long id or an out-of-range
                    # version into a silently truncated row. A concurrent first
                    # push of the same id is still a conflict, not a 500.
                    try:
                        await cur.execute(
                            "INSERT INTO vault_objects "
                            "(id, object_type, payload, owner_id, signature_user_id, write_policy, access_level, target_user_id, parent_ref, "
                            "version, commit_seq, is_deleted, payload_hash, client_signature, modified_at, dek_scope) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (
                                obj.id, obj.object_type, payload_bytes, user_id, user_id,
                                provided_policy or "owner_only", obj.access_level,
                                obj.target_user_id, obj.parent_ref,
                                obj.version, commit_seq, obj.is_deleted,
                                obj.payload_hash, signature_bytes, now_ms, dek_scope,
                            ),
                        )
                    except Exception as exc:
                        if not _is_duplicate_key(exc):
                            raise
                        conflicts.append(PushObjectResult(id=obj.id, error="conflict"))
                        continue

                    # Envelope ACL metadata is server-visible by design (spec 4.2);
                    # a team folder's write_acl comes from the team log instead.
                    if stored_type == "envelope" and not team_log.is_team_key(
                        team_state, obj.parent_ref, envelope_acl_node
                    ):
                        if obj.is_deleted:
                            await cur.execute(
                                "DELETE FROM write_acl WHERE user_id = %s AND node_id = %s",
                                (obj.target_user_id, envelope_acl_node),
                            )
                        elif obj.access_level == "write":
                            await cur.execute(
                                "INSERT IGNORE INTO write_acl (user_id, node_id, granted_at) "
                                "VALUES (%s, %s, %s)",
                                (obj.target_user_id, envelope_acl_node, now_ms),
                            )

                    accepted.append(PushObjectResult(id=obj.id, commit_seq=commit_seq))

                elif existing[0] < obj.version and _builds_on(
                    obj, stored_type, existing[0], existing[1]
                ):
                    # Ownership ACL enforcement (spec 3.4): editing an existing
                    # node/entry requires being the owner, an admin, or the object
                    # having write_policy='shared'. Others have read-only access
                    # even when they hold folder write_acl.
                    existing_owner = existing[2]
                    existing_policy = existing[3]
                    is_owner = existing_owner == user_id
                    if (
                        not is_admin
                        and stored_type in ("node", "entry")
                        and not is_owner
                        and existing_policy != "shared"
                        and not own_cleanup
                    ):
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="not owner (read-only)"
                        ))
                        continue

                    # Only owner/admin may change the write_policy, and only when
                    # explicitly provided; otherwise the existing policy is preserved
                    # (clients that omit the field must never clobber it).
                    if (is_admin or is_owner) and provided_policy is not None:
                        new_policy = provided_policy
                    else:
                        new_policy = existing_policy

                    # Newer version — accept
                    commit_seq = next_seq
                    next_seq += 1

                    await cur.execute(
                        "UPDATE vault_objects SET "
                        "payload = %s, version = %s, commit_seq = %s, is_deleted = %s, "
                        "payload_hash = %s, client_signature = %s, signature_user_id = %s, modified_at = %s, write_policy = %s, "
                        "parent_ref = %s, target_user_id = %s, access_level = %s, dek_scope = %s "
                        "WHERE id = %s AND version = %s",
                        (
                            payload_bytes, obj.version, commit_seq, obj.is_deleted,
                            obj.payload_hash, signature_bytes, user_id, now_ms, new_policy,
                            obj.parent_ref, obj.target_user_id, obj.access_level, dek_scope, obj.id,
                            existing[0],
                        ),
                    )
                    # Compare-and-swap on the version read above: a concurrent
                    # writer that got there first turns this into a conflict.
                    if cur.rowcount != 1:
                        conflicts.append(PushObjectResult(
                            id=obj.id, error="conflict",
                            server_version=existing[0], server_payload_hash=existing[1],
                        ))
                        continue

                    if stored_type == "envelope":
                        old_parent, old_target, old_access = existing[5], existing[6], existing[7]
                        await cur.execute(
                            "SELECT parent_ref FROM vault_objects "
                            "WHERE id = %s AND object_type = 'dek'",
                            (old_parent,),
                        )
                        old_dek_row = await cur.fetchone()
                        old_acl_node = old_dek_row[0] if old_dek_row else None
                        if team_log.is_team_key(team_state, old_parent, old_acl_node):
                            old_access = None  # the team log keeps that write_acl
                        if old_access == "write" and old_acl_node and (
                            obj.is_deleted
                            or obj.access_level != "write"
                            or obj.parent_ref != old_parent
                            or obj.target_user_id != old_target
                        ):
                            await cur.execute(
                                "DELETE FROM write_acl WHERE user_id = %s AND node_id = %s",
                                (old_target, old_acl_node),
                            )
                        if (
                            not obj.is_deleted and obj.access_level == "write"
                            and not team_log.is_team_key(
                                team_state, obj.parent_ref, envelope_acl_node
                            )
                        ):
                            await cur.execute(
                                "INSERT IGNORE INTO write_acl (user_id, node_id, granted_at) "
                                "VALUES (%s, %s, %s)",
                                (obj.target_user_id, envelope_acl_node, now_ms),
                            )

                    accepted.append(PushObjectResult(id=obj.id, commit_seq=commit_seq))

                elif (
                    existing[0] == obj.version
                    and existing[1] == obj.payload_hash
                    and (
                        existing[5] == obj.parent_ref
                        # Stateful test R10-G (seed 377002): the resend of a
                        # landed key change carries a folder's old key that a
                        # re-key pulled meanwhile unbound on the device; the
                        # same wrap naming no folder is still that retry, and
                        # the stored folder stays.
                        or (stored_type == "dek" and obj.parent_ref is None)
                    )
                    and existing[6] == obj.target_user_id
                    and existing[7] == obj.access_level
                    and existing[8] == obj.is_deleted
                ):
                    # Idempotent retry means the complete signed object is identical.
                    accepted.append(PushObjectResult(id=obj.id, commit_seq=None))

                else:
                    # Conflict
                    conflicts.append(PushObjectResult(
                        id=obj.id,
                        error="conflict",
                        server_version=existing[0],
                        server_payload_hash=existing[1],
                    ))

            # If atomic_batch and any conflicts, rollback everything
            if req.atomic_batch and conflicts:
                raise ApiError(
                    409, ATOMIC_BATCH_CONFLICT,
                    {"message": "Atomic batch conflict", "conflicts": [c.model_dump() for c in conflicts]},
                )

            commit_token = None
            last_seq = next_seq - 1
            if last_seq > seq_before_push:
                await cur.execute(
                    "UPDATE commit_counter SET next_seq = %s WHERE id = 1", (next_seq,)
                )
                commit_token = secrets.token_hex(16)
                await cur.execute(
                    "INSERT INTO commit_log (last_seq, first_seq, token) VALUES (%s, %s, %s)",
                    (last_seq, seq_before_push + 1, commit_token),
                )

            rotated_token_epoch = None
            if rotation is not None:
                rotated_token_epoch = await _apply_key_rotation(
                    cur, config, user_id, username, current_pk, rotation,
                    advances_epoch=req.key_epoch > server_key_epoch,
                    old_key_epoch=server_key_epoch,
                    retired_seq=seq_before_push,
                    checked_vouchers=vouchers_pre,
                )

            await cur.execute(
                "UPDATE sync_state SET key_epoch = %s, last_activity = %s "
                "WHERE user_id = %s",
                (req.key_epoch, now_ms, user_id),
            )
        return PushResponse(
            accepted=accepted, conflicts=conflicts, commit_token=commit_token,
        ), rotated_token_epoch

    try:
        # Review 7c10379: pushes of one worker wait here, not on the
        # commit_counter row lock with a pool connection each; ten of them
        # took the whole pool and /health answered 503.
        async with _push_gate():
            response, rotated_token_epoch = await run_transaction(db, _apply)
    except WrongCurrentProof:
        # Counted outside the rolled-back push: guessing the password here
        # is bounded by the same per-name lock as /recover.
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                locked = await record_wrong_account_proof(cur, config, user_id)
        if locked:
            raise HTTPException(status_code=423, detail="Recovery locked. Contact admin.")
        raise
    if rotated_token_epoch is not None:
        response.token = create_jwt(
            jwt_mgr.signing_key, user_id, username, bool(is_admin),
            config.jwt_expiry_seconds, token_epoch=rotated_token_epoch,
        )
    return response


# Lockout review #11: the server cannot decrypt the keypair, but it can refuse
# material no client could ever open: the plain envelope header must be a
# canonical KEYPAIR_WRAP (alg 1, schema 1, kind 7) around at least the padded
# 64-byte keypair (53 header + 2 length + 64 + 16 tag).
_KEYPAIR_ENVELOPE_PREFIX = bytes((1, 1, 7))
_KEYPAIR_ENVELOPE_MIN_LEN = 53 + 2 + 64 + 16
_KEY_MATERIAL_ARCHIVE_KEEP = 10


def _is_keypair_envelope(encrypted_keypair_hex: str) -> bool:
    try:
        blob = bytes.fromhex(encrypted_keypair_hex)
    except ValueError:
        return False
    return len(blob) >= _KEYPAIR_ENVELOPE_MIN_LEN and blob[:3] == _KEYPAIR_ENVELOPE_PREFIX


async def _archive_key_material(cur, user_id: str, key_epoch: int, now_ms: int) -> None:
    """Keep the material a rotation replaces (lockout review #11).

    An in-place overwrite left nothing to fall back to when the new material
    turned out unusable; the last few generations stay readable with the old
    password: the owner reads (or purges) them with the current password at
    /api/me/key-material-archive, and they are deleted after
    SEZAM_KEY_MATERIAL_ARCHIVE_DAYS (review 688edcb).
    """
    await cur.execute(
        "SELECT encrypted_keypair, argon2_salt, argon2_params, auth_salt "
        "FROM users WHERE id = %s",
        (user_id,),
    )
    row = await cur.fetchone()
    if not row or not row[0]:
        return
    from ulid import ULID
    await cur.execute(
        "INSERT INTO user_key_material_archive "
        "(id, user_id, key_epoch, encrypted_keypair, argon2_salt, argon2_params, "
        "auth_salt, archived_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (str(ULID()), user_id, key_epoch, row[0], row[1], row[2], row[3], now_ms),
    )
    await cur.execute(
        "SELECT id, archived_at FROM user_key_material_archive WHERE user_id = %s",
        (user_id,),
    )
    rows = sorted(await cur.fetchall(), key=lambda r: (r[1], r[0]), reverse=True)
    for stale_id, _ in rows[_KEY_MATERIAL_ARCHIVE_KEEP:]:
        await cur.execute(
            "DELETE FROM user_key_material_archive WHERE id = %s", (stale_id,)
        )


async def _rotate_identity(
    cur, user_id: str, identity, now_ms: int, retired_seq: int,
    checked_vouchers: Optional[list] = None,
) -> None:
    """Replace the account's public identity keys and archive the old ones.

    The archive row carries the new key's rotation certificate, through which
    clients keep trusting records the old key signed (GET /api/users/:id/keys),
    the old key's authorization of the rotation, and ``retired_seq``: clients
    trust the old key only for objects committed up to it, so whoever holds
    the leaked key cannot sign new DEKs, envelopes or records (review 688edcb V4).
    """
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    from ulid import ULID

    await cur.execute(
        "SELECT signing_pk, encryption_pk FROM users WHERE id = %s FOR UPDATE", (user_id,)
    )
    row = await cur.fetchone()
    if not row or not row[0] or not row[1]:
        raise HTTPException(status_code=409, detail="The account has no identity keys")
    old_signing_pk, old_encryption_pk = bytes(row[0]), bytes(row[1])
    new_signing_pk = bytes.fromhex(identity.new_signing_pk)
    new_encryption_pk = bytes.fromhex(identity.new_encryption_pk)
    if new_signing_pk == old_signing_pk or new_encryption_pk == old_encryption_pk:
        raise ApiError(400, IDENTITY_ROTATION_NEEDS_NEW_KEYS, "An identity rotation needs new keys")
    message = key_rotation_message(
        user_id, old_signing_pk, old_encryption_pk, new_signing_pk, new_encryption_pk
    )
    try:
        VerifyKey(old_signing_pk).verify(
            message, bytes.fromhex(identity.authorization_signature)
        )
    except (BadSignatureError, ValueError):
        raise HTTPException(
            status_code=401, detail="The current identity key did not authorize the rotation"
        )
    try:
        VerifyKey(new_signing_pk).verify(message, bytes.fromhex(identity.rotation_signature))
    except (BadSignatureError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid rotation certificate")
    await cur.execute(
        "SELECT 1 FROM user_key_archives WHERE user_id = %s AND signing_pk = %s",
        (user_id, new_signing_pk),
    )
    if await cur.fetchone():
        raise HTTPException(status_code=409, detail="An archived identity key cannot return")
    await cur.execute(
        "INSERT INTO user_key_archives (id, user_id, signing_pk, encryption_pk, "
        "key_fingerprint, archived_at, successor_signing_pk, rotation_signature, "
        "authorization_signature, retired_seq) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            str(ULID()), user_id, old_signing_pk, old_encryption_pk,
            hashlib.sha256(old_signing_pk + old_encryption_pk).hexdigest(), now_ms,
            new_signing_pk, bytes.fromhex(identity.rotation_signature),
            bytes.fromhex(identity.authorization_signature), retired_seq,
        ),
    )
    await cur.execute(
        "UPDATE users SET signing_pk = %s, encryption_pk = %s, key_fingerprint = %s "
        "WHERE id = %s",
        (
            new_signing_pk, new_encryption_pk,
            hashlib.sha256(new_signing_pk + new_encryption_pk).hexdigest(), user_id,
        ),
    )
    # Goal #443: what the old key signed, vouched for by the new one.
    if checked_vouchers is None:
        checked_vouchers = await key_vouchers.checked(
            user_id, new_signing_pk, [vl.model_dump() for vl in identity.key_vouchers]
        )
    vouched: set = set()
    for checked_list in checked_vouchers:
        await key_vouchers.store(cur, user_id, new_signing_pk, checked_list, now_ms)
        vouched.update(checked_list[1])
    await _require_vouched(cur, user_id, old_signing_pk, vouched)


async def _require_vouched(cur, user_id: str, old_signing_pk: bytes, vouched: set) -> None:
    """Goal #443: after the rotation a live object the old key signed verifies
    only where the new key's lists name it; one pushed by another device after
    this one fetched /api/users/me/signed-objects would be lost to every new
    device. 409: fetch the list again."""
    from types import SimpleNamespace

    await cur.execute(
        "SELECT id, object_type, parent_ref, target_user_id, is_deleted, version, payload_hash, "
        "client_signature FROM vault_objects WHERE signature_user_id = %s",
        (user_id,),
    )
    for obj_id, object_type, parent_ref, target_user_id, is_deleted, version, payload_hash, signature in (
        await cur.fetchall()
    ):
        fields = {
            "id": obj_id, "object_type": object_type, "parent_ref": parent_ref,
            "target_user_id": target_user_id, "is_deleted": int(is_deleted or 0),
            "version": version, "payload_hash": payload_hash,
        }
        # R17-N1: the entry names the whole message the old key signed.
        if not signature or key_vouchers.core.object_entry(fields, user_id, old_signing_pk) in vouched:
            continue
        if _verify_sync_signature(SimpleNamespace(**fields), bytes(signature), old_signing_pk):
            raise ApiError(
                409, KEY_VOUCHERS_INCOMPLETE,
                f"The identity rotation's key vouchers leave out {obj_id} version {version}, "
                "signed by the retired key",
            )


class WrongCurrentProof(ApiError):
    def __init__(self) -> None:
        super().__init__(403, WRONG_CURRENT_PASSWORD, "Wrong current account password")


async def _readmission_rotation(cur, team_state, user_id: str, current_pk: bytes, identity) -> bool:
    """Review 8595ec1 (R10-F): a restore from before a member's rotation left
    the account on the key the log retired, and the member lost the device
    with the log's key. With an admin's key-reset grant (used up here; the
    rotation still needs the password) the account rotates to keys the log
    never saw. The log keeps naming the lost keys: nothing signed by the new
    ones counts in the team until the admin readmits the member
    ('sezam team-log readmit', after comparing the fingerprint)."""
    member = team_state.members.get(user_id)
    if member is None or not member.active or not team_log.key_retired(team_state, user_id, current_pk):
        return False
    if identity.new_signing_pk in team_state.seen_keys or identity.new_encryption_pk in team_state.seen_keys:
        return False
    await cur.execute("SELECT key_reset_until FROM users WHERE id = %s FOR UPDATE", (user_id,))
    row = await cur.fetchone()
    if not row or row[0] is None or int(row[0]) <= int(time.time() * 1000):
        return False
    await cur.execute(
        "UPDATE users SET key_reset_until = %s, key_reset_by = %s WHERE id = %s", (None, None, user_id)
    )
    return True


async def _authorize_key_material_change(
    cur, config: ServerConfig, user_id: str, rotation, now_ms: int
) -> None:
    """Review 688edcb K1: replacing the key material needs more than the
    identity key. Someone holding only a stolen keypair (exactly the case an
    identity rotation exists for) could otherwise set their own password and
    lock the owner out for good. Accepted: the current password's auth
    proof, a challenge signed by the org recovery key for the recovery
    admin's account, or a key-reset grant another admin issued (used once).

    Review e4cd15a #2: a correct proof is accepted first; otherwise a recovery
    proof or an admin's grant is, BEFORE a wrong proof is refused and counted.
    A device whose journal carries a proof of a password the server no longer
    has (or none at all) was otherwise stuck for good: the grant meant for it
    never got looked at, and every retry counted towards the 24 h name lock.

    Review e4cd15a (low): a locked name verifies one proof per window here
    (like /recover); the holder of a stolen identity key guessed unlimited.
    """
    await cur.execute(
        "SELECT verify_salt, auth_proof_hash, key_reset_until, recovery_locked, "
        "last_recovery_attempt FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    row = await cur.fetchone()
    verify_salt, stored_hash, reset_until, locked, last_attempt = (
        row if row else (None, None, None, None, None)
    )
    if not verify_salt or not stored_hash:
        return  # the account has no password on the server yet
    wait_s = 0
    if rotation.current_auth_proof is not None:
        wait_s = await key_gate_wait_s(cur, config, user_id, now_ms, locked, last_attempt)
    if rotation.current_auth_proof is not None and not wait_s:
        computed = compute_auth_proof_hash(
            bytes(verify_salt), bytes.fromhex(rotation.current_auth_proof)
        )
        if hmac.compare_digest(computed, stored_hash):
            return
    recovery_refused = False
    if rotation.recovery_challenge and rotation.recovery_signature:
        recovered_for = await consume_org_recovery_proof(
            cur, bytes.fromhex(rotation.recovery_challenge),
            bytes.fromhex(rotation.recovery_signature),
        )
        if recovered_for == user_id:
            return
        recovery_refused = True
    if reset_until and int(reset_until) > now_ms:
        await cur.execute(
            "UPDATE users SET key_reset_until = %s, key_reset_by = %s WHERE id = %s",
            (None, None, user_id),
        )
        return
    if wait_s:
        raise HTTPException(
            status_code=429,
            detail="The account is locked after wrong passwords; the current password "
            f"is checked again in {wait_s} s.",
            headers={"Retry-After": str(wait_s)},
        )
    if rotation.current_auth_proof is not None:
        raise WrongCurrentProof()
    if recovery_refused:
        raise HTTPException(status_code=401, detail="Invalid recovery proof")
    raise ApiError(
        403, KEY_CHANGE_NEEDS_PROOF,
        "Replacing the key material needs the current account password "
        "(or an admin's key reset)",
    )


async def _apply_key_rotation(
    cur, config: ServerConfig, user_id: str, username: str, signing_pk: bytes,
    rotation, *, advances_epoch: bool, old_key_epoch: int, retired_seq: int,
    checked_vouchers: Optional[list] = None,
) -> Optional[int]:
    """Replace the account key material inside the push transaction.

    Returns the new token_epoch, or None for an idempotent retry of a rotation
    that an earlier (lost-response) attempt already applied.

    With ``rotation.identity`` the identity keypair is replaced too: the
    challenge is then signed by the new key (a retry after a lost response
    finds it already current), the old key's authorization signature is
    checked against the key the account has now.
    """
    identity = rotation.identity
    challenge_pk = (
        bytes.fromhex(identity.new_signing_pk) if identity is not None else signing_pk
    )
    await consume_signed_challenge(
        cur, config, username, rotation.challenge, rotation.signature, challenge_pk
    )
    await cur.execute(
        "SELECT encrypted_keypair, token_epoch FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    row = await cur.fetchone()
    new_keypair = bytes.fromhex(rotation.encrypted_keypair)
    if not advances_epoch:
        if row and row[0] is not None and bytes(row[0]) == new_keypair:
            return None
        raise HTTPException(
            status_code=409,
            detail="Key material can only be replaced together with a key epoch advance.",
        )
    now_ms = int(time.time() * 1000)
    await _authorize_key_material_change(cur, config, user_id, rotation, now_ms)
    verify_salt = os.urandom(32)
    kdf_json = require_kdf_params_json(rotation.argon2_params)
    new_token_epoch = int((row[1] if row else 0) or 0) + 1
    if identity is not None:
        await _rotate_identity(cur, user_id, identity, now_ms, retired_seq, checked_vouchers)
    await _archive_key_material(cur, user_id, old_key_epoch, now_ms)
    await cur.execute(
        "UPDATE users SET "
        "encrypted_keypair = %s, argon2_salt = %s, auth_salt = %s, "
        "verify_salt = %s, auth_proof_hash = %s, argon2_params = %s, "
        "token_epoch = %s "
        "WHERE id = %s",
        (
            new_keypair,
            bytes.fromhex(rotation.argon2_salt),
            bytes.fromhex(rotation.auth_salt),
            verify_salt,
            compute_auth_proof_hash(verify_salt, bytes.fromhex(rotation.auth_proof)),
            kdf_json,
            new_token_epoch,
            user_id,
        ),
    )
    return new_token_epoch


_PULL_MAX_OBJECTS = 250
_PULL_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_PULL_OBJECT_METADATA_BUDGET = 1024


@router.get("/sync", response_model=PullResponse)
async def sync_pull(
    request: Request,
    since_commit_seq: int = Query(0, ge=0, alias="since_commit_seq"),
    full_resync: bool = Query(False, alias="full_resync"),
    cursor: Optional[int] = Query(None, ge=0),
    check_seq: Optional[int] = Query(None, ge=0),
    check_token: Optional[str] = Query(None, max_length=64),
    db: Database = Depends(get_db),
    user: dict = Depends(get_rotation_user),
):
    """Delta pull — objects with commit_seq > since_commit_seq.

    There is no ETag / 304 (sync redesign S2): the client's checkpoint is its
    only pull state. The reply's ``check_token`` is the server's token for
    ``check_seq``, so a client sees a server that handed that seq out again.
    """
    user_id = user["sub"]

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            # Check gc_floor_seq
            await cur.execute(
                "SELECT gc_floor_seq FROM commit_counter WHERE id = 1"
            )
            gc_row = await cur.fetchone()
            gc_floor = gc_row[0] if gc_row else 0

            if full_resync and since_commit_seq != 0:
                raise HTTPException(
                    status_code=400,
                    detail="Explicit full resync requires since_commit_seq=0.",
                )
            # A pull from 0 has no baseline that a collected tombstone could
            # leave stale (a brand-new device), so only real deltas get 410.
            if 0 < since_commit_seq < gc_floor and not full_resync:
                raise HTTPException(
                    status_code=410,
                    detail="Data too old. Explicit full resync required.",
                )
            page_after = cursor if cursor is not None else since_commit_seq
            if page_after < since_commit_seq:
                raise HTTPException(status_code=400, detail="Invalid sync cursor.")
            server_check_token = (
                await _commit_token(cur, check_seq) if check_seq and cursor is None else None
            )

            await cur.execute(
                "SELECT MAX(commit_seq) FROM vault_objects "
                "WHERE object_type != 'key_archive'"
            )
            max_row = await cur.fetchone()
            current_max = max_row[0] if max_row and max_row[0] else 0
            team_log_head = team_log.head(await team_log.load_state(cur))

            # Content-blind design still exposes every encrypted object, but only
            # through bounded pages so one pull cannot materialize the whole vault.
            # Size the page from payload lengths first; only then load the
            # payloads that fit, so the DB never hands over ~250 MiB per page.
            await cur.execute(
                "SELECT commit_seq, LENGTH(payload) "
                "FROM vault_objects WHERE commit_seq > %s "
                "AND object_type != 'key_archive' ORDER BY commit_seq "
                "LIMIT %s",
                (page_after, _PULL_MAX_OBJECTS + 1),
            )
            candidates = await cur.fetchall()
            selected = 0
            last_seq = page_after
            response_bytes = 0
            for candidate_seq, payload_size in candidates:
                candidate_size = (
                    4 * ((payload_size + 2) // 3) + _PULL_OBJECT_METADATA_BUDGET
                )
                if selected and (
                    selected >= _PULL_MAX_OBJECTS
                    or response_bytes + candidate_size > _PULL_MAX_RESPONSE_BYTES
                ):
                    break
                selected += 1
                last_seq = candidate_seq
                response_bytes += candidate_size
            has_more = selected < len(candidates)
            rows = []
            if selected:
                await cur.execute(
                    "SELECT id, object_type, payload, owner_id, parent_ref, target_user_id, "
                    "version, commit_seq, is_deleted, payload_hash, client_signature, modified_at, "
                    "write_policy, access_level, signature_user_id, dek_scope "
                    "FROM vault_objects WHERE commit_seq > %s AND commit_seq <= %s "
                    "AND object_type != 'key_archive' ORDER BY commit_seq "
                    "LIMIT %s",
                    (page_after, last_seq, selected),
                )
                rows = list(await cur.fetchall())
            await cur.execute(
                "SELECT key_epoch FROM sync_state WHERE user_id = %s",
                (user_id,),
            )
            epoch_row = await cur.fetchone()
            server_key_epoch = epoch_row[0] if epoch_row else 0
            await cur.execute("SELECT encrypted_keypair FROM users WHERE id = %s", (user_id,))
            keypair_row = await cur.fetchone()
            key_material_hash = (
                hashlib.sha256(bytes(keypair_row[0])).hexdigest()
                if keypair_row and keypair_row[0] is not None else None
            )
            # The counter never decreases (tombstone GC can delete the row
            # holding MAX(commit_seq)), so it is the honest head.
            await cur.execute("SELECT next_seq - 1 FROM commit_counter WHERE id = 1")
            counter_row = await cur.fetchone()
            head_seq = max(current_max, counter_row[0] if counter_row else 0)
            max_seq = max([since_commit_seq] + [r[7] for r in rows if r[7]])
            max_token = await _commit_token(cur, max_seq)

    return PullResponse(
        objects=[_pull_object(r) for r in rows],
        max_commit_seq=max_seq,
        key_epoch=server_key_epoch,
        key_material_hash=key_material_hash,
        has_more=has_more,
        next_cursor=max_seq if has_more else None,
        head_commit_seq=head_seq,
        gc_floor_seq=gc_floor or 0,
        check_token=server_check_token,
        max_token=max_token,
        team_log_head=team_log_head,
    )


async def _commit_token(cur, seq: int) -> Optional[str]:
    """The token of the push transaction that committed ``seq``, if logged.

    Review 7c10379: one primary-key seek. ``first_seq <= seq AND last_seq >= seq``
    read every later push's row, under the global push lock.
    """
    if seq <= 0:
        return None
    await cur.execute(
        "SELECT token, first_seq FROM commit_log WHERE last_seq > %s ORDER BY last_seq LIMIT 1",
        (seq - 1,),
    )
    row = await cur.fetchone()
    return row[0] if row and int(row[1]) <= seq else None


def _sealing_dek_id(payload: bytes, entry: bool = False) -> Optional[str]:
    """The DEK id in a sealed blob's header (alg, schema, kind, 26-byte id, nonce).

    An entry's payload is u32be(len(meta)) + meta + data: its meta's header.
    """
    if entry:
        if len(payload) < 4:
            return None
        payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
    if len(payload) < 53 + 16:
        return None
    try:
        return payload[3:29].decode("ascii")
    except UnicodeDecodeError:
        return None


async def _team_log_refusal(
    cur, state, user_id: str, obj, stored_type: str, existing, payload: bytes,
    batch_dek_ids: frozenset[str], cache: dict,
) -> Optional[str]:
    """Why the team log refuses this write, or None (design §4.3.4-6)."""
    if existing is None:
        refusal = team_log.reserved_refusal(state, user_id, obj.id, stored_type)
        if refusal:
            return refusal
    if stored_type == "dek":
        # A team folder's new key lands with its folder.key record.
        if (
            existing is None and not obj.is_deleted and obj.parent_ref in state.folders
            and obj.id not in state.dek_index
        ):
            return "folder key missing from the team log"
        return None
    if stored_type not in ("node", "entry"):
        return None
    if obj.is_deleted:
        if existing is None:
            return None
        await cur.execute("SELECT payload FROM vault_objects WHERE id = %s", (obj.id,))
        row = await cur.fetchone()
        stored = _sealing_dek_id(bytes(row[0]), stored_type == "entry") if row and row[0] else None
        refusal = team_log.tombstone_refusal(state, user_id, stored)
        if refusal or obj.parent_ref == existing[5]:
            return refusal
        # Review c78fd19 (#1): a tombstone that also moves the object (a
        # device deleted what it had moved) moves it as a live write would.
        folder = await team_log.team_folder_above(cur, state, obj.parent_ref, cache)
        old_folder = await team_log.team_folder_above(cur, state, existing[5], cache)
        own_personal = old_folder is not None and await _own_personal_object(
            cur, state, user_id, existing, obj.id
        )
        return team_log.move_refusal(state, user_id, old_folder, folder, own_personal)
    folder = await team_log.team_folder_above(cur, state, obj.parent_ref, cache)
    if existing is not None and not existing[8]:
        # Finding 205: moving out of a team folder removes from it. TL7: one's
        # own personal object may leave for the personal root.
        old_folder = await team_log.team_folder_above(cur, state, existing[5], cache)
        own_personal = old_folder is not None and await _own_personal_object(
            cur, state, user_id, existing, obj.id
        )
        refusal = team_log.move_refusal(state, user_id, old_folder, folder, own_personal)
        if refusal:
            return refusal
    dek_id = _sealing_dek_id(payload, stored_type == "entry")
    own = dek_id in batch_dek_ids or await _own_personal_key(cur, state, user_id, dek_id)
    return team_log.item_refusal(state, user_id, obj.id, folder, dek_id, own)


async def _own_personal_object(cur, state, user_id: str, existing, obj_id: str) -> bool:
    """Is the stored node/entry ``obj_id`` the user's own, sealed with a key of theirs
    outside the log (a personal folder's or a tier-2 item's, bound to a folder or not)?

    Its owner may already delete it (tombstone_refusal: no log key), so moving
    it out of the team tree gives nothing more.
    """
    if existing is None or existing[2] != user_id or existing[4] not in ("node", "entry"):
        return False
    await cur.execute("SELECT payload FROM vault_objects WHERE id = %s", (obj_id,))
    row = await cur.fetchone()
    if not row or not row[0]:
        return False
    stored = _sealing_dek_id(bytes(row[0]), existing[4] == "entry")
    if stored is None or (state is not None and stored in state.dek_index):
        return False
    await cur.execute(
        "SELECT 1 FROM vault_objects WHERE id = %s AND object_type = 'dek' "
        "AND owner_id = %s AND is_deleted = 0",
        (stored, user_id),
    )
    return bool(await cur.fetchone())


async def _own_personal_key(cur, state, user_id: str, dek_id: Optional[str]) -> bool:
    """Is ``dek_id`` the user's personal key: theirs, outside the log, bound to no
    folder (an admin's folder key outside the log is not personal)?"""
    if dek_id is None or dek_id in state.dek_index:
        return False
    await cur.execute(
        "SELECT owner_id, parent_ref FROM vault_objects "
        "WHERE id = %s AND object_type = 'dek' AND is_deleted = 0",
        (dek_id,),
    )
    row = await cur.fetchone()
    return row is not None and row[0] == user_id and row[1] is None


async def _live_envelopes(cur, objects) -> frozenset[str]:
    """The envelopes this push withdraws that were live before it.

    A re-seal (identity rotation) withdraws the old envelope in the same
    batch; the loop may have applied that tombstone before it reaches the new
    one. Only an envelope live when the batch came vouches for it.
    """
    if not any(o.object_type == "envelope" and not o.is_deleted for o in objects):
        return frozenset()
    live = set()
    for obj in objects:
        if obj.object_type != "envelope" or not obj.is_deleted:
            continue
        await cur.execute("SELECT is_deleted FROM vault_objects WHERE id = %s", (obj.id,))
        row = await cur.fetchone()
        if row is not None and not row[0]:
            live.add(obj.id)
    return frozenset(live)


async def _sibling_folder_keys(cur, objects, check_seq: int) -> list[PushObjectResult]:
    """New folder keys of a re-key batch that race one the device never saw.

    Stateful test SM16 (R16-Z): two devices of one admin re-keyed a folder
    after the same revocation. GC had collected the folder's items, so the
    second batch built on the collected copies and landed: two live keys of
    one folder, and the devices kept different ones. A key of the folder
    committed after the device's checked commit makes this batch's new key a
    sibling; the device pulls and drops its batch (superseded re-key).
    """
    batch_ids = {obj.id for obj in objects}
    new_keys = [
        obj for obj in objects
        if obj.object_type == "dek" and not obj.is_deleted and obj.parent_ref
        and obj.scope != "tier2"
    ]
    refused = []
    for obj in new_keys:
        await cur.execute("SELECT 1 FROM vault_objects WHERE id = %s", (obj.id,))
        if await cur.fetchone():
            continue  # the resend of a key this server holds
        await cur.execute(
            "SELECT id, commit_seq, dek_scope FROM vault_objects "
            "WHERE parent_ref = %s AND object_type = 'dek' AND is_deleted = 0",
            (obj.parent_ref,),
        )
        rivals = [
            row[0] for row in await cur.fetchall()
            if row[0] not in batch_ids and int(row[1]) > check_seq and row[2] != "tier2"
        ]
        if rivals:
            refused.append(PushObjectResult(
                id=obj.id, error=f"folder {obj.parent_ref} got key {rivals[0]} meanwhile",
                code=FOLDER_KEY_MOVED,
            ))
    return refused


async def _own_batch_dek_ids(cur, user_id: str, objects, prechecked) -> frozenset[str]:
    """The DEKs of this push a member's new folder may count as their own.

    Capability run 172 (H4): the set took every DEK object of the request,
    including the ones refused below, so a DEK object named after the shared
    root DEK - refused as 'not owner' - vouched for a folder sealed with the
    shared key. Only a live DEK object with personal metadata whose id is new
    or already the member's counts, the same checks the push applies to it.
    """
    own = set()
    for obj in objects:
        if obj.object_type != "dek" or obj.is_deleted or prechecked[id(obj)].error:
            continue
        if (
            obj.parent_ref is not None or obj.target_user_id is not None
            or obj.access_level is not None or obj.write_policy == "shared"
        ):
            continue
        await cur.execute("SELECT owner_id FROM vault_objects WHERE id = %s", (obj.id,))
        row = await cur.fetchone()
        if row is None or row[0] == user_id:
            own.add(obj.id)
    return frozenset(own)


async def _sealed_with_own_dek(
    cur, user_id: str, payload: bytes, batch_dek_ids: frozenset[str]
) -> bool:
    """Is this node's meta sealed with a DEK of the author's own?

    Review 7c10379 H4: the personal-tree start below the root took any
    folder, so a read-only member made folders sealed with the shared root
    key, and items in them, that colleagues saw as the company's own. A
    personal folder's meta is sealed with its own personal DEK (web
    createPersonalFolder); a DEK a member pushes is always theirs alone.
    """
    dek_id = _sealing_dek_id(payload)
    if dek_id is None:
        return False
    if dek_id in batch_dek_ids:
        return True
    await cur.execute(
        "SELECT 1 FROM vault_objects WHERE id = %s AND object_type = 'dek' "
        "AND owner_id = %s AND is_deleted = 0",
        (dek_id, user_id),
    )
    return bool(await cur.fetchone())


async def _has_write_authority(
    cur, user_id: str, parent_id: str, object_type: str = "entry",
    own_seal: Optional[Callable[[], Awaitable[bool]]] = None,
    cache: Optional[dict] = None,
    batch_dek_ids: frozenset[str] = frozenset(),
) -> bool:
    """May ``user_id`` write a ``object_type`` directly below node ``parent_id``?

    Walk up through nodes the user owns to the first node they do not own
    (the share boundary). Writing needs write_acl on that boundary, so an
    admin downgrading the share to read-only also stops writes inside
    subfolders the user created there. Only a fully owned tree hanging
    directly below the top-level root (a personal tree) needs no ACL.

    Review d615826: a member could never start such a tree, because its
    first folder sits directly below the root they do not own; the web's
    personal folder was refused. A folder of their own directly below a
    top-level node is that start; an entry there still needs write_acl.
    Review 7c10379 H4: and only when ``own_seal`` proves the folder is sealed
    with the author's own key.

    Review a159e97 H7: ``cache`` (one per push) keeps the node rows and
    write_acl answers read here; the push drops a node's row when it writes
    that node. A member's push of 50k items deep in a share ran up to 63
    SELECTs per item under the global lock (248 s).

    Review a159e97 H8: a tree directly below the root is the user's personal
    one only when its top folder is sealed with a DEK of theirs. A member
    granted write on the root made a folder there (sealed with the shared
    key) and kept writing in it after the admin took the write away.
    """
    cache = {} if cache is None else cache
    current = parent_id
    below = None  # the node visited before ``current``
    for _ in range(64):
        row = await personal_tree.node_row(cur, current, cache)
        if not row:
            return False
        owner_id, parent_ref = row
        if owner_id != user_id:
            # Review 1141a20 (R9-F): a personal tree starts top-level (TL7) or,
            # as before, directly below the org root; never below another
            # member's personal root.
            org_top = parent_ref is None and not await personal_tree.is_personal_root(
                cur, owner_id, cache
            )
            if org_top and below is not None and await _top_folder_is_own(
                cur, user_id, below, batch_dek_ids, cache
            ):
                return True  # inside a personal tree directly below the root
            if org_top and object_type == "node" and own_seal is not None:
                if await own_seal():
                    return True  # the start of a personal tree
            key = ("write_acl", current)
            if key not in cache:
                await cur.execute(
                    "SELECT 1 FROM write_acl WHERE user_id = %s AND node_id = %s",
                    (user_id, current),
                )
                cache[key] = bool(await cur.fetchone())
            return cache[key]
        if parent_ref is None:
            return True  # user owns the whole chain up to a top-level node
        below, current = current, parent_ref
    return False


_PULL_COLUMNS = (
    "id, object_type, payload, owner_id, parent_ref, target_user_id, "
    "version, commit_seq, is_deleted, payload_hash, client_signature, modified_at, "
    "write_policy, access_level, signature_user_id, dek_scope"
)


def _pull_object(r) -> PullObject:
    """A vault_objects row selected as ``_PULL_COLUMNS``, as a pull serves it."""
    return PullObject(
        id=r[0],
        object_type=r[1],
        payload=base64.b64encode(r[2]).decode("ascii"),
        owner_id=r[3],
        signature_user_id=r[14] or r[3],
        parent_ref=r[4],
        target_user_id=r[5],
        version=r[6],
        commit_seq=r[7],
        is_deleted=r[8],
        payload_hash=r[9],
        client_signature=r[10].hex() if r[10] else None,
        modified_at=r[11],
        write_policy=r[12] if r[12] else "owner_only",
        access_level=r[13],
        scope=r[15],
    )


async def _stored_object(cur, obj_id: str) -> Optional[PullObject]:
    """The stored, signed copy of ``obj_id`` (R16-Z SM22: a refused folder move
    goes back to its parent, which the client takes only under that signature)."""
    await cur.execute(f"SELECT {_PULL_COLUMNS} FROM vault_objects WHERE id = %s", (obj_id,))
    row = await cur.fetchone()
    return _pull_object(row) if row else None


_MAX_MOVE_CHECK_DEPTH = 1024


async def _is_below(cur, node_id: str, ancestor_id: str, cache: dict) -> bool:
    """Whether stored ``node_id`` is ``ancestor_id`` or lies below it.

    Stops at a chain that loops without reaching it (a cycle stored before
    R16-Z SM22): such a move does not close a new one. R17-N11: it ran under
    the global push lock with one SELECT per level for every moved folder;
    the rows come from the push's authority cache now (shared with the
    personal-tree walk, read again after the push writes a node), and a chain
    deeper than _MAX_MOVE_CHECK_DEPTH counts as below (the move is refused).
    """
    seen = set()
    current = node_id
    while current is not None and current not in seen:
        if current == ancestor_id or len(seen) >= _MAX_MOVE_CHECK_DEPTH:
            return True
        seen.add(current)
        row = await personal_tree.node_row(cur, current, cache)
        current = row[1] if row else None
    return False


_MAX_BURIED_CHECK = 10_000


async def _buries_others(
    cur, user_id: str, node_id: str, removed_here: Optional[set[str]], cleared: set[str]
) -> bool:
    """Would deleting folder ``node_id`` bury an item of another account?

    Below it may live only the user's own items and folders, each folder going
    in this push too and holding nothing of others itself. ``cleared`` keeps
    the folders found clean, so a tree deleted in one push is read once.
    ``removed_here`` None: a move, whose own folders stay below it.
    """
    stack, seen = [node_id], []
    while stack:
        current = stack.pop()
        if current in cleared:
            continue
        if len(seen) >= _MAX_BURIED_CHECK:
            return True  # too big to tell: refused
        seen.append(current)
        await cur.execute(
            "SELECT id, object_type, owner_id FROM vault_objects "
            "WHERE parent_ref = %s AND object_type IN ('node', 'entry') AND is_deleted = 0",
            (current,),
        )
        for child, kind, owner in await cur.fetchall():
            if owner != user_id:
                return True
            if kind == "node":
                if removed_here is not None and child not in removed_here:
                    return True
                stack.append(child)
    cleared.update(seen)
    return False


def _forget_written(cache: dict, obj_id: str, object_type: str) -> None:
    """What the push's authority cache reads again after the push wrote ``obj_id``:
    that node, every write_acl answer after an envelope (it may grant or take
    write) and every personal-tree answer after a DEK (its folders' seal)."""
    cache.pop(("node", obj_id), None)
    cache.pop(("own_top", obj_id), None)
    kind = {"envelope": "write_acl", "dek": "own_top"}.get(object_type)
    if kind:
        for key in [k for k in cache if k[0] == kind]:
            del cache[key]


async def _top_folder_is_own(
    cur, user_id: str, node_id: str, batch_dek_ids: frozenset[str], cache: dict
) -> bool:
    """Is the folder ``node_id`` (directly below the root) sealed with a DEK of the user's?"""
    key = ("own_top", node_id)
    if key not in cache:
        await cur.execute("SELECT payload FROM vault_objects WHERE id = %s", (node_id,))
        row = await cur.fetchone()
        cache[key] = bool(row) and await _sealed_with_own_dek(
            cur, user_id, bytes(row[0] or b""), batch_dek_ids
        )
    return cache[key]


def unknown_name_kdf(name_mac: bytes, in_use: list[Optional[str]]) -> dict:
    """KDF params to report for a name without an account (R16-L5).

    Real accounts carry the params of the device that set the password, and
    the desktop calibrates them (benchmark_argon2: time_cost 4, 5..., memory
    128 or 64 MiB), so one of two client defaults marked nearly every desktop
    account as real. An unknown name now gets params of the accounts on this
    server, picked per name in proportion to how many use them, so a name's
    params say no more than that some account uses them. A server with no
    account answers with a client default, as before.
    """
    counts: dict[str, int] = {}
    for stored in in_use:
        key = json.dumps(account_kdf_params(stored), sort_keys=True)
        counts[key] = counts.get(key, 0) + 1
    pick = int.from_bytes(name_mac[:8], "big")
    if not counts:
        return dict(CLIENT_DEFAULT_ACCOUNT_KDFS[pick % len(CLIENT_DEFAULT_ACCOUNT_KDFS)])
    pick %= sum(counts.values())
    for key in sorted(counts):
        if pick < counts[key]:
            return json.loads(key)
        pick -= counts[key]
    raise AssertionError("unreachable")


@router.get("/meta", response_model=MetaResponse)
async def get_meta(
    username: Optional[str] = Query(None),
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Public metadata endpoint (no auth required).

    Without username: returns version + default argon2 web params.
    With username: returns per-user argon2_salt + auth_salt (for provisioning/recovery).
    User enumeration protection: fake salt for non-existent users.
    """
    resp = MetaResponse(
        version="1.0",
        # Defaults for NEW accounts (web onboarding); includes hash_len so
        # clients can validate the 64-byte KEK||auth_proof split.
        argon2_web_params=dict(DEFAULT_ACCOUNT_KDF),
    )

    username = normalize_username(username or "")  # N3: same account as every other endpoint
    if username:
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT argon2_salt, auth_salt, argon2_params, username "
                    "FROM users WHERE username = %s",
                    (username,),
                )
                row = await cur.fetchone()
                # Review 18c300f R16-L5: run for every name, so the answer
                # about an unknown one takes the same queries.
                await cur.execute("SELECT argon2_params FROM users")
                in_use = [stored for (stored,) in await cur.fetchall()]
        # The column collation is case/accent-insensitive: "ADMIN" would find
        # "admin" and return its real salts, while a nonexistent name gets
        # fake ones — an enumeration oracle. Only an exact match is real.
        if row and row[3] != username:
            row = None

        fake_auth_salt = generate_fake_salt(config.hmac_server_secret, username, kind="auth").hex()
        if row and row[0]:
            resp.argon2_salt = row[0].hex()
            # R16-L5: a legacy account without one answered None, which no
            # unknown name does; no client reads it.
            resp.auth_salt = row[1].hex() if row[1] else fake_auth_salt
            resp.argon2_params = account_kdf_params(row[2])
        else:
            resp.argon2_params = unknown_name_kdf(
                unknown_name_mac(config.hmac_server_secret, username), in_use
            )
            # Fake salt — deterministic per username, same response time
            fake = generate_fake_salt(config.hmac_server_secret, username)
            resp.argon2_salt = fake.hex()
            resp.auth_salt = fake_auth_salt

    return resp
