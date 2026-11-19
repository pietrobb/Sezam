"""Secure Share endpoints.

Spec 6, 8.6:
  POST   /api/share        (create share link)
  POST   /api/share/:id    (consume share — atomic, PIN in body)
  PATCH  /api/share/:id    (admin: unlock or deactivate)
  DELETE /api/share/:id    (owner/admin: revoke + delete)
  GET    /api/shares       (admin: list active)
"""

from __future__ import annotations

import asyncio
import base64
import functools
import time

import argon2
from fastapi import APIRouter, Depends, HTTPException, Request
from ulid import ULID

from ..auth import compute_ip_hmac
from ..config import ServerConfig
from ..database import Database
from ..dependencies import get_config, get_current_user, get_db, require_admin
from ..models.schemas import (
    ShareCreateRequest,
    ShareInfo,
    ShareNotification,
    ShareResponse,
    ShareUpdateRequest,
    ShareViewRequest,
    validate_share_pin_hash,
)

# ── Per-IP PIN rate limiting (database-backed across all workers) ──
_PIN_WINDOW_MS = 15 * 60 * 1000
_PIN_MAX_PER_IP = 3
_SHARE_ERROR_MIN_SECONDS = 0.35
_SHARE_UNAVAILABLE_DETAIL = "Share unavailable"
_DUMMY_PIN_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$TF6gtT/xqLf4jG7Hx6RQVw$"
    "EFZkKuvk4GchfQuN6d7L/9uaJO5q2e6nV+DRRt7bQEM"
)
_PIN_HASHER = argon2.PasswordHasher()
# Each verification needs ~64 MiB; bound concurrent work per worker process.
_ARGON2_SLOTS = asyncio.Semaphore(4)

router = APIRouter(prefix="/api", tags=["share"])


def _run_dummy_pin_check(pin: str | None) -> None:
    try:
        _PIN_HASHER.verify(_DUMMY_PIN_HASH, pin or "")
    except argon2.exceptions.VerifyMismatchError:
        pass


async def _raise_share_unavailable(
    started_at: float,
    *,
    db: Database,
    ip_hmac: bytes,
    now_ms: int,
    dummy_pin: str | None = None,
    pin_work_done: bool = False,
) -> None:
    # The dummy Argon2 hides which failure this was, but it is still Argon2:
    # it counts against the IP window like a PIN attempt, so unknown share
    # ids are no free anonymous CPU burner (review 2052248). Past the limit
    # only the response-time floor remains.
    if not pin_work_done and await _reserve_pin_attempt(db, ip_hmac, now_ms):
        async with _ARGON2_SLOTS:
            await asyncio.to_thread(_run_dummy_pin_check, dummy_pin)
    remaining = _SHARE_ERROR_MIN_SECONDS - (time.perf_counter() - started_at)
    if remaining > 0:
        await asyncio.sleep(remaining)
    raise HTTPException(status_code=404, detail=_SHARE_UNAVAILABLE_DETAIL)


@router.post("/share")
async def create_share(
    req: ShareCreateRequest,
    request: Request,
    db: Database = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Create a share link. ID is 256-bit random base64url from client."""
    now_ms = int(time.time() * 1000)
    blob = base64.b64decode(req.encrypted_blob)

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO shared_links "
                "(id, encrypted_blob, created_by, created_at, expires_at, max_views, "
                "view_count, pin_hash, pin_attempts, is_locked, notify_on_view) "
                "VALUES (%s, %s, %s, %s, %s, %s, 0, %s, 0, 0, %s)",
                (
                    req.id, blob, user["sub"], now_ms, req.expires_at,
                    req.max_views, req.pin_hash, int(req.notify_on_view),
                ),
            )
        await conn.commit()

    return {"status": "ok", "id": req.id}


@router.post("/share/{share_id}", response_model=ShareResponse)
async def view_share(
    share_id: str,
    req: ShareViewRequest,
    request: Request = None,
    db: Database = Depends(get_db),
    config: ServerConfig = Depends(get_config),
):
    """Consume a share link (public endpoint, PIN in POST body).

    Argon2 never runs on the event loop or while a row lock is held: the
    per-IP attempt is reserved first (max 3 failures per IP per 15 min, also
    under concurrency), the PIN is verified in a bounded worker pool, and the
    view is consumed afterwards in a short locked transaction that re-checks
    the share state. Constant response time for all error states.
    """
    started_at = time.perf_counter()
    now_ms = int(time.time() * 1000)
    client_ip = request.client.host if request and request.client else "unknown"
    ip_hmac = compute_ip_hmac(config.hmac_server_secret, client_ip)
    fail = functools.partial(
        _raise_share_unavailable, started_at, db=db, ip_hmac=ip_hmac, now_ms=now_ms
    )

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT expires_at, max_views, view_count, pin_hash, is_locked "
                "FROM shared_links WHERE id = %s",
                (share_id,),
            )
            row = await cur.fetchone()
    if not row:
        await fail(dummy_pin=req.pin)
    expires_at, max_views, view_count, pin_hash, is_locked = row

    if now_ms > expires_at:
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                await cur.execute("DELETE FROM shared_links WHERE id = %s", (share_id,))
        await fail(dummy_pin=req.pin)

    # Public failures deliberately share one status, body, Argon2 cost,
    # and response-time floor so share state cannot be enumerated.
    if is_locked or view_count >= max_views:
        await fail(dummy_pin=req.pin)

    if pin_hash:
        if not req.pin:
            await fail()
        try:
            validate_share_pin_hash(pin_hash)
        except ValueError:
            await _lock_share(db, share_id)
            await fail(dummy_pin=req.pin)

        if not await _reserve_pin_attempt(db, ip_hmac, now_ms):
            await fail(pin_work_done=True)

        outcome = await _verify_pin_off_loop(pin_hash, req.pin)
        if outcome is None:
            await _lock_share(db, share_id)
            await fail(pin_work_done=True)
        if not outcome:
            async with db.transaction() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE shared_links SET pin_attempts = pin_attempts + 1 "
                        "WHERE id = %s",
                        (share_id,),
                    )
                    await cur.execute(
                        "SELECT pin_attempts FROM shared_links WHERE id = %s",
                        (share_id,),
                    )
                    attempts_row = await cur.fetchone()
                    if attempts_row and attempts_row[0] >= 10:
                        await cur.execute(
                            "UPDATE shared_links SET is_locked = 1 WHERE id = %s",
                            (share_id,),
                        )
            await fail(pin_work_done=True)

    consumed = await _consume_view(db, share_id, pin_hash, ip_hmac, now_ms, request, config)
    if consumed is None:
        # Outside the transaction: fail() may take a pool connection of its
        # own, and holding two per request deadlocks the pool (review d615826).
        await fail(pin_work_done=bool(pin_hash))
    return consumed


async def _consume_view(
    db: Database, share_id: str, pin_hash, ip_hmac: bytes, now_ms: int,
    request: Request, config: ServerConfig,
) -> ShareResponse | None:
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            if pin_hash:
                # The reservation only counts failures: refund it on success.
                await cur.execute(
                    "UPDATE share_pin_rate_limits SET failure_count = failure_count - 1 "
                    "WHERE ip_hmac = %s AND failure_count > %s",
                    (ip_hmac, 0),
                )
            # Re-check under a short lock: the share may have been viewed,
            # locked or revoked while the PIN was being verified.
            await cur.execute(
                "SELECT encrypted_blob, expires_at, max_views, view_count, "
                "is_locked, created_by, notify_on_view "
                "FROM shared_links WHERE id = %s FOR UPDATE",
                (share_id,),
            )
            current = await cur.fetchone()
            if (
                not current
                or now_ms > current[1]
                or current[4]
                or current[3] >= current[2]
            ):
                return None
            blob, _, max_views, view_count, _, owner_id, notify_on_view = current
            # Review 8595ec1: a link outlives no revocation of its author
            # (member.remove, a restored backup that still holds the link).
            await cur.execute("SELECT status FROM users WHERE id = %s", (owner_id,))
            author = await cur.fetchone()
            if not author or author[0] != "active":
                return None

            if view_count + 1 >= max_views:
                # Last allowed view: the ciphertext must not outlive it. The
                # row stays for the owner's view history and notifications.
                await cur.execute(
                    "UPDATE shared_links SET view_count = view_count + 1, "
                    "encrypted_blob = %s WHERE id = %s",
                    (b"", share_id),
                )
            else:
                await cur.execute(
                    "UPDATE shared_links SET view_count = view_count + 1 WHERE id = %s",
                    (share_id,),
                )
            view_id = str(ULID())
            ua_hmac = compute_ip_hmac(
                config.hmac_server_secret,
                request.headers.get("user-agent", "unknown"),
            )
            await cur.execute(
                "INSERT INTO share_views "
                "(id, share_id, viewed_at, viewer_ip_hmac, user_agent_hmac, "
                "owner_id, notification_pending) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    view_id, share_id, now_ms, ip_hmac, ua_hmac,
                    owner_id, int(bool(notify_on_view)),
                ),
            )

    return ShareResponse(
        encrypted_blob=base64.b64encode(blob).decode("ascii"),
        view_count=view_count + 1,
        max_views=max_views,
    )


async def _lock_share(db: Database, share_id: str) -> None:
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE shared_links SET is_locked = 1 WHERE id = %s", (share_id,)
            )


async def _reserve_pin_attempt(db: Database, ip_hmac: bytes, now_ms: int) -> bool:
    """Count this attempt against the IP window before any Argon2 work.

    Serialized per IP in MariaDB, so parallel requests and multiple workers
    cannot exceed the limit; a successful verification refunds it.
    """
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO share_pin_rate_limits "
                "(ip_hmac, window_started_at, failure_count) VALUES (%s, %s, 0) "
                "ON DUPLICATE KEY UPDATE ip_hmac = ip_hmac",
                (ip_hmac, now_ms),
            )
            await cur.execute(
                "SELECT window_started_at, failure_count "
                "FROM share_pin_rate_limits WHERE ip_hmac = %s FOR UPDATE",
                (ip_hmac,),
            )
            window_started_at, failure_count = await cur.fetchone()
            if window_started_at <= now_ms - _PIN_WINDOW_MS:
                await cur.execute(
                    "UPDATE share_pin_rate_limits "
                    "SET window_started_at = %s, failure_count = 0 WHERE ip_hmac = %s",
                    (now_ms, ip_hmac),
                )
                failure_count = 0
            if failure_count >= _PIN_MAX_PER_IP:
                return False
            await cur.execute(
                "UPDATE share_pin_rate_limits "
                "SET failure_count = failure_count + 1 WHERE ip_hmac = %s",
                (ip_hmac,),
            )
    return True


async def _verify_pin_off_loop(pin_hash: str, pin: str) -> bool | None:
    """True/False for match/mismatch, None for an unusable stored hash."""

    def verify() -> bool | None:
        try:
            return _PIN_HASHER.verify(pin_hash, pin)
        except argon2.exceptions.VerifyMismatchError:
            return False
        except (
            argon2.exceptions.InvalidHashError,
            argon2.exceptions.VerificationError,
            argon2.exceptions.UnsupportedParametersError,
        ):
            return None

    async with _ARGON2_SLOTS:
        return await asyncio.to_thread(verify)


@router.get("/share-notifications", response_model=list[ShareNotification])
async def poll_share_notifications(
    db: Database = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Atomically claim pending view notifications for the authenticated owner."""
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, share_id, viewed_at FROM share_views "
                "WHERE owner_id = %s AND notification_pending = %s "
                "ORDER BY viewed_at ASC FOR UPDATE",
                (user["sub"], 1),
            )
            rows = await cur.fetchall()
            for row in rows:
                await cur.execute(
                    "UPDATE share_views SET notification_pending = 0 "
                    "WHERE id = %s AND owner_id = %s",
                    (row[0], user["sub"]),
                )

    return [
        ShareNotification(id=row[0], share_id=row[1], viewed_at=row[2])
        for row in rows
    ]


@router.patch("/share/{share_id}")
async def update_share(
    share_id: str,
    req: ShareUpdateRequest,
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: unlock locked share or deactivate it."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            if req.action == "unlock":
                await cur.execute(
                    "UPDATE shared_links SET is_locked = 0, pin_attempts = 0 WHERE id = %s",
                    (share_id,),
                )
            elif req.action == "deactivate":
                # Set expires_at to now → effectively expired
                now_ms = int(time.time() * 1000)
                await cur.execute(
                    "UPDATE shared_links SET expires_at = %s WHERE id = %s",
                    (now_ms, share_id),
                )
            else:
                raise HTTPException(status_code=400, detail="Invalid action. Use 'unlock' or 'deactivate'.")

            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Share not found")
        await conn.commit()

    return {"status": "ok"}


@router.delete("/share/{share_id}")
async def delete_share(
    share_id: str,
    db: Database = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Revoke and delete share link + blob. Only owner or admin can delete.

    Non-admin path uses atomic DELETE ... WHERE id AND created_by to avoid
    TOCTOU race between ownership check and deletion.
    """
    is_admin = user.get("is_admin", False)
    user_id = user["sub"]

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            if is_admin:
                await cur.execute(
                    "DELETE FROM shared_links WHERE id = %s", (share_id,)
                )
            else:
                # Atomic ownership check + delete in a single statement
                await cur.execute(
                    "DELETE FROM shared_links WHERE id = %s AND created_by = %s",
                    (share_id, user_id),
                )

            if cur.rowcount == 0:
                # Distinguish between "not found" and "not owner"
                if not is_admin:
                    await cur.execute(
                        "SELECT 1 FROM shared_links WHERE id = %s", (share_id,)
                    )
                    if await cur.fetchone():
                        raise HTTPException(
                            status_code=403,
                            detail="Only the owner or admin can delete this share",
                        )
                raise HTTPException(status_code=404, detail="Share not found")
        await conn.commit()

    return {"status": "ok"}


@router.get("/shares", response_model=list[ShareInfo])
async def list_shares(
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: list active share links."""
    now_ms = int(time.time() * 1000)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, created_by, created_at, expires_at, max_views, view_count, "
                "is_locked, notify_on_view FROM shared_links "
                "WHERE expires_at > %s ORDER BY created_at DESC",
                (now_ms,),
            )
            rows = await cur.fetchall()

    return [
        ShareInfo(
            id=r[0], created_by=r[1], created_at=r[2], expires_at=r[3],
            max_views=r[4], view_count=r[5], is_locked=bool(r[6]),
            notify_on_view=bool(r[7]),
        )
        for r in rows
    ]
