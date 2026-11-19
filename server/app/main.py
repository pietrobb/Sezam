"""Sezam server — FastAPI entry point.

Content-blind blob store with Ed25519 challenge-response auth.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import asyncio
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .auth import OUTDATED_CLIENT_SIGNATURE, OutdatedClientSignature
from .config import JWTKeyManager, ServerConfig
from .database import Database
from .dependencies import get_db, set_globals
from .errors import ApiError
from .models.schemas import MAX_REQUEST_BODY_BYTES
from . import team_log as team_log_state
from .routers import ai_policy, audit, auth, recovery, share, sync, team_log, users

logger = logging.getLogger(__name__)


async def _cleanup_spent_challenges(db: Database, ttl_seconds: int) -> None:
    """Delete spent challenges older than TTL (spec: 5 min)."""
    cutoff_ms = int(time.time() * 1000) - ttl_seconds * 1000
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM spent_challenges WHERE used_at < %s", (cutoff_ms,)
            )
            await cur.execute(
                "DELETE FROM auth_challenge_limits WHERE window_started_at < %s",
                (cutoff_ms,),
            )
            await cur.execute(
                "DELETE FROM org_recovery_rate_limits WHERE window_started_at < %s",
                (int(time.time() * 1000) - 60 * 60 * 1000,),
            )
        await conn.commit()


async def _cleanup_recovery_name_limits(db: Database, idle_seconds: int) -> None:
    """Drop shadow recovery counters of names nobody tried for a while."""
    cutoff_ms = int(time.time() * 1000) - idle_seconds * 1000
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM recovery_name_limits WHERE last_recovery_attempt < %s",
                (cutoff_ms,),
            )
            await cur.execute(
                "DELETE FROM recovery_probe_slots WHERE probe_at < %s", (cutoff_ms,)
            )
            await cur.execute(
                "DELETE FROM recovery_name_rations WHERE window_started_at < %s",
                (cutoff_ms,),
            )
            await cur.execute(
                "DELETE FROM recovery_ip_limits WHERE window_started_at < %s",
                (int(time.time() * 1000) - 3600 * 1000,),
            )
        await conn.commit()


async def _cleanup_key_material_archive(db: Database, keep_days: int) -> None:
    """Review 688edcb: each archived generation is the account keypair under
    an old password - an offline-guessing target if the database leaks."""
    cutoff_ms = int(time.time() * 1000) - keep_days * 86_400_000
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM user_key_material_archive WHERE archived_at < %s",
                (cutoff_ms,),
            )
        await conn.commit()


async def _cleanup_revoked_tokens(db: Database) -> None:
    """Delete revoked tokens past their JWT expiry (spec: auto-cleanup)."""
    now_ms = int(time.time() * 1000)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM revoked_tokens WHERE expires_at < %s", (now_ms,)
            )
        await conn.commit()


async def _cleanup_expired_shares(db: Database) -> None:
    """Delete expired share links (spec: cron job every hour)."""
    now_ms = int(time.time() * 1000)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "DELETE FROM shared_links WHERE expires_at < %s", (now_ms,)
            )
            await cur.execute(
                "DELETE FROM share_pin_rate_limits WHERE window_started_at < %s",
                (now_ms - 15 * 60 * 1000,),
            )
            # Parts of a staged push nobody completed within a day.
            await cur.execute(
                "DELETE FROM sync_staged_objects WHERE created_at < %s",
                (now_ms - 24 * 3600 * 1000,),
            )
        await conn.commit()


# Review d150605 N7: how far the GC clock may move on the first run of a
# process, which has no elapsed time of its own to go by.
GC_CLOCK_RESTART_STEP_MS = 86_400_000
# (monotonic time, GC clock written) of this process's last GC run.
_gc_clock_last_run: tuple[float, int] | None = None


def _gc_clock(stored_ms: int, stored_wall_ms: int, wall_ms: int) -> int:
    """The time tombstone GC goes by: the wall clock, but never faster than time passes.

    Review d150605 N7: a server clock set forward by more than the retention
    (a bad NTP source, a reset RTC) made every tombstone look expired, and one
    GC run collected all of them. Between runs the clock advances at most by
    the elapsed monotonic time; it never goes back. A long outage leaves it
    behind, which only keeps tombstones longer.

    Review 8595ec1: the elapsed time was per worker while the clock is shared.
    Each new worker's first run moved it a full day, and workers taking turns
    each added their own elapsed time. A worker now moves it at most to what
    it wrote last plus its own elapsed time; a first run at most by the wall
    time since the last run of any worker, and never more than a day.
    """
    global _gc_clock_last_run
    now = time.monotonic()
    last, _gc_clock_last_run = _gc_clock_last_run, None
    if not stored_ms:
        result = wall_ms
    else:
        if last is None:
            since_wall = wall_ms - stored_wall_ms if stored_wall_ms else GC_CLOCK_RESTART_STEP_MS
            limit = stored_ms + min(GC_CLOCK_RESTART_STEP_MS, max(0, since_wall))
        else:
            limit = last[1] + int((now - last[0]) * 1000) + 60_000
        if wall_ms > limit:
            logger.warning(
                "Server clock is %d s ahead of the time that passed since the last "
                "tombstone GC; GC goes by the elapsed time",
                (wall_ms - limit) // 1000,
            )
        result = max(stored_ms, min(wall_ms, limit))
    _gc_clock_last_run = (now, result)
    return result


async def _cleanup_tombstones(db: Database, tombstone_gc_days: int) -> None:
    """Delete tombstoned vault_objects older than tombstone_gc_days.

    Updates gc_floor_seq to the max commit_seq of deleted tombstones
    BEFORE removing them, so clients that haven't synced in time
    get a 410 (full resync required).
    """
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            # Same lock order as sync_push (commit_counter first), so GC and a
            # push never wait for each other's vault_objects locks.
            await cur.execute(
                "SELECT gc_floor_seq, gc_clock_ms, gc_clock_wall_ms FROM commit_counter "
                "WHERE id = 1 FOR UPDATE"
            )
            row = await cur.fetchone()
            gc_floor = (row[0] if row else 0) or 0
            wall_ms = int(time.time() * 1000)
            clock_ms = _gc_clock(
                (row[1] if row else 0) or 0, (row[2] if row else 0) or 0, wall_ms
            )
            await cur.execute(
                "UPDATE commit_counter SET gc_clock_ms = %s, gc_clock_wall_ms = %s WHERE id = 1",
                (clock_ms, wall_ms),
            )
            cutoff_ms = clock_ms - tombstone_gc_days * 86400 * 1000
            await cur.execute(
                "SELECT id, commit_seq, object_type, version, payload_hash FROM vault_objects "
                "WHERE is_deleted = 1 AND modified_at < %s",
                (cutoff_ms,),
            )
            # Review d150605 S5: an envelope tombstone stays. Collected, the
            # access it took away came back when an outdated device resent the
            # envelope: the server took it as a new object and restored write_acl.
            tombstones = await cur.fetchall()
            doomed = {
                oid: seq for oid, seq, object_type, _v, _h in tombstones
                if object_type != "envelope"
            }
            ledger = {
                oid: (version, payload_hash)
                for oid, _seq, object_type, version, payload_hash in tombstones
                if object_type in ("node", "entry")
            }
            if doomed:
                # Review d150605 #1: a deleted folder that something kept still
                # hangs below (a live item an older server let in, or a tombstone
                # that stays) keeps its tombstone. Collecting it left that item
                # without a parent and broke every new device and full resync.
                await cur.execute(
                    "SELECT id, object_type, parent_ref FROM vault_objects "
                    "WHERE parent_ref IS NOT NULL"
                )
                children = [
                    (oid, parent) for oid, object_type, parent in await cur.fetchall()
                    if object_type in ("node", "entry") and parent
                ]
                while True:
                    still_parents = {parent for oid, parent in children if oid not in doomed}
                    kept = still_parents & doomed.keys()
                    if not kept:
                        break
                    for oid in kept:
                        del doomed[oid]

            if doomed:
                # Update gc_floor_seq BEFORE deleting the tombstones
                await cur.execute(
                    "UPDATE commit_counter SET gc_floor_seq = %s WHERE id = 1",
                    (max(gc_floor, max(doomed.values())),),
                )
                for oid in doomed:
                    if oid in ledger:
                        await cur.execute(
                            "INSERT INTO collected_objects (id, version, payload_hash, commit_seq) "
                            "VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE "
                            "version = VALUES(version), payload_hash = VALUES(payload_hash), "
                            "commit_seq = VALUES(commit_seq)",
                            (oid, *ledger[oid], doomed[oid]),
                        )
                    await cur.execute(
                        "DELETE FROM vault_objects WHERE id = %s AND is_deleted = 1",
                        (oid,),
                    )
                    # Only the collected folder's write_acl goes. Review
                    # 8595ec1: dropping every row of a folder that is not live
                    # also took it from a folder in the trash, and restored it
                    # came back read-only for its members.
                    await cur.execute("DELETE FROM write_acl WHERE node_id = %s", (oid,))


async def _periodic_cleanup(db: Database, config: ServerConfig) -> None:
    """Background task running periodic cleanups.

    Every worker runs this loop, but only the holder of the database
    maintenance lock does the work, so cleanups never run N times in parallel.
    """
    while True:
        try:
            if not await db.hold_maintenance_lock():
                await asyncio.sleep(config.cleanup_interval_seconds)
                continue
            await _cleanup_spent_challenges(db, config.spent_challenge_ttl_seconds)
            await _cleanup_revoked_tokens(db)
            await _cleanup_expired_shares(db)
            await _cleanup_tombstones(db, config.tombstone_gc_days)
            await _cleanup_recovery_name_limits(db, config.recovery_lock_seconds)
            await _cleanup_key_material_archive(db, config.key_material_archive_days)
        except Exception:
            # Keep the loop alive, but a failing cleanup must be visible.
            logger.exception("Periodic cleanup failed")
        await asyncio.sleep(config.cleanup_interval_seconds)


DB_PING_TIMEOUT_S = 5
WATCHDOG_INTERVAL_S = 30
WATCHDOG_MAX_FAILURES = 6
WATCHDOG_BUSY_MAX_S = 900


async def _db_ping(db: Database) -> None:
    async def ping() -> None:
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
                await cur.fetchone()

    await asyncio.wait_for(ping(), timeout=DB_PING_TIMEOUT_S)


async def _db_watchdog(db: Database, exit_process=os._exit) -> None:
    """Exit this worker when its pool stays unusable (review d615826 #1).

    An unhealthy container keeps running under `restart: unless-stopped`;
    only a process exit is recovered (uvicorn respawns the worker, Docker
    restarts a dead container).

    Review a159e97 (medium): a pool whose every connection serves a long push
    is busy, not dead; the watchdog killed such a worker mid-push. When the
    pool is all in use and the database answers on a connection of the
    watchdog's own, that counts as busy, for at most WATCHDOG_BUSY_MAX_S.
    """
    failures = 0
    busy_since = None
    while True:
        await asyncio.sleep(WATCHDOG_INTERVAL_S)
        try:
            await _db_ping(db)
            failures = 0
            busy_since = None
        except Exception:
            if db.pool_exhausted():
                try:
                    await asyncio.wait_for(
                        db.ping_outside_pool(DB_PING_TIMEOUT_S), timeout=DB_PING_TIMEOUT_S
                    )
                except Exception as exc:
                    logger.error("DB pool all in use and the database does not answer: %s", exc)
                else:
                    busy_since = time.monotonic() if busy_since is None else busy_since
                    if time.monotonic() - busy_since < WATCHDOG_BUSY_MAX_S:
                        logger.warning("DB pool busy (every connection in use); the database answers")
                        continue
            failures += 1
            logger.error("DB ping failed (%d/%d)", failures, WATCHDOG_MAX_FAILURES)
            if failures >= WATCHDOG_MAX_FAILURES:
                logger.critical("DB pool unusable; exiting the worker for a restart")
                exit_process(1)
                return


async def _warm_team_log(db: Database) -> None:
    """Replay the stored team log once at start (review c78fd19: the first
    requests of a fresh worker each waited for the whole replay)."""
    try:
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                await team_log_state.load_state(cur)
    except Exception as exc:  # a request replays it again and reports why
        logger.warning("Team log not replayed at start: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown: connect DB, load JWT key, start cleanup tasks."""
    config = ServerConfig.from_env()
    db = Database(config)
    jwt_mgr = JWTKeyManager(config.jwt_signing_key_path)

    await db.connect()
    await db.create_schema()
    jwt_mgr.bind_database(db.instance_id)
    set_globals(config, db, jwt_mgr)

    # Start periodic cleanup background task
    cleanup_task = asyncio.create_task(_periodic_cleanup(db, config))
    watchdog_task = asyncio.create_task(_db_watchdog(db))
    warm_task = asyncio.create_task(_warm_team_log(db))

    yield

    for task in (cleanup_task, watchdog_task, warm_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await db.close()


app = FastAPI(
    title="Sezam Server",
    description="Content-blind encrypted credential vault server",
    version="0.1.0",
    lifespan=lifespan,
)

@app.exception_handler(OutdatedClientSignature)
async def _outdated_client_signature(request: Request, exc: OutdatedClientSignature):
    return JSONResponse(status_code=426, content={"detail": OUTDATED_CLIENT_SIGNATURE})


@app.exception_handler(ApiError)
async def _api_error(request: Request, exc: ApiError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "code": exc.code},
        headers=exc.headers,
    )


_WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
app.mount("/static", StaticFiles(directory=_WEB_ROOT / "static"), name="static")

# CORS — loaded from SEZAM_CORS_ORIGINS env var
app.add_middleware(
    CORSMiddleware,
    allow_origins=ServerConfig.cors_origins_from_env(),
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Security headers middleware

class _RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_body_size: int):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_content_length = headers.get(b"content-length")
        if raw_content_length is not None:
            try:
                content_length = int(raw_content_length)
            except (TypeError, ValueError):
                response = PlainTextResponse("Invalid Content-Length", status_code=400)
                await response(scope, receive, send)
                return
            if content_length < 0:
                response = PlainTextResponse("Invalid Content-Length", status_code=400)
                await response(scope, receive, send)
                return
            if content_length > self.max_body_size:
                response = PlainTextResponse("Request body too large", status_code=413)
                await response(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_size:
                    raise _RequestBodyTooLarge
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestBodyTooLarge:
            if response_started:
                raise
            response = PlainTextResponse("Request body too large", status_code=413)
            await response(scope, receive, send)


app.add_middleware(RequestBodyLimitMiddleware, max_body_size=MAX_REQUEST_BODY_BYTES)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
        path = request.url.path
        is_share_response = (
            path in {"/api/share", "/api/shares", "/s"}
            or path.startswith(("/api/share/", "/s/"))
        )
        if is_share_response:
            # frame-ancestors: a framing page could overlay the PIN form and
            # the revealed secret (clickjacking).
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                # Crypto libraries are self-hosted (web/static/js/vendor):
                # no third-party script origin at all.
                "script-src 'self' 'wasm-unsafe-eval'; "
                "style-src 'self' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "worker-src 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; base-uri 'self'"
            )
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Routers
app.include_router(auth.bootstrap_router)
app.include_router(auth.router)
app.include_router(auth.keypair_router)
app.include_router(users.router)
app.include_router(sync.router)
app.include_router(team_log.router)
app.include_router(share.router)
app.include_router(audit.router)
app.include_router(recovery.router)
app.include_router(ai_policy.router)


@app.get("/health")
async def health(db: Database = Depends(get_db)):
    # Reports a wedged pool; Docker only marks the container unhealthy and
    # never restarts it, so _db_watchdog is what ends a wedged worker.
    try:
        await _db_ping(db)
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ok", "version": "0.1.0"}


_STATIC_REF = re.compile(r'((?:src|href)=")(/static/[A-Za-z0-9_./-]+)(?:\?v=[^"]*)?(")')


@functools.lru_cache(maxsize=4)
def _web_shell(name: str) -> str:
    """The page with each /static asset it names versioned by its content.

    Review c78fd19 (web): the version in the URL was set by hand, and a
    teamlog.js changed under the same ?v= came from the browser's cache next
    to the new app.js, which then failed every login. A file of another
    content now has another URL (also the vendor files, whose SRI hash
    changes with them).
    """
    html = (_WEB_ROOT / "templates" / name).read_text(encoding="utf-8")

    def versioned(match: re.Match) -> str:
        asset = _WEB_ROOT / match.group(2).lstrip("/")
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()[:16]
        return f"{match.group(1)}{match.group(2)}?v={digest}{match.group(3)}"

    return _STATIC_REF.sub(versioned, html)


def _shell_response(name: str) -> HTMLResponse:
    # no-cache: the browser asks again for the page, and so learns new URLs.
    return HTMLResponse(_web_shell(name), headers={"Cache-Control": "no-cache"})


@app.get("/", response_class=HTMLResponse)
async def web_vault():
    """Serve the web vault shell (all crypto runs client-side)."""
    return _shell_response("index.html")


@app.get("/s/{share_id}", response_class=HTMLResponse)
async def share_page(share_id: str):
    """Serve the public recipient shell; the URL fragment never reaches here."""
    return _shell_response("share.html")
