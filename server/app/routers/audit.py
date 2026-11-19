"""Audit log endpoint — admin-only access to server_audit table.

GET  /api/audit      — paginated, filterable JSON
GET  /api/audit/csv  — CSV export with same filters
POST /api/audit/log  — client-side event logging (field access, entry views)
"""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.responses import Response as StarletteResponse

from ..audit import log_server_audit
from ..database import Database
from ..dependencies import get_db, require_admin, require_full_jwt
from ..models.schemas import AuditEntry, AuditLogRequest, AuditResponse

router = APIRouter(prefix="/api", tags=["audit"])

# Allowed actions for client-side audit logging
_ALLOWED_CLIENT_ACTIONS = frozenset({
    "field_show", "field_copy",
    "entry_view", "entry_edit", "entry_delete", "entry_create",
    "folder_create",
})


def _build_audit_query(
    action: str | None,
    user: str | None,
    ip: str | None,
    since: int | None,
    until: int | None,
):
    """Build WHERE clause and params for audit queries."""
    conditions = []
    params = []

    if action:
        conditions.append("sa.action = %s")
        params.append(action)

    if user:
        conditions.append("u.username LIKE %s")
        params.append(f"%{user}%")

    if ip:
        conditions.append("sa.client_ip LIKE %s")
        params.append(f"{ip}%")

    if since:
        conditions.append("sa.timestamp >= %s")
        params.append(since)

    if until:
        conditions.append("sa.timestamp <= %s")
        params.append(until)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    return where_clause, params


@router.post("/audit/log")
async def log_client_event(
    body: AuditLogRequest,
    request: Request,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
):
    """Store a content-blind event only after verifying its dedicated signature."""
    if body.action not in _ALLOWED_CLIENT_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Invalid action: {body.action}")

    expected_hash = hashlib.sha256(body.action.encode("utf-8")).hexdigest()
    if body.request_hash.lower() != expected_hash:
        raise HTTPException(status_code=400, detail="request_hash does not match audit event")

    user_id = user["sub"]
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT signing_pk FROM users WHERE id = %s", (user_id,))
            key_row = await cur.fetchone()
    if not key_row:
        raise HTTPException(status_code=401, detail="Unknown audit signer")

    try:
        await log_server_audit(
            db,
            audit_id=body.id,
            user_id=user_id,
            action=body.action,
            timestamp=body.timestamp,
            request_hash=body.request_hash.lower(),
            signature=bytes.fromhex(body.signature),
            signing_pk=key_row[0],
            client_ip=request.client.host if request.client else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"ok": True}


@router.get("/audit", response_model=AuditResponse)
async def get_audit_log(
    action: Optional[str] = Query(None, description="Filter by action type (exact match)"),
    user: Optional[str] = Query(None, description="Filter by username (substring match)"),
    ip: Optional[str] = Query(None, description="Filter by IP address (prefix match)"),
    since: Optional[int] = Query(None, description="Only entries after this timestamp (Unix ms)"),
    until: Optional[int] = Query(None, description="Only entries before this timestamp (Unix ms)"),
    limit: int = Query(200, ge=1, le=1000, description="Max entries to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Return server audit log entries (admin only).

    Supports rich filtering by action, username, IP, time range.
    Returns paginated results with total count.
    """
    where_clause, params = _build_audit_query(action, user, ip, since, until)

    # Get total count first
    count_query = (
        f"SELECT COUNT(*) FROM server_audit sa "
        f"LEFT JOIN users u ON sa.user_id = u.id "
        f"{where_clause}"
    )

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(count_query, tuple(params))
            count_row = await cur.fetchone()
            total = count_row[0] if count_row else 0

            # Fetch page
            data_query = (
                f"SELECT sa.id, sa.user_id, u.username, sa.action, sa.timestamp, "
                f"sa.request_hash, sa.commit_seq_range, sa.client_signature, sa.client_ip "
                f"FROM server_audit sa "
                f"LEFT JOIN users u ON sa.user_id = u.id "
                f"{where_clause} "
                f"ORDER BY sa.timestamp DESC "
                f"LIMIT %s OFFSET %s"
            )
            data_params = list(params) + [limit, offset]
            await cur.execute(data_query, tuple(data_params))
            rows = await cur.fetchall()

    entries = []
    for r in rows:
        entries.append(AuditEntry(
            id=r[0],
            user_id=r[1],
            username=r[2] or r[1],
            action=r[3],
            timestamp=r[4],
            request_hash=r[5],
            commit_seq_range=r[6],
            client_signature=r[7].hex(),
            client_ip=r[8],
        ))

    return AuditResponse(entries=entries, total=total, limit=limit, offset=offset)


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Neutralize spreadsheet formulas (usernames/actions are user-controlled)."""
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


def _csv_time(ts_ms) -> str:
    """UTC time of an audit row; an out-of-range stamp is kept as raw ms.

    One record stamped e.g. 1e15 ms (year ~33658) used to make the whole
    export fail with a 500 (review 2052248).
    """
    try:
        dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, TypeError, ValueError):
        return f"{ts_ms} ms"


@router.get("/audit/csv")
async def get_audit_csv(
    action: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    since: Optional[int] = Query(None),
    until: Optional[int] = Query(None),
    limit: int = Query(1000, ge=1, le=10000),
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Export audit log as CSV (admin only). Same filters as GET /api/audit."""
    where_clause, params = _build_audit_query(action, user, ip, since, until)

    data_query = (
        f"SELECT sa.id, sa.user_id, u.username, sa.action, sa.timestamp, "
        f"sa.request_hash, sa.commit_seq_range, sa.client_ip "
        f"FROM server_audit sa "
        f"LEFT JOIN users u ON sa.user_id = u.id "
        f"{where_clause} "
        f"ORDER BY sa.timestamp DESC "
        f"LIMIT %s"
    )
    data_params = list(params) + [limit]

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(data_query, tuple(data_params))
            rows = await cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Action", "Username", "IP", "Request Hash", "Commit Seq Range"])

    for r in rows:
        writer.writerow([csv_safe(value) for value in (
            _csv_time(r[4]),
            r[3],               # action
            r[2] or r[1],       # username or user_id
            r[7] or "",         # client_ip
            r[5] or "",         # request_hash
            r[6] or "",         # commit_seq_range
        )])

    csv_content = output.getvalue()
    return StarletteResponse(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=sezam-audit.csv",
        },
    )
