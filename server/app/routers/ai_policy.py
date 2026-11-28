"""Remote AI kill switch relay (AI broker TODO, section 1 phase 2).

PUT  /api/ai-policy   store the owner's signed {enabled, epoch}
GET  /api/ai-policy   the account's latest policy, for its brokers to poll
PUT  /api/ai-anchor   raise one vault's 'off' anchor (review c78fd19 R13-11)
GET  /api/ai-anchor/{anchor}

The server is not trusted with it: every broker verifies the signature
against the owner's key from its own vault and no policy can turn AI access
on. The server still checks the signature against the account's current
signing key and keeps the epoch strictly increasing, so it never stores or
replays anything the owner did not sign.

Signed messages: the shared core's ai_policy_message and ai_anchor_message
(docs/CORE_UNIFICATION.md U6c), the bytes the desktop and the phone sign.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Path
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..auth import _core_message
from ..database import Database, run_transaction
from ..dependencies import get_db, require_full_jwt
from ..models.schemas import (
    HEX_KEY,
    AIAnchor,
    AIAnchorPut,
    AIAnchorResponse,
    AIPolicy,
    AIPolicyPut,
    AIPolicyResponse,
)

router = APIRouter(prefix="/api", tags=["ai-policy"])

def policy_message(user_id: str, enabled: bool, epoch: int) -> bytes:
    return _core_message("ai_policy_message", user_id=user_id, enabled=enabled, epoch=epoch)


@router.put("/ai-policy", response_model=AIPolicyResponse)
async def put_ai_policy(
    req: AIPolicyPut,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
):
    user_id = user["sub"]
    signature = bytes.fromhex(req.signature)
    now_ms = int(time.time() * 1000)

    async def _apply(conn) -> AIPolicy:
        async with conn.cursor() as cur:
            await cur.execute("SELECT signing_pk FROM users WHERE id = %s", (user_id,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="User not found")
            try:
                VerifyKey(bytes(row[0])).verify(
                    policy_message(user_id, req.enabled, req.epoch), signature
                )
            except (BadSignatureError, ValueError):
                raise HTTPException(status_code=400, detail="invalid ai_policy signature")
            await cur.execute(
                "SELECT epoch FROM ai_policies WHERE user_id = %s FOR UPDATE", (user_id,)
            )
            current = await cur.fetchone()
            if current and req.epoch <= current[0]:
                raise HTTPException(
                    status_code=409,
                    detail="Stale ai_policy epoch; it must be higher than the stored one.",
                )
            await cur.execute(
                "INSERT INTO ai_policies (user_id, enabled, epoch, signature, updated_at) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), epoch = VALUES(epoch), "
                "signature = VALUES(signature), updated_at = VALUES(updated_at)",
                (user_id, int(req.enabled), req.epoch, signature, now_ms),
            )
        return AIPolicy(
            user_id=user_id, enabled=req.enabled, epoch=req.epoch,
            signature=req.signature.lower(), updated_at=now_ms,
        )

    return AIPolicyResponse(policy=await run_transaction(db, _apply))


@router.get("/ai-policy", response_model=AIPolicyResponse)
async def get_ai_policy(
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
):
    user_id = user["sub"]
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT enabled, epoch, signature, updated_at FROM ai_policies "
                "WHERE user_id = %s",
                (user_id,),
            )
            row = await cur.fetchone()
    if not row:
        return AIPolicyResponse(policy=None)
    return AIPolicyResponse(policy=AIPolicy(
        user_id=user_id, enabled=bool(row[0]), epoch=int(row[1]),
        signature=bytes(row[2]).hex(), updated_at=int(row[3]),
    ))


# Review c78fd19 R13-11: one vault file on one machine per anchor; a new KEK
# or a moved vault starts a new one. The oldest goes past this many.
MAX_ANCHORS_PER_USER = 32


def anchor_message(user_id: str, anchor: str, epoch: int, mac: str) -> bytes:
    return _core_message(
        "ai_anchor_message", user_id=user_id, anchor=anchor, epoch=epoch, mac=mac,
    )


@router.put("/ai-anchor", response_model=AIAnchorResponse)
async def put_ai_anchor(
    req: AIAnchorPut,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
):
    """Raise a vault's anchor. Never lowered: a lower epoch is 409.

    Review 8bc70f7 R14-M3: any holder of the account's JWT could write
    anchors: create new ones until the account's oldest (the real one) was
    deleted, or store a higher epoch with a MAC no broker accepts, after which
    the real 'off' could not be anchored again. A write now needs the
    account's current signing key."""
    user_id = user["sub"]
    anchor = req.anchor.lower()
    now_ms = int(time.time() * 1000)

    async def _apply(conn) -> AIAnchor:
        async with conn.cursor() as cur:
            await cur.execute("SELECT signing_pk FROM users WHERE id = %s", (user_id,))
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="User not found")
            try:
                VerifyKey(bytes(row[0])).verify(
                    anchor_message(user_id, anchor, req.epoch, req.mac.lower()),
                    bytes.fromhex(req.signature),
                )
            except (BadSignatureError, ValueError):
                raise HTTPException(status_code=400, detail="invalid ai_anchor signature")
            await cur.execute(
                "SELECT user_id, epoch, mac FROM ai_anchors WHERE anchor_key = %s FOR UPDATE",
                (anchor,),
            )
            current = await cur.fetchone()
            if current and current[0] != user_id:
                raise HTTPException(status_code=409, detail="ai_anchor belongs to another account")
            if current and req.epoch < current[1]:
                raise HTTPException(
                    status_code=409,
                    detail="Stale ai_anchor epoch; it must not be lower than the stored one.",
                )
            if current and req.epoch == current[1]:
                return AIAnchor(anchor=anchor, epoch=int(current[1]), mac=current[2])
            if not current:
                await cur.execute(
                    "SELECT anchor_key FROM ai_anchors WHERE user_id = %s ORDER BY updated_at",
                    (user_id,),
                )
                held = await cur.fetchall()
                for (oldest,) in held[: max(len(held) - MAX_ANCHORS_PER_USER + 1, 0)]:
                    await cur.execute("DELETE FROM ai_anchors WHERE anchor_key = %s", (oldest,))
            await cur.execute(
                "INSERT INTO ai_anchors (anchor_key, user_id, epoch, mac, updated_at) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE epoch = VALUES(epoch), mac = VALUES(mac), "
                "updated_at = VALUES(updated_at)",
                (anchor, user_id, req.epoch, req.mac.lower(), now_ms),
            )
        return AIAnchor(anchor=anchor, epoch=req.epoch, mac=req.mac.lower())

    return AIAnchorResponse(anchor=await run_transaction(db, _apply))


@router.get("/ai-anchor/{anchor}", response_model=AIAnchorResponse)
async def get_ai_anchor(
    anchor: str = Path(pattern=HEX_KEY),
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
):
    anchor = anchor.lower()
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT epoch, mac FROM ai_anchors WHERE anchor_key = %s AND user_id = %s",
                (anchor, user["sub"]),
            )
            row = await cur.fetchone()
    if not row:
        return AIAnchorResponse(anchor=None)
    return AIAnchorResponse(anchor=AIAnchor(anchor=anchor, epoch=int(row[0]), mac=row[1]))
