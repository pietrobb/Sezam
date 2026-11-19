"""Remote AI kill switch relay (AI broker TODO, section 1 phase 2).

PUT  /api/ai-policy   store the owner's signed {enabled, epoch}
GET  /api/ai-policy   the account's latest policy, for its brokers to poll

The server is not trusted with it: every broker verifies the signature
against the owner's key from its own vault and no policy can turn AI access
on. The server still checks the signature against the account's current
signing key and keeps the epoch strictly increasing, so it never stores or
replays anything the owner did not sign.

Signed message (shared with sezam.mcp.remote_policy and the mobile client)::

    b"sezam-ai-policy-v1" || user_id (26 B ASCII) || u8(enabled) || u64be(epoch)
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from ..database import Database, run_transaction
from ..dependencies import get_db, require_full_jwt
from ..models.schemas import AIPolicy, AIPolicyPut, AIPolicyResponse

router = APIRouter(prefix="/api", tags=["ai-policy"])

POLICY_CONTEXT = b"sezam-ai-policy-v1"


def policy_message(user_id: str, enabled: bool, epoch: int) -> bytes:
    user = user_id.encode("ascii")
    if len(user) != 26:
        raise ValueError("user_id must be a 26-character ULID")
    return POLICY_CONTEXT + user + bytes([1 if enabled else 0]) + epoch.to_bytes(8, "big")


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
