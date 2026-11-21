"""POST /api/objects/held: which of the given objects the server holds now.

A device whose atomic batch (a member re-key) went out and whose reply was
lost cannot tell from its own state whether the batch landed: the reply, a
later pull or a conflict copy may all be missing (capability run 437, nightly
run 44891798136). The batch's new DEK ids are fresh and only ever sent inside
it, so the server holding one of them answers the question. The server shows
every object to every account on a pull anyway (content-blind design); this
only says which of the named ones exist, without their payloads.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..database import Database
from ..dependencies import get_db, get_rotation_user

router = APIRouter(prefix="/api", tags=["sync"])

MAX_HELD_IDS = 200


class HeldRequest(BaseModel):
    ids: list[str] = Field(max_length=MAX_HELD_IDS)


class HeldObject(BaseModel):
    id: str
    object_type: str
    version: int
    is_deleted: bool


class HeldResponse(BaseModel):
    objects: list[HeldObject]


@router.post("/objects/held", response_model=HeldResponse)
async def held_objects(
    body: HeldRequest,
    db: Database = Depends(get_db),
    user: dict = Depends(get_rotation_user),
) -> HeldResponse:
    held = []
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            for object_id in dict.fromkeys(body.ids):
                await cur.execute(
                    "SELECT id, object_type, version, is_deleted FROM vault_objects WHERE id = %s",
                    (object_id,),
                )
                row = await cur.fetchone()
                if row and row[1] != "key_archive":
                    held.append(HeldObject(
                        id=row[0], object_type=row[1], version=row[2], is_deleted=bool(row[3]),
                    ))
    return HeldResponse(objects=held)
