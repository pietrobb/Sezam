"""Team log endpoints (docs/DESIGN_TEAM_LOG.md §5, TL3).

  GET  /api/team-log?since=<seq>   records after ``since`` and the head
  POST /api/team-log               append records onto the head
  POST /api/team-log/restore       records a restored server lost, from a device

A push that changes the team carries its records in ``PushRequest.team_log``
instead, so the log and the objects land in one transaction.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from .. import team_log
from ..database import Database, run_transaction
from ..dependencies import get_db, get_team_log_reader, require_full_jwt
from ..models.schemas import TeamLogAppend, TeamLogResponse
from .sync import _push_gate

router = APIRouter(prefix="/api/team-log", tags=["team-log"])


@router.get("", response_model=TeamLogResponse)
async def get_team_log(
    since: int = Query(default=-1, ge=-1),
    db: Database = Depends(get_db),
    user: dict = Depends(get_team_log_reader),
) -> TeamLogResponse:
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            state = await team_log.load_state(cur)
            records = await team_log.records_after(cur, since) if state is not None else []
    return TeamLogResponse(records=records, head=team_log.head(state))


@router.post("", response_model=TeamLogResponse)
async def append_team_log(
    req: TeamLogAppend,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
) -> TeamLogResponse:
    records = [r.model_dump() for r in req.records]

    async def _apply(conn):
        async with conn.cursor() as cur:
            # Same lock as a push: appends and pushes are serialized.
            await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
            await cur.fetchone()
            return await team_log.append(cur, records, user["sub"])

    async with _push_gate():
        state = await run_transaction(db, _apply)
    return TeamLogResponse(records=[], head=team_log.head(state))


@router.post("/restore", response_model=TeamLogResponse)
async def restore_team_log(
    req: TeamLogAppend,
    db: Database = Depends(get_db),
    user: dict = Depends(require_full_jwt),
) -> TeamLogResponse:
    """Records this server lost, uploaded again by a device that holds them."""
    records = [r.model_dump() for r in req.records]

    async def _apply(conn):
        async with conn.cursor() as cur:
            await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
            await cur.fetchone()
            return await team_log.restore(cur, records, user["sub"])

    async with _push_gate():
        state = await run_transaction(db, _apply)
    return TeamLogResponse(records=[], head=team_log.head(state))
