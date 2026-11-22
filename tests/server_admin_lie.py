"""A server that takes ``users.is_admin`` as the admin, as before R15-F1-S2.

INV-1: the team log says who the admin is (server/app/authority.team_admin);
the users row is its cache. Client tests that guard against a lying or older
server ("the server calls him admin") put this one in place: whoever the
users row or the log names is an admin to it.
"""
from __future__ import annotations

from contextlib import contextmanager

from server.app import authority

_TEAM_ADMIN, _ADMIN_BY = authority.team_admin, authority.admin_by


def _admin_by(state, user_id: str, cached: bool) -> bool:
    return bool(cached) or _ADMIN_BY(state, user_id, cached)


async def _team_admin(cur, user_id: str, *, state=None, cached=None) -> bool:
    if cached is None:
        await cur.execute("SELECT status, is_admin FROM users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
        cached = row is not None and row[0] == "active" and bool(row[1])
    return bool(cached) or await _TEAM_ADMIN(cur, user_id, state=state, cached=cached)


def users_row_decides(monkeypatch) -> None:
    """For the rest of the test (pytest's monkeypatch undoes it)."""
    monkeypatch.setattr(authority, "team_admin", _team_admin)
    monkeypatch.setattr(authority, "admin_by", _admin_by)


@contextmanager
def users_row_deciding():
    authority.team_admin, authority.admin_by = _team_admin, _admin_by
    try:
        yield
    finally:
        authority.team_admin, authority.admin_by = _TEAM_ADMIN, _ADMIN_BY
