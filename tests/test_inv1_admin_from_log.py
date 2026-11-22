"""INV-1 / R15-F1-S2 (docs/ROOT_CAUSE_PLAN.md): who is the team admin comes
from the replayed team log alone. ``users.is_admin`` is the log's cache; a
server whose cache says otherwise (a stale row, a tampered database) decides
nothing by it. Only an organisation without a log reads it (NO_LOG, until S6).
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    app_client,
    mock_db,
)
from tests.test_team_log_server import ADMIN, BOB, Team, _auth, _founded, _row

DAN = "01JM0000000000000000000009"


@pytest.mark.asyncio
async def test_a_member_the_cache_calls_admin_is_no_admin(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    _row(mock_db, BOB)["is_admin"] = 1
    _create_regular_user(mock_db._storage, DAN, "dan")
    assert (await app_client.post("/api/users/invite", headers=_auth(team.token[BOB]))).status_code == 403
    assert (await app_client.get("/api/users", headers=_auth(team.token[BOB]))).status_code == 403
    assert (await app_client.delete(f"/api/users/{DAN}", headers=_auth(team.token[BOB]))).status_code == 403
    assert _row(mock_db, DAN)["status"] == "active"


@pytest.mark.asyncio
async def test_the_admin_the_cache_forgot_is_still_the_admin(app_client, mock_db):
    team = Team(mock_db)
    await _founded(app_client, team)
    _row(mock_db, ADMIN)["is_admin"] = 0
    _create_regular_user(mock_db._storage, DAN, "dan")
    assert (await app_client.post("/api/users/invite", headers=_auth(team.token[ADMIN]))).status_code == 200
    assert (await app_client.get("/api/users", headers=_auth(team.token[ADMIN]))).status_code == 200
    assert (await app_client.delete(f"/api/users/{DAN}", headers=_auth(team.token[ADMIN]))).status_code == 200


@pytest.mark.asyncio
async def test_without_a_log_the_cache_decides(app_client, mock_db):
    """NO_LOG: before a genesis there is nothing else to ask (S6 removes it)."""
    team = Team(mock_db)
    assert (await app_client.post("/api/users/invite", headers=_auth(team.token[ADMIN]))).status_code == 200
    assert (await app_client.post("/api/users/invite", headers=_auth(team.token[BOB]))).status_code == 403


SERVER = pathlib.Path(__file__).resolve().parent.parent / "server" / "app"
READS_CACHE = re.compile(r"\b(SELECT|WHERE)\b[^;]*\bis_admin\b", re.I | re.S)


def _cache_reads() -> set[str]:
    """``module:function`` of every top-level function or method whose SQL reads users.is_admin."""
    found = set()
    for path in SERVER.rglob("*.py"):
        module = ".".join(path.relative_to(SERVER).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defs = [(n.name, n) for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            defs += [(f"{cls.name}.{n.name}", n) for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for name, fn in defs:
            if any(isinstance(c, ast.Constant) and isinstance(c.value, str) and READS_CACHE.search(c.value)
                   for c in ast.walk(fn)):
                found.add(f"{module}:{name}")
    return found


def test_every_read_of_the_cache_is_registered():
    """S2: users.is_admin decides only through authority.team_admin; any other
    read is listed in authority.CACHE_READS with why it decides nothing."""
    from server.app.authority import CACHE_READS  # not at the top: the red line runs on the code before it

    found = _cache_reads()
    assert sorted(found - CACHE_READS.keys()) == [], "reads of users.is_admin missing from CACHE_READS"
    assert sorted(CACHE_READS.keys() - found) == [], "CACHE_READS entries that no longer read users.is_admin"


def test_the_cache_read_detector_sees_a_read():
    assert READS_CACHE.search("SELECT status, is_admin FROM users WHERE id = %s")
    assert READS_CACHE.search("SELECT id FROM users WHERE is_admin = %s AND status = %s")
    assert not READS_CACHE.search("UPDATE users SET is_admin = %s WHERE id = %s")
    assert not READS_CACHE.search("INSERT INTO users (id, is_admin) VALUES (%s, %s)")
