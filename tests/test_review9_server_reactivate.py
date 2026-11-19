"""Review 1141a20 (R9-F): reactivate brought back a member the team log removed.

``PATCH /api/users/{id}/reactivate`` set a revoked account active again
without a log record, so a member removed by a signed member.remove signed
in again. With a team log, such a member comes back only through a signed
member.add, which now reactivates the account itself (same key material,
tokens from before the removal stay dead).
"""

from __future__ import annotations

import pytest

from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)
from tests.test_team_log_server import ADMIN, BOB, Team, _append, _auth, _founded, _row


async def _removed_bob(client, db) -> Team:
    team = Team(db)
    await _founded(client, team)
    remove = team.record("member.remove", ADMIN, {"user_id": BOB})
    team.accept(remove)
    assert (await _append(client, team, ADMIN, remove)).status_code == 200
    assert _row(db, BOB)["status"] == "revoked"
    return team


@pytest.mark.asyncio
async def test_reactivate_does_not_bring_back_a_member_the_log_removed(app_client, mock_db):  # noqa: F811
    team = await _removed_bob(app_client, mock_db)
    resp = await app_client.patch(f"/api/users/{BOB}/reactivate", headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 409, resp.text
    assert _row(mock_db, BOB)["status"] == "revoked"


@pytest.mark.asyncio
async def test_a_signed_re_add_brings_the_member_back(app_client, mock_db):  # noqa: F811
    team = await _removed_bob(app_client, mock_db)
    epoch = _row(mock_db, BOB).get("token_epoch") or 0
    readd = team.add(BOB)
    team.accept(readd)
    resp = await _append(app_client, team, ADMIN, readd)
    assert resp.status_code == 200, resp.text
    row = _row(mock_db, BOB)
    assert row["status"] == "active"
    assert (row.get("token_epoch") or 0) == epoch  # tokens from before the removal stay dead


@pytest.mark.asyncio
async def test_a_re_add_without_key_material_is_refused(app_client, mock_db):  # noqa: F811
    team = await _removed_bob(app_client, mock_db)
    _row(mock_db, BOB)["encrypted_keypair"] = None
    readd = team.add(BOB)
    resp = await _append(app_client, team, ADMIN, readd)
    assert resp.status_code == 400, resp.text
    assert _row(mock_db, BOB)["status"] == "revoked"


@pytest.mark.asyncio
async def test_reactivate_still_undoes_a_revocation_outside_the_log(app_client, mock_db):  # noqa: F811
    from tests.test_team_log_server import CAROL

    team = Team(mock_db)  # no log yet
    _row(mock_db, CAROL)["status"] = "revoked"
    resp = await app_client.patch(f"/api/users/{CAROL}/reactivate", headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200, resp.text
    assert _row(mock_db, CAROL)["status"] == "active"
