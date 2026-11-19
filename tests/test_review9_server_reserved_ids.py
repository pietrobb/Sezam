"""Review 1141a20 (R9-F): a member took an id the team log announced first.

An admin appends ``folder.key`` (folder F, key K) and pushes F and K after it,
in a later batch. In between, a member pushed a node F of their own (or a key
object K, or an entry named F), owned it on the server, and the admin's folder
landed as 'not owner'. Every client then read the log's team folder from the
member's object.

An id the log announced is reserved: only an admin or the record's author
creates it, and only as what the log says it is (F a node, K a key).
"""

from __future__ import annotations

import pytest

from tests.test_review6_web_member_personal_folder import sealed
from tests.test_review7_member_root_write_h4 import _push, _wire
from tests.test_team_log_server import ADMIN, BOB, FOLDER, K1, Team, _append, _founded
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)

BOB_DEK = "01JD0000000000000000000B0B"


async def _announced(app_client, mock_db):  # noqa: F811
    team = Team(mock_db)
    await _founded(app_client, team)
    key = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None})
    team.accept(key)
    assert (await _append(app_client, team, ADMIN, key)).status_code == 200
    return team


def _stored(mock_db, obj_id):  # noqa: F811
    return next((o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id), None)


async def _bob(app_client, team, *objects):  # noqa: F811
    return await _push(app_client, team.token[BOB], list(objects))


@pytest.mark.asyncio
async def test_a_member_cannot_take_the_announced_folder_id(app_client, mock_db):  # noqa: F811
    announced = await _announced(app_client, mock_db)
    sk = announced.sk[BOB]
    body = await _bob(
        app_client, announced,
        _wire(sk, BOB_DEK, "dek", None, 1, b"k" * 72),
        _wire(sk, FOLDER, "node", None, 1, sealed(BOB_DEK)),
    )
    assert [a["id"] for a in body["accepted"]] == [BOB_DEK], body
    assert _stored(mock_db, FOLDER) is None


@pytest.mark.asyncio
async def test_a_member_cannot_take_the_announced_key_id(app_client, mock_db):  # noqa: F811
    announced = await _announced(app_client, mock_db)
    body = await _bob(app_client, announced, _wire(announced.sk[BOB], K1, "dek", None, 1, b"k" * 72))
    assert body["accepted"] == [], body
    assert _stored(mock_db, K1) is None


@pytest.mark.asyncio
async def test_a_member_cannot_take_the_folder_id_as_an_entry(app_client, mock_db):  # noqa: F811
    announced = await _announced(app_client, mock_db)
    sk = announced.sk[BOB]
    body = await _bob(
        app_client, announced,
        _wire(sk, BOB_DEK, "dek", None, 1, b"k" * 72),
        _wire(sk, "01JF00000000000000000B0B01", "node", None, 1, sealed(BOB_DEK)),
        _wire(sk, FOLDER, "entry", "01JF00000000000000000B0B01", 1, sealed(BOB_DEK)),
    )
    assert FOLDER not in [a["id"] for a in body["accepted"]], body
    assert _stored(mock_db, FOLDER) is None


@pytest.mark.asyncio
async def test_the_admin_still_cannot_take_the_key_id_for_another_type(app_client, mock_db):  # noqa: F811
    announced = await _announced(app_client, mock_db)
    sk = announced.sk[ADMIN]
    body = await _push(app_client, announced.token[ADMIN], [_wire(sk, K1, "node", None, 1, sealed(K1))])
    assert body["accepted"] == [], body


@pytest.mark.asyncio
async def test_the_admin_lands_the_announced_folder_and_key(app_client, mock_db):  # noqa: F811
    announced = await _announced(app_client, mock_db)
    sk = announced.sk[ADMIN]
    body = await _push(app_client, announced.token[ADMIN], [
        _wire(sk, FOLDER, "node", None, 1, sealed(K1)),
        _wire(sk, K1, "dek", FOLDER, 1, b"k" * 72),
    ])
    assert len(body["accepted"]) == 2, body
    assert _stored(mock_db, FOLDER)["owner_id"] == ADMIN
    assert _stored(mock_db, K1)["owner_id"] == ADMIN
