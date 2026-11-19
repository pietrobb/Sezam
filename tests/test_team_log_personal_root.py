"""TL7: a member's personal things live in a personal root, not under the org root.

docs/DESIGN_TEAM_LOG.md §10: a personal root is a top-level folder sealed with
the member's own key. A member may start one; nothing else of theirs is
top-level. An own personal object already inside a team folder (an old
personal folder below the root, a tier-2 item) may leave for it without write
access there (move_refusal own_personal); someone else's may not.
"""

from __future__ import annotations

import pytest

from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)
from tests.test_team_log_server import ADMIN, BOB, CAROL, FOLDER, K1, Team, _auth, _founded
from tests.test_team_log_server_push import ENTRY, _entry, _errors, _obj, _push, _sealed, _team_folder

ROOT = "01JN0000000000000000000P01"
OWN = "01JD0000000000000000000P01"
CAROL_ITEM = "01JE0000000000000000000P01"


def _stored(mock_db, obj_id: str) -> dict | None:
    return next((o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id), None)


async def _personal_root(client, team: Team, user: str) -> None:
    resp = await _push(client, team, user, [
        _obj(team.sk[user], OWN, "dek", b"own key" * 10),
        _obj(team.sk[user], ROOT, "node", _sealed(OWN)),
    ])
    assert resp.status_code == 200, resp.text


async def _set_access(client, team: Team, user: str, level: str | None) -> None:
    record = team.record("access.set", ADMIN, {"folder": FOLDER, "user_id": user, "level": level})
    team.accept(record)
    resp = await client.post("/api/team-log", json={"records": [record]}, headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("logged", [False, True])
async def test_a_member_starts_a_personal_root_of_their_own_key(app_client, mock_db, logged):
    team = Team(mock_db)
    if logged:
        await _founded(app_client, team)
    await _personal_root(app_client, team, CAROL)
    assert _stored(mock_db, ROOT)["parent_ref"] is None
    assert (await _push(app_client, team, CAROL, [
        _entry(team, CAROL, OWN, CAROL_ITEM, parent=ROOT)])).status_code == 200
    # A top-level folder under someone else's key, or a top-level item, stays refused.
    foreign = "01JN0000000000000000000P02"
    assert _errors(await _push(app_client, team, CAROL, [
        _obj(team.sk[CAROL], foreign, "node", _sealed(K1))])) == ["write_acl denied (top-level)"]
    assert _errors(await _push(app_client, team, CAROL, [
        _entry(team, CAROL, OWN, "01JE0000000000000000000P02", parent=None)])) == [
        "write_acl denied (top-level)"]


@pytest.mark.asyncio
@pytest.mark.parametrize("key_bound_to", [None, FOLDER])
async def test_an_own_personal_item_leaves_a_team_folder_for_the_personal_root(app_client, mock_db, key_bound_to):
    team = Team(mock_db)
    await _team_folder(app_client, team)
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K1)])).status_code == 200
    # Carol kept a tier-2 item in F1 while she could write there; now she reads.
    await _set_access(app_client, team, CAROL, "write")
    resp = await _push(app_client, team, CAROL, [
        _obj(team.sk[CAROL], OWN, "dek", b"own key" * 10),
        _entry(team, CAROL, OWN, CAROL_ITEM),
    ])
    assert resp.status_code == 200, resp.text
    # The desktop binds a tier-2 key to the item's folder (from before the log).
    _stored(mock_db, OWN)["parent_ref"] = key_bound_to
    await _set_access(app_client, team, CAROL, "read")
    root_key = "01JD0000000000000000000P02"
    resp = await _push(app_client, team, CAROL, [
        _obj(team.sk[CAROL], root_key, "dek", b"own key" * 10),
        _obj(team.sk[CAROL], ROOT, "node", _sealed(root_key)),
    ])
    assert resp.status_code == 200, resp.text
    # Bob's team item stays in F1 ...
    assert _errors(await _push(app_client, team, CAROL, [
        _entry(team, CAROL, OWN, ENTRY, version=2, parent=ROOT)])) != []
    assert _stored(mock_db, ENTRY)["parent_ref"] == FOLDER
    # ... Carol's own goes to her personal root.
    resp = await _push(app_client, team, CAROL, [_entry(team, CAROL, OWN, CAROL_ITEM, version=2, parent=ROOT)])
    assert resp.status_code == 200, resp.text
    assert _stored(mock_db, CAROL_ITEM)["parent_ref"] == ROOT


@pytest.mark.asyncio
async def test_an_own_personal_item_may_not_go_to_another_team_folder(app_client, mock_db):
    """The exemption is for leaving the company tree, not for moving inside it."""
    team = Team(mock_db)
    await _team_folder(app_client, team)
    await _set_access(app_client, team, CAROL, "write")
    resp = await _push(app_client, team, CAROL, [
        _obj(team.sk[CAROL], OWN, "dek", b"own key" * 10),
        _entry(team, CAROL, OWN, CAROL_ITEM),
    ])
    assert resp.status_code == 200, resp.text
    await _set_access(app_client, team, CAROL, "read")
    # A subfolder of F1 sealed by the admin with the folder's key: still F1's team tree.
    sub = "01JN0000000000000000000P03"
    rekey = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 1, "dek_id": "01JD0000000000000000000P09",
                                               "prev_dek_id": K1})
    team.accept(rekey)
    resp = await _push(app_client, team, ADMIN, [
        _obj(team.sk[ADMIN], "01JD0000000000000000000P09", "dek", b"wrapped" * 10, parent=FOLDER),
        _obj(team.sk[ADMIN], sub, "node", _sealed("01JD0000000000000000000P09"), parent=FOLDER),
    ], [rekey])
    assert resp.status_code == 200, resp.text
    assert _errors(await _push(app_client, team, CAROL, [
        _entry(team, CAROL, OWN, CAROL_ITEM, version=2, parent=sub)])) != []
    assert _stored(mock_db, CAROL_ITEM)["parent_ref"] == FOLDER
