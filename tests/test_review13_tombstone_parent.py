"""Review c78fd19 (R13 high #1): a member could delete anything for good.

A tombstone that named the member's own personal root as its parent made the
server count the deletion as the owner clearing their personal tree
(own_cleanup): the team folder the object really lives in has no personal
owner, so it dropped out of the owner set, and every write check was skipped.
Bob's team entry was gone for good, its owner could not restore it.

The authority over a deletion now comes from where the object is stored; a
tombstone may not move the object.
"""

from __future__ import annotations

import pytest

from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)
from tests.test_team_log_personal_root import OWN, ROOT, _personal_root, _stored
from tests.test_team_log_server import ADMIN, BOB, CAROL, FOLDER, K1, Team
from tests.test_team_log_server_push import ENTRY, _entry, _errors, _obj, _push, _sealed, _team_folder


async def _bobs_entry_in_the_team_folder(app_client, team: Team) -> None:
    await _team_folder(app_client, team)
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K1)])).status_code == 200


async def _bobs_entry_in_a_shared_folder_without_log(app_client, mock_db, team: Team) -> None:
    """An organisation without a team log: write_acl decides."""
    sk = team.sk[ADMIN]
    resp = await _push(app_client, team, ADMIN, [
        _obj(sk, FOLDER, "node", _sealed(K1)),
        _obj(sk, K1, "dek", b"wrapped K1" * 8, parent=FOLDER),
    ])
    assert resp.status_code == 200, resp.text
    mock_db._storage.setdefault("write_acl", []).append({"user_id": BOB, "node_id": FOLDER, "granted_at": 1})
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K1)])).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("logged", [False, True])
async def test_a_member_cannot_delete_a_team_entry_through_their_personal_root(app_client, mock_db, logged):
    team = Team(mock_db)
    if logged:
        await _bobs_entry_in_the_team_folder(app_client, team)
    else:
        await _bobs_entry_in_a_shared_folder_without_log(app_client, mock_db, team)
    await _personal_root(app_client, team, CAROL)  # Carol cannot write FOLDER

    tombstone = _obj(team.sk[CAROL], ENTRY, "entry", b"", parent=ROOT, version=2, deleted=1)
    errors = _errors(await _push(app_client, team, CAROL, [tombstone]))
    assert errors and all("tombstone" in e or "write" in e or "personal" in e for e in errors), errors
    stored = _stored(mock_db, ENTRY)
    assert (stored["is_deleted"], stored["version"], stored["parent_ref"]) == (0, 1, FOLDER)


@pytest.mark.asyncio
@pytest.mark.parametrize("logged", [False, True])
async def test_a_tombstone_that_moves_the_object_needs_the_rights_of_the_move(app_client, mock_db, logged):
    """A device deletes what it moved before the move was sent: the tombstone
    names the new parent. That stays possible for whoever may make the move
    (Bob writes FOLDER and owns ROOT), as a move followed by a delete is."""
    team = Team(mock_db)
    if logged:
        await _bobs_entry_in_the_team_folder(app_client, team)
    else:
        await _bobs_entry_in_a_shared_folder_without_log(app_client, mock_db, team)
    await _personal_root(app_client, team, BOB)

    moved = _obj(team.sk[BOB], ENTRY, "entry", b"", parent=ROOT, version=2, deleted=1)
    resp = await _push(app_client, team, BOB, [moved])
    assert resp.status_code == 200, resp.text
    assert (_stored(mock_db, ENTRY)["is_deleted"], _stored(mock_db, ENTRY)["parent_ref"]) == (1, ROOT)


@pytest.mark.asyncio
async def test_the_owner_still_clears_a_colleagues_object_from_their_personal_tree(app_client, mock_db):
    """R9-F stays: what someone hung below Carol's personal root, Carol may delete."""
    team = Team(mock_db)
    await _team_folder(app_client, team)
    await _personal_root(app_client, team, CAROL)
    foreign = "01JE0000000000000000000P77"
    # Bob's item below Carol's root (an older server let it in).
    item = _entry(team, BOB, OWN, foreign, parent=ROOT)
    mock_db._storage["vault_objects"].append({
        **{k: item[k] for k in ("id", "object_type", "parent_ref", "version", "is_deleted", "payload_hash")},
        "payload": b"x", "created_by": BOB, "updated_by": BOB, "commit_seq": 99, "modified_at": 1,
        "client_signature": b"", "write_policy": "owner_only", "key_epoch": 0, "target_user_id": None,
        "access_level": None,
    })
    gone = _obj(team.sk[CAROL], foreign, "entry", b"", parent=ROOT, version=2, deleted=1)
    resp = await _push(app_client, team, CAROL, [gone])
    assert resp.status_code == 200, resp.text
    assert _stored(mock_db, foreign)["is_deleted"] == 1
    assert ADMIN  # the admin is not involved
