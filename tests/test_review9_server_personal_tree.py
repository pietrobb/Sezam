"""Review 1141a20 (R9-F): another account wrote into a member's personal root.

The start of a personal tree (d615826, 7c10379 H4) took a folder sealed with
the author's own key directly below *any* top-level node. TL7 made each
member's personal root a top-level node, so Alice hung a folder of her own key
below Bob's personal root, kept items in it, and Bob could not delete his root
afterwards ('folder holds items of others'), nor her items ('not owner').

A personal root (a top-level node sealed with its owner's folderless key) now
belongs to its owner alone: nobody else, admin included, creates, moves in or
edits anything in its tree. Its owner may delete what another account left
there before. The org root still takes a member's legacy personal folder, and
a member's TL7 personal root stays top-level.
"""

from __future__ import annotations

import pytest

from tests.test_review6_web_member_personal_folder import ALICE_DEK, ROOT, sealed
from tests.test_review7_member_root_write_h4 import ADMIN, ROOT_DEK, _object, _push, _wire
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    _push_object,
    app_client,
    mock_db,
)

ALICE = "USER0000000000000000000001"
BOB = "USER0000000000000000000002"
BOB_DEK = "BOBDEK00000000000000000001"
BOB_ROOT = "BOBPERSONAL000000000000001"
BOB_ENTRY = "BOBENTRY000000000000000001"


@pytest.fixture
def team(mock_db):  # noqa: F811
    storage = mock_db._storage
    admin_sk, _ = _create_admin_user(storage, ADMIN, "admin")
    alice_sk, _ = _create_regular_user(storage, ALICE, "alice")
    bob_sk, _ = _create_regular_user(storage, BOB, "bob")
    objects = storage["vault_objects"]
    objects.append(_object(ROOT, "node", ADMIN, payload=sealed(ROOT_DEK)))
    objects.append(_object(ROOT_DEK, "dek", ADMIN, parent=ROOT))
    objects.append(_object(ALICE_DEK, "dek", ALICE))
    objects.append(_object(BOB_DEK, "dek", BOB))
    objects.append(_object(BOB_ROOT, "node", BOB, payload=sealed(BOB_DEK)))
    objects.append(_object(BOB_ENTRY, "entry", BOB, BOB_ROOT, sealed(BOB_DEK)))
    return {
        "admin": (admin_sk, _create_jwt(ADMIN, "admin", True)),
        "alice": (alice_sk, _create_jwt(ALICE, "alice", False)),
        "bob": (bob_sk, _create_jwt(BOB, "bob", False)),
    }


def _stored(mock_db, obj_id):  # noqa: F811
    return next((o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id), None)


@pytest.mark.asyncio
async def test_a_member_cannot_start_a_folder_below_another_members_personal_root(
    app_client, team, mock_db,  # noqa: F811
):
    sk, token = team["alice"]
    folder, entry = "ALICEINBOB0000000000000001", "ALICEINBOBENTRY00000000001"
    body = await _push(app_client, token, [
        _wire(sk, folder, "node", BOB_ROOT, 1, sealed(ALICE_DEK)),
        _wire(sk, entry, "entry", folder, 1, sealed(ALICE_DEK)),
    ])
    assert body["accepted"] == [], body
    assert _stored(mock_db, folder) is None and _stored(mock_db, entry) is None


@pytest.mark.asyncio
async def test_a_member_cannot_move_a_folder_of_theirs_into_another_members_personal_root(
    app_client, team, mock_db,  # noqa: F811
):
    sk, token = team["alice"]
    mine = "ALICEPERSONAL0000000000001"
    mock_db._storage["vault_objects"].append(_object(mine, "node", ALICE, payload=sealed(ALICE_DEK)))
    child = "ALICECHILD0000000000000001"
    mock_db._storage["vault_objects"].append(_object(child, "node", ALICE, mine, sealed(ALICE_DEK)))
    body = await _push(app_client, token, [_wire(sk, child, "node", BOB_ROOT, 2, sealed(ALICE_DEK))])
    assert body["accepted"] == [], body
    assert _stored(mock_db, child)["parent_ref"] == mine


@pytest.mark.asyncio
async def test_the_admin_cannot_write_into_a_members_personal_tree(app_client, team, mock_db):  # noqa: F811
    sk, token = team["admin"]
    body = await _push(app_client, token, [
        _wire(sk, "ADMININBOB0000000000000001", "entry", BOB_ROOT, 1, sealed(ROOT_DEK)),
        _wire(sk, BOB_ENTRY, "entry", BOB_ROOT, 2, sealed(ROOT_DEK)),
        _wire(sk, BOB_ROOT, "node", None, 2, sealed(ROOT_DEK)),
    ])
    assert body["accepted"] == [], body
    assert _stored(mock_db, "ADMININBOB0000000000000001") is None
    assert _stored(mock_db, BOB_ENTRY)["version"] == 1
    assert _stored(mock_db, BOB_ROOT)["version"] == 1


@pytest.mark.asyncio
async def test_the_owner_deletes_what_another_account_left_in_their_personal_root(
    app_client, team, mock_db,  # noqa: F811
):
    """Data written before the fix: Bob clears it and then his whole root."""
    objects = mock_db._storage["vault_objects"]
    folder, entry = "ALICEINBOB0000000000000001", "ALICEINBOBENTRY00000000001"
    objects.append(_object(folder, "node", ALICE, BOB_ROOT, sealed(ALICE_DEK)))
    objects.append(_object(entry, "entry", ALICE, folder, sealed(ALICE_DEK)))
    sk, token = team["bob"]
    gone = await _push_object(app_client, token, sk, entry, "entry", folder, 2, sealed(ALICE_DEK), is_deleted=1)
    assert len(gone.json()["accepted"]) == 1, gone.json()
    gone = await _push_object(app_client, token, sk, folder, "node", BOB_ROOT, 2, sealed(ALICE_DEK), is_deleted=1)
    assert len(gone.json()["accepted"]) == 1, gone.json()
    gone = await _push_object(app_client, token, sk, BOB_ENTRY, "entry", BOB_ROOT, 2, sealed(BOB_DEK), is_deleted=1)
    assert len(gone.json()["accepted"]) == 1, gone.json()
    gone = await _push_object(app_client, token, sk, BOB_ROOT, "node", None, 2, sealed(BOB_DEK), is_deleted=1)
    assert len(gone.json()["accepted"]) == 1, gone.json()


@pytest.mark.asyncio
async def test_the_owner_may_delete_but_not_edit_another_accounts_item_in_their_root(
    app_client, team, mock_db,  # noqa: F811
):
    entry = "ALICEINBOBENTRY00000000002"
    mock_db._storage["vault_objects"].append(_object(entry, "entry", ALICE, BOB_ROOT, sealed(ALICE_DEK)))
    sk, token = team["bob"]
    edit = await _push_object(app_client, token, sk, entry, "entry", BOB_ROOT, 2, sealed(BOB_DEK))
    assert edit.json()["accepted"] == [], edit.json()
    # Alice keeps no say over it: she cannot edit it there either.
    alice_sk, alice_token = team["alice"]
    edit = await _push_object(app_client, alice_token, alice_sk, entry, "entry", BOB_ROOT, 2, sealed(ALICE_DEK))
    assert edit.json()["accepted"] == [], edit.json()


@pytest.mark.asyncio
async def test_personal_trees_of_their_own_still_work(app_client, team, mock_db):  # noqa: F811
    """TL7 top-level root, a legacy personal folder below the org root, items in both."""
    sk, token = team["alice"]
    top, legacy = "ALICEPERSONAL0000000000002", "ALICELEGACY000000000000002"
    body = await _push(app_client, token, [
        _wire(sk, top, "node", None, 1, sealed(ALICE_DEK)),
        _wire(sk, "ALICETOPENTRY0000000000002", "entry", top, 1, sealed(ALICE_DEK)),
        _wire(sk, legacy, "node", ROOT, 1, sealed(ALICE_DEK)),
        _wire(sk, "ALICELEGENTRY0000000000002", "entry", legacy, 1, sealed(ALICE_DEK)),
    ])
    assert len(body["accepted"]) == 4, body
    sk, token = team["bob"]
    body = await _push(app_client, token, [
        _wire(sk, "BOBFOLDER00000000000000002", "node", BOB_ROOT, 1, sealed(BOB_DEK)),
        _wire(sk, "BOBENTRY000000000000000002", "entry", BOB_ROOT, 1, sealed(BOB_DEK)),
    ])
    assert len(body["accepted"]) == 2, body


SHARED = "ADMINFOLDER000000000000001"
BOB_SUB = "BOBSUBFOLDER00000000000001"


def _bob_folder_in_a_share(mock_db, foreign_entry: bool):  # noqa: F811
    objects = mock_db._storage["vault_objects"]
    objects.append(_object(SHARED, "node", ADMIN, ROOT, sealed(ROOT_DEK)))
    mock_db._storage["write_acl"].append({"user_id": BOB, "node_id": SHARED, "granted_at": 1})
    objects.append(_object(BOB_SUB, "node", BOB, SHARED, sealed(ROOT_DEK)))
    inner = "BOBINNER000000000000000001"
    objects.append(_object(inner, "node", BOB, BOB_SUB, sealed(ROOT_DEK)))
    owner = ADMIN if foreign_entry else BOB
    objects.append(_object("DEEPENTRY00000000000000001", "entry", owner, inner, sealed(ROOT_DEK)))


@pytest.mark.asyncio
async def test_a_member_cannot_move_a_folder_holding_items_of_others_out_of_the_share(
    app_client, team, mock_db,  # noqa: F811
):
    """Review 1141a20: the bury check ran on deletes only, so a member's move
    carried an admin's item out of the shared (team) folder."""
    _bob_folder_in_a_share(mock_db, foreign_entry=True)
    sk, token = team["bob"]
    body = await _push(app_client, token, [_wire(sk, BOB_SUB, "node", BOB_ROOT, 2, sealed(ROOT_DEK))])
    assert body["accepted"] == [], body
    assert _stored(mock_db, BOB_SUB)["parent_ref"] == SHARED


@pytest.mark.asyncio
async def test_a_member_moves_a_folder_holding_only_their_own_items(app_client, team, mock_db):  # noqa: F811
    _bob_folder_in_a_share(mock_db, foreign_entry=False)
    sk, token = team["bob"]
    body = await _push(app_client, token, [_wire(sk, BOB_SUB, "node", BOB_ROOT, 2, sealed(ROOT_DEK))])
    assert len(body["accepted"]) == 1, body


@pytest.mark.asyncio
async def test_after_a_handover_the_former_admins_org_root_is_still_the_org_root(
    app_client, mock_db,  # noqa: F811
):
    """The org root stays its maker's after the role moves on: no member's root."""
    from tests.test_team_log_server import ADMIN as FOUNDER
    from tests.test_team_log_server import BOB as HEIR
    from tests.test_team_log_server import CAROL, Team, _append, _founded

    team = Team(mock_db)
    await _founded(app_client, team)
    promote = team.record("member.role", FOUNDER, {"user_id": HEIR, "role": "admin"})
    team.accept(promote)
    demote = team.record("member.role", FOUNDER, {"user_id": FOUNDER, "role": "member"})
    team.accept(demote)
    assert (await _append(app_client, team, FOUNDER, promote, demote)).status_code == 200
    org_root, org_dek = "ORGROOT0000000000000000001", "ORGDEK00000000000000000001"
    carol_dek, carol_root = "CAROLDEK000000000000000001", "CAROLROOT00000000000000001"
    objects = mock_db._storage["vault_objects"]
    objects.append(_object(org_root, "node", FOUNDER, payload=sealed(org_dek)))
    objects.append(_object(org_dek, "dek", FOUNDER, parent=org_root))
    objects.append(_object(carol_dek, "dek", CAROL))
    objects.append(_object(carol_root, "node", CAROL, payload=sealed(carol_dek)))
    epoch = next(u for u in mock_db._storage["users"] if u["id"] == HEIR).get("token_epoch") or 0
    carol, heir = _create_jwt(CAROL, "carol", False), _create_jwt(HEIR, "bob", True, token_epoch=epoch)
    legacy = _wire(team.sk[CAROL], "CAROLLEGACY000000000000001", "node", org_root, 1, sealed(carol_dek))
    body = await _push(app_client, carol, [legacy])
    assert len(body["accepted"]) == 1, body
    shared = _wire(team.sk[HEIR], "HEIRFOLDER0000000000000001", "node", org_root, 1, sealed(org_dek))
    body = await _push(app_client, heir, [shared])
    assert len(body["accepted"]) == 1, body
    # Carol's own top-level root stays hers: the new admin writes nothing there.
    intruder = _wire(team.sk[HEIR], "HEIRINCAROL000000000000001", "entry", carol_root, 1, sealed(org_dek))
    body = await _push(app_client, heir, [intruder])
    assert body["accepted"] == [], body
