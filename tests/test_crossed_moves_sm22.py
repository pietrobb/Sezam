"""R16-Z SM22 (gate 16, team_log): crossed folder moves left a parent cycle.

Two devices each moved one folder below the other before either saw the
other's move (A: X under Y, B: Y under X). Each move was fine against what the
server held when it came, so the server took both, and every device that
pulled them held X and Y as each other's parent. Unlock rebuilds the search
index, which walks every entry's folder path up to the root: on a cycle that
walk never ends, and the device never opened again (gate 16's team_log worker
sat over an hour in ``vault.unlock``).

Invariant: the folder tree has no cycle. The server refuses a move whose new
parent lies below the moved folder, as it is stored when the move comes.
"""

from __future__ import annotations

import pytest

from tests.test_review6_web_member_personal_folder import ROOT, sealed
from tests.test_review7_member_root_write_h4 import ADMIN, ROOT_DEK, _object, _push, _wire
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    app_client,
    mock_db,
)

X = "CROSSEDX000000000000000001"
Y = "CROSSEDY000000000000000001"
Z = "CROSSEDZ000000000000000001"


@pytest.fixture
def admin(mock_db):  # noqa: F811
    storage = mock_db._storage
    sk, _ = _create_admin_user(storage, ADMIN, "admin")
    objects = storage["vault_objects"]
    objects.append(_object(ROOT, "node", ADMIN, payload=sealed(ROOT_DEK)))
    objects.append(_object(ROOT_DEK, "dek", ADMIN, parent=ROOT))
    for folder in (X, Y, Z):
        objects.append(_object(folder, "node", ADMIN, ROOT, sealed(ROOT_DEK)))
    return sk, _create_jwt(ADMIN, "admin", True)


def _parent(mock_db, obj_id):  # noqa: F811
    return next(o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id)["parent_ref"]


@pytest.mark.asyncio
async def test_a_move_below_the_moved_folder_itself_is_refused(app_client, admin, mock_db):  # noqa: F811
    sk, token = admin
    body = await _push(app_client, token, [_wire(sk, X, "node", Y, 2, sealed(ROOT_DEK))])
    assert [a["id"] for a in body["accepted"]] == [X], body
    # The other device, not having seen that move, puts Y below X.
    body = await _push(app_client, token, [_wire(sk, Y, "node", X, 2, sealed(ROOT_DEK))])
    assert body["accepted"] == [], body
    conflict = body["conflicts"][0]
    assert conflict["code"] == "folder_move_cycle", body
    assert conflict["server_parent_ref"] == ROOT and conflict["server_version"] == 1, body
    assert _parent(mock_db, X) == Y and _parent(mock_db, Y) == ROOT


@pytest.mark.asyncio
async def test_a_longer_crossed_chain_in_one_batch_is_refused(app_client, admin, mock_db):  # noqa: F811
    sk, token = admin
    # X under Y and Y under Z land; then Z under X would close X -> Y -> Z -> X.
    body = await _push(app_client, token, [
        _wire(sk, X, "node", Y, 2, sealed(ROOT_DEK)),
        _wire(sk, Y, "node", Z, 2, sealed(ROOT_DEK)),
        _wire(sk, Z, "node", X, 2, sealed(ROOT_DEK)),
    ])
    assert sorted(a["id"] for a in body["accepted"]) == [X, Y], body
    assert [c["id"] for c in body["conflicts"]] == [Z], body
    assert _parent(mock_db, Z) == ROOT


@pytest.mark.asyncio
async def test_an_ordinary_move_still_lands(app_client, admin, mock_db):  # noqa: F811
    sk, token = admin
    body = await _push(app_client, token, [_wire(sk, X, "node", Y, 2, sealed(ROOT_DEK))])
    assert [a["id"] for a in body["accepted"]] == [X], body
    body = await _push(app_client, token, [_wire(sk, Z, "node", X, 2, sealed(ROOT_DEK))])
    assert [a["id"] for a in body["accepted"]] == [Z], body
