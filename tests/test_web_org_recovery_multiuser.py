"""Lockout review #3 (web): org recovery in an organization with several users.

The old code compared every DEK object the server returned (colleagues' too)
with the DEKs this browser holds, so recovery failed whenever anyone else had
a vault on the server.
"""

from __future__ import annotations

import json

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401


def _own(objects: list[dict], opened: list[str]):
    sync_objects = {obj["id"]: obj for obj in objects}
    script = (
        f"ownKekDekIdsToRewrap({json.dumps(sync_objects)}, {json.dumps(opened)}, 'ME')"
    )
    return _run(["ownKekDekIdsToRewrap"], script)


def _dek(dek_id: str, owner: str | None, deleted: int = 0) -> dict:
    obj = {"id": dek_id, "object_type": "dek", "is_deleted": deleted}
    if owner is not None:
        obj["owner_id"] = owner
    return obj


def test_colleagues_deks_do_not_block_recovery():
    objects = [_dek("MINE", "ME"), _dek("THEIRS", "OTHER"), _dek("GONE", "ME", 1)]
    assert _own(objects, ["MINE"]) == ["MINE"]


def test_an_own_dek_the_old_kek_cannot_open_stops_recovery():
    objects = [_dek("MINE", "ME"), _dek("BROKEN", "ME")]
    assert _own(objects, ["MINE"]) is None


def test_dek_without_owner_counts_as_own_and_no_dek_at_all_stops():
    assert _own([_dek("LEGACY", None)], []) is None
    assert _own([_dek("THEIRS", "OTHER")], []) is None


def test_recovery_rewraps_only_own_kek_deks():
    body = _function("handleOrgRecovery")
    assert "rewrapOwnDeks(newKek, _sodium)" in body
    rewrap = _function("rewrapOwnDeks")
    assert "ownKekDekIdsToRewrap(state.syncObjects, state.kekDekIds, state.userId)" in rewrap
    for source in (body, rewrap):
        assert "Object.entries(state.deks)" not in source
