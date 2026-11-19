"""Review d615826 (web): org recovery in an organization with more than one user.

The server sends every object to everyone, colleagues' DEK objects too, with
their owner_id. The pull kept a record of each object without owner_id, and
ownKekDekIdsToRewrap counts an object without owner_id as ours: every
colleague's DEK, which our KEK never opens, stopped the recovery
(recovery.unlock_all_deks_failed) as soon as a second user had a vault.
"""

from __future__ import annotations

import json

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401

# As GET /api/sync returns them (server/app/routers/sync.py pull).
PULLED = [
    {"id": "MINE", "object_type": "dek", "owner_id": "ME", "version": 1, "is_deleted": 0, "payload": ""},
    {"id": "THEIRS", "object_type": "dek", "owner_id": "BOB", "version": 1, "is_deleted": 0, "payload": ""},
    {"id": "NODE", "object_type": "node", "owner_id": "BOB", "version": 1, "is_deleted": 0, "payload": ""},
]


def test_pulled_colleague_dek_does_not_stop_org_recovery():
    script = f"""
      const syncObjects = {{}};
      for (const obj of {json.dumps(PULLED)}) syncObjects[obj.id] = syncObjectRecord(obj);
      return ownKekDekIdsToRewrap(syncObjects, ['MINE'], 'ME');
    """
    assert _run(["syncObjectRecord", "ownKekDekIdsToRewrap"], f"(() => {{ {script} }})()") == ["MINE"]


def test_pull_keeps_its_records_through_sync_object_record():
    pull = _function("pullAndBuildTreeLocked")
    assert "candidateSyncObjects[obj.id] = syncObjectRecord(obj);" in pull
    assert "owner_id: obj.owner_id || null," in _function("syncObjectRecord")
