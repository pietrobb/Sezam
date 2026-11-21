"""Capability run 437 (goal #429): whether a re-key batch landed is asked of the server.

POST /api/objects/held names which of the given objects the server holds,
without payloads; the desktop asks it for the batch's new DEK ids before it
closes or undoes a re-key whose reply was lost. The end-to-end case is
tests/test_sync_state_machine.py::test_sync_state_machine_rekey_landed_with_its_reply_lost_is_not_abandoned.
"""

from __future__ import annotations

import hashlib

import pytest

from server.app.routers.sync_held import MAX_HELD_IDS
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_jwt,
    _create_regular_user,
    app_client,
    mock_db,
)

ALICE = "USER0000000000000000000001"
DEK = "DEK00000000000000000000001"
GONE = "DEK00000000000000000000002"
ARCHIVE = "KEYARCHIVE0000000000000001"


def _object(object_id: str, object_type: str, deleted: int = 0) -> dict:
    return {
        "id": object_id, "object_type": object_type, "payload": b"secret",
        "owner_id": ALICE, "signature_user_id": ALICE, "write_policy": "owner_only",
        "target_user_id": None, "parent_ref": None, "access_level": None,
        "version": 3, "commit_seq": 7, "is_deleted": deleted,
        "payload_hash": hashlib.sha256(b"secret").hexdigest(),
        "client_signature": b"x" * 64, "modified_at": 1,
    }


def _auth() -> dict:
    return {"Authorization": f"Bearer {_create_jwt(ALICE, 'alice', False)}"}


@pytest.mark.asyncio
async def test_the_server_says_which_objects_it_holds(app_client, mock_db):  # noqa: F811
    _create_regular_user(mock_db._storage, ALICE, "alice")
    mock_db._storage["vault_objects"] += [
        _object(DEK, "dek"), _object(GONE, "dek", deleted=1), _object(ARCHIVE, "key_archive"),
    ]
    reply = await app_client.post(
        "/api/objects/held", json={"ids": [DEK, GONE, ARCHIVE, "NOTHERE", DEK]}, headers=_auth(),
    )
    assert reply.status_code == 200, reply.text
    assert reply.json()["objects"] == [
        {"id": DEK, "object_type": "dek", "version": 3, "is_deleted": False},
        {"id": GONE, "object_type": "dek", "version": 3, "is_deleted": True},
    ]


@pytest.mark.asyncio
async def test_the_lookup_needs_a_session_and_is_bounded(app_client, mock_db):  # noqa: F811
    _create_regular_user(mock_db._storage, ALICE, "alice")
    assert (await app_client.post("/api/objects/held", json={"ids": [DEK]})).status_code in (401, 422)
    too_many = [f"ID{i:024d}" for i in range(MAX_HELD_IDS + 1)]
    reply = await app_client.post("/api/objects/held", json={"ids": too_many}, headers=_auth())
    assert reply.status_code == 422, reply.text
