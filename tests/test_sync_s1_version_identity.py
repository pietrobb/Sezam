"""Sync redesign S1 (docs/SYNC_SINGLE_SOURCE.md point 1), server side.

A version is the pair (number, payload hash). A folder or entry change must
name the server copy it was made on by both; the same number with other
content is a conflict, and so is a change naming no base. Tombstone GC keeps
the collected copy's pair, so a write to that id builds on it and (id,
version) never names two contents.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from server.app.main import _cleanup_tombstones
from tests.test_review8_member_push_h7 import ALICE, _folders, _push
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    _sign_sync_object,
    app_client,
    mock_db,
)

ENTRY = "ALICEENTRY0000000000000001"


def _write(sk, parent, version, payload: bytes, base=None, deleted=0) -> dict:
    p_hash = hashlib.sha256(payload).hexdigest()
    obj = {
        "id": ENTRY, "object_type": "entry", "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "version": version, "is_deleted": deleted,
        "payload_hash": p_hash, "write_policy": "owner_only",
        "signature": _sign_sync_object(sk, ENTRY, "entry", parent, None, deleted, version, p_hash),
    }
    if base is not None:
        obj["base_version"], obj["base_payload_hash"] = base
    return obj


def _h(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stored(mock_db):
    return next(o for o in mock_db._storage["vault_objects"] if o["id"] == ENTRY)


@pytest.mark.asyncio
async def test_same_number_other_content_is_a_conflict(app_client, mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    folder = _folders(mock_db._storage)
    assert (await _push(app_client, [_write(sk, folder, 1, b"v1")])).json()["accepted"]

    for base in (None, (1, _h(b"another v1"))):
        reply = (await _push(app_client, [_write(sk, folder, 2, b"v2", base)])).json()
        assert not reply["accepted"], reply
        conflict = reply["conflicts"][0]
        assert (conflict["server_version"], conflict["server_payload_hash"]) == (1, _h(b"v1"))
    assert _stored(mock_db)["payload_hash"] == _h(b"v1")

    reply = (await _push(app_client, [_write(sk, folder, 2, b"v2", (1, _h(b"v1")))])).json()
    assert reply["accepted"], reply
    assert (_stored(mock_db)["version"], _stored(mock_db)["payload_hash"]) == (2, _h(b"v2"))


@pytest.mark.asyncio
async def test_a_collected_tombstone_keeps_its_version(app_client, mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    folder = _folders(mock_db._storage)
    assert (await _push(app_client, [_write(sk, folder, 1, b"v1")])).json()["accepted"]
    gone = _write(sk, folder, 2, b"gone", (1, _h(b"v1")), deleted=1)
    assert (await _push(app_client, [gone])).json()["accepted"]
    _stored(mock_db)["modified_at"] = 0
    await _cleanup_tombstones(mock_db, 0)
    assert all(o["id"] != ENTRY for o in mock_db._storage["vault_objects"])

    # Sent as new, on the old copy, or again at the collected version: each
    # would make (id, 2) or (id, 1) name other content.
    for refused in (
        _write(sk, folder, 1, b"new"),
        _write(sk, folder, 2, b"edit", (1, _h(b"v1"))),
        _write(sk, folder, 2, b"edit", (2, _h(b"gone"))),
    ):
        reply = (await _push(app_client, [refused])).json()
        assert not reply["accepted"], reply
        conflict = reply["conflicts"][0]
        assert (conflict["server_version"], conflict["server_payload_hash"]) == (2, _h(b"gone"))

    revived = _write(sk, folder, 3, b"back", (2, _h(b"gone")))
    assert (await _push(app_client, [revived])).json()["accepted"]
    assert (_stored(mock_db)["version"], _stored(mock_db)["payload_hash"]) == (3, _h(b"back"))
    assert not mock_db._storage["collected_objects"]
