"""Review main@a159e97 H8, server: a member's folder below the root.

A member granted write on the root made a folder there, sealed with the
shared key like any company folder. The server took every tree of the member's
directly below the root for a personal one, so after the admin took the write
away the member went on writing in that folder. And a member's folder
tombstone was taken with items of others still in it: they were buried.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from tests.test_review8_member_push_h7 import ADMIN, ALICE, ROOT, _entry, _node, _push
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    _sign_sync_object,
    app_client,
    mock_db,
)

ROOT_DEK = "ROOTDEK0000000000000000001"
ALICE_DEK = "ALICEDEK000000000000000001"
FOLDER = "ALICEFOLDER000000000000001"


def _sealed(dek_id: str) -> bytes:
    """A blob shaped like an AEAD envelope (alg, schema, kind, DEK id, nonce, ciphertext)."""
    return bytes([1, 1, 2]) + dek_id.encode("ascii") + b"\x00" * 24 + b"c" * 32


def _dek(dek_id: str, owner: str) -> dict:
    return {**_node(dek_id, owner, None), "object_type": "dek", "payload": b"k" * 72}


def _setup(storage: dict, folder_dek: str) -> None:
    storage["vault_objects"] += [
        _node(ROOT, ADMIN, None), _dek(ROOT_DEK, ADMIN), _dek(ALICE_DEK, ALICE),
        {**_node(FOLDER, ALICE, ROOT), "payload": _sealed(folder_dek)},
    ]


def _tombstone(sk, node_id: str, parent: str) -> dict:
    payload = b"gone " + node_id.encode()
    p_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": node_id, "object_type": "node", "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "version": 2, "base_version": 1, "is_deleted": 1,
        "base_payload_hash": hashlib.sha256(b"n").hexdigest(),  # _node's payload
        "payload_hash": p_hash, "write_policy": "owner_only",
        "signature": _sign_sync_object(sk, node_id, "node", parent, None, 1, 2, p_hash),
    }


@pytest.mark.asyncio
async def test_a_shared_folder_a_member_made_below_the_root_needs_her_write(app_client, mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    _setup(mock_db._storage, ROOT_DEK)
    acl = mock_db._storage.setdefault("write_acl", [])
    acl.append({"user_id": ALICE, "node_id": ROOT, "granted_at": 1})
    first = (await _push(app_client, [_entry(sk, "ALICEENTRY0000000000000001", FOLDER)])).json()
    assert len(first["accepted"]) == 1, first
    acl.clear()  # the admin took the write away
    later = (await _push(app_client, [_entry(sk, "ALICEENTRY0000000000000002", FOLDER)])).json()
    assert later["conflicts"][0]["error"] == "write_acl denied", later


@pytest.mark.asyncio
async def test_a_personal_folder_below_the_root_needs_no_write(app_client, mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    _setup(mock_db._storage, ALICE_DEK)
    reply = (await _push(app_client, [_entry(sk, "ALICEENTRY0000000000000001", FOLDER)])).json()
    assert len(reply["accepted"]) == 1, reply


@pytest.mark.asyncio
async def test_a_member_does_not_bury_items_of_others(app_client, mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    _setup(mock_db._storage, ALICE_DEK)
    sub = "ALICESUBFOLDER000000000001"
    mock_db._storage["vault_objects"] += [
        _node(sub, ALICE, FOLDER),
        {**_node("ADMINENTRY0000000000000001", ADMIN, sub), "object_type": "entry"},
    ]
    reply = (await _push(app_client, [_tombstone(sk, FOLDER, ROOT), _tombstone(sk, sub, FOLDER)])).json()
    assert {c["id"] for c in reply["conflicts"]} == {FOLDER, sub}, reply
    assert not any(o["is_deleted"] for o in mock_db._storage["vault_objects"] if o["id"] in (FOLDER, sub))


@pytest.mark.asyncio
async def test_a_member_deletes_a_tree_of_her_own_in_one_push(app_client, mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    _setup(mock_db._storage, ALICE_DEK)
    sub = "ALICESUBFOLDER000000000001"
    mock_db._storage["vault_objects"] += [
        _node(sub, ALICE, FOLDER),
        {**_node("ALICEENTRY0000000000000009", ALICE, sub), "object_type": "entry"},
    ]
    reply = (await _push(app_client, [_tombstone(sk, sub, FOLDER), _tombstone(sk, FOLDER, ROOT)])).json()
    assert {a["id"] for a in reply["accepted"]} == {FOLDER, sub}, reply
    # A folder of hers left live below would be buried with what others put in later.
    left = "ALICEFOLDER000000000000002"
    mock_db._storage["vault_objects"] += [
        _node(left, ALICE, ROOT), _node("ALICESUBFOLDER000000000002", ALICE, left),
    ]
    reply = (await _push(app_client, [_tombstone(sk, left, ROOT)])).json()
    assert reply["conflicts"][0]["id"] == left, reply
