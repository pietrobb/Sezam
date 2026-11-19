"""Review main@a159e97 H7, server: a read-only member's push held the global lock.

The push checked write authority per object, up to 63 SELECTs walking the
folder chain under the commit_counter lock (50k staged objects: 248 s); an
atomic batch went on checking after its first conflict, though it is refused
whole; a member's object naming a target user share-locked that users row
until commit (the admin's login waited, 500); and a member's push had no size
limit but the global one.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    MockCursor,
    _create_jwt,
    _create_regular_user,
    _sign_sync_object,
    app_client,
    mock_db,
)

ADMIN = "ADMIN000000000000000000001"
ALICE = "USER0000000000000000000001"
ROOT = "SHAREDROOT0000000000000001"
SHARE = "ADMINSHARE0000000000000001"
DEPTH = 30


def _node(node_id: str, owner: str, parent: str | None) -> dict:
    return {
        "id": node_id, "object_type": "node", "payload": b"n",
        "owner_id": owner, "signature_user_id": owner,
        "write_policy": "owner_only", "target_user_id": None, "parent_ref": parent,
        "access_level": None, "version": 1, "commit_seq": 1, "is_deleted": 0,
        "payload_hash": hashlib.sha256(b"n").hexdigest(),
        "client_signature": b"x" * 64, "modified_at": 1,
    }


def _folders(storage: dict) -> str:
    """A share of the admin's, alice granted write on it, her folders DEPTH deep below."""
    storage["vault_objects"].append(_node(ROOT, ADMIN, None))
    storage["vault_objects"].append(_node(SHARE, ADMIN, ROOT))
    storage.setdefault("write_acl", []).append({"user_id": ALICE, "node_id": SHARE, "granted_at": 1})
    parent = SHARE
    for i in range(DEPTH):
        node_id = f"ALICEFOLDER{i:015d}"
        storage["vault_objects"].append(_node(node_id, ALICE, parent))
        parent = node_id
    return parent


def _entry(sk, entry_id: str, parent: str, target: str | None = None) -> dict:
    payload = b"entry " + entry_id.encode()
    p_hash = hashlib.sha256(payload).hexdigest()
    obj = {
        "id": entry_id, "object_type": "entry", "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "version": 1, "is_deleted": 0, "payload_hash": p_hash,
        "signature": _sign_sync_object(sk, entry_id, "entry", parent, target, 0, 1, p_hash),
        "write_policy": "owner_only",
    }
    if target is not None:
        obj["target_user_id"] = target
    return obj


@pytest.fixture
def queries(monkeypatch):
    seen: list[str] = []
    real = MockCursor.execute

    async def execute(self, query, args=()):
        seen.append(" ".join(query.split()))
        return await real(self, query, args)

    monkeypatch.setattr(MockCursor, "execute", execute)
    return seen


def _count(queries: list[str], fragment: str) -> int:
    return sum(fragment in q for q in queries)


async def _push(client, objects, atomic: bool = False):
    return await client.post(
        "/api/sync", json={"objects": objects, "atomic_batch": atomic},
        headers={"Authorization": f"Bearer {_create_jwt(ALICE, 'alice', False)}"},
    )


@pytest.mark.asyncio
async def test_a_members_push_deep_in_her_folders_reads_each_folder_once(app_client, mock_db, queries):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    deepest = _folders(mock_db._storage)
    objects = [_entry(sk, f"ALICEENTRY{i:016d}", deepest) for i in range(50)]
    queries.clear()
    reply = await _push(app_client, objects)
    assert len(reply.json()["accepted"]) == 50, reply.json()
    walked = _count(queries, "SELECT owner_id, parent_ref FROM vault_objects")
    acl = _count(queries, "SELECT 1 FROM write_acl")
    # Uncached: 50 * (DEPTH + 1) folder reads and 50 write_acl reads. Each
    # folder on the path is read once: hers, the share and the org root (whose
    # tree it is, R9-F personal-tree check).
    assert walked <= DEPTH + 2, walked
    assert acl == 1, acl


@pytest.mark.asyncio
async def test_a_folder_the_push_writes_is_read_again(app_client, mock_db, queries):  # noqa: F811
    """The cache must not keep a folder the push just deleted."""
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    deepest = _folders(mock_db._storage)
    first = _entry(sk, "ALICEENTRY0000000000000001", deepest)
    # Alice deletes her deepest folder, then writes into it in the same push.
    parent = f"ALICEFOLDER{DEPTH - 2:015d}"
    payload = b"gone"
    p_hash = hashlib.sha256(payload).hexdigest()
    tombstone = {
        "id": deepest, "object_type": "node", "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "version": 2, "base_version": 1, "is_deleted": 1,
        "base_payload_hash": hashlib.sha256(b"n").hexdigest(),
        "payload_hash": p_hash, "write_policy": "owner_only",
        "signature": _sign_sync_object(sk, deepest, "node", parent, None, 1, 2, p_hash),
    }
    second = _entry(sk, "ALICEENTRY0000000000000002", deepest)
    reply = (await _push(app_client, [first, tombstone, second])).json()
    accepted = {a["id"] for a in reply["accepted"]}
    assert {first["id"], deepest} <= accepted, reply
    assert second["id"] not in accepted, reply


@pytest.mark.asyncio
async def test_an_atomic_batch_stops_at_its_first_conflict(app_client, mock_db, queries):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    deepest = _folders(mock_db._storage)
    refused = _entry(sk, "ALICEENTRY0000000000000000", "NOSUCHFOLDER00000000000001")
    rest = [_entry(sk, f"ALICEENTRY{i:016d}", deepest) for i in range(1, 41)]
    queries.clear()
    reply = await _push(app_client, [refused, *rest], atomic=True)
    assert reply.status_code == 409, reply.text
    looked_up = _count(queries, "FROM vault_objects WHERE id = %s FOR UPDATE")
    assert looked_up == 1, looked_up
    assert not any(o["id"] == rest[0]["id"] for o in mock_db._storage["vault_objects"])


@pytest.mark.asyncio
async def test_a_member_names_no_target_user(app_client, mock_db, queries):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    deepest = _folders(mock_db._storage)
    queries.clear()
    reply = (await _push(app_client, [_entry(sk, "ALICEENTRY0000000000000001", deepest, target=ADMIN)])).json()
    assert reply["conflicts"][0]["error"] == "target_user_id is admin only", reply
    assert _count(queries, "LOCK IN SHARE MODE") == 0


@pytest.mark.asyncio
async def test_a_members_push_has_a_size_limit(app_client, mock_db):  # noqa: F811
    from server.app.dependencies import get_config

    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    deepest = _folders(mock_db._storage)
    get_config().member_push_max_objects = 5
    objects = [_entry(sk, f"ALICEENTRY{i:016d}", deepest) for i in range(6)]
    assert (await _push(app_client, objects)).status_code == 413
    staged = await app_client.post(
        "/api/sync/stage",
        json={"batch_id": "BATCH000000000000000000001", "start": 3, "objects": objects[:3]},
        headers={"Authorization": f"Bearer {_create_jwt(ALICE, 'alice', False)}"},
    )
    assert staged.status_code == 413, staged.text
    assert len((await _push(app_client, objects[:5])).json()["accepted"]) == 5
