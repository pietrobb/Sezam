"""Review 7c10379 (server, medium): the global push lock and the DB pool.

A 100k-object push held the commit_counter row lock for 67 s: every object
took two more statements to count its commit_seq. Meanwhile each waiting
push held a pool connection on that row lock, ten of them took the whole
pool and /health answered 503. The commit_seq is now counted in the push and
written once, and the pushes of one worker wait for the lock without a
connection.
"""

from __future__ import annotations

import asyncio
import hashlib
from contextlib import asynccontextmanager

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    MockCursor,
    _create_jwt,
    _create_regular_user,
    _push_object,
    _sign_sync_object,
    app_client,
    mock_db,
)

ALICE = "USER0000000000000000000001"


@pytest.fixture
def alice(mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    return sk, _create_jwt(ALICE, "alice", False)


def _dek(sk, n: int) -> dict:
    import base64

    obj_id = f"LOCKWORKDEK{n:015d}"
    payload = b"k" * 72
    p_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": obj_id, "object_type": "dek",
        "payload": base64.b64encode(payload).decode("ascii"),
        "parent_ref": None, "version": 1, "is_deleted": 0, "payload_hash": p_hash,
        "signature": _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, p_hash),
    }


@pytest.mark.asyncio
async def test_a_push_counts_commit_seqs_without_a_statement_per_object(
    app_client, alice, mock_db, monkeypatch  # noqa: F811
):
    sk, token = alice
    counter_writes = []
    execute = MockCursor.execute

    async def _counting(self, query, args=()):
        if query.strip().upper().startswith("UPDATE COMMIT_COUNTER"):
            counter_writes.append(query)
        return await execute(self, query, args)

    monkeypatch.setattr(MockCursor, "execute", _counting)
    answer = await app_client.post(
        "/api/sync", json={"objects": [_dek(sk, n) for n in range(30)], "atomic_batch": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    seqs = [a["commit_seq"] for a in answer.json()["accepted"]]
    assert seqs == list(range(1, 31)), answer.text
    assert len(counter_writes) == 1, counter_writes
    assert mock_db._storage["commit_counter"][0]["next_seq"] == 31

    again = await _push_object(app_client, token, sk, "LOCKWORKNEXT00000000000001", "dek", None, 1, b"k" * 72)
    assert again.json()["accepted"][0]["commit_seq"] == 31


@pytest.mark.asyncio
async def test_waiting_pushes_hold_no_pool_connection(app_client, alice, mock_db):  # noqa: F811
    sk, token = alice
    open_now, peak = 0, 0
    transaction = mock_db.transaction

    @asynccontextmanager
    async def _waiting_on_the_row_lock():
        nonlocal open_now, peak
        async with transaction() as conn:
            open_now += 1
            peak = max(peak, open_now)
            try:
                await asyncio.sleep(0.05)  # FOR UPDATE on commit_counter
                yield conn
            finally:
                open_now -= 1

    mock_db.transaction = _waiting_on_the_row_lock
    answers = await asyncio.gather(*(
        _push_object(app_client, token, sk, f"LOCKWORKWAIT{n:014d}", "dek", None, 1, b"k" * 72)
        for n in range(6)
    ))
    assert all(len(a.json()["accepted"]) == 1 for a in answers), [a.text for a in answers]
    assert peak == 1, f"{peak} pushes held a connection on the push lock at once"
