"""Review 7c10379 H7: a few small pushes took gigabytes of memory.

Every push naming a staged batch (up to 256 MiB) read and parsed it before
any lock, and the pushes of one account were not serialized: four 200-byte
pushes took 3.2 GB and the container was killed. An account's stage requests
and staged pushes now run one at a time across workers (sync_push_claims),
the batch is read once, a chunk of rows at a time, and nothing malformed is
staged.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import threading
import time

import pytest

from server.app.routers import sync as sync_mod
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_jwt,
    _create_regular_user,
    _sign_sync_object,
    app_client,
    mock_db,
)

ALICE = "USER0000000000000000000001"
BATCH = "STAGEDBATCH000000000000001"
COUNT = 20


def _dek(sk, n: int, payload: bytes = b"k" * 72) -> dict:
    obj_id = f"STAGEDDEK{n:017d}"
    p_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": obj_id, "object_type": "dek",
        "payload": base64.b64encode(payload).decode("ascii"),
        "parent_ref": None, "version": 1, "is_deleted": 0, "payload_hash": p_hash,
        "signature": _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, p_hash),
        "write_policy": "owner_only",
    }


@pytest.fixture
def alice(mock_db):  # noqa: F811
    sk, _ = _create_regular_user(mock_db._storage, ALICE, "alice")
    return sk, {"Authorization": f"Bearer {_create_jwt(ALICE, 'alice', False)}"}


async def _stage(client, headers, objects, start=0):
    return await client.post(
        "/api/sync/stage", json={"batch_id": BATCH, "start": start, "objects": objects},
        headers=headers,
    )


async def _staged_push(client, headers):
    return await client.post("/api/sync", json={
        "objects": [], "atomic_batch": True,
        "staged_batch_id": BATCH, "staged_count": COUNT,
    }, headers=headers)


@pytest.mark.asyncio
async def test_small_pushes_naming_one_staged_batch_hold_it_one_at_a_time(
    app_client, alice, mock_db, monkeypatch  # noqa: F811
):
    sk, headers = alice
    staged = await _stage(app_client, headers, [_dek(sk, n) for n in range(COUNT)])
    assert staged.status_code == 200, staged.text

    held, peak, guard = 0, 0, threading.Lock()
    check = sync_mod._check_objects

    def _holding_the_batch(objects, signing_pks):
        nonlocal held, peak
        if len(objects) < COUNT:
            return check(objects, signing_pks)
        with guard:
            held += 1
            peak = max(peak, held)
        time.sleep(0.2)  # the parsed batch stays in this push's memory
        try:
            return check(objects, signing_pks)
        finally:
            with guard:
                held -= 1

    monkeypatch.setattr(sync_mod, "_check_objects", _holding_the_batch)
    monkeypatch.setattr(sync_mod, "STAGED_READ_CHUNK", 7, raising=False)
    answers = await asyncio.gather(*(_staged_push(app_client, headers) for _ in range(4)))

    assert peak == 1, f"{peak} pushes held the staged batch at once"
    accepted = [a for a in answers if a.status_code == 200 and a.json()["accepted"]]
    assert len(accepted) == 1 and len(accepted[0].json()["accepted"]) == COUNT, [a.text for a in answers]
    assert all(a.status_code == 409 for a in answers if a not in accepted)
    assert not mock_db._storage.get("sync_staged_objects")
    assert not mock_db._storage.get("sync_push_claims")


@pytest.mark.asyncio
async def test_a_malformed_object_is_never_staged(app_client, alice, mock_db):  # noqa: F811
    sk, headers = alice
    bad = _dek(sk, 1)
    bad["payload"] = base64.b64encode(b"something else").decode("ascii")
    answer = await _stage(app_client, headers, [_dek(sk, 0), bad])
    assert answer.status_code == 400, answer.text
    assert "payload hash mismatch" in answer.json()["detail"]
    assert not mock_db._storage.get("sync_staged_objects")


@pytest.mark.asyncio
async def test_a_live_claim_makes_the_push_wait_and_a_dead_one_is_taken_over(
    app_client, alice, mock_db, monkeypatch  # noqa: F811
):
    sk, headers = alice
    assert (await _stage(app_client, headers, [_dek(sk, n) for n in range(COUNT)])).status_code == 200
    monkeypatch.setattr(sync_mod, "PUSH_CLAIM_WAIT_S", 0.3)
    now_ms = int(time.time() * 1000)
    claims = mock_db._storage.setdefault("sync_push_claims", [])
    claims.append({"user_id": ALICE, "claim_id": "a" * 32, "claimed_at": now_ms})

    busy = await _staged_push(app_client, headers)
    assert busy.status_code == 503, busy.text
    assert len(mock_db._storage["sync_staged_objects"]) == COUNT  # untouched

    claims[0]["claimed_at"] = now_ms - sync_mod.PUSH_CLAIM_TTL_MS - 1  # its worker died
    taken = await _staged_push(app_client, headers)
    assert taken.status_code == 200 and len(taken.json()["accepted"]) == COUNT, taken.text
    assert not mock_db._storage.get("sync_push_claims")
