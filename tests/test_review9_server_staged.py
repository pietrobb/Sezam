"""Review 1141a20 (medium), server R9-F / F3: one member stalled every staged push.

A refused push left its staged rows behind, so a tiny POST naming the batch
made the server read and parse the whole batch again under the server-wide
staged gate, as often as the member liked. The gate itself went to whoever
polled first, so the account that just released it took it straight back.
Now a push naming a batch always uses it up, and the gate goes in order of
arrival.
"""

from __future__ import annotations

import asyncio

import pytest

from server.app.routers import sync as sync_mod
from tests.test_review7_staged_push_memory_h7 import COUNT, _dek, _stage, _staged_push, alice  # noqa: F401
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)


def _claim(db, user_id):
    claim = getattr(sync_mod, "_claim_staged_gate", None)
    if claim is None:  # before the fix: the bare gate row
        return sync_mod._claim_account_push(db, 1, sync_mod._STAGED_GATE)
    return claim(db, user_id)


async def _release(db, user_id, claim_id):
    release = getattr(sync_mod, "_release_staged_gate", None)
    if release is None:
        await sync_mod._release_account_push(db, 1, claim_id, sync_mod._STAGED_GATE)
    else:
        await release(db, user_id, claim_id)


@pytest.mark.asyncio
async def test_a_refused_staged_push_uses_its_batch_up(app_client, alice, mock_db, monkeypatch):  # noqa: F811
    sk, headers = alice
    bad = _dek(sk, 0)
    bad["signature"] = "00" * 64
    staged = await _stage(app_client, headers, [bad] + [_dek(sk, i) for i in range(1, COUNT)])
    assert staged.status_code == 200, staged.text

    parsed = 0
    check = sync_mod._check_objects

    def _counting(objects, signing_pks):
        nonlocal parsed
        if len(objects) >= COUNT:
            parsed += 1
        return check(objects, signing_pks)

    monkeypatch.setattr(sync_mod, "_check_objects", _counting)
    first = await _staged_push(app_client, headers)
    assert first.status_code != 200 or not first.json()["accepted"], first.text
    assert not mock_db._storage.get("sync_staged_objects"), "the refused batch stayed staged"
    for _ in range(5):
        again = await _staged_push(app_client, headers)
        assert again.status_code == 409, again.text
    assert parsed == 1, f"the batch was parsed {parsed} times"
    assert not mock_db._storage.get("sync_staged_gate")


@pytest.mark.asyncio
async def test_an_accepted_staged_push_still_lands(app_client, alice, mock_db):  # noqa: F811
    sk, headers = alice
    assert (await _stage(app_client, headers, [_dek(sk, i) for i in range(COUNT)])).status_code == 200
    answer = await _staged_push(app_client, headers)
    assert answer.status_code == 200 and len(answer.json()["accepted"]) == COUNT, answer.text
    assert not mock_db._storage.get("sync_staged_objects")


@pytest.mark.asyncio
async def test_the_staged_gate_goes_in_order_of_arrival(mock_db):  # noqa: F811
    order = []
    first = await _claim(mock_db, "USER0000000000000000000001")

    async def _take(user_id):
        claim_id = await _claim(mock_db, user_id)
        order.append(user_id)
        await asyncio.sleep(0.05)
        await _release(mock_db, user_id, claim_id)

    waiting = asyncio.create_task(_take("USER0000000000000000000002"))
    await asyncio.sleep(0.6)  # the waiter is well into its backoff
    await _release(mock_db, "USER0000000000000000000001", first)
    again = asyncio.create_task(_take("USER0000000000000000000001"))
    await asyncio.wait_for(asyncio.gather(waiting, again), 10)
    assert order == ["USER0000000000000000000002", "USER0000000000000000000001"], order
    assert not mock_db._storage.get("sync_staged_gate")


def test_the_schema_splits_into_whole_statements():
    """create_schema splits SCHEMA_SQL on ';': one in a comment broke the queue
    table's CREATE on MariaDB (tests/test_review9_server_mariadb.py found it)."""
    from server.app.database import SCHEMA_SQL

    for statement in SCHEMA_SQL.split(";"):
        code = "\n".join(line for line in statement.splitlines() if not line.strip().startswith("--")).strip()
        assert not code or code.split()[0].upper() in ("CREATE", "INSERT", "ALTER"), statement[:200]


@pytest.mark.asyncio
async def test_a_waiter_that_died_does_not_hold_the_queue(mock_db, monkeypatch):  # noqa: F811
    if not hasattr(sync_mod, "_claim_staged_gate"):
        pytest.fail("no queue for the staged gate")
    now = int(sync_mod.time.time() * 1000)
    mock_db._storage.setdefault("sync_staged_queue", []).append({
        "user_id": "USER0000000000000000000009", "claim_id": "dead",
        "queued_at": now - 60_000, "seen_at": now - 60_000,
    })
    claim_id = await asyncio.wait_for(_claim(mock_db, "USER0000000000000000000001"), 5)
    await _release(mock_db, "USER0000000000000000000001", claim_id)
    assert not mock_db._storage.get("sync_staged_queue")
