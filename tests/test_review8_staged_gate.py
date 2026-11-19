"""Review main@a159e97 (medium), server: staged batches of several accounts at once.

7c10379 H7 kept one staged push per account; each worker still held the
parsed batch of a different account (~770 MB for the largest), four workers
~3 GB. One staged batch is now held server-wide at a time (sync_staged_gate).
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from server.app.routers import sync as sync_mod
from tests.test_review7_staged_push_memory_h7 import COUNT, _dek, _stage, _staged_push
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_jwt,
    _create_regular_user,
    app_client,
    mock_db,
)


@pytest.mark.asyncio
async def test_staged_pushes_of_different_accounts_hold_their_batches_one_at_a_time(
    app_client, mock_db, monkeypatch  # noqa: F811
):
    accounts = []
    for n, name in enumerate(("alice", "bob", "carol")):
        user_id = f"USER{n + 1:022d}"
        sk, _ = _create_regular_user(mock_db._storage, user_id, name)
        headers = {"Authorization": f"Bearer {_create_jwt(user_id, name, False)}"}
        objects = [{**_dek(sk, n * 100 + i)} for i in range(COUNT)]
        staged = await _stage(app_client, headers, objects)
        assert staged.status_code == 200, staged.text
        accounts.append(headers)

    held, peak, guard = 0, 0, threading.Lock()
    check = sync_mod._check_objects

    def _holding_the_batch(objects, signing_pks):
        nonlocal held, peak
        if len(objects) < COUNT:
            return check(objects, signing_pks)
        with guard:
            held += 1
            peak = max(peak, held)
        time.sleep(0.2)
        try:
            return check(objects, signing_pks)
        finally:
            with guard:
                held -= 1

    monkeypatch.setattr(sync_mod, "_check_objects", _holding_the_batch)
    answers = await asyncio.gather(*(_staged_push(app_client, h) for h in accounts))
    assert peak == 1, f"{peak} staged batches held at once"
    assert all(a.status_code == 200 and len(a.json()["accepted"]) == COUNT for a in answers), [
        a.text for a in answers
    ]
    assert not mock_db._storage.get("sync_staged_gate")
