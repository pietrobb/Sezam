"""Regressions for review main@d615826, R6-A (server availability)."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    MockDatabase,
    _create_admin_user,
    _create_jwt,
    _push_object,
    app_client,
)

ADMIN_ID = "ADMIN000000000000000000001"


class _OnePerTaskDatabase(MockDatabase):
    """A pool that refuses a second connection to a task still holding one.

    The real aiomysql pool would just wait for it, and with enough parallel
    requests every connection is held by a request waiting for another one.
    """

    def __init__(self):
        super().__init__()
        self.nested: list[str] = []
        self._holders: set[asyncio.Task] = set()

    @asynccontextmanager
    async def _held(self):
        task = asyncio.current_task()
        if task in self._holders:
            self.nested.append(task.get_name())
            raise RuntimeError("second pool connection while holding one")
        self._holders.add(task)
        try:
            await asyncio.sleep(0)  # let parallel requests interleave
            yield
        finally:
            self._holders.discard(task)

    @asynccontextmanager
    async def acquire(self):
        async with self._held():
            async with super().acquire() as conn:
                yield conn

    @asynccontextmanager
    async def transaction(self):
        async with self._held():
            async with super().transaction() as conn:
                yield conn


@pytest_asyncio.fixture
async def mock_db():
    db = _OnePerTaskDatabase()
    await db.create_schema()
    return db


@pytest.mark.asyncio
async def test_h1_consumed_share_recheck_never_takes_a_second_connection(
    app_client, mock_db, monkeypatch,
):
    from server.app.routers import share

    monkeypatch.setattr(share, "_SHARE_ERROR_MIN_SECONDS", 0)
    _create_admin_user(mock_db._storage)
    now_ms = int(time.time() * 1000)
    share_id = "S" * 43
    mock_db._storage["shared_links"].append({
        "id": share_id, "encrypted_blob": b"secret", "created_by": ADMIN_ID,
        "created_at": now_ms, "expires_at": now_ms + 3_600_000,
        "max_views": 1, "view_count": 0, "pin_hash": None,
        "pin_attempts": 0, "is_locked": 0, "notify_on_view": 0,
    })

    responses = await asyncio.gather(*(
        app_client.post(f"/api/share/{share_id}", json={}) for _ in range(8)
    ))

    assert mock_db.nested == []
    assert sorted(r.status_code for r in responses) == [200] + [404] * 7


@pytest.mark.asyncio
async def test_h1_health_checks_the_database(app_client, mock_db, monkeypatch):
    assert (await app_client.get("/health")).status_code == 200

    @asynccontextmanager
    async def broken_acquire():
        raise ConnectionError("pool exhausted")
        yield  # pragma: no cover

    monkeypatch.setattr(mock_db, "acquire", broken_acquire)
    assert (await app_client.get("/health")).status_code == 503


def test_limiter_rows_are_created_with_an_exclusive_lock():
    """INSERT IGNORE on an existing row takes only a shared lock; two requests
    that then lock the row FOR UPDATE (or UPDATE it) deadlock on each other and
    one gets a 500. Real-MariaDB check: tests/test_review6_server_mariadb.py."""
    import pathlib
    import re

    routers = pathlib.Path(__file__).parent.parent / "server" / "app" / "routers"
    offenders = []
    for path in routers.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"INSERT IGNORE INTO (\w+)", text):
            table = m.group(1)
            following = text[m.end():m.end() + 1200]
            if re.search(
                rf"(FROM {table}\b[^\"]*\"?\s*\"?[^\"]*FOR UPDATE|UPDATE {table}\b)", following,
            ):
                offenders.append(f"{path.name}: {table}")
    assert offenders == []


@pytest.mark.asyncio
async def test_unknown_target_user_is_a_conflict(app_client, mock_db):
    """On MariaDB the foreign key failed the whole push with a 500
    (tests/test_review6_server_mariadb.py)."""
    import base64
    import hashlib

    from tests.test_server_spec import _sign_sync_object

    sk, _ = _create_admin_user(mock_db._storage)
    token = _create_jwt(ADMIN_ID, "admin", True)
    payload = b"entry"
    p_hash = hashlib.sha256(payload).hexdigest()
    target = "T" * 26
    resp = await app_client.post("/api/sync", json={"objects": [{
        "id": "E" * 26, "object_type": "entry", "payload": base64.b64encode(payload).decode(),
        "parent_ref": None, "target_user_id": target, "version": 1, "is_deleted": 0,
        "payload_hash": p_hash,
        "signature": _sign_sync_object(sk, "E" * 26, "entry", None, target, 0, 1, p_hash),
    }], "atomic_batch": False}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["conflicts"][0]["error"] == "unknown target user"


@pytest.mark.asyncio
async def test_push_verifies_signatures_before_the_global_lock(
    app_client, mock_db, monkeypatch,
):
    from server.app.routers import sync

    sk, _ = _create_admin_user(mock_db._storage)
    token = _create_jwt(ADMIN_ID, "admin", True)
    in_transaction = False
    verified_under_lock: list[bool] = []
    real_run, real_verify = sync.run_transaction, sync._verify_sync_signature

    async def tracking_run(db, body):
        nonlocal in_transaction
        in_transaction = True
        try:
            return await real_run(db, body)
        finally:
            in_transaction = False

    def tracking_verify(obj, signature, pk):
        verified_under_lock.append(in_transaction)
        return real_verify(obj, signature, pk)

    monkeypatch.setattr(sync, "run_transaction", tracking_run)
    monkeypatch.setattr(sync, "_verify_sync_signature", tracking_verify)

    good = await _push_object(app_client, token, sk, "N" * 26, "node", None, 1, b"meta")
    assert good.status_code == 200 and len(good.json()["accepted"]) == 1
    forged = await _push_object(
        app_client, token, SigningKey.generate(), "M" * 26, "node", None, 1, b"meta",
    )
    assert forged.json()["conflicts"][0]["error"] == "invalid signature"
    assert verified_under_lock and not any(verified_under_lock)
