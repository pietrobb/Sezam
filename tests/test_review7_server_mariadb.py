"""Review 7c10379 (R7-H, server T-table): locking reads of rows that do not
exist yet must not deadlock parallel requests.

On MariaDB a ``SELECT ... FOR UPDATE`` that finds nothing takes a gap lock;
two requests holding the same gap then deadlock on their INSERTs and one of
them ends as a 500. Runs against a real MariaDB (SEZAM_TEST_MARIADB, see
tests/test_review2_server_mariadb.py); skipped without it.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time

import pytest
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

pytest.importorskip("aiomysql")

from tests.test_review2_server_mariadb import _add_user, mariadb  # noqa: E402,F401


async def _client(db, tmp_path):
    from server.app.config import JWTKeyManager, ServerConfig
    from server.app.dependencies import set_globals
    from server.app.main import app

    key_file = tmp_path / "jwt.bin"
    key_file.write_bytes(bytes(SigningKey.generate()))
    set_globals(ServerConfig(hmac_server_secret="r7h-test-secret-0123456789"), db,
                JWTKeyManager(str(key_file)))
    return AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test")


@pytest.mark.asyncio
async def test_parallel_registrations_of_new_names_never_deadlock(mariadb, tmp_path):  # noqa: F811
    admin_id, _ = await _add_user(mariadb, "admin")
    now_ms = int(time.time() * 1000)
    tokens = [os.urandom(16).hex() for _ in range(24)]
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            for token in tokens:
                await cur.execute(
                    "INSERT INTO invitation_tokens "
                    "(token_hash, created_by, created_at, expires_at, is_used) "
                    "VALUES (%s, %s, %s, %s, 0)",
                    (hashlib.sha256(token.encode()).hexdigest(), admin_id, now_ms,
                     now_ms + 3_600_000),
                )
        await conn.commit()

    async with await _client(mariadb, tmp_path) as client:
        responses = await asyncio.gather(*(
            client.post("/api/users/register", json={
                "invitation_token": token, "username": f"member{i // 2 if i < 4 else i:02d}",
                "signing_pk": os.urandom(32).hex(), "encryption_pk": os.urandom(32).hex(),
            })
            for i, token in enumerate(tokens)
        ))

    codes = [r.status_code for r in responses]
    # The first four take two names twice: the UNIQUE username decides, 409.
    assert sorted(codes[:2]) == sorted(codes[2:4]) == [200, 409]
    assert codes[4:] == [200] * (len(tokens) - 4)


@pytest.mark.asyncio
async def test_parallel_bootstraps_are_one_admin_and_403s(mariadb, tmp_path):  # noqa: F811
    async with await _client(mariadb, tmp_path) as client:
        responses = await asyncio.gather(*(
            client.post("/api/bootstrap", json={
                "username": f"boss{i}", "signing_pk": os.urandom(32).hex(),
                "encryption_pk": os.urandom(32).hex(),
            })
            for i in range(16)
        ))
    assert sorted(r.status_code for r in responses) == [200] + [403] * 15


@pytest.mark.asyncio
async def test_parallel_first_probes_of_locked_names_never_deadlock(mariadb):  # noqa: F811
    """A locked name's probe slot (the key-material archive here; /recover
    takes its slots the same way) used to be read FOR UPDATE before it
    existed: different names' first probes deadlocked."""
    from ulid import ULID

    from server.app.config import ServerConfig
    from server.app.routers.auth import _take_archive_probe_slot

    config = ServerConfig(hmac_server_secret="r7h-test-secret-0123456789")
    now_ms = int(time.time() * 1000)

    async def probe(user_id: str):
        async with mariadb.transaction() as conn:
            async with conn.cursor() as cur:
                await _take_archive_probe_slot(cur, conn, config, user_id, now_ms)
                await asyncio.sleep(0.05)  # the request's proof check

    user_ids = [str(ULID()) for _ in range(20)]
    results = await asyncio.gather(*(probe(u) for u in user_ids), return_exceptions=True)
    assert [r for r in results if r is not None] == []

    # Each name's window is now taken: its next probe waits.
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as refused:
        await probe(user_ids[0])
    assert refused.value.status_code == 429


@pytest.mark.asyncio
async def test_two_admins_first_org_recovery_store_is_one_setup_and_409s(
    mariadb, monkeypatch,  # noqa: F811
):
    """Before any org recovery the blob row is missing: parallel first stores
    of several admins deadlocked (500) instead of one setup and 409s."""
    from fastapi import HTTPException

    from server.app.config import ServerConfig
    from server.app.models.schemas import OrgRecoveryStoreRequest
    from server.app.routers import recovery

    async def password_checked(*_args, **_kwargs):
        await asyncio.sleep(0.05)  # the proof check, with the blob row locked

    monkeypatch.setattr(recovery, "_require_current_password", password_checked)
    admins = [(await _add_user(mariadb, f"admin{i}"))[0] for i in range(6)]
    req = OrgRecoveryStoreRequest(
        wrapped_kek="00" * 60, recovery_signing_pk="11" * 32, key_epoch=0,
    )

    async def store(admin_id: str):
        try:
            await recovery._store_recovery_blob(
                mariadb, ServerConfig(hmac_server_secret="r7h-test-secret-0123456789"),
                req, {"sub": admin_id}, b"\0" * 60, b"\x11" * 32, int(time.time() * 1000),
            )
        except HTTPException as exc:
            return exc.status_code
        return 200

    results = await asyncio.gather(*(store(a) for a in admins), return_exceptions=True)
    assert sorted(results, key=str) == [200] + [409] * 5


async def _abandoned_pending_account(db, admin_id: str, username: str) -> tuple[str, str]:
    """A registration whose keypair upload never happened (lockout review
    #10: its name is free again), plus an invitation for the name's next
    registration. Returns (account id, invitation token)."""
    from ulid import ULID

    account = str(ULID())
    token = os.urandom(16).hex()
    long_ago = int(time.time() * 1000) - 7 * 86_400_000
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO users (id, username, signing_pk, encryption_pk, "
                "key_fingerprint, status, is_admin, created_at) "
                "VALUES (%s, %s, %s, %s, %s, 'pending', 0, %s)",
                (account, username, os.urandom(32), os.urandom(32), "e" * 64, long_ago),
            )
            await cur.execute(
                "INSERT INTO invitation_tokens "
                "(token_hash, created_by, created_at, expires_at, is_used) "
                "VALUES (%s, %s, %s, %s, 0)",
                (hashlib.sha256(token.encode()).hexdigest(), admin_id, long_ago,
                 long_ago + 30 * 86_400_000),
            )
        await conn.commit()
    return account, token


def _register(client, token: str, username: str):
    return client.post("/api/users/register", json={
        "invitation_token": token, "username": username,
        "signing_pk": os.urandom(32).hex(), "encryption_pk": os.urandom(32).hex(),
    })


async def _object_kept(db, obj_id: str) -> bool:
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1 FROM vault_objects WHERE id = %s", (obj_id,))
            return bool(await cur.fetchone())


@pytest.mark.asyncio
async def test_an_account_granted_an_object_keeps_its_name(mariadb, tmp_path):  # noqa: F811
    """Dropping the abandoned account cascaded into vault_objects: the
    admin's signed object granted to it was deleted with no tombstone."""
    from ulid import ULID

    from tests.test_review2_server_mariadb import _push
    from tests.test_review6_server_mariadb import _signed_for

    admin_id, sk = await _add_user(mariadb, "admin")
    account, token = await _abandoned_pending_account(mariadb, admin_id, "bob")
    granted = _signed_for(sk, str(ULID()), "entry", account)
    assert [a.id for a in (await _push(mariadb, admin_id, [granted])).accepted] == [granted.id]

    async with await _client(mariadb, tmp_path) as client:
        assert (await _register(client, token, "bob")).status_code == 409
    assert await _object_kept(mariadb, granted.id)


@pytest.mark.asyncio
async def test_a_push_racing_the_drop_of_its_target_account(mariadb, tmp_path):  # noqa: F811
    """The push checked its target user without a lock: a registration that
    dropped the abandoned account in between failed the whole push on the
    foreign key (500), or its cascade deleted the object just accepted."""
    from ulid import ULID

    from tests.test_review2_server_mariadb import _push
    from tests.test_review6_server_mariadb import _signed_for

    admin_id, sk = await _add_user(mariadb, "admin")
    outcomes = set()
    async with await _client(mariadb, tmp_path) as client:
        for i in range(40):
            name = f"bob{i}"
            account, token = await _abandoned_pending_account(mariadb, admin_id, name)
            granted = _signed_for(sk, str(ULID()), "entry", account)

            async def push():
                await asyncio.sleep(0 if i % 2 else 0.001 * (i % 7))
                result = await _push(mariadb, admin_id, [granted])
                return "accepted" if result.accepted else result.conflicts[0].error

            async def register():
                await asyncio.sleep(0.004 * (i % 5) if i % 2 else 0)
                return (await _register(client, token, name)).status_code

            pushed, registered = await asyncio.gather(
                push(), register(), return_exceptions=True
            )
            outcomes.add((pushed if isinstance(pushed, str) else repr(pushed)[:80],
                          registered, await _object_kept(mariadb, granted.id)))
    # Either the push came first (the name stays taken) or the account was
    # gone before it (one conflict, nothing stored).
    assert outcomes <= {("accepted", 409, True), ("unknown target user", 200, False)}
