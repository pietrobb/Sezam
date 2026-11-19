"""Follow-up review 2052248, finding 5: concurrent pushes must not deadlock.

These run against a REAL MariaDB/MySQL server, because the mock database has
no row/gap locks. Point SEZAM_TEST_MARIADB at a throwaway server, e.g.
``root:secret@127.0.0.1:3306``; every test creates and drops its own schema.
Without the variable the tests are skipped.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import secrets
import time
from types import SimpleNamespace

import pytest
import pytest_asyncio
from nacl.signing import SigningKey
from ulid import ULID

aiomysql = pytest.importorskip("aiomysql")

from server.app.database import Database  # noqa: E402
from server.app.models.schemas import PushRequest, SyncObject  # noqa: E402
from server.app.routers.sync import sync_push  # noqa: E402

_DSN = os.environ.get("SEZAM_TEST_MARIADB", "")


def _parse_dsn(dsn: str) -> dict:
    creds, _, hostport = dsn.rpartition("@")
    user, _, password = creds.partition(":")
    host, _, port = hostport.partition(":")
    return {"user": user, "password": password, "host": host, "port": int(port or 3306)}


@pytest_asyncio.fixture
async def mariadb():
    if not _DSN:
        if os.environ.get("SEZAM_REQUIRE_MARIADB"):
            pytest.fail("SEZAM_REQUIRE_MARIADB is set but SEZAM_TEST_MARIADB is not")
        pytest.skip("SEZAM_TEST_MARIADB not set (needs a real MariaDB)")
    params = _parse_dsn(_DSN)
    name = f"sezam_t_{secrets.token_hex(6)}"
    admin = await aiomysql.connect(
        host=params["host"], port=params["port"], user=params["user"],
        password=params["password"], autocommit=True,
    )
    async with admin.cursor() as cur:
        await cur.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
    db = Database(SimpleNamespace(
        db_host=params["host"], db_port=params["port"], db_user=params["user"],
        db_password=params["password"], db_name=name,
    ))
    await db.connect()
    try:
        await db.create_schema()
        yield db
    finally:
        await db.close()
        async with admin.cursor() as cur:
            await cur.execute(f"DROP DATABASE `{name}`")
        admin.close()


async def _add_user(db: Database, username: str) -> tuple[str, SigningKey]:
    user_id = str(ULID())
    sk = SigningKey.generate()
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO users (id, username, signing_pk, encryption_pk, "
                "key_fingerprint, status, is_admin, created_at) "
                "VALUES (%s, %s, %s, %s, %s, 'active', 1, %s)",
                (user_id, username, bytes(sk.verify_key), os.urandom(32),
                 "f" * 64, int(time.time() * 1000)),
            )
    return user_id, sk


def _signed(sk: SigningKey, obj_id: str, version: int, object_type: str = "entry") -> SyncObject:
    payload = os.urandom(48)
    payload_hash = hashlib.sha256(payload).hexdigest()
    ot = object_type.encode()
    canonical = (
        obj_id.encode().ljust(26, b"\x00")[:26]
        + bytes([len(ot)]) + ot
        + b"\x00" * 26 + b"\x00" * 26
        + bytes([0])
        + version.to_bytes(4, "big")
        + bytes.fromhex(payload_hash)
    )
    return SyncObject(
        id=obj_id, object_type=object_type,
        payload=base64.b64encode(payload).decode(),
        version=version, payload_hash=payload_hash,
        signature=sk.sign(canonical).signature.hex(),
    )


async def _push(db: Database, user_id: str, objects: list[SyncObject]):
    return await sync_push(
        PushRequest(objects=objects), None, db, {"sub": user_id, "is_admin": True},
        None, None,  # config / jwt manager: only needed for a key_rotation
    )


@pytest.mark.asyncio
async def test_concurrent_new_object_pushes_from_two_users_never_deadlock(mariadb):
    """Review: 25/60 concurrent pushes of 2 users failed with a deadlock (500).

    The per-id FOR UPDATE on a not-yet-existing id took a gap lock; two pushes
    holding the same gap then both waited for the other's insert intention.
    """
    users = [await _add_user(mariadb, f"user{i}") for i in range(2)]
    jobs = []
    for round_ in range(30):
        for user_id, sk in users:
            batch = [_signed(sk, str(ULID()), 1) for _ in range(3)]
            jobs.append(_push(mariadb, user_id, batch))

    results = await asyncio.gather(*jobs, return_exceptions=True)

    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, f"{len(failures)}/{len(jobs)} pushes failed: {failures[0]!r}"
    seqs = [a.commit_seq for r in results for a in r.accepted]
    assert all(not r.conflicts for r in results)
    assert len(seqs) == len(jobs) * 3
    assert len(set(seqs)) == len(seqs)


@pytest.mark.asyncio
async def test_two_devices_of_one_user_update_and_create_concurrently(mariadb):
    """Two devices of the same user: concurrent edits of existing objects mixed
    with new objects all commit (no deadlock) and keep unique commit_seqs."""
    user_id, sk = await _add_user(mariadb, "solo")
    existing = [str(ULID()) for _ in range(20)]
    firsts = [_signed(sk, oid, 1) for oid in existing]
    await _push(mariadb, user_id, firsts)

    jobs = []
    for first in firsts:
        # Since S1 an edit names the copy it was made on (version, payload hash).
        edit = _signed(sk, first.id, 2).model_copy(
            update={"base_version": 1, "base_payload_hash": first.payload_hash}
        )
        jobs.append(_push(mariadb, user_id, [edit, _signed(sk, str(ULID()), 1)]))
        jobs.append(_push(mariadb, user_id, [_signed(sk, str(ULID()), 1)]))

    results = await asyncio.gather(*jobs, return_exceptions=True)

    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, f"{len(failures)}/{len(jobs)} pushes failed: {failures[0]!r}"
    seqs = [a.commit_seq for r in results for a in r.accepted]
    assert len(seqs) == 60
    assert len(set(seqs)) == len(seqs)


@pytest.mark.asyncio
async def test_tombstone_gc_running_during_pushes_never_deadlocks(mariadb):
    from server.app.main import _cleanup_tombstones

    user_id, sk = await _add_user(mariadb, "gc")
    for _ in range(4):
        doomed = [str(ULID()) for _ in range(10)]
        await _push(mariadb, user_id, [_signed(sk, oid, 1) for oid in doomed])
        async with mariadb.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE vault_objects SET is_deleted = 1, modified_at = 0 WHERE id IN ("
                    + ",".join(["%s"] * len(doomed)) + ")",
                    doomed,
                )
        jobs = [_push(mariadb, user_id, [_signed(sk, str(ULID()), 1)]) for _ in range(15)]
        jobs.insert(7, _cleanup_tombstones(mariadb, 1))
        results = await asyncio.gather(*jobs, return_exceptions=True)
        failures = [r for r in results if isinstance(r, BaseException)]
        assert not failures, repr(failures[0]) if failures else ""


def test_run_transaction_retries_deadlocks_only():
    """Unit check (no MariaDB needed) of the retry wrapper itself."""
    import pymysql
    from contextlib import asynccontextmanager

    from server.app.database import TRANSACTION_ATTEMPTS, run_transaction

    class _DB:
        rollbacks = 0

        @asynccontextmanager
        async def transaction(self):
            try:
                yield object()
            except Exception:
                _DB.rollbacks += 1
                raise

    calls = []

    async def flaky(conn):
        calls.append(conn)
        if len(calls) < 3:
            raise pymysql.err.OperationalError(1213, "Deadlock found")
        return "ok"

    assert asyncio.run(run_transaction(_DB(), flaky)) == "ok"
    assert len(calls) == 3 and _DB.rollbacks == 2

    async def always_timeout(conn):
        calls.append(conn)
        raise pymysql.err.OperationalError(1205, "Lock wait timeout exceeded")

    calls.clear()
    with pytest.raises(pymysql.err.OperationalError):
        asyncio.run(run_transaction(_DB(), always_timeout))
    assert len(calls) == TRANSACTION_ATTEMPTS

    async def other_error(conn):
        calls.append(conn)
        raise pymysql.err.OperationalError(2013, "Lost connection")

    calls.clear()
    with pytest.raises(pymysql.err.OperationalError):
        asyncio.run(run_transaction(_DB(), other_error))
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_same_new_id_from_two_devices_is_one_accept_one_conflict(mariadb):
    user_id, sk = await _add_user(mariadb, "race")
    oid = str(ULID())
    results = await asyncio.gather(
        *[_push(mariadb, user_id, [_signed(sk, oid, 1)]) for _ in range(6)],
        return_exceptions=True,
    )
    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, repr(failures[0]) if failures else ""
    assert sum(len(r.accepted) for r in results) == 1
    assert sum(len(r.conflicts) for r in results) == 5


@pytest.mark.asyncio
async def test_pool_sessions_reject_truncation_instead_of_storing_it(mariadb):
    """Review 2052248: a too-long id must fail, not be stored cut to 26 chars."""
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT @@SESSION.sql_mode")
            assert "STRICT_ALL_TABLES" in (await cur.fetchone())[0]
            await cur.execute("CREATE TEMPORARY TABLE t_ids (id VARCHAR(26), v INTEGER)")
            for row in (("X" * 40, 1), ("Y" * 26, 2**32 - 1)):
                with pytest.raises(aiomysql.DataError):
                    await cur.execute("INSERT INTO t_ids (id, v) VALUES (%s, %s)", row)
            await cur.execute("SELECT COUNT(*) FROM t_ids")
            assert (await cur.fetchone())[0] == 0
