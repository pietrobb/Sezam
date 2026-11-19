"""Review 4acfdde (R11 #1): the server must start on a database an older
version created.

Before the schema named its collation (review 8595ec1), tables got the
server's default: utf8mb4_general_ci on MariaDB 10.x. The new tables named
utf8mb4_uca1400_ai_ci, and a foreign key between columns of different
collations fails (errno 150), so create_schema aborted on the first new
table referencing users. New tables now take the collation of the existing
users table.

The MariaDB tests are skipped without SEZAM_TEST_MARIADB
(see tests/test_review2_server_mariadb.py).
"""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("aiomysql")

import aiomysql  # noqa: E402
import pymysql  # noqa: E402
import pytest_asyncio  # noqa: E402

from server.app import database  # noqa: E402
from server.app.database import Database  # noqa: E402
from tests.test_review2_server_mariadb import _DSN, _parse_dsn  # noqa: E402

LEGACY = "utf8mb4_general_ci"


def _statement(sql: str, table: str) -> str:
    for statement in sql.split(";"):
        if f"CREATE TABLE IF NOT EXISTS {table} (" in statement:
            return statement.strip()
    raise AssertionError(table)


def _tables(sql: str) -> set[str]:
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+) \(", sql))


def test_schema_for_a_legacy_collation_changes_every_utf8mb4_table():
    legacy = database.schema_sql_for("utf8mb4", LEGACY)
    assert _tables(legacy) == _tables(database.SCHEMA_SQL)
    assert database.SCHEMA_COLLATION not in legacy
    assert legacy.count(f"COLLATE={LEGACY}") == database.SCHEMA_SQL.count(database.SCHEMA_TABLE_OPTIONS)
    with pytest.raises(ValueError):
        database.schema_sql_for("utf8mb4", "x; DROP TABLE users")


class _Cursor:
    def __init__(self, users_row, collations):
        self.users_row, self.collations, self.result = users_row, collations, None

    async def execute(self, sql, args=()):
        if "information_schema.COLUMNS" in sql:
            self.result = [self.users_row] if self.users_row else []
        elif sql.startswith("SHOW COLLATION"):
            self.result = [(c,) for c in self.collations if c == args[0]]

    async def fetchone(self):
        return self.result[0] if self.result else None

    async def fetchall(self):
        return self.result


def test_new_database_on_a_server_without_uca1400_fails_clearly():
    with pytest.raises(RuntimeError, match="MariaDB 10.10"):
        asyncio.run(database._schema_sql(_Cursor(None, [LEGACY])))
    assert asyncio.run(database._schema_sql(_Cursor(None, [database.SCHEMA_COLLATION]))) == database.SCHEMA_SQL
    legacy = asyncio.run(database._schema_sql(_Cursor(("utf8mb4", LEGACY), [LEGACY])))
    assert legacy == database.schema_sql_for("utf8mb4", LEGACY)


@pytest_asyncio.fixture
async def legacy_db():
    """A database where an older version created users and shared_links in
    utf8mb4_general_ci, and nothing else yet."""
    if not _DSN:
        pytest.skip("SEZAM_TEST_MARIADB not set (needs a real MariaDB)")
    params = _parse_dsn(_DSN)
    name = f"sezam_t_{secrets.token_hex(6)}"
    admin = await aiomysql.connect(
        host=params["host"], port=params["port"], user=params["user"],
        password=params["password"], autocommit=True,
    )
    async with admin.cursor() as cur:
        await cur.execute(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4")
        await cur.execute(f"USE `{name}`")
        legacy = database.SCHEMA_SQL.replace("utf8mb4_uca1400_ai_ci", LEGACY)
        await cur.execute(_statement(legacy, "users"))
        await cur.execute(_statement(legacy, "shared_links"))
    db = Database(SimpleNamespace(
        db_host=params["host"], db_port=params["port"], db_user=params["user"],
        db_password=params["password"], db_name=name,
    ))
    await db.connect()
    try:
        yield db, admin
    finally:
        await db.close()
        async with admin.cursor() as cur:
            await cur.execute(f"DROP DATABASE `{name}`")
        admin.close()


async def _rows(db, sql: str, args=()):
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, args)
            return await cur.fetchall()


@pytest.mark.asyncio
async def test_server_starts_on_a_database_with_legacy_users_collation(legacy_db):
    db, admin = legacy_db
    # The cause, on this very database: a new table in the pinned collation
    # cannot reference the legacy users table.
    async with admin.cursor() as cur:
        with pytest.raises(pymysql.err.OperationalError) as refused:
            await cur.execute(_statement(database.SCHEMA_SQL, "user_key_archives"))
    assert refused.value.args[0] == 1005 and "150" in str(refused.value)

    await db.create_schema()
    await db.create_schema()  # the next start (and every worker) too

    present = {name for (name,) in await _rows(
        db, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()"
    )}
    assert _tables(database.SCHEMA_SQL) <= present
    fks = {(t, r) for t, r in await _rows(
        db,
        "SELECT TABLE_NAME, REFERENCED_TABLE_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS "
        "WHERE CONSTRAINT_SCHEMA = DATABASE()",
    )}
    assert ("user_key_archives", "users") in fks
    assert ("share_views", "shared_links") in fks
    assert ("sync_state", "users") in fks
    for name, collation in await _rows(
        db,
        "SELECT TABLE_NAME, TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()",
    ):
        if collation.startswith("utf8mb4"):
            assert collation == LEGACY, name

    # The foreign keys work: rows reference the user and go with it.
    now = int(time.time() * 1000)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO users (id, username, signing_pk, encryption_pk, key_fingerprint, "
                "status, created_at) VALUES ('U1', 'alice', 'x', 'y', 'f', 'active', %s)",
                (now,),
            )
            await cur.execute(
                "INSERT INTO write_acl (user_id, node_id, granted_at) VALUES ('U1', 'N1', %s)", (now,)
            )
            with pytest.raises(pymysql.err.IntegrityError):
                await cur.execute(
                    "INSERT INTO write_acl (user_id, node_id, granted_at) VALUES ('nobody', 'N1', %s)",
                    (now,),
                )
            await cur.execute("DELETE FROM users WHERE id = 'U1'")
    assert not await _rows(db, "SELECT * FROM write_acl")
