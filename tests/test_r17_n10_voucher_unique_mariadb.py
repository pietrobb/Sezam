"""Review c02cc47 R17-N10 on a real MariaDB: a voucher list is kept once.

A database from before the fix may already hold copies of one list; the
upgrade keeps the oldest and then adds UNIQUE (user_id, signing_pk,
signature), and a list sent again after it is stored once.
"""

from __future__ import annotations

import os
import time

import pytest
from ulid import ULID

from tests.test_review2_server_mariadb import _add_user, mariadb  # noqa: F401


async def _insert(cur, user_id: str, signing_pk: bytes, signature: bytes, ignore: bool = False) -> str:
    row_id = str(ULID())
    await cur.execute(
        f"INSERT {'IGNORE ' if ignore else ''}INTO key_vouchers "
        "(id, user_id, signing_pk, entries, signature, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (row_id, user_id, signing_pk, "[]", signature, int(time.time() * 1000)),
    )
    time.sleep(0.002)  # the next ULID sorts after this one
    return row_id


async def _rows(cur) -> list[tuple]:
    await cur.execute("SELECT id, signature FROM key_vouchers ORDER BY id")
    return list(await cur.fetchall())


@pytest.mark.asyncio
async def test_the_upgrade_keeps_one_copy_and_later_copies_are_not_stored(mariadb):  # noqa: F811
    user_id, sk = await _add_user(mariadb, "alice")
    key, sig, other_sig = bytes(sk.verify_key), os.urandom(64), os.urandom(64)
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            # The database as it was before the fix: no unique key, three copies.
            await cur.execute("ALTER TABLE key_vouchers DROP INDEX IF EXISTS uq_kv_list")
            oldest = await _insert(cur, user_id, key, sig)
            await _insert(cur, user_id, key, sig)
            await _insert(cur, user_id, key, sig)
            kept_other = await _insert(cur, user_id, key, other_sig)
            await conn.commit()

    await mariadb.create_schema()  # the upgrade runs the migrations

    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            assert await _rows(cur) == [(oldest, sig), (kept_other, other_sig)]
            await _insert(cur, user_id, key, sig, ignore=True)
            assert cur.rowcount == 0
            await conn.commit()
            assert len(await _rows(cur)) == 2
            await cur.execute(
                "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'key_vouchers' AND INDEX_NAME = 'uq_kv_list' AND NON_UNIQUE = 0"
            )
            assert (await cur.fetchone())[0] == 3  # one row per column of the key
