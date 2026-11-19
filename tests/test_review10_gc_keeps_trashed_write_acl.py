"""Review 8595ec1 (R10-H): tombstone GC took the write access of folders in the trash.

After collecting expired tombstones, GC dropped every write_acl row whose
folder was not live - also a folder deleted yesterday and still in the trash.
Restored from the trash, the folder came back for its members read-only: their
envelopes were unchanged, so nothing granted write again.

Runs against a real MariaDB (SEZAM_TEST_MARIADB): the mock database does not
evaluate the subquery the old cleanup used.
"""

from __future__ import annotations

import os
import time

import pytest
from ulid import ULID

pytest.importorskip("aiomysql")

from server.app.main import _cleanup_tombstones  # noqa: E402
from tests.test_review2_server_mariadb import _add_user, mariadb  # noqa: E402, F401

DAY_MS = 86_400_000


async def _acl(db) -> set[tuple[str, str]]:
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT user_id, node_id FROM write_acl")
            return {tuple(row) for row in await cur.fetchall()}


@pytest.mark.asyncio
async def test_gc_keeps_write_acl_of_a_folder_in_the_trash(mariadb):  # noqa: F811
    admin, _ = await _add_user(mariadb, "admin")
    member, _ = await _add_user(mariadb, "member")
    now_ms = int(time.time() * 1000)
    live, trashed, expired = str(ULID()), str(ULID()), str(ULID())
    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            for seq, (node, deleted, modified) in enumerate((
                (live, 0, now_ms), (trashed, 1, now_ms), (expired, 1, now_ms - 91 * DAY_MS),
            ), start=1):
                await cur.execute(
                    "INSERT INTO vault_objects (id, object_type, payload, owner_id, version, "
                    "commit_seq, is_deleted, payload_hash, modified_at) "
                    "VALUES (%s, 'node', %s, %s, 1, %s, %s, %s, %s)",
                    (node, os.urandom(16), admin, seq, deleted, "0" * 64, modified),
                )
                await cur.execute(
                    "INSERT INTO write_acl (user_id, node_id, granted_at) VALUES (%s, %s, %s)",
                    (member, node, now_ms),
                )

    await _cleanup_tombstones(mariadb, 90)

    async with mariadb.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT id FROM vault_objects")
            ids = {row[0] for row in await cur.fetchall()}
    assert ids == {live, trashed}
    assert await _acl(mariadb) == {(member, live), (member, trashed)}
