"""Stored key voucher lists (goal #443, src/sezam/key_vouchers.py).

The server only keeps them: it stores a list only under the key that signed
it, and serves the lists of the account's current key. Clients check every
signature themselves; a list of an older key counts for nothing.

R17-N10 (review c02cc47): nothing bounded them. A JWT alone posted the same
list again and again (hundreds of MiB stored), and one GET read and decoded
them all on the event loop (tens of seconds, the worker blocked). A list is
kept once (UNIQUE user, key, signature: a list sent again is the stored one),
a key holds at most MAX_LISTS_PER_KEY lists and MAX_BYTES_PER_KEY of entries,
the signature is checked and the lists decoded off the event loop (for a
rotation before the push's global lock), and the GET is paged.
"""

from __future__ import annotations

import asyncio
import json

from ulid import ULID

try:  # the repository checkout
    from sezam import key_vouchers as core
except ImportError:  # the Docker image ships the file as key_vouchers_core.py
    from . import key_vouchers_core as core  # type: ignore[no-redef]

from .errors import INVALID_KEY_VOUCHERS, KEY_VOUCHERS_FULL, ApiError

MAX_LISTS_PER_KEY = core.MAX_LISTS_PER_KEY
MAX_BYTES_PER_KEY = 32 * 1024 * 1024
PAGE_BYTES = 4 * 1024 * 1024


def check(user_id: str, signing_pk: bytes, voucher_list: dict) -> tuple[dict, list]:
    """(the list, its canonical entries) if ``signing_pk`` signed it for
    ``user_id``; 400 otherwise. CPU-bound: run it off the event loop."""
    if not core.list_valid(user_id, signing_pk, voucher_list):
        raise ApiError(400, INVALID_KEY_VOUCHERS, "The key voucher list is not signed by the account's key")
    return voucher_list, core.canonical_entries(voucher_list["entries"])


async def checked(user_id: str, signing_pk: bytes, voucher_lists: list[dict]) -> list[tuple[dict, list]]:
    """``check`` of every list, in a worker thread."""
    return await asyncio.to_thread(lambda: [check(user_id, signing_pk, vl) for vl in voucher_lists])


async def store(cur, user_id: str, signing_pk: bytes, checked_list: tuple[dict, list], now_ms: int) -> None:
    """Keep a list ``check`` passed; the same list again is the stored one (413 when the key is full)."""
    voucher_list, entries = checked_list
    signature = bytes.fromhex(voucher_list["signature"])
    text = json.dumps(entries, separators=(",", ":"))
    await cur.execute(
        "SELECT 1 FROM key_vouchers WHERE user_id = %s AND signing_pk = %s AND signature = %s",
        (user_id, bytes(signing_pk), signature),
    )
    if await cur.fetchone():
        return
    await cur.execute(
        "SELECT LENGTH(entries) FROM key_vouchers WHERE user_id = %s AND signing_pk = %s",
        (user_id, bytes(signing_pk)),
    )
    lengths = [int(row[0]) for row in await cur.fetchall()]
    count, size = len(lengths), sum(lengths)
    if count >= MAX_LISTS_PER_KEY or size + len(text) > MAX_BYTES_PER_KEY:
        raise ApiError(
            413, KEY_VOUCHERS_FULL,
            f"The key holds {count} voucher lists ({size} bytes); at most {MAX_LISTS_PER_KEY} "
            f"and {MAX_BYTES_PER_KEY} bytes",
        )
    await cur.execute(
        "INSERT IGNORE INTO key_vouchers (id, user_id, signing_pk, entries, signature, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (str(ULID()), user_id, bytes(signing_pk), text, signature, now_ms),
    )


async def lists_of(cur, user_id: str, signing_pk: bytes, after: str = "") -> tuple[list[dict], str]:
    """A page of the lists ``signing_pk`` signed for ``user_id``, as posted,
    from the list after id ``after``; and the id to ask after next ("" at the end)."""
    await cur.execute(
        "SELECT id, LENGTH(entries) FROM key_vouchers WHERE user_id = %s AND signing_pk = %s AND id > %s "
        "ORDER BY id",
        (user_id, bytes(signing_pk), after),
    )
    ids, size = [], 0
    rows = await cur.fetchall()
    for list_id, length in rows:
        if ids and size + int(length) > PAGE_BYTES:
            break
        ids.append(list_id)
        size += int(length)
    if not ids:
        return [], ""
    await cur.execute(
        "SELECT entries, signature FROM key_vouchers WHERE user_id = %s AND signing_pk = %s "
        "AND id > %s AND id <= %s ORDER BY id",
        (user_id, bytes(signing_pk), after, ids[-1]),
    )
    stored = await cur.fetchall()
    pk_hex = bytes(signing_pk).hex()
    lists = await asyncio.to_thread(lambda: [
        {"signing_pk": pk_hex, "entries": json.loads(entries), "signature": bytes(sig).hex()}
        for entries, sig in stored
    ])
    return lists, (ids[-1] if len(ids) < len(rows) else "")
