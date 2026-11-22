"""Stored key voucher lists (goal #443, src/sezam/key_vouchers.py).

The server only keeps them: it stores a list only under the key that signed
it, and serves the lists of the account's current key. Clients check every
signature themselves; a list of an older key counts for nothing.
"""

from __future__ import annotations

import json

from ulid import ULID

try:  # the repository checkout
    from sezam import key_vouchers as core
except ImportError:  # the Docker image ships the file as key_vouchers_core.py
    from . import key_vouchers_core as core  # type: ignore[no-redef]

from .errors import INVALID_KEY_VOUCHERS, ApiError


async def store(cur, user_id: str, signing_pk: bytes, voucher_list, now_ms: int) -> None:
    """Keep ``voucher_list`` if ``signing_pk`` signed it for ``user_id``; 400 otherwise."""
    if not core.list_valid(user_id, signing_pk, voucher_list):
        raise ApiError(400, INVALID_KEY_VOUCHERS, "The key voucher list is not signed by the account's key")
    entries = core.canonical_entries(voucher_list["entries"])
    await cur.execute(
        "INSERT INTO key_vouchers (id, user_id, signing_pk, entries, signature, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (
            str(ULID()), user_id, bytes(signing_pk), json.dumps(entries, separators=(",", ":")),
            bytes.fromhex(voucher_list["signature"]), now_ms,
        ),
    )


async def lists_of(cur, user_id: str, signing_pk: bytes) -> list[dict]:
    """The lists ``signing_pk`` signed for ``user_id``, as posted."""
    await cur.execute(
        "SELECT entries, signature FROM key_vouchers WHERE user_id = %s AND signing_pk = %s ORDER BY id",
        (user_id, bytes(signing_pk)),
    )
    return [
        {"signing_pk": bytes(signing_pk).hex(), "entries": json.loads(entries), "signature": bytes(sig).hex()}
        for entries, sig in await cur.fetchall()
    ]
