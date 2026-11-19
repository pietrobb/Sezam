"""Review d615826 (server): IP limiters must not deadlock under concurrency.

Runs against a real MariaDB (SEZAM_TEST_MARIADB, see
tests/test_review2_server_mariadb.py); skipped without it.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time

import pytest
from ulid import ULID

pytest.importorskip("aiomysql")

from server.app.models.schemas import SyncObject  # noqa: E402
from server.app.routers.share import _reserve_pin_attempt  # noqa: E402
from tests.test_review2_server_mariadb import _add_user, _push, mariadb  # noqa: E402,F401


@pytest.mark.asyncio
async def test_parallel_pin_reservations_of_one_ip_never_deadlock(mariadb):  # noqa: F811
    ip_hmac = os.urandom(32).hex()
    now_ms = int(time.time() * 1000)
    for _round in range(5):
        results = await asyncio.gather(
            *(_reserve_pin_attempt(mariadb, ip_hmac, now_ms) for _ in range(8)),
            return_exceptions=True,
        )
        assert not [r for r in results if isinstance(r, BaseException)]
        ip_hmac = os.urandom(32).hex()


def _signed_for(sk, obj_id: str, object_type: str, target_user_id: str | None) -> SyncObject:
    payload = os.urandom(48)
    payload_hash = hashlib.sha256(payload).hexdigest()
    ot = object_type.encode()
    target = target_user_id.encode().ljust(26, b"\x00") if target_user_id else b"\x00" * 26
    canonical = (
        obj_id.encode().ljust(26, b"\x00") + bytes([len(ot)]) + ot
        + b"\x00" * 26 + target + bytes([0]) + (1).to_bytes(4, "big")
        + bytes.fromhex(payload_hash)
    )
    return SyncObject(
        id=obj_id, object_type=object_type, payload=base64.b64encode(payload).decode(),
        version=1, payload_hash=payload_hash, target_user_id=target_user_id,
        signature=sk.sign(canonical).signature.hex(),
    )


@pytest.mark.asyncio
async def test_unknown_target_user_is_one_conflict_not_a_failed_push(mariadb):  # noqa: F811
    user_id, sk = await _add_user(mariadb, "fk")
    good = _signed_for(sk, str(ULID()), "entry", None)
    orphan = _signed_for(sk, str(ULID()), "entry", str(ULID()))

    result = await _push(mariadb, user_id, [good, orphan])

    assert [a.id for a in result.accepted] == [good.id]
    assert [c.id for c in result.conflicts] == [orphan.id]
