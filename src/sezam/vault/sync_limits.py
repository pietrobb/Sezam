"""What one POST /api/sync may carry (review 526419e #1).

Must stay within server.app.models.schemas: MAX_SYNC_OBJECTS objects,
MAX_SYNC_PAYLOAD_BYTES per decoded payload and MAX_REQUEST_BODY_BYTES per
request. A push over any of them was refused with 422 as a whole, every time.
"""

from __future__ import annotations

import json

MAX_OBJECT_PAYLOAD_BYTES = 1024 * 1024
# server.app.models.schemas MAX_STAGED_*: one all-or-nothing unit sent in parts
# (review d150605 #3), minus the same room for the request's own fields.
MAX_STAGED_OBJECTS = 100_000
MAX_STAGED_BYTES = 255 * 1024 * 1024
# The JSON fields around one payload (id, hashes, signature, refs).
_OBJECT_JSON_OVERHEAD = 700


class SyncUnitTooLarge(RuntimeError, ValueError):
    """An all-or-nothing unit (or one object) the server can never take.

    A RuntimeError where a push fails, a ValueError where a change is refused.
    """


def payload_too_large(payload_len: int) -> bool:
    return payload_len > MAX_OBJECT_PAYLOAD_BYTES


def estimated_object_bytes(payload_len: int) -> int:
    """JSON size of a sync object whose decoded payload has payload_len bytes."""
    return 4 * ((payload_len + 2) // 3) + _OBJECT_JSON_OVERHEAD


def object_json_bytes(obj: dict) -> int:
    return len(json.dumps(obj)) + 2


def require_fits_atomic_unit(count: int, total_bytes: int, what: str) -> None:
    """An all-or-nothing unit goes staged in parts (review d150605 #3), up to
    the server's staging limits."""
    if count > MAX_STAGED_OBJECTS or total_bytes > MAX_STAGED_BYTES:
        raise SyncUnitTooLarge(
            f"{what} has to reach the server as one unit, but it is {count} "
            f"objects / {total_bytes // 1024} KiB and the server takes at most "
            f"{MAX_STAGED_OBJECTS} objects / {MAX_STAGED_BYTES // (1024 * 1024)} MiB "
            "in one unit."
        )


def split_for_push(objects: list[dict]) -> list[list[dict]]:
    """Consecutive chunks within the server's per-request limits, order kept
    (the core's rule, docs/CORE_UNIFICATION.md U6)."""
    from . import sync_core

    chunks, start = [], 0
    for count in sync_core.call("split_for_push", sizes=[object_json_bytes(o) for o in objects]):
        chunks.append(objects[start:start + count])
        start += count
    return chunks
