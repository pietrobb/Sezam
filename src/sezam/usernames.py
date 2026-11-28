"""Account name as every client sends it (review 688edcb N3): trimmed of the
union of what Python, JS and Dart trim and NFC, so one visible name is one
account on every device. The core's rule (docs/CORE_UNIFICATION.md U6); the
server and the reseed signature use the same bytes.
"""

from __future__ import annotations



def normalize_username(value: str) -> str:
    from .vault import sync_core

    return sync_core.call("normalize_username", value=value)
