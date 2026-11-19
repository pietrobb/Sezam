"""Account name as every client sends it (review 688edcb N3).

Trimmed of the union of what Python, JS and Dart trim (NBSP, BOM, NEL,
\\x1c-\\x1f, zero-width space) and NFC, so one visible name is one account on
every device. Must equal server.app.models.schemas.normalize_username, the
reseed signature covers these bytes.
"""

from __future__ import annotations

import re
import unicodedata

_EDGE = re.compile(r"^[\s\ufeff\u200b\x1c-\x1f\x85]+|[\s\ufeff\u200b\x1c-\x1f\x85]+$")


def normalize_username(value: str) -> str:
    return _EDGE.sub("", unicodedata.normalize("NFC", value))
