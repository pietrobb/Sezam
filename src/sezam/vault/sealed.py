"""Opening a sync object's blob at the version it is sealed at.

A live row's blobs are sealed at the row version. A delete only bumps the
row version: a tombstone's blobs stay sealed one version below it, or more
after other clients' bumps. Trash restore, conflict resolution and dropping
a re-key all read tombstones; each had its own copy of this rule and one
drifted (review d150605 #2).
"""

from __future__ import annotations

from nacl.exceptions import CryptoError

from ..crypto.aead import BlobKind, decrypt
from ..models import ulid_to_bytes

MAX_VERSION_TRIES = 256


def sealed_version_candidates(version: int, deleted: bool) -> list[int]:
    """Versions a blob of a row at ``version`` may be sealed at, likeliest first."""
    if not deleted:
        return [version]
    tries = [version - 1, version] + list(
        range(version - 2, max(-1, version - MAX_VERSION_TRIES), -1)
    )
    return [v for v in tries if v >= 0]


def open_sealed(
    blob: bytes, dek: bytes, object_id: str, version: int, kind: BlobKind, *, deleted: bool
) -> tuple[bytes, int]:
    """Plaintext of ``blob`` and the version it is sealed at.

    Raises CryptoError when no candidate version opens it.
    """
    blob = bytes(blob)
    raw_id = ulid_to_bytes(object_id)
    for candidate in sealed_version_candidates(version, deleted):
        try:
            return decrypt(blob, dek, raw_id, candidate, expected_blob_kind=kind), candidate
        except (CryptoError, ValueError):
            continue
    raise CryptoError(f"{object_id} does not open at version {version} or below")
