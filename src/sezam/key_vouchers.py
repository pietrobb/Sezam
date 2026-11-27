"""Key vouchers: which object versions a retired identity key still vouches for.

Review e443cbc R15, goal #443 (INV-3). A rotated account's old signing key
stays in its key ring so that what it signed before the rotation still
verifies. Which objects that is was bounded by ``retired_seq`` and each
object's ``commit_seq``, both set by the server alone: a server holding a
leaked retired key could sign any object with it and serve both numbers to a
device that had not pinned a bound (a new device, a full resync, every web
session).

A voucher list names the object versions instead, as (id, version, digest),
and is signed by the account's CURRENT signing key. A retired key's signature
counts only for a listed version; lists signed by any other key (an older
current key included) count for nothing, so each rotation carries the
account's lists forward under the new key.

R17-N1 (review c02cc47): the digest is that of the whole signed message (id,
type, parent, target, tombstone flag, version, payload hash) together with the
signer's account and key (``object_entry``). It was the payload hash alone: a
server holding a leaked retired key signed a vouched version again with
another parent, as deleted or for another signer, and every client took it.

Self-contained (PyNaCl + stdlib) so that the server uses the very same file
(the Docker image ships it as server/app/key_vouchers_core.py). Web
(web/static/js/app.js) and mobile (mobile/lib/services/sync_service.dart)
build the same message and must pass tests/vectors/key_vouchers.json.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Iterable, Mapping, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

DOMAIN = b"sezam-key-vouchers-v2\x00"
ENTRY_DOMAIN = b"sezam-key-voucher-entry-v2\x00"
MAX_ENTRIES = 200_000
_ID = re.compile(r"^[0-9A-Za-z]{26}$")  # OBJECT_ID in server/app/models/schemas.py
_HASH = re.compile(r"^[0-9a-f]{64}$")

Entry = tuple[str, int, str]


def ulid_to_bytes(ulid_str: str) -> bytes:
    """Same bytes as sezam.models.ulid_to_bytes; a copy, so the image needs no sezam package (R17-N2)."""
    raw = ulid_str.encode("ascii")
    if len(raw) > 26 or b"\x00" in raw:
        raise ValueError(f"An id is at most 26 ASCII characters without NUL, not {ulid_str!r}")
    return raw.ljust(26, b"\x00")


def signed_message(
    id: str, object_type: str, parent_ref: Optional[str], target_user_id: Optional[str],
    is_deleted: int, version: int, payload_hash: str,
) -> bytes:
    """The bytes a sync object's signature covers (spec 8.2); ValueError on a
    value the fixed-width fields cannot hold exactly (R15 #428)."""
    if type(is_deleted) not in (int, bool) or is_deleted not in (0, 1):
        raise ValueError(f"is_deleted must be 0 or 1, not {is_deleted!r}")
    if type(version) is not int or not 0 <= version <= 0xFFFFFFFF:
        raise ValueError(f"version must fit a u32, not {version!r}")
    ot = object_type.encode("utf-8")
    return (
        ulid_to_bytes(id)
        + struct.pack("B", len(ot)) + ot
        + (ulid_to_bytes(parent_ref) if parent_ref else b"\x00" * 26)
        + (ulid_to_bytes(target_user_id) if target_user_id else b"\x00" * 26)
        + struct.pack("B", is_deleted)
        + struct.pack(">I", version)
        + bytes.fromhex(payload_hash)
    )


def entry_digest(signer_id: str, signing_pk: bytes, message: bytes) -> str:
    """The digest a voucher entry names: the signed message, its signer's
    account and the key that signed it (R17-N1)."""
    if len(bytes(signing_pk)) != 32:
        raise ValueError("A signing key is 32 bytes")
    return hashlib.sha256(
        ENTRY_DOMAIN + ulid_to_bytes(signer_id) + bytes(signing_pk) + bytes(message)
    ).hexdigest()


def object_entry(obj: Mapping, signer_id: str, signing_pk: bytes) -> Optional[Entry]:
    """(id, version, digest) of a served sync object as ``signing_pk`` of
    ``signer_id`` signed it, or None when its fields are malformed."""
    try:
        version = obj.get("version", 1)
        payload_hash = obj["payload_hash"]
        message = signed_message(
            obj["id"], obj["object_type"], obj.get("parent_ref"), obj.get("target_user_id"),
            obj.get("is_deleted", 0), version, payload_hash.lower(),
        )
        return (obj["id"], version, entry_digest(signer_id, signing_pk, message))
    except (KeyError, ValueError, TypeError, AttributeError):
        return None


def canonical_entries(entries: Iterable) -> list[Entry]:
    """Sorted, de-duplicated (id, version, digest); ValueError on any malformed one."""
    out: set[Entry] = set()
    for entry in entries:
        if not isinstance(entry, (list, tuple)) or len(entry) != 3:
            raise ValueError("A voucher entry is [id, version, digest]")
        obj_id, version, payload_hash = entry
        if not isinstance(obj_id, str) or not _ID.match(obj_id):
            raise ValueError("A voucher entry needs a 26-character object id")
        if isinstance(version, bool) or not isinstance(version, int) or not 0 <= version < 2 ** 64:
            raise ValueError("A voucher entry needs an unsigned 64-bit version")
        if not isinstance(payload_hash, str) or not _HASH.match(payload_hash):
            raise ValueError("A voucher entry needs a lowercase hex SHA-256 digest")
        out.add((obj_id, version, payload_hash))
    if len(out) > MAX_ENTRIES:
        raise ValueError("Too many voucher entries")
    return sorted(out)


def voucher_message(user_id: str, signing_pk: bytes, entries: Iterable) -> bytes:
    """Bytes the account's current key signs for a voucher list."""
    if len(bytes(signing_pk)) != 32:
        raise ValueError("A voucher signing key is 32 bytes")
    items = canonical_entries(entries)
    return (
        DOMAIN
        + ulid_to_bytes(user_id)
        + bytes(signing_pk)
        + len(items).to_bytes(4, "big")
        + b"".join(
            obj_id.encode("ascii") + version.to_bytes(8, "big") + bytes.fromhex(payload_hash)
            for obj_id, version, payload_hash in items
        )
    )


def sign_vouchers(user_id: str, signing_key: SigningKey, entries: Iterable) -> dict:
    """A voucher list as posted: {signing_pk, entries, signature} (hex)."""
    signing_pk = bytes(signing_key.verify_key)
    items = canonical_entries(entries)
    return {
        "signing_pk": signing_pk.hex(),
        "entries": [list(item) for item in items],
        "signature": signing_key.sign(voucher_message(user_id, signing_pk, items)).signature.hex(),
    }


def list_valid(user_id: str, signing_pk: bytes, voucher_list) -> bool:
    """Is ``voucher_list`` signed by ``signing_pk`` for ``user_id``?"""
    if not isinstance(voucher_list, dict):
        return False
    try:
        if bytes.fromhex(voucher_list.get("signing_pk") or "") != bytes(signing_pk):
            return False
        message = voucher_message(user_id, signing_pk, voucher_list.get("entries") or [])
        VerifyKey(bytes(signing_pk)).verify(message, bytes.fromhex(voucher_list.get("signature") or ""))
    except (BadSignatureError, ValueError, TypeError, AttributeError):
        return False
    return True


def vouched(user_id: str, current_signing_pk: bytes, lists) -> frozenset[Entry]:
    """Every (id, version, digest) a list signed by the current key names.

    A list signed by another key, for another account, or not verifying
    vouches for nothing.
    """
    out: set[Entry] = set()
    for voucher_list in lists if isinstance(lists, list) else []:
        if list_valid(user_id, current_signing_pk, voucher_list):
            out.update(canonical_entries(voucher_list["entries"]))
    return frozenset(out)
