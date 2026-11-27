"""Key vouchers: which object versions a retired identity key still vouches for.

Review e443cbc R15, goal #443 (INV-3). A rotated account's old signing key
stays in its key ring so that what it signed before the rotation still
verifies. A voucher list names the object versions it vouches for as (id,
version, digest), signed by the account's CURRENT signing key; a retired key's
signature counts only for a listed version (R17-N1: the digest covers the whole
signed message, its signer's account and key).

The rules and every byte are the Rust core's (core/src/vouchers.rs, the same
copy the web and the phone use; docs/CORE_UNIFICATION.md U5). This file is
the desktop's and the server's door to it: it only verifies the Ed25519
signatures the core names, with PyNaCl. Self-contained (PyNaCl, stdlib and the
core) so that the server uses the very same file (the Docker image ships it as
server/app/key_vouchers_core.py).
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping, Optional

import sezam_sync_core
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

DOMAIN = b"sezam-key-vouchers-v2\x00"
MAX_ENTRIES = 200_000
# R17-N10: the server keeps at most this many lists per key and serves at
# least one per page, so a client reads at most this many pages.
MAX_LISTS_PER_KEY = 64
MAX_PAGES = MAX_LISTS_PER_KEY
MAX_VERSION = 2 ** 53 - 1

Entry = tuple[str, int, str]
# R17-N1 (S4 style): every field a sync object's signature covers, in
# signed_message order (tests/vectors/signed_fields.json).
SIGNED_FIELDS = ("id", "object_type", "parent_ref", "target_user_id", "is_deleted", "version", "payload_hash")


def _call(op: str, **arguments: Any) -> Any:
    out = json.loads(sezam_sync_core.call(op, json.dumps(arguments)))
    if "error" in out:
        raise ValueError(f"sync core {op}: {out['error']}")
    return out["ok"]


def _entries(items: list) -> list[Entry]:
    return [(obj_id, version, digest) for obj_id, version, digest in items]


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
    obj = {
        "id": id, "object_type": object_type, "parent_ref": parent_ref, "target_user_id": target_user_id,
        "is_deleted": is_deleted, "version": version, "payload_hash": payload_hash,
    }
    return bytes.fromhex(_call("key_voucher_signed_message", object=obj))


def object_entry(obj: Mapping, signer_id: str, signing_pk: bytes) -> Optional[Entry]:
    """(id, version, digest) of a served sync object as ``signing_pk`` of
    ``signer_id`` signed it, or None when its fields are malformed."""
    try:
        signed = {name: obj[name] for name in SIGNED_FIELDS if name in obj}
        out = _call(
            "key_voucher_object_entry", object=signed, signer_id=signer_id, signing_pk=bytes(signing_pk).hex(),
        )
    except (ValueError, TypeError, AttributeError):
        return None
    return None if out is None else (out[0], out[1], out[2])


def canonical_entries(entries: Iterable) -> list[Entry]:
    """Sorted, de-duplicated (id, version, digest); ValueError on any malformed one."""
    return _entries(_call("key_voucher_canonical", entries=[list(e) if isinstance(e, tuple) else e for e in entries]))


def voucher_message(user_id: str, signing_pk: bytes, entries: Iterable) -> bytes:
    """Bytes the account's current key signs for a voucher list."""
    return bytes.fromhex(_voucher(user_id, signing_pk, entries)["message"])


def _voucher(user_id: str, signing_pk: bytes, entries: Iterable) -> dict:
    if len(bytes(signing_pk)) != 32:
        raise ValueError("A voucher signing key is 32 bytes")
    return _call(
        "key_voucher_message", user_id=user_id, signing_pk=bytes(signing_pk).hex(),
        entries=[list(e) if isinstance(e, tuple) else e for e in entries],
    )


def sign_vouchers(user_id: str, signing_key: SigningKey, entries: Iterable) -> dict:
    """A voucher list as posted: {signing_pk, entries, signature} (hex)."""
    signing_pk = bytes(signing_key.verify_key)
    out = _voucher(user_id, signing_pk, entries)
    return {
        "signing_pk": signing_pk.hex(),
        "entries": out["entries"],
        "signature": signing_key.sign(bytes.fromhex(out["message"])).signature.hex(),
    }


def _verified(user_id: str, signing_pk: bytes, lists: Any) -> list[bool]:
    checks = _call("key_voucher_lists", user_id=user_id, current_signing_pk=bytes(signing_pk).hex(), lists=lists)
    out = []
    for check in checks:
        try:
            VerifyKey(bytes(signing_pk)).verify(bytes.fromhex(check["message"]), bytes.fromhex(check["signature"]))
            out.append(True)
        except (BadSignatureError, TypeError, ValueError):
            out.append(False)
    return out


def list_valid(user_id: str, signing_pk: bytes, voucher_list) -> bool:
    """Is ``voucher_list`` signed by ``signing_pk`` for ``user_id``?"""
    try:
        return _verified(user_id, signing_pk, [voucher_list]) == [True]
    except (ValueError, TypeError):
        return False


def vouched(user_id: str, current_signing_pk: bytes, lists) -> frozenset[Entry]:
    """Every (id, version, digest) a list signed by the current key names.

    A list signed by another key, for another account, or not verifying
    vouches for nothing.
    """
    try:
        verified = _verified(user_id, current_signing_pk, lists)
        out = _call(
            "key_voucher_vouched", user_id=user_id, current_signing_pk=bytes(current_signing_pk).hex(),
            lists=lists, verified=verified,
        )
    except (ValueError, TypeError):
        return frozenset()
    return frozenset(_entries(out))
