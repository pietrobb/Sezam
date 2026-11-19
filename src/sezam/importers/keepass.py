"""KeePass .kdbx import.

Spec 10.1: Import via pykeepass library.
Requires: pip install pykeepass
"""

from __future__ import annotations

import getpass
from pathlib import Path

from . import import_entry


def import_keepass(
    vault,
    source: str | Path,
    password: str | None = None,
    tier: int | None = None,
    conflict_mode: str = "duplicate",
) -> int:
    """Import entries from a KeePass .kdbx file.

    Returns number of entries imported.
    """
    try:
        from pykeepass import PyKeePass
    except ImportError:
        raise ImportError(
            "pykeepass is required for KeePass import. "
            "Install it with: pip install pykeepass"
        )

    if password is None:
        password = getpass.getpass("KeePass master password: ")

    kp = PyKeePass(str(source), password=password)
    return _import_database(vault, kp, tier, conflict_mode)


def _import_database(vault, kp, tier: int | None, conflict_mode: str) -> int:
    count = 0
    claimed: set[str] = set()
    recycle_bin = getattr(kp, "recyclebin_group", None)

    for entry in kp.entries:
        if entry.title is None:
            continue
        # Deleted entries live on in the recycle bin; they are not live data.
        if recycle_bin is not None and _in_group(entry.group, recycle_bin):
            continue

        # Build folder path from KeePass group hierarchy
        group_path = _group_to_path(entry.group)

        fields = []
        sort_order = 0

        if entry.username:
            fields.append({
                "key": "username",
                "value": entry.username,
                "sensitive": False,
                "sort_order": sort_order,
            })
            sort_order += 1

        if entry.password:
            fields.append({
                "key": "password",
                "value": entry.password,
                "sensitive": True,
                "sort_order": sort_order,
            })
            sort_order += 1

        if entry.url:
            fields.append({
                "key": "url",
                "value": entry.url,
                "sensitive": False,
                "sort_order": sort_order,
            })
            sort_order += 1

        if entry.notes:
            fields.append({
                "key": "notes",
                "value": entry.notes,
                "sensitive": False,
                "sort_order": sort_order,
            })
            sort_order += 1

        custom = dict(entry.custom_properties or {})
        totp = _extract_totp(entry, custom)
        if totp:
            fields.append({
                "key": "totp_secret",
                "value": totp,
                "sensitive": True,
                "field_type": "totp",
                "sort_order": sort_order,
            })
            sort_order += 1

        # Custom fields
        for key, value in custom.items():
            if key.startswith("_"):
                continue
            fields.append({
                "key": key,
                "value": value or "",
                "sensitive": True,
                "sort_order": sort_order,
            })
            sort_order += 1

        if not fields:
            continue

        # Ensure folder exists
        node_id = _ensure_folder_path(vault, group_path)
        if import_entry(
            vault, node_id, entry.title, fields, tier, conflict_mode, claimed=claimed
        ):
            count += 1

    return count


def _in_group(group, ancestor) -> bool:
    current = group
    while current is not None:
        if current is ancestor or (
            getattr(current, "uuid", None) is not None
            and getattr(current, "uuid", None) == getattr(ancestor, "uuid", None)
        ):
            return True
        current = current.parentgroup
    return False


_TIMEOTP_PREFIX = "TimeOtp-"
_LEGACY_TOTP_KEYS = ("totp", "otp", "totp_secret", "TOTP Seed")


def _extract_totp(entry, custom: dict) -> str | None:
    """TOTP of a KeePass entry as a raw base32 seed or otpauth:// URI.

    Pops the consumed keys from ``custom``. pykeepass reserves the KeePassXC
    ``otp`` string (otpauth URI), so it never shows up in custom_properties;
    KeePass 2.47+ stores its native TOTP as ``TimeOtp-*`` strings.
    """
    otp = getattr(entry, "otp", None)
    if otp:
        return otp

    for key in list(custom):
        if key.lower() in {k.lower() for k in _LEGACY_TOTP_KEYS}:
            value = custom.pop(key)
            if value:
                return value

    native = {k[len(_TIMEOTP_PREFIX):]: custom.pop(k) for k in list(custom) if k.startswith(_TIMEOTP_PREFIX)}
    secret = _native_secret_base32(native)
    if not secret:
        return None
    from urllib.parse import quote, urlencode

    params = {"secret": secret}
    if native.get("Period"):
        params["period"] = native["Period"]
    if native.get("Length"):
        params["digits"] = native["Length"]
    # KeePass writes HMAC-SHA-1 / HMAC-SHA-256 / HMAC-SHA-512.
    algorithm = (native.get("Algorithm") or "").upper().replace("HMAC-", "").replace("-", "")
    if algorithm:
        params["algorithm"] = algorithm
    label = quote(entry.title or "Sezam", safe="")
    return f"otpauth://totp/{label}?{urlencode(params)}"


def _native_secret_base32(native: dict) -> str | None:
    """KeePass stores the seed as exactly one of four encodings."""
    import base64

    if native.get("Secret-Base32"):
        return native["Secret-Base32"].replace(" ", "").upper().rstrip("=")
    if native.get("Secret-Hex"):
        raw = bytes.fromhex(native["Secret-Hex"].replace(" ", ""))
    elif native.get("Secret-Base64"):
        raw = base64.b64decode(native["Secret-Base64"])
    elif native.get("Secret"):
        raw = native["Secret"].encode("utf-8")
    else:
        return None
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _group_to_path(group) -> str:
    """Convert KeePass group to folder path."""
    parts = []
    current = group
    while current and current.name:
        if current.name not in ("Root", "root", ""):
            parts.append(current.name)
        current = current.parentgroup
    parts.reverse()
    return "/".join(parts)


def _ensure_folder_path(vault, folder_path: str) -> str:
    """Create folder hierarchy if needed."""
    if not folder_path:
        return vault.db.get_meta("root_node_id")

    parts = [p for p in folder_path.split("/") if p]
    current_node = vault.db.get_meta("root_node_id")

    for part in parts:
        children = vault.list_nodes(current_node)
        found = None
        for child in children:
            if child["name"].lower() == part.lower():
                found = child["id"]
                break
        if found is None:
            found = vault.create_node(part, current_node)
        current_node = found

    return current_node
