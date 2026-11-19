"""Bitwarden JSON import.

Spec 10.1: Import from Bitwarden JSON export format.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import import_entry
# '/' nests folders as in Bitwarden; '\/' is a slash inside a name, as Sezam
# exports it (review d150605 N9).
from .csv_import import _ensure_folder_path


def import_bitwarden(
    vault,
    source: str | Path,
    tier: int | None = None,
    conflict_mode: str = "duplicate",
) -> int:
    """Import entries from a Bitwarden JSON export.

    Returns number of entries imported. Bitwarden writes JSON null for
    absent values (folderId, uris, fields, notes, ...), so every lookup
    falls back on ``or`` instead of a ``get`` default.
    """
    with open(source, encoding="utf-8") as f:
        data = json.load(f)

    # Build folder lookup
    folders: dict[str | None, str] = {}
    for folder in data.get("folders") or []:
        folders[folder.get("id")] = folder.get("name") or ""

    count = 0
    claimed: set[str] = set()
    for item in data.get("items") or []:
        item_type = item.get("type") or 1
        if item_type != 1:  # Only login items
            continue

        name = item.get("name") or "Untitled"
        folder_id = item.get("folderId")
        folder_name = folders.get(folder_id, "")

        login = item.get("login") or {}
        fields = []
        sort_order = 0

        if login.get("username"):
            fields.append({
                "key": "username",
                "value": login["username"],
                "sensitive": False,
                "sort_order": sort_order,
            })
            sort_order += 1

        if login.get("password"):
            fields.append({
                "key": "password",
                "value": login["password"],
                "sensitive": True,
                "sort_order": sort_order,
            })
            sort_order += 1

        # URIs
        for uri_entry in login.get("uris") or []:
            uri = (uri_entry or {}).get("uri") or ""
            if uri:
                fields.append({
                    "key": "url",
                    "value": uri,
                    "sensitive": False,
                    "sort_order": sort_order,
                })
                sort_order += 1
                break  # Only first URI

        # TOTP
        if login.get("totp"):
            fields.append({
                "key": "totp_secret",
                "value": login["totp"],
                "sensitive": True,
                "sort_order": sort_order,
                "field_type": "totp",
            })
            sort_order += 1

        if item.get("notes"):
            fields.append({
                "key": "notes",
                "value": item["notes"],
                "sensitive": False,
                "sort_order": sort_order,
            })
            sort_order += 1

        # Custom fields
        for custom_field in item.get("fields") or []:
            f_name = custom_field.get("name") or "field"
            f_value = custom_field.get("value")
            f_type = custom_field.get("type") or 0  # 0=text, 1=hidden, 2=boolean

            fields.append({
                "key": f_name,
                "value": "" if f_value is None else str(f_value),
                "sensitive": f_type == 1,
                "sort_order": sort_order,
            })
            sort_order += 1

        # Review d150605 N9: an item without fields was dropped; Sezam
        # exports an entry without fields as one, so it came back missing.
        node_id = _ensure_folder_path(vault, folder_name)
        if import_entry(vault, node_id, name, fields, tier, conflict_mode, claimed=claimed):
            count += 1

    return count
