"""CSV import for Sezam vault.

Spec 10.1 CSV format:
  folder,name,field_key,field_value,sensitive,tier
  servers/hetzner,SSH Access,host,192.168.1.1,false,0
  servers/hetzner,SSH Access,password,tajne123,true,0

Optional columns: ``entry`` (tells same-named entries apart) and
``field_type`` (e.g. ``totp``).
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from ..securefile import csv_unescape
from . import import_entry

_VALID_TIERS = {"0", "1", "2"}


def split_folder_path(path: str) -> list[str]:
    """Folder names of a CSV folder path (review 526419e N1).

    '/' separates folders; '\\/' and '\\\\' are a slash and a backslash inside a
    name. Any other backslash is literal, so older files read as before.
    """
    parts: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(path):
        char = path[i]
        if char == "\\" and i + 1 < len(path) and path[i + 1] in "/\\":
            current.append(path[i + 1])
            i += 2
            continue
        if char == "/":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    return [part for part in parts if part]


def join_folder_path(parts) -> str:
    """The inverse of split_folder_path."""
    return "/".join(part.replace("\\", "\\\\").replace("/", "\\/") for part in parts)


def import_csv(
    vault,
    source: str | Path,
    tier: int | None = None,
    conflict_mode: str = "duplicate",
) -> int:
    """Import entries from a Sezam-format CSV file.

    Groups rows into entries (see read_csv_entries).
    Returns number of entries imported.
    """
    count = 0
    claimed: set[str] = set()
    for item in read_csv_entries(source):
        # Resolve or create folder path
        node_id = _ensure_folder_path(vault, item["folder"])
        entry_tier = item["tier"] if item["tier"] is not None else tier
        if import_entry(
            vault, node_id, item["name"], item["fields"], entry_tier, conflict_mode,
            claimed=claimed,
        ):
            count += 1

    return count


def read_csv_entries(source: str | Path) -> list[dict]:
    """Rows grouped into entries: {folder, name, fields, tier}, in file order.

    Rows of one (folder, name) form one entry. Two entries with the same
    name in one folder (lockout review M3) are told apart by the optional
    ``entry`` column that ``sezam export --format csv`` writes; without it,
    a field key that repeats starts the next entry of that name.
    """
    entries: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    tiers: dict[tuple[str, str, str], int | None] = {}
    occurrence: dict[tuple[str, str], int] = defaultdict(int)

    with open(source, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        has_entry_column = "entry" in (reader.fieldnames or [])
        for line, row in enumerate(reader, start=2):
            folder = join_folder_path(split_folder_path(csv_unescape(row.get("folder") or "")))
            name = csv_unescape(row.get("name") or "").strip()
            field_key = csv_unescape(row.get("field_key") or "").strip()
            field_value = csv_unescape(row.get("field_value") or "")
            field_type = csv_unescape(row.get("field_type") or "").strip() or None
            sensitive = (row.get("sensitive") or "false").lower() in ("true", "1", "yes")
            tier_str = (row.get("tier") or "").strip()
            if tier_str and tier_str not in _VALID_TIERS:
                # A typo must not silently drop a secret to tier 0/inherit,
                # nor create a tier nothing else understands.
                raise ValueError(f"Line {line}: invalid tier {tier_str!r} (expected 0, 1 or 2)")
            row_tier = int(tier_str) if tier_str else None

            if not name:
                continue

            if has_entry_column:
                key = (folder, name, (row.get("entry") or "").strip())
            else:
                key = (folder, name, str(occurrence[(folder, name)]))
                if field_key and any(f["key"] == field_key for f in entries.get(key, ())):
                    occurrence[(folder, name)] += 1
                    key = (folder, name, str(occurrence[(folder, name)]))
            fields = entries[key]  # a row without field_key is an entry without fields
            if field_key:
                field = {
                    "key": field_key,
                    "value": field_value,
                    "sensitive": sensitive,
                    "sort_order": len(fields),
                }
                if field_type:
                    field["field_type"] = field_type
                fields.append(field)
            if row_tier is not None:
                tiers[key] = row_tier

    return [
        {"folder": folder, "name": name, "fields": fields, "tier": tiers.get((folder, name, tag))}
        for (folder, name, tag), fields in entries.items()
    ]


def _ensure_folder_path(vault, folder_path: str) -> str:
    """Create folder hierarchy if needed, return leaf node ID."""
    if not folder_path:
        return vault.db.get_meta("root_node_id")

    parts = split_folder_path(folder_path)
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
