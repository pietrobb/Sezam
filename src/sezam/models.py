"""Data models for Sezam vault objects."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ulid import ULID


def new_ulid() -> str:
    """Generate a new ULID as a 26-char string."""
    return str(ULID())


def ulid_to_bytes(ulid_str: str) -> bytes:
    """Encode a 26-char ULID string as 26 ASCII bytes for AAD/envelope headers.

    Spec §2.6 defines dek_id/object_id as 26 bytes = the ULID canonical string.
    Web (TextEncoder over the 26-char string) and mobile (utf8 of the string)
    both encode this way, so the desktop client must match them byte-for-byte or
    cross-client Poly1305 verification fails. Shorter ids are right-padded with
    NUL to a fixed 26 bytes, matching JS `padEnd(26,'\\0')` / Dart `padRight(26)`.
    """
    return ulid_str.encode("ascii").ljust(26, b"\x00")[:26]


def bytes_to_ulid(data: bytes) -> str:
    """Decode 26 ASCII bytes (NUL-padded) back to the ULID string."""
    return data.rstrip(b"\x00").decode("ascii")


@dataclass
class NodeMeta:
    """Decrypted content of nodes.encrypted_meta."""

    name: str
    tier: Optional[int] = None  # None = inherit from parent
    sync_flag: str = "clean"
    created_at: int = 0  # Unix ms
    modified_at: int = 0  # Unix ms
    ai_read_secret: Optional[bool] = None  # Per-folder AI secret read permission
    personal: bool = False  # Personal root: meta under its own DEK (web marker)

    def __post_init__(self):
        now = int(time.time() * 1000)
        if self.created_at == 0:
            self.created_at = now
        if self.modified_at == 0:
            self.modified_at = now

    def to_json(self) -> bytes:
        d: dict[str, Any] = {
            "name": self.name,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }
        if self.tier is not None:
            d["tier"] = self.tier
        if self.sync_flag != "clean":
            d["sync_flag"] = self.sync_flag
        if self.ai_read_secret is not None:
            d["ai_read_secret"] = self.ai_read_secret
        if self.personal:
            d["personal"] = True
        return json.dumps(d, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> NodeMeta:
        d = json.loads(data)
        return cls(
            name=d["name"],
            tier=d.get("tier"),
            sync_flag=d.get("sync_flag", "clean"),
            created_at=d.get("created_at", 0),
            modified_at=d.get("modified_at", 0),
            ai_read_secret=d.get("ai_read_secret"),
            personal=d.get("personal") is True,
        )


@dataclass
class EntryField:
    """A single field within an entry."""

    key: str
    value: str
    sensitive: bool = False
    sort_order: int = 0
    field_type: Optional[str] = None  # e.g. "totp" for TOTP seeds

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "sensitive": self.sensitive,
            "sort_order": self.sort_order,
        }
        if self.field_type:
            d["field_type"] = self.field_type
        return d

    @classmethod
    def from_dict(cls, d: dict) -> EntryField:
        return cls(
            key=d["key"],
            value=d["value"],
            sensitive=d.get("sensitive", False),
            sort_order=d.get("sort_order", 0),
            field_type=d.get("field_type"),
        )


@dataclass
class EntryMeta:
    """Decrypted content of entries.encrypted_meta."""

    name: str
    tier: Optional[int] = None
    created_at: int = 0
    modified_at: int = 0
    tags: list[str] = field(default_factory=list)
    ai_read_secret: Optional[bool] = None
    allowed_actions: Optional[list[str]] = None
    local_root: Optional[str] = None
    max_session_minutes: Optional[int] = None
    remote_root: Optional[str] = None

    def __post_init__(self):
        now = int(time.time() * 1000)
        if self.created_at == 0:
            self.created_at = now
        if self.modified_at == 0:
            self.modified_at = now

    def to_json(self) -> bytes:
        d: dict[str, Any] = {
            "name": self.name,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }
        if self.tier is not None:
            d["tier"] = self.tier
        if self.tags:
            d["tags"] = self.tags
        if self.ai_read_secret is not None:
            d["ai_read_secret"] = self.ai_read_secret
        if self.allowed_actions is not None:
            d["allowed_actions"] = self.allowed_actions
        if self.local_root is not None:
            d["local_root"] = self.local_root
        if self.max_session_minutes is not None:
            d["max_session_minutes"] = self.max_session_minutes
        if self.remote_root is not None:
            d["remote_root"] = self.remote_root
        return json.dumps(d, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> EntryMeta:
        d = json.loads(data)
        return cls(
            name=d["name"],
            tier=d.get("tier"),
            created_at=d.get("created_at", 0),
            modified_at=d.get("modified_at", 0),
            tags=d.get("tags", []),
            ai_read_secret=d.get("ai_read_secret"),
            allowed_actions=d.get("allowed_actions"),
            local_root=d.get("local_root"),
            max_session_minutes=d.get("max_session_minutes"),
            remote_root=d.get("remote_root"),
        )


@dataclass
class EntryData:
    """Decrypted content of entries.encrypted_data."""

    fields: list[EntryField]

    def to_json(self) -> bytes:
        return json.dumps(
            {"fields": [f.to_dict() for f in self.fields]},
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> EntryData:
        d = json.loads(data)
        return cls(fields=[EntryField.from_dict(f) for f in d["fields"]])

    def get_field(self, key: str) -> Optional[EntryField]:
        for f in self.fields:
            if f.key == key:
                return f
        return None
