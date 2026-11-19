"""``sezam ai log``: the AI broker's audit records for a human (AI broker
TODO, section 8).

Reads the encrypted audit details of the broker's records (MCP tools, SSH
agent signatures, owner approvals and refusals, kill switch) from an
unlocked vault and turns each into one line: time, agent, entry, action,
command or paths, result, bytes. Intent (``… started``) and outcome are
separate records, so an operation that never finished is visible too.
Every value the agent could have chosen is passed through ``visible_text``
so it cannot move the cursor or hide text in the terminal.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator, Optional

from ..crypto.aead import BlobKind, decrypt, parse_envelope
from ..models import bytes_to_ulid, ulid_to_bytes
from .approval import visible_text

if TYPE_CHECKING:
    from ..vault.crud import Vault

AI_KINDS = ("mcp_ssh", "mcp_secret", "mcp_ftp", "mcp_http", "mcp_approval", "ai_on", "ai_off")

_SINCE = re.compile(r"(\d+)([smhd])")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_since(text: str) -> int:
    """'90s', '15m', '1h', '7d' → seconds."""
    match = _SINCE.fullmatch(text.strip().lower())
    if not match or int(match.group(1)) <= 0:
        raise ValueError("--since takes a number with s, m, h or d (e.g. 1h, 7d).")
    return int(match.group(1)) * _UNIT[match.group(2)]


@dataclass
class Record:
    at_ms: int
    kind: str
    detail: Optional[dict]  # None: details missing or unreadable


def entry_paths(vault: "Vault") -> dict[str, str]:
    """entry id → path, for every entry (names only, nothing decrypted
    beyond what listing does and no read audit records)."""
    out: dict[str, str] = {}

    def walk(node_id: str, prefix: str) -> None:
        for entry in vault.list_entries(node_id):
            out[entry["id"]] = prefix + entry["name"]
        for child in vault.list_nodes(node_id):
            walk(child["id"], f"{prefix}{child['name']}/")

    walk(vault.db.get_meta("root_node_id"), "")
    return out


def ai_records(vault: "Vault", since_ms: int = 0) -> Iterator[Record]:
    placeholders = ",".join("?" for _ in AI_KINDS)
    rows = vault.db.fetchall(
        f"SELECT id, action, encrypted_details, timestamp FROM audit_log "
        f"WHERE action IN ({placeholders}) AND timestamp >= ? ORDER BY timestamp, id",
        (*AI_KINDS, since_ms),
    )
    deks: dict[str, bytearray] = {}
    for row in rows:
        yield Record(row["timestamp"], row["action"], _details(vault, row, deks))


def _details(vault: "Vault", row, deks: dict) -> Optional[dict]:
    blob = row["encrypted_details"]
    if not blob:
        return None
    try:
        dek_id = bytes_to_ulid(parse_envelope(blob).dek_id)
        if dek_id not in deks:
            deks[dek_id] = vault._dek_mgr.unlock_dek(dek_id)
        plain = decrypt(
            blob, deks[dek_id], ulid_to_bytes(row["id"]), 1,
            expected_blob_kind=BlobKind.AUDIT_DETAILS,
        )
        detail = json.loads(plain)
    except Exception:
        return None
    return detail if isinstance(detail, dict) else None


def _size(n) -> str:
    if not isinstance(n, int) or isinstance(n, bool):
        return ""
    return f"{n} B" if n < 10240 else f"{n // 1024} KiB"


def _what(op: str, d: dict) -> str:
    """Command, paths or target of an operation."""
    if op == "execute":
        if d.get("command") is not None:
            return f"$ {d['command']}"
        return f"command sha256 {str(d.get('command_sha256', ''))[:12]}…"
    if op == "upload":
        return f"{d.get('local_path', '?')} -> {d.get('remote_path', '?')}"
    if op == "download":
        return f"{d.get('remote_path', '?')} -> {d.get('local_path', '?')}"
    if op == "read_secret":
        return f"field {d.get('field')}"
    if op == "use":
        return str(d.get("action", ""))
    if op.startswith("agent_sign"):
        text = f"{d.get('username')}@{d.get('host')}:{d.get('port')}"
        if d.get("cert_key_id"):
            text += f" cert {d['cert_key_id']}"
        if d.get("bound_host_key") is None and "bound_host_key" in d:
            text += " (host not bound)"
        if d.get("forwarded"):
            text += " (forwarded)"
        return text
    if op == "session_resize":
        return f"{d.get('width')}x{d.get('height')}"
    if op == "rename":
        return f"{d.get('remote_path', '?')} -> {d.get('new_remote_path', '?')}"
    if op in ("list", "delete", "mkdir"):
        return str(d.get("remote_path", "?"))
    if op == "request":
        return f"{d.get('method', '?')} {d.get('url', '?')}"
    return ""


def _bytes(d: dict) -> str:
    parts = []
    if d.get("stdout_bytes") is not None:
        parts.append(f"out {_size(d['stdout_bytes'])}")
    if d.get("stderr_bytes"):
        parts.append(f"err {_size(d['stderr_bytes'])}")
    if d.get("input_bytes") is not None:
        parts.append(f"in {_size(d['input_bytes'])}")
    if d.get("response_bytes") is not None:
        parts.append(f"out {_size(d['response_bytes'])}")
    if d.get("bytes") is not None:
        files = f"{d['files']} file(s) " if d.get("files") is not None else ""
        parts.append(f"{files}{_size(d['bytes'])}")
    return ", ".join(parts)


_APPROVAL = {
    "approved": "APPROVED by owner",
    "denied": "DENIED by owner",
    "timeout": "DENIED (no answer)",
    "expired": "DENIED (no answer)",
    "not_allowed": "DENIED (policy)",
}


def describe(record: Record, paths: dict[str, str]) -> dict:
    """The columns of one record (raw, not yet escaped)."""
    d = record.detail or {}
    row = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.at_ms / 1000)),
        "agent": str(d.get("agent") or "-"),
        "entry": "-",
        "action": record.kind,
        "what": "",
        "result": "",
        "bytes": "",
    }
    if record.kind in ("ai_on", "ai_off"):
        row["action"] = "AI " + record.kind[3:].upper()
        row["what"] = f"from {d.get('source', '?')} on {d.get('host', '?')}"
        if d.get("epoch") is not None:
            row["what"] += f", epoch {d['epoch']}"
        row["result"] = "ok" if record.detail is not None else "(details unreadable)"
        return row
    entry_id = d.get("entry_id")
    if entry_id is not None:
        row["entry"] = paths.get(entry_id, f"(deleted entry {entry_id})")
    if record.detail is None:
        row["result"] = "(details unreadable)"
        return row
    if record.kind == "mcp_approval":
        row["action"] = f"approval {d.get('action', '?')}"
        row["result"] = _APPROVAL.get(str(d.get("result")), str(d.get("result")))
        return row

    op = str(d.get("operation", "?"))
    if op.endswith("_start"):
        base, result = op[: -len("_start")], "started"
    elif op.endswith("_failed"):
        base, result = op[: -len("_failed")], f"FAILED {d.get('code', '')}".strip()
    elif op == "agent_sign_denied":
        base, result = op, f"DENIED {d.get('reason', '')}".strip()
    else:
        base, result = op, "ok"
        if d.get("exit_code") is not None:
            result += f", exit {d['exit_code']}"
        if d.get("http_status") is not None:
            result += f", HTTP {d['http_status']}"
        if d.get("result") not in (None, "ok"):
            result = str(d["result"])
    if base.startswith("agent_sign"):
        row["action"] = "ssh-agent sign"
        if d.get("approval") and result == "ok":
            result += f" ({d['approval']})"
    else:
        prefix = {"mcp_secret": "secret", "mcp_ftp": "ftp", "mcp_http": "http"}.get(
            record.kind, "ssh"
        )
        row["action"] = f"{prefix} {base.replace('_', ' ')}"
    row["what"] = _what(base, d)
    if record.kind == "mcp_ftp" and d.get("encrypted") is False:
        row["what"] += " (PLAIN FTP, unencrypted)"
    if record.kind == "mcp_http" and d.get("encrypted") is False:
        row["what"] += " (PLAIN HTTP, unencrypted)"
    row["result"] = result
    row["bytes"] = _bytes(d)
    return row


def format_log(records: list[Record], paths: dict[str, str]) -> list[str]:
    lines = []
    for record in records:
        row = {k: visible_text(v) for k, v in describe(record, paths).items()}
        line = f"{row['time']}  {row['agent']:<12} {row['entry']:<28} {row['action']:<20} {row['result']}"
        if row["bytes"]:
            line += f"  [{row['bytes']}]"
        if row["what"]:
            line += f"\n    {row['what']}"
        lines.append(line)
    return lines
