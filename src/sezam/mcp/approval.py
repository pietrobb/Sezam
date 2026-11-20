"""Approval state — in-memory only, single-use, TTL.

Spec 7.3: Approval state is ONLY in-memory (dict in Python process).
Not in vault_meta, not in SQLite. Process restart = all approvals expire.
TTL: default 5 min, per-request, single-use (one read, then expires).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ApprovalRequest:
    """A pending approval request from an MCP agent."""
    request_id: str
    path: str
    action: str  # 'read_secret', 'use_secret'
    agent_name: str
    details: dict = field(default_factory=dict)
    # What the operation really touches, taken from the vault entry by the
    # broker (never from the agent): entry name, SSH host/port/username.
    target: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    ttl_seconds: int = 300  # 5 min
    status: str = "pending"  # pending, approved, denied, expired
    # Offered by the broker: the owner may also allow the same thing
    # without asking for this many minutes (0 = not offered).
    grant_minutes: int = 0
    granted: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class ApprovalManager:
    """In-memory approval state manager. Thread-safe."""

    def __init__(self, default_ttl: int = 300):
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl
        self._on_request_callback = None

    def set_on_request(self, callback) -> None:
        """Set callback for when a new approval request is created.

        Callback signature: (request: ApprovalRequest) -> None
        Used to trigger GUI notification.
        """
        self._on_request_callback = callback

    def request_approval(
        self,
        request_id: str,
        path: str,
        action: str,
        agent_name: str = "unknown",
        details: Optional[dict] = None,
        target: Optional[dict] = None,
        grant_minutes: int = 0,
    ) -> ApprovalRequest:
        """Create a new approval request. Returns the request object."""
        req = ApprovalRequest(
            request_id=request_id,
            path=path,
            action=action,
            agent_name=agent_name,
            details=details or {},
            target=target or {},
            ttl_seconds=self._default_ttl,
            grant_minutes=grant_minutes,
        )
        with self._lock:
            self._requests[request_id] = req

        if self._on_request_callback:
            self._on_request_callback(req)

        return req

    def approve(self, request_id: str, *, grant: bool = False) -> bool:
        """Admin approves a request; ``grant`` also accepts the offered
        time-limited permission (only if one was offered)."""
        with self._lock:
            req = self._requests.get(request_id)
            if req is None or req.is_expired:
                return False
            if req.status != "pending":
                return False
            req.status = "approved"
            req.granted = grant and req.grant_minutes > 0
            return True

    def deny(self, request_id: str) -> bool:
        """Admin denies a request."""
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return False
            req.status = "denied"
            return True

    def check_and_consume(self, request_id: str) -> str:
        """Check approval status and consume if approved (single-use).

        Returns: 'approved', 'denied', 'pending', 'expired', 'not_found'
        """
        with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return "not_found"
            if req.is_expired:
                del self._requests[request_id]
                return "expired"
            if req.status == "approved":
                # Single-use: consume and delete
                del self._requests[request_id]
                return "approved"
            if req.status == "denied":
                del self._requests[request_id]
                return "denied"
            return "pending"

    def is_pending(self, request_id: str) -> bool:
        """Whether the request still waits for an answer (not expired,
        answered or cleared)."""
        with self._lock:
            req = self._requests.get(request_id)
            return req is not None and req.status == "pending" and not req.is_expired

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all pending (non-expired) requests."""
        with self._lock:
            self._cleanup_expired()
            return [r for r in self._requests.values() if r.status == "pending"]

    def _cleanup_expired(self) -> None:
        expired = [k for k, v in self._requests.items() if v.is_expired]
        for k in expired:
            del self._requests[k]

    def clear_all(self) -> None:
        """Clear all approvals (lock/restart)."""
        with self._lock:
            self._requests.clear()


_ESCAPED_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}
# Default-ignorable characters outside the Cf category: they render as
# nothing (or as blank) and so can hide or fake text just like ZWSP.
_INVISIBLE = {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0}
_INVISIBLE_RANGES = ((0x180B, 0x180F), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def _hidden(ch: str) -> bool:
    import unicodedata

    category = unicodedata.category(ch)
    if category in _ESCAPED_CATEGORIES or (category == "Zs" and ch != " "):
        return True
    code = ord(ch)
    return code in _INVISIBLE or any(lo <= code <= hi for lo, hi in _INVISIBLE_RANGES)


def visible_text(text: str, *, keep_newlines: bool = False) -> str:
    """Escape characters that can disguise approval text.

    Bidi overrides/isolates, zero-width, other format/control characters,
    non-ASCII spaces and blank fillers could make an agent-supplied path or
    command read differently from what will run, so they are shown as
    \\uXXXX (\\UXXXXXXXX above the BMP) instead of being rendered.
    """
    out = []
    for ch in str(text):
        if keep_newlines and ch == "\n":
            out.append(ch)
        elif _hidden(ch):
            code = ord(ch)
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            out.append(ch)
    return "".join(out)


_TARGET_LABELS = (
    ("entry", "Entry"),
    ("host", "Host"),
    ("port", "Port"),
    ("username", "User"),
    ("host_key", "Host key (verified)"),
    ("host_unverified", "Host key"),
    ("forwarded", "Agent forwarded"),
    ("certificate", "Certificate"),
    ("request", "Request"),
    ("encryption", "Encryption"),
    ("warning", "WARNING"),
)

SSH_AGENT_ACTION = "use_secret:ssh_agent"


def _login_text(request: ApprovalRequest) -> str:
    target = request.target
    return (
        f"log in as {visible_text(target.get('username', '?'))} on "
        f"{visible_text(target.get('host', '?'))}:{visible_text(target.get('port', '?'))}"
    )


def approval_message(request: ApprovalRequest) -> str:
    import json

    target = "".join(
        f"{label}: {visible_text(request.target[key])}\n"
        for key, label in _TARGET_LABELS
        if request.target.get(key) not in (None, "")
    )
    details = json.dumps(request.details, ensure_ascii=False, indent=2)
    headline = (
        f"An AI agent wants to {_login_text(request)} with the vault key.\n\n"
        if request.action == SSH_AGENT_ACTION
        else ""
    )
    if request.target.get("warning"):
        headline = f"WARNING: {visible_text(request.target['warning'])}\n\n" + headline
    return (
        headline
        + f"Agent: {visible_text(request.agent_name)}\n"
        f"Vault entry: {visible_text(request.path)}\n"
        f"Action: {visible_text(request.action)}\n\n"
        + (f"Target (from the vault entry):\n{target}\n" if target else "")
        + f"Details:\n{visible_text(details[:60000], keep_newlines=True)}"
        "\n\nAllow this operation once?"
    )


def grant_message(request: ApprovalRequest) -> str:
    """Second question after an approval that offers a time-limited grant."""
    host_key = request.target.get("host_key")
    return (
        f"Also let AI agents {_login_text(request)} without asking for the next "
        f"{request.grant_minutes} minutes?\n\n"
        f"Entry: {visible_text(request.target.get('entry') or request.path)}\n"
        + (f"Host key: {visible_text(host_key)}\n" if host_key else "")
        + (
            f"Host key: {visible_text(request.target['host_unverified'])}\n"
            if request.target.get("host_unverified") else ""
        )
        + "\nThe permission ends earlier when the vault locks or AI access is turned off."
    )


def _ask(message: str) -> bool:
    """A local Yes/No dialog with No as the default; any error is No."""
    import sys

    try:
        if sys.platform == "win32":
            import ctypes

            MB_YESNO = 0x00000004
            MB_ICONWARNING = 0x00000030
            MB_DEFBUTTON2 = 0x00000100  # "No" is the default button
            MB_SETFOREGROUND = 0x00010000
            return ctypes.windll.user32.MessageBoxW(
                None,
                message,
                "Sezam AI approval",
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND,
            ) == 6
        import tkinter
        from tkinter import messagebox

        root = tkinter.Tk()
        root.withdraw()
        try:
            return messagebox.askyesno(
                "Sezam AI approval",
                message,
                icon="warning",
                default=messagebox.NO,
                parent=root,
            ) is True
        finally:
            root.destroy()
    except Exception:
        return False


def install_desktop_approval_handler(manager: ApprovalManager) -> None:
    """Show a local OS confirmation dialog for every Tier 1 request; when the
    broker offers a time-limited grant, ask about it separately (default No).

    Requests from parallel agent calls are asked one at a time, each with
    its own grant question right after it, so an answer can never land on a
    different request than the one shown. A request that expired or was
    cleared while waiting for its turn is not shown at all."""
    one_dialog = threading.Lock()

    def handle(request: ApprovalRequest) -> None:
        with one_dialog:
            if not manager.is_pending(request.request_id):
                return
            if not _ask(approval_message(request)):
                manager.deny(request.request_id)
                return
            grant = request.grant_minutes > 0 and _ask(grant_message(request))
            manager.approve(request.request_id, grant=grant)

    manager.set_on_request(handle)
