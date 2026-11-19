"""MCP Broker — vault operations for AI agents.

Spec 7.3: MCP never gets raw DEK or raw secret.
Broker decrypts, performs operation, returns result, zeroizes.

Tool signatures:
  vault_list(path) -> {nodes: [...], entries: [...]}
  vault_read(path, field) -> {status, value?}
  vault_search(query) -> {results: [...]}
  vault_use(path, action, params) -> {status, output}

Tier enforcement:
  Tier 0: auto (no approval needed)
  Tier 1: approval required
  Tier 2: deny (agent cannot even see existence)
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from ..vault import ai_access
from ..vault.crud import Vault
from .approval import ApprovalManager
from .ftp import PLAIN_FTP_WARNING, FTPCredentials, FTPManager
from .http_api import PLAIN_HTTP_WARNING, HTTPManager, HTTPTarget
from .redact import audit_text
from .ssh import (
    MAX_COMMAND_BYTES,
    MAX_STDIN_BYTES,
    SSHBrokerError,
    SSHCredentials,
    SSHManager,
    validate_local_root,
    validate_remote_root,
)


logger = logging.getLogger(__name__)

APPROVAL_TIMEOUT = 60  # seconds to wait for approval

FTP_OPS = ("list", "upload", "download", "delete", "mkdir", "rename")
FTP_ENCRYPTION = {
    "explicit": "FTPS (explicit TLS, certificate verified)",
    "implicit": "FTPS (implicit TLS, certificate verified)",
    "plain": "NONE - plain FTP",
}
PLAIN_FTP_APPROVAL_WARNING = (
    "Plain FTP (allow_plain_ftp): the password and all data cross the network unencrypted."
)
PLAIN_HTTP_APPROVAL_WARNING = (
    "Plain HTTP (allow_plain_http): the credential and all data cross the network unencrypted."
)


def _policy_tier(meta: dict) -> Optional[int]:
    """Explicit tier from decrypted metadata, validated (fail closed).

    Metadata can come from any synced client, so only the ints 0, 1 and 2
    are tiers; any other value (a string, bool, float, negative or unknown
    number) hides the object as tier 2 instead of raising or under-protecting.
    """
    tier = meta.get("tier")
    if tier is None:
        return None
    if type(tier) is int and tier in (0, 1, 2):
        return tier
    return 2


DEFAULT_MAX_SESSION_MINUTES = 60
MAX_SESSION_MINUTES_LIMIT = 24 * 60


def _session_lifetime(meta: dict) -> int:
    """Maximum SSH session lifetime in seconds from ``max_session_minutes``.

    Unset means the 60-minute default; a malformed value refuses the session.
    """
    minutes = meta.get("max_session_minutes")
    if minutes is None:
        return DEFAULT_MAX_SESSION_MINUTES * 60
    if type(minutes) is not int or not 1 <= minutes <= MAX_SESSION_MINUTES_LIMIT:
        raise SSHBrokerError("policy_invalid", "max_session_minutes policy is invalid.")
    return minutes * 60


def _allowed_actions(meta: dict) -> frozenset[str]:
    """Explicitly allowed MCP actions: only a list of strings counts.

    A string would make ``action in value`` a substring match, so anything
    other than a list of strings allows nothing.
    """
    actions = meta.get("allowed_actions")
    if not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
        return frozenset()
    return frozenset(actions)


def _approval_target(entry: dict, action: str, details: Optional[dict] = None) -> dict:
    """What the approval dialog shows as the real target: the entry name and,
    for SSH actions, the host, port and username the broker will connect to
    (parsed exactly as the connection parses them, never agent-supplied).
    For HTTP: the method and full URL exactly as the request will be sent
    (host from the entry, path checked against its policy first)."""
    target: dict = {"entry": entry.get("name")}
    if action == "http":
        http_target = HTTPTarget.from_entry(entry)
        details = details or {}
        method, url_path = http_target.check(details.get("method"), details.get("request_path"))
        http_target.check_body(details.get("body"), details.get("headers"))
        target.update(
            host=http_target.host, port=http_target.port,
            request=f"{method} {http_target.origin}{url_path}",
            encryption="TLS (certificate verified)" if http_target.encrypted else "NONE - plain HTTP",
        )
        if not http_target.encrypted:
            target["warning"] = PLAIN_HTTP_APPROVAL_WARNING
    elif action == "ftp":
        credentials = FTPCredentials.from_entry(entry)
        target.update(
            host=credentials.host, port=credentials.port, username=credentials.username,
            encryption=FTP_ENCRYPTION[credentials.mode],
        )
        if not credentials.encrypted:
            target["warning"] = PLAIN_FTP_APPROVAL_WARNING
    elif action.startswith("ssh_"):
        credentials = SSHCredentials.from_entry(entry)
        target.update(
            host=credentials.host, port=credentials.port, username=credentials.username
        )
    return target


class MCPBroker:
    """Vault broker for MCP agents. Never exposes raw keys or secrets."""

    def __init__(
        self,
        vault: Vault,
        approval_mgr: ApprovalManager,
        ssh_manager: Optional[SSHManager] = None,
        ftp_manager: Optional[FTPManager] = None,
        http_manager: Optional[HTTPManager] = None,
    ):
        self._vault = vault
        self._approval = approval_mgr
        self._ssh = ssh_manager or SSHManager()
        self._ftp = ftp_manager or FTPManager()
        self._http = http_manager or HTTPManager()
        # Read by the managers once a connection stands (review 7c10379).
        self._ssh.cut_check = self._ftp.cut_check = self._http.cut_check = self._cut_requested
        # Set by disable_ai(): refused in memory before anything else, so the
        # brake holds even if writing the persistent state fails. The epoch
        # it was persisted at is the only way to clear it: the switch read
        # back as on at that epoch or later means 'sezam ai on' (password).
        self._ai_off = False
        self._ai_off_epoch: Optional[int] = None
        # The highest epoch read back as off while this process runs.
        self._off_floor = 0
        self._brake_lock = threading.Lock()
        # mcp-serve attaches its remote_policy.RemotePolicyPoller here.
        self.remote_policy = None

    def disable_ai(
        self, source: str, extra: dict | None = None
    ) -> ai_access.AIAccessState | None:
        """The kill switch, in order: in-memory flag, close every SSH
        session, persist off + epoch, audit (inside ``ai_access.disable``).
        Returns the persisted state, or None if it could not be written
        (the in-memory flag then stays until restart)."""
        self._ai_off = True  # first, without waiting for any lock
        with self._brake_lock:
            self._ai_off = True
            self._ai_off_epoch = None
        self._close_connections()
        try:
            state = ai_access.disable(self._vault, source, extra)
        except Exception:
            logger.exception("Could not persist ai_off; staying off in memory")
            return None
        with self._brake_lock:
            if self._ai_off:
                self._ai_off_epoch = max(state.epoch, self._ai_off_epoch or 0)
        return state

    def _cut_requested(self) -> bool:
        if self._ai_off or not self._vault.is_unlocked:
            return True
        # Review 1141a20: also the saved switch. A brake that reached the
        # vault but not this broker (control channel busy or down) let a
        # request in its connect phase go out until the backstop's next tick.
        try:
            return self._ai_is_off()
        except Exception:
            logger.exception("Could not read the kill switch; cutting")
            return True

    def _close_connections(self) -> None:
        """Every SSH session, every running FTP transfer and HTTP request."""
        try:
            self._ssh.close_all()
        finally:
            try:
                self._ftp.close_all()
            finally:
                self._http.close_all()

    def enforce_kill_switch(self) -> bool:
        """Periodic backstop: if AI access is off (in memory or persisted),
        close every SSH session. Returns True while it is off."""
        if self._ai_is_off():
            self._close_connections()
            return True
        return False

    def _ai_is_off(self) -> bool:
        """Review 7c10379 H6: a locked vault's unchecked 'on' released the
        in-memory brake, after which a replayed old 'on' held at the next
        unlock. The brake is released only by a verified 'on' at its epoch
        or later, and an 'on' below the highest epoch this process has seen
        off (also an 'ai off' from another process) counts as off."""
        state = ai_access.read_state(self._vault)
        # Review 1141a20 M-AI3: calls run side by side; the floor only rises
        # and the brake is released only against the epoch it was set at.
        with self._brake_lock:
            if not state.enabled:
                self._off_floor = max(self._off_floor, state.epoch)
                return True
            if self._ai_off:
                off_epoch = self._ai_off_epoch
                verified = ai_access.verified_on_epoch(self._vault)
                if off_epoch is None or verified is None or verified < off_epoch:
                    return True
                self._ai_off = False
            return state.epoch < self._off_floor

    def status(self) -> dict:
        """Kill switch and lock state for the control channel (no secrets)."""
        off = self._ai_is_off()
        return {
            "ai_access": "off" if off else "on",
            "epoch": ai_access.read_state(self._vault).epoch,
            "vault_unlocked": self._vault.is_unlocked,
            "ssh_sessions": self._ssh.session_count(),
            "sessions": self._ssh.session_summaries(),
            "remote_policy": (
                self.remote_policy.last_result if self.remote_policy is not None else "off"
            ),
        }

    def access_overview(self) -> list[dict]:
        """Every entry an agent can see and what it may do there, resolved
        exactly as the tools resolve it (no secret values). For the owner:
        works whatever the kill switch says, needs an unlocked vault."""
        rows: list[dict] = []
        for path, entry, tier in self._visible_entries():
            try:
                max_minutes: Any = _session_lifetime(entry) // 60
            except SSHBrokerError:
                max_minutes = "invalid"
            local_root = entry.get("local_root")
            try:
                remote_root = (
                    None if entry.get("remote_root") is None
                    else validate_remote_root(entry["remote_root"])
                )
            except SSHBrokerError:
                remote_root = "invalid"
            rows.append({
                "id": entry["id"],
                "path": path,
                "tier": tier,
                "actions": sorted(_allowed_actions(entry)),
                "read_secret": self._can_read_secret(entry),
                "local_root": local_root if local_root is None or isinstance(local_root, str) else "invalid",
                "remote_root": remote_root,
                "max_session_minutes": max_minutes,
            })
        return rows

    def _visible_entries(self) -> Iterator[tuple[str, dict, int]]:
        """(path, policy, effective tier) of every entry an agent can see,
        from the decrypted policies only (no secret fields)."""

        def walk(node_id: str, prefix: str) -> Iterator[tuple[str, dict, int]]:
            if self._get_effective_node_tier(self._vault.read_node(node_id)) >= 2:
                return  # a tier 2 folder hides everything below it
            for listed in self._vault.list_entries(node_id):
                policy = self._vault.read_entry_policy(listed["id"])
                if policy is None:
                    continue
                entry = {**policy, "ai_read_secret": listed.get("ai_read_secret")}
                tier = self._get_effective_tier(entry)
                if tier < 2:
                    yield prefix + listed["name"], entry, tier
            for child in self._vault.list_nodes(node_id):
                yield from walk(child["id"], f"{prefix}{child['name']}/")

        yield from walk(self._vault.db.get_meta("root_node_id"), "")

    def _require_access(self) -> None:
        """Vault unlocked and the AI kill switch on, checked on every call
        (an unreadable switch counts as off); otherwise every SSH session
        is closed and the call refused."""
        if self._ai_is_off():
            self._close_connections()
            raise MCPError("ai_disabled", "AI access is turned off ('sezam ai on').")
        if not self._vault.is_unlocked:
            self._close_connections()
            raise MCPError("vault_locked", "Unlock vault in desktop app.")

    def _iter_node_policy(self, node_id: Optional[str]):
        """Yield decrypted folder policies from nearest folder to root."""
        while node_id is not None:
            node = self._vault.read_node(node_id)
            yield node
            node_id = node["parent_id"]

    def _hidden_by_folder(self, node_id: Optional[str]) -> bool:
        """Tier 2 on any folder is a ceiling: nothing below it is visible,
        whatever lower tier an entry or subfolder sets for itself."""
        return any(
            _policy_tier(node) is not None and _policy_tier(node) >= 2
            for node in self._iter_node_policy(node_id)
        )

    def _get_effective_node_tier(self, node: dict) -> int:
        """Resolve a folder tier from the nearest explicit ancestor."""
        if self._hidden_by_folder(node.get("parent_id")):
            return 2
        if _policy_tier(node) is not None:
            return _policy_tier(node)
        for ancestor in self._iter_node_policy(node.get("parent_id")):
            if _policy_tier(ancestor) is not None:
                return _policy_tier(ancestor)
        return 1

    def _get_effective_tier(self, entry: dict) -> int:
        """Resolve an entry tier from the entry or nearest explicit folder."""
        if self._hidden_by_folder(entry.get("node_id")):
            return 2
        if _policy_tier(entry) is not None:
            return _policy_tier(entry)
        for node in self._iter_node_policy(entry.get("node_id")):
            if _policy_tier(node) is not None:
                return _policy_tier(node)
        return 1

    def _can_read_secret(self, entry: dict) -> bool:
        """Resolve the explicit raw-secret capability, defaulting to deny."""
        if entry.get("ai_read_secret") is not None:
            return entry["ai_read_secret"] is True
        for node in self._iter_node_policy(entry.get("node_id")):
            if node.get("ai_read_secret") is not None:
                return node["ai_read_secret"] is True
        return False

    def _authorize_action(
        self,
        path: str,
        action: str,
        agent_name: str,
        details: Optional[dict] = None,
    ) -> tuple[Optional[dict], Optional[dict]]:
        self._require_access()
        entry = self._vault.find_entry_by_path(path)
        if entry is None or self._get_effective_tier(entry) >= 2:
            return None, {"status": "not_found"}

        if action not in _allowed_actions(entry):
            self._audit_decision(entry, action, agent_name, "not_allowed")
            return None, {
                "status": "denied",
                "error": f"Action '{action}' is not explicitly allowed for this entry.",
            }

        if self._get_effective_tier(entry) >= 1:
            try:
                target = _approval_target(entry, action, details)
            except SSHBrokerError as exc:
                return None, self._ssh_error(exc)
            result, _ = self._await_approval(path, action, agent_name, details or {}, target)
            self._audit_decision(entry, action, agent_name, result)
            if result != "approved":
                return None, {"status": result}
            # The switch may have been turned off while the dialog was open.
            self._require_access()

        return entry, None

    def _await_approval(
        self,
        path: str,
        action: str,
        agent_name: str,
        details: dict,
        target: dict,
        *,
        grant_minutes: int = 0,
    ) -> tuple[str, bool]:
        """Ask the owner. Returns ('approved' | 'denied' | 'expired' |
        'timeout', whether the offered ``grant_minutes`` grant was accepted)."""
        request_id = str(uuid.uuid4())
        request = self._approval.request_approval(
            request_id=request_id,
            path=path,
            action=f"use_secret:{action}",
            agent_name=agent_name,
            details=details,
            target=target,
            grant_minutes=grant_minutes,
        )
        start = time.time()
        while time.time() - start < APPROVAL_TIMEOUT:
            result = self._approval.check_and_consume(request_id)
            if result in ("approved", "denied", "expired"):
                return result, result == "approved" and request.granted
            time.sleep(0.1)
        return "timeout", False

    def _audit_decision(self, entry: dict, action: str, agent_name: str, result: str) -> None:
        """Record the owner's answer (or a policy refusal) for ``sezam ai log``.

        An approval that cannot be recorded is not acted on; a refusal
        stands even if its record fails.
        """
        try:
            self._audit_ssh(
                entry, "approval", kind="mcp_approval", action=action,
                agent=agent_name, result=result,
            )
        except Exception:
            if result == "approved":
                raise
            logger.warning("Refusal of %r could not be audited", action)

    def _audit_ssh(
        self, entry: dict, operation: str, *, kind: str = "mcp_ssh", **details: Any
    ) -> None:
        payload = {"entry_id": entry.get("id"), "operation": operation, **details}
        self._vault._audit_log(
            kind, json.dumps(payload, sort_keys=True).encode(), strict=True
        )

    @contextmanager
    def _audited_ssh(
        self, entry: dict, operation: str, *, kind: str = "mcp_ssh", **details: Any
    ) -> Iterator[dict]:
        """Audit before the side effect, then record how it ended.

        If the intent record cannot be written the operation never starts,
        and any exception (not only SSHBrokerError) is recorded as a failure.
        """
        self._audit_ssh(entry, f"{operation}_start", kind=kind, **details)
        outcome: dict = {}
        try:
            yield outcome
        except SSHBrokerError as exc:
            self._audit_ssh(
                entry, f"{operation}_failed", kind=kind, code=exc.code, **details
            )
            raise
        except BaseException as exc:
            self._audit_ssh(
                entry, f"{operation}_failed", kind=kind, code="internal_error",
                error_type=type(exc).__name__, **details,
            )
            raise
        # 'sezam ai off' or a lock that landed while it ran: what it
        # produced is not handed to the agent.
        if not self._vault.is_unlocked:
            self._close_connections()
            raise MCPError("vault_locked", "Unlock vault in desktop app.")
        if self._ai_is_off():
            self._close_connections()
            self._audit_ssh(
                entry, f"{operation}_failed", kind=kind, code="cut_off", **details
            )
            raise MCPError("ai_disabled", "AI access is turned off ('sezam ai on').")
        self._audit_ssh(entry, operation, kind=kind, **details, **outcome)

    def _release_secret(self, entry: dict, field: dict, agent_name: str) -> dict:
        """Hand a raw field value to the agent, audited before and after."""
        with self._audited_ssh(
            entry, "read_secret", kind="mcp_secret", field=field["key"], agent=agent_name
        ):
            return {"status": "ok", "value": field["value"]}

    def _transfer_scope(self, entry: dict) -> dict:
        """Local transfer root from the entry's ``local_root`` policy (or the
        default transfer directory), with the vault directory always protected,
        and the entry's ``remote_root`` (None: no remote confinement)."""
        protected = (self._vault.path,)
        value = entry.get("local_root")
        root = None if value is None else validate_local_root(value, protected)
        remote = entry.get("remote_root")
        remote_root = None if remote is None else validate_remote_root(remote)
        return {"local_root": root, "protected": protected, "remote_root": remote_root}

    @staticmethod
    def _ssh_error(error: SSHBrokerError) -> dict:
        return {"status": "error", "code": error.code, "error": str(error)}

    # ── vault_list ──

    def vault_list(self, path: str = "") -> dict:
        """List nodes and entries at a path. Tier 2 entries are invisible."""
        self._require_access()

        if path:
            node_id, _ = self._vault.resolve_path(path)
            if node_id is None:
                return {"nodes": [], "entries": []}
        else:
            node_id = self._vault.db.get_meta("root_node_id")

        current_node = self._vault.read_node(node_id)
        if self._get_effective_node_tier(current_node) >= 2:
            return {"nodes": [], "entries": []}

        nodes = self._vault.list_nodes(node_id)
        entries = self._vault.list_entries(node_id)

        visible_nodes = [
            {"name": node["name"]}
            for node in nodes
            if self._get_effective_node_tier(node) < 2
        ]
        visible_entries = [
            {"name": entry["name"], "path": f"{path}/{entry['name']}".strip("/")}
            for entry in entries
            if self._get_effective_tier(entry) < 2
        ]

        return {"nodes": visible_nodes, "entries": visible_entries}

    # ── vault_read ──

    def vault_read(
        self, path: str, field: Optional[str] = None, agent_name: str = "unknown"
    ) -> dict:
        """Read entry metadata or field value.

        Tier 0: returns immediately
        Tier 1: requires approval (returns 'pending' status)
        Tier 2: returns 'not_found' (kryptograficky nemozne)

        For field values with sensitive=True, default is use_secret (not read_secret).
        read_secret requires explicit ai_read_secret=True in encrypted_meta.
        """
        self._require_access()

        entry = self._vault.find_entry_by_path(path)
        if entry is None:
            return {"status": "not_found"}

        tier = self._get_effective_tier(entry)

        if tier >= 2:
            return {"status": "not_found"}  # Pretend it doesn't exist

        if field is None:
            # Return metadata only (name, field keys — not values)
            return {
                "status": "ok",
                "name": entry["name"],
                "fields": [f["key"] for f in entry["fields"]],
                "tags": entry.get("tags", []),
            }

        # Field value requested
        field_data = None
        for f in entry["fields"]:
            if f["key"] == field:
                field_data = f
                break

        if field_data is None:
            return {"status": "not_found", "error": f"Field '{field}' not found"}

        if not self._can_read_secret(entry):
            return {
                "status": "denied",
                "error": "read_secret not permitted. Use vault_use instead, or set ai_read_secret=true.",
            }

        if tier == 0:
            return self._release_secret(entry, field_data, agent_name)

        # Tier 1 — capability opt-in plus human approval are both required
        request_id = str(uuid.uuid4())
        self._approval.request_approval(
            request_id=request_id,
            path=path,
            action=f"read_secret:{field}",
            agent_name=agent_name,
            target=_approval_target(entry, "read_secret"),
        )

        # Wait for approval (blocking, with timeout)
        start = time.time()
        while time.time() - start < APPROVAL_TIMEOUT:
            result = self._approval.check_and_consume(request_id)
            if result == "approved":
                self._audit_decision(entry, "read_secret", agent_name, result)
                self._require_access()
                return self._release_secret(entry, field_data, agent_name)
            elif result == "denied":
                self._audit_decision(entry, "read_secret", agent_name, result)
                return {"status": "denied"}
            elif result == "expired":
                self._audit_decision(entry, "read_secret", agent_name, "timeout")
                return {"status": "timeout"}
            time.sleep(0.5)

        self._audit_decision(entry, "read_secret", agent_name, "timeout")
        return {"status": "timeout"}

    # ── vault_search ──

    def vault_search(self, query: str) -> dict:
        """Search entries. Tier 2 entries excluded from results."""
        self._require_access()

        results = self._vault.search(query)
        # Filter tier 2
        filtered = []
        for r in results:
            try:
                entry = self._vault.read_entry(r["entry_id"])
                if self._get_effective_tier(entry) < 2:
                    filtered.append({
                        "name": r["name"],
                        "path": r["path"],
                    })
            except Exception:
                continue

        return {"results": filtered}

    # ── vault_use ──

    def vault_use(
        self,
        path: str,
        action: str,
        params: Optional[dict] = None,
        agent_name: str = "unknown",
    ) -> dict:
        """Use a secret without exposing it. Broker performs the operation.

        Supported actions (Phase 3):
          - totp_code: generate TOTP code from stored seed
          - (future: ssh_connect, api_request, db_query)

        Agent never sees the raw secret — only the operation result.
        """
        entry, error = self._authorize_action(path, action, agent_name, params)
        if error:
            return error

        if action != "totp_code":
            return {"status": "error", "error": f"Unknown action: {action}"}
        with self._audited_ssh(
            entry, "use", kind="mcp_secret", action=action, agent=agent_name
        ) as outcome:
            result = self._action_totp(entry)
            outcome["result"] = result["status"]
        return result

    # ── SSH tools ──

    def ssh_execute(
        self,
        path: str,
        command: str,
        *,
        timeout: int = 60,
        pty: bool = False,
        stdin: Optional[str] = None,
        agent_name: str = "unknown",
    ) -> dict:
        if not isinstance(command, str) or not command or "\x00" in command:
            return {"status": "error", "code": "invalid_request", "error": "Invalid command."}
        if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
            return {"status": "error", "code": "invalid_request", "error": "Command is too large."}
        if stdin is not None and (
            not isinstance(stdin, str) or len(stdin.encode("utf-8")) > MAX_STDIN_BYTES
        ):
            return {"status": "error", "code": "invalid_request", "error": "stdin is too large."}

        entry, error = self._authorize_action(
            path,
            "ssh_execute",
            agent_name,
            {"command": command, "stdin": stdin, "timeout": timeout, "pty": pty},
        )
        if error:
            return error
        command_hash = hashlib.sha256(command.encode("utf-8")).hexdigest()
        stdin_hash = hashlib.sha256(stdin.encode("utf-8")).hexdigest() if stdin else None
        try:
            with self._audited_ssh(
                entry, "execute", command_sha256=command_hash, stdin_sha256=stdin_hash,
                command=audit_text(entry, command), agent=agent_name,
            ) as outcome:
                result = self._ssh.execute(
                    entry, command, timeout=timeout, pty=pty, stdin=stdin
                )
                outcome.update(
                    exit_code=result.get("exit_code"),
                    stdout_bytes=len(result.get("stdout", "").encode("utf-8")),
                    stderr_bytes=len(result.get("stderr", "").encode("utf-8")),
                )
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ssh_session_open(
        self,
        path: str,
        *,
        term: str = "xterm-256color",
        width: int = 120,
        height: int = 40,
        agent_name: str = "unknown",
    ) -> dict:
        entry, error = self._authorize_action(
            path,
            "ssh_session",
            agent_name,
            {"interactive_session": True, "term": term},
        )
        if error:
            return error
        try:
            with self._audited_ssh(entry, "session_open", agent=agent_name) as outcome:
                result = self._ssh.open_session(
                    entry,
                    owner=agent_name,
                    term=term,
                    width=width,
                    height=height,
                    max_lifetime=_session_lifetime(entry),
                )
                outcome["session_id"] = result.get("session_id")
                if self._ai_off:
                    # ai_off landed while connecting: the new session must
                    # not survive the close_all() that already ran.
                    self._close_connections()
                    raise MCPError("ai_disabled", "AI access is turned off ('sezam ai on').")
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def _live_session_entry_id(self, session_id: str, agent_name: str) -> str:
        """Entry of an open session, re-checked against the current policy.

        An approved session must not outlive the permission: if the entry
        was deleted, hidden (tier 2), lost ``ssh_session`` or its
        ``max_session_minutes`` (as it is now, not as it was at open) has
        elapsed, the session is closed. Every session read/write/resize
        passes through here, and so through the kill switch.
        """
        self._require_access()
        entry_id = self._ssh.session_entry_id(session_id, owner=agent_name)
        try:
            policy = self._vault.read_entry_policy(entry_id)
            lifetime = _session_lifetime(policy) if policy is not None else None
        except Exception:
            policy = lifetime = None
        if (
            policy is None
            or lifetime is None
            or self._get_effective_tier(policy) >= 2
            or "ssh_session" not in _allowed_actions(policy)
        ):
            with self._audited_ssh({"id": entry_id}, "session_policy_revoked", agent=agent_name):
                self._ssh.close_session(session_id, owner=agent_name)
            raise SSHBrokerError("policy_revoked", "SSH session is no longer permitted.")
        if self._ssh.session_age(session_id, owner=agent_name) > lifetime:
            with self._audited_ssh({"id": entry_id}, "session_expired", agent=agent_name):
                self._ssh.close_session(session_id, owner=agent_name)
            raise SSHBrokerError("session_expired", "SSH session reached max_session_minutes.")
        return entry_id

    def ssh_session_write(
        self, session_id: str, data: str, *, agent_name: str = "unknown"
    ) -> dict:
        self._require_access()
        try:
            entry_id = self._live_session_entry_id(session_id, agent_name)
            digest = hashlib.sha256(str(data).encode("utf-8")).hexdigest()
            with self._audited_ssh(
                {"id": entry_id}, "session_write", input_sha256=digest, agent=agent_name,
                input_bytes=len(str(data).encode("utf-8")),
            ):
                result = self._ssh.write_session(session_id, data, owner=agent_name)
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ssh_session_read(
        self,
        session_id: str,
        *,
        max_bytes: int = 65536,
        wait_ms: int = 0,
        agent_name: str = "unknown",
    ) -> dict:
        self._require_access()
        try:
            entry_id = self._live_session_entry_id(session_id, agent_name)
            with self._audited_ssh({"id": entry_id}, "session_read", agent=agent_name) as outcome:
                result = self._ssh.read_session(
                    session_id,
                    owner=agent_name,
                    max_bytes=max_bytes,
                    wait_ms=wait_ms,
                )
                outcome.update(
                    stdout_bytes=len(result.get("stdout", "").encode("utf-8")),
                    stderr_bytes=len(result.get("stderr", "").encode("utf-8")),
                )
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ssh_session_resize(
        self,
        session_id: str,
        width: int,
        height: int,
        *,
        agent_name: str = "unknown",
    ) -> dict:
        self._require_access()
        try:
            entry_id = self._live_session_entry_id(session_id, agent_name)
            with self._audited_ssh(
                {"id": entry_id}, "session_resize", width=width, height=height, agent=agent_name
            ):
                result = self._ssh.resize_session(
                    session_id, owner=agent_name, width=width, height=height
                )
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ssh_session_close(
        self, session_id: str, *, agent_name: str = "unknown"
    ) -> dict:
        self._require_access()
        try:
            entry_id = self._ssh.session_entry_id(session_id, owner=agent_name)
            with self._audited_ssh({"id": entry_id}, "session_close", agent=agent_name):
                result = self._ssh.close_session(session_id, owner=agent_name)
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ssh_upload(
        self,
        path: str,
        local_path: str,
        remote_path: str,
        *,
        recursive: bool = False,
        overwrite: bool = False,
        agent_name: str = "unknown",
    ) -> dict:
        entry, error = self._authorize_action(
            path,
            "ssh_upload",
            agent_name,
            {
                "local_path": local_path,
                "remote_path": remote_path,
                "recursive": recursive,
                "overwrite": overwrite,
            },
        )
        if error:
            return error
        try:
            with self._audited_ssh(
                entry, "upload", remote_path=remote_path, local_path=local_path, agent=agent_name
            ) as outcome:
                result = self._ssh.upload(
                    entry,
                    local_path,
                    remote_path,
                    recursive=recursive,
                    overwrite=overwrite,
                    **self._transfer_scope(entry),
                )
                outcome.update(files=result.get("files"), bytes=result.get("bytes"))
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ssh_download(
        self,
        path: str,
        remote_path: str,
        local_path: str,
        *,
        recursive: bool = False,
        overwrite: bool = False,
        agent_name: str = "unknown",
    ) -> dict:
        entry, error = self._authorize_action(
            path,
            "ssh_download",
            agent_name,
            {
                "remote_path": remote_path,
                "local_path": local_path,
                "recursive": recursive,
                "overwrite": overwrite,
            },
        )
        if error:
            return error
        try:
            with self._audited_ssh(
                entry, "download", remote_path=remote_path, local_path=local_path, agent=agent_name
            ) as outcome:
                result = self._ssh.download(
                    entry,
                    remote_path,
                    local_path,
                    recursive=recursive,
                    overwrite=overwrite,
                    **self._transfer_scope(entry),
                )
                outcome.update(files=result.get("files"), bytes=result.get("bytes"))
            return result
        except SSHBrokerError as exc:
            return self._ssh_error(exc)

    def ftp(
        self,
        path: str,
        op: str,
        remote_path: str,
        *,
        local_path: Optional[str] = None,
        new_remote_path: Optional[str] = None,
        recursive: bool = False,
        overwrite: bool = False,
        agent_name: str = "unknown",
    ) -> dict:
        """FTP/FTPS operation (``op`` in FTP_OPS) with the entry's
        credentials, under the ``ftp`` action of its policy."""
        invalid = {"status": "error", "code": "invalid_request"}
        if op not in FTP_OPS:
            return {**invalid, "error": f"op must be one of {', '.join(FTP_OPS)}."}
        if not isinstance(remote_path, str) or not remote_path:
            return {**invalid, "error": "remote_path is required."}
        if op in ("upload", "download") and (not isinstance(local_path, str) or not local_path):
            return {**invalid, "error": f"local_path is required for {op}."}
        if op == "rename" and (not isinstance(new_remote_path, str) or not new_remote_path):
            return {**invalid, "error": "new_remote_path is required for rename."}
        if not isinstance(recursive, bool) or not isinstance(overwrite, bool):
            return {**invalid, "error": "recursive and overwrite must be booleans."}

        details: dict[str, Any] = {"op": op, "remote_path": remote_path}
        if op in ("upload", "download"):
            details.update(local_path=local_path, recursive=recursive)
        if op == "rename":
            details["new_remote_path"] = new_remote_path
        if op in ("upload", "download", "rename"):
            details["overwrite"] = overwrite

        entry, error = self._authorize_action(path, "ftp", agent_name, details)
        if error:
            return error
        credentials = None
        try:
            credentials = FTPCredentials.from_entry(entry)
            scope = self._transfer_scope(entry)
            with self._audited_ssh(
                entry, op, kind="mcp_ftp", agent=agent_name,
                encrypted=credentials.encrypted, **{k: v for k, v in details.items() if k != "op"},
            ) as outcome:
                remote_root = scope["remote_root"]
                if op == "list":
                    result = self._ftp.list(entry, remote_path, remote_root=remote_root)
                    outcome["entries"] = len(result.get("entries", []))
                elif op == "upload":
                    result = self._ftp.upload(
                        entry, local_path, remote_path, recursive=recursive,
                        overwrite=overwrite, **scope,
                    )
                elif op == "download":
                    result = self._ftp.download(
                        entry, remote_path, local_path, recursive=recursive,
                        overwrite=overwrite, **scope,
                    )
                elif op == "delete":
                    result = self._ftp.delete(entry, remote_path, remote_root=remote_root)
                elif op == "mkdir":
                    result = self._ftp.mkdir(entry, remote_path, remote_root=remote_root)
                else:
                    result = self._ftp.rename(
                        entry, remote_path, new_remote_path, overwrite=overwrite,
                        remote_root=remote_root,
                    )
                if "files" in result:
                    outcome.update(files=result.get("files"), bytes=result.get("bytes"))
            return result
        except SSHBrokerError as exc:
            failed = self._ssh_error(exc)
            if credentials is not None and not credentials.encrypted:
                failed["warning"] = PLAIN_FTP_WARNING
            return failed

    def http_request(
        self,
        path: str,
        method: str,
        request_path: str,
        *,
        body: Optional[str] = None,
        headers: Optional[dict] = None,
        agent_name: str = "unknown",
    ) -> dict:
        """HTTP/API request to the entry's base_url with the entry's auth
        header, under the ``http`` action of its policy."""
        invalid = {"status": "error", "code": "invalid_request"}
        if not isinstance(method, str) or not method:
            return {**invalid, "error": "method is required."}
        if not isinstance(request_path, str) or not request_path:
            return {**invalid, "error": "request_path is required."}
        if body is not None and not isinstance(body, str):
            return {**invalid, "error": "body must be a string."}
        if headers is not None and not isinstance(headers, dict):
            return {**invalid, "error": "headers must be an object."}

        details: dict[str, Any] = {"method": method.upper(), "request_path": request_path}
        if headers:
            details["headers"] = headers
        if body is not None:
            details["body"] = body

        entry, error = self._authorize_action(path, "http", agent_name, details)
        if error:
            return error
        target = None
        try:
            target = HTTPTarget.from_entry(entry)
            verb, url_path = target.check(method, request_path)
            target.check_body(body, headers)
            with self._audited_ssh(
                entry, "request", kind="mcp_http", agent=agent_name, method=verb,
                url=audit_text(entry, target.origin + url_path), encrypted=target.encrypted,
                input_bytes=len(body.encode("utf-8")) if body is not None else 0,
            ) as outcome:
                result = self._http.request(
                    entry, verb, request_path, body=body, headers=headers
                )
                outcome.update(
                    http_status=result["http_status"],
                    response_bytes=len(result["body"].encode("utf-8")),
                )
            return result
        except SSHBrokerError as exc:
            failed = self._ssh_error(exc)
            if target is not None and not target.encrypted:
                failed["warning"] = PLAIN_HTTP_WARNING
            return failed

    def close(self) -> None:
        self._close_connections()

    def _action_totp(self, entry: dict) -> dict:
        """Generate TOTP code from stored seed. Agent gets only the 6 digits."""
        from ..totp import generate_totp, time_remaining

        for f in entry["fields"]:
            if f.get("field_type") == "totp" or f["key"].lower() in (
                "totp_secret", "totp", "otp",
            ):
                try:
                    code = generate_totp(f["value"])
                    remaining = time_remaining()
                    return {
                        "status": "ok",
                        "output": code,
                        "remaining_seconds": remaining,
                    }
                except Exception as e:
                    return {"status": "error", "error": f"TOTP generation failed: {e}"}

        return {"status": "error", "error": "No TOTP seed found in entry"}


class MCPError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)
