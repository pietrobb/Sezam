"""MCP Server — exposes vault tools via MCP protocol.

Spec 7.3: Runs as part of desktop app process.
Auth: Unix socket / named pipe with filesystem permissions.
Optionally: per-session API token generated at startup.

Transports:
  - stdio (default): JSON-RPC over stdin/stdout
  - socket: Unix socket (Linux/Mac) or named pipe (Windows)
"""

from __future__ import annotations

import json
import logging
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from ..vault.crud import Vault
from .approval import ApprovalManager
from .broker import MCPBroker, MCPError
from .control import ACCEPT_BACKOFF_MAX, Admission, bind_unix_socket, serve_listener

# Review 1141a20 H7: bounds of the MCP endpoint (see _new_admission).
MCP_MAX_CONNECTIONS = 64
MCP_MAX_PEER_CONNECTIONS = 16
# Longest JSON-RPC line accepted (stdio, socket, pipe); a longer one is
# answered with an error and its connection closed instead of buffered.
MAX_LINE = 8 * 1024 * 1024
_TOO_LARGE_ERROR = {"id": None, "error": {"code": -32600, "message": "Request too large"}}
_TOO_LARGE = (json.dumps(_TOO_LARGE_ERROR) + "\n").encode("utf-8")


logger = logging.getLogger(__name__)


class SezamMCPServer:
    """MCP Server exposing vault tools.

    Tools include vault discovery/use plus credential-free SSH command,
    interactive session, and SFTP operations.
    """

    _MAX_PIPE_CONNECT_FAILURES = 10

    def __init__(self, vault: Vault, session_token: Optional[str] = None):
        self._vault = vault
        self._approval = ApprovalManager()
        self._broker = MCPBroker(vault, self._approval)
        self._session_token = session_token
        self._protocol_version = "2024-11-05"
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._activity_lock = threading.Lock()
        self._calls_in_flight = 0
        self._last_activity = time.monotonic()

    def mark_active(self) -> None:
        """Restart the idle timer (e.g. when the vault is unlocked again)."""
        with self._activity_lock:
            self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        """Seconds since the last tool call ended (0 while one is running)."""
        with self._activity_lock:
            if self._calls_in_flight:
                return 0.0
            return time.monotonic() - self._last_activity

    @property
    def approval_manager(self) -> ApprovalManager:
        return self._approval

    @property
    def broker(self) -> MCPBroker:
        return self._broker

    def get_tools(self) -> list[dict]:
        """Return MCP tool definitions."""
        return [
            {
                "name": "vault_list",
                "description": "List folders and entries at a path in the vault. Tier 2 entries are hidden.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Vault path (e.g. 'Servers/Hetzner'). Empty = root.",
                            "default": "",
                        },
                    },
                },
            },
            {
                "name": "vault_read",
                "description": "Read entry metadata or a specific field value. Tier 1 entries require approval.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Full path to entry (e.g. 'Servers/Hetzner/SSH Root')",
                        },
                        "field": {
                            "type": "string",
                            "description": "Field key to read (e.g. 'password'). Omit for metadata only.",
                        },
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "vault_search",
                "description": "Search vault entries by name, field keys, or tags.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "vault_use",
                "description": "Use a secret without seeing it. The vault broker performs the operation and returns only the result. Supported actions: totp_code.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Full path to entry"},
                        "action": {"type": "string", "description": "Action to perform"},
                        "params": {"type": "object", "description": "Action-specific parameters"},
                    },
                    "required": ["path", "action"],
                },
            },
            {
                "name": "ssh_execute",
                "description": "Execute a command over SSH using a Sezam entry. Credentials are never returned to the client.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Vault path to the SSH entry"},
                        "command": {"type": "string", "description": "Remote command"},
                        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 60},
                        "pty": {"type": "boolean", "default": False},
                        "stdin": {"type": "string", "description": "Optional standard input"},
                    },
                    "required": ["path", "command"],
                },
            },
            {
                "name": "ssh_session_open",
                "description": "Open an approved interactive SSH shell. The returned session is an expiring capability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "term": {"type": "string", "default": "xterm-256color"},
                        "width": {"type": "integer", "default": 120},
                        "height": {"type": "integer", "default": 40},
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "ssh_session_write",
                "description": "Write text to an existing Sezam SSH session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "data": {"type": "string"},
                    },
                    "required": ["session_id", "data"],
                },
            },
            {
                "name": "ssh_session_read",
                "description": "Read currently available output from an existing SSH session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "max_bytes": {"type": "integer", "default": 65536},
                        "wait_ms": {"type": "integer", "minimum": 0, "maximum": 5000, "default": 0},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "ssh_session_resize",
                "description": "Resize the pseudo-terminal of an existing SSH session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "width": {"type": "integer"},
                        "height": {"type": "integer"},
                    },
                    "required": ["session_id", "width", "height"],
                },
            },
            {
                "name": "ssh_session_close",
                "description": "Close an existing SSH session and destroy its capability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "string"}},
                    "required": ["session_id"],
                },
            },
            {
                "name": "ssh_upload",
                "description": "Upload a local file or directory over SFTP using Sezam credentials.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "local_path": {
                            "type": "string",
                            "description": "Path inside the Sezam transfer directory (~/SezamTransfers or SEZAM_MCP_TRANSFER_DIR); relative paths are resolved against it.",
                        },
                        "remote_path": {"type": "string"},
                        "recursive": {"type": "boolean", "default": False},
                        "overwrite": {"type": "boolean", "default": False},
                    },
                    "required": ["path", "local_path", "remote_path"],
                },
            },
            {
                "name": "ssh_download",
                "description": "Download a remote file or directory over SFTP using Sezam credentials.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "remote_path": {"type": "string"},
                        "local_path": {
                            "type": "string",
                            "description": "Path inside the Sezam transfer directory (~/SezamTransfers or SEZAM_MCP_TRANSFER_DIR); relative paths are resolved against it.",
                        },
                        "recursive": {"type": "boolean", "default": False},
                        "overwrite": {"type": "boolean", "default": False},
                    },
                    "required": ["path", "remote_path", "local_path"],
                },
            },
            {
                "name": "ftp",
                "description": (
                    "FTP/FTPS operation with a Sezam entry (for hostings without SSH). TLS is "
                    "mandatory unless the entry allows plain FTP; credentials are never returned. "
                    "delete removes one file or one empty directory."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Vault path to the FTP entry"},
                        "op": {
                            "type": "string",
                            "enum": ["list", "upload", "download", "delete", "mkdir", "rename"],
                        },
                        "remote_path": {"type": "string"},
                        "local_path": {
                            "type": "string",
                            "description": "upload/download: path inside the Sezam transfer directory (or the entry's local_root).",
                        },
                        "new_remote_path": {"type": "string", "description": "rename: the new name"},
                        "recursive": {"type": "boolean", "default": False},
                        "overwrite": {"type": "boolean", "default": False},
                    },
                    "required": ["path", "op", "remote_path"],
                },
            },
            {
                "name": "http_request",
                "description": (
                    "HTTP/API request to the base_url of a Sezam entry; the broker adds the "
                    "auth header (never returned) and enforces the entry's allowed methods and "
                    "path prefixes. Redirects are not followed."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Vault path to the HTTP entry"},
                        "method": {
                            "type": "string",
                            "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                        },
                        "request_path": {
                            "type": "string",
                            "description": "Path (and query) relative to the entry's base_url, e.g. /wp-json/wp/v2/posts?per_page=5",
                        },
                        "body": {"type": "string"},
                        "headers": {
                            "type": "object",
                            "description": "Only Accept, Content-Type, If-Match, If-None-Match.",
                            "additionalProperties": {"type": "string"},
                        },
                    },
                    "required": ["path", "method", "request_path"],
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, arguments: dict) -> dict:
        """Handle an MCP tool call. Returns result dict."""
        with self._activity_lock:
            self._calls_in_flight += 1
        try:
            return self._handle_tool_call(tool_name, arguments)
        finally:
            with self._activity_lock:
                self._calls_in_flight -= 1
                self._last_activity = time.monotonic()

    def _handle_tool_call(self, tool_name: str, arguments: dict) -> dict:
        try:
            if tool_name == "vault_list":
                return self._broker.vault_list(arguments.get("path", ""))

            elif tool_name == "vault_read":
                return self._broker.vault_read(
                    path=arguments["path"],
                    field=arguments.get("field"),
                )

            elif tool_name == "vault_search":
                return self._broker.vault_search(arguments["query"])

            elif tool_name == "vault_use":
                return self._broker.vault_use(
                    path=arguments["path"],
                    action=arguments["action"],
                    params=arguments.get("params"),
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_execute":
                return self._broker.ssh_execute(
                    path=arguments["path"],
                    command=arguments["command"],
                    timeout=arguments.get("timeout", 60),
                    pty=arguments.get("pty", False),
                    stdin=arguments.get("stdin"),
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_session_open":
                return self._broker.ssh_session_open(
                    path=arguments["path"],
                    term=arguments.get("term", "xterm-256color"),
                    width=arguments.get("width", 120),
                    height=arguments.get("height", 40),
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_session_write":
                return self._broker.ssh_session_write(
                    arguments["session_id"],
                    arguments["data"],
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_session_read":
                return self._broker.ssh_session_read(
                    arguments["session_id"],
                    max_bytes=arguments.get("max_bytes", 65536),
                    wait_ms=arguments.get("wait_ms", 0),
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_session_resize":
                return self._broker.ssh_session_resize(
                    arguments["session_id"],
                    arguments["width"],
                    arguments["height"],
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_session_close":
                return self._broker.ssh_session_close(
                    arguments["session_id"], agent_name="mcp-client"
                )

            elif tool_name == "ssh_upload":
                return self._broker.ssh_upload(
                    path=arguments["path"],
                    local_path=arguments["local_path"],
                    remote_path=arguments["remote_path"],
                    recursive=arguments.get("recursive", False),
                    overwrite=arguments.get("overwrite", False),
                    agent_name="mcp-client",
                )

            elif tool_name == "ssh_download":
                return self._broker.ssh_download(
                    path=arguments["path"],
                    remote_path=arguments["remote_path"],
                    local_path=arguments["local_path"],
                    recursive=arguments.get("recursive", False),
                    overwrite=arguments.get("overwrite", False),
                    agent_name="mcp-client",
                )

            elif tool_name == "ftp":
                return self._broker.ftp(
                    path=arguments["path"],
                    op=arguments["op"],
                    remote_path=arguments["remote_path"],
                    local_path=arguments.get("local_path"),
                    new_remote_path=arguments.get("new_remote_path"),
                    recursive=arguments.get("recursive", False),
                    overwrite=arguments.get("overwrite", False),
                    agent_name="mcp-client",
                )

            elif tool_name == "http_request":
                return self._broker.http_request(
                    path=arguments["path"],
                    method=arguments["method"],
                    request_path=arguments["request_path"],
                    body=arguments.get("body"),
                    headers=arguments.get("headers"),
                    agent_name="mcp-client",
                )

            else:
                return {"status": "error", "error": f"Unknown tool: {tool_name}"}

        except MCPError as exc:
            status = "ai_disabled" if exc.code == "ai_disabled" else "error"
            return {"status": status, "code": exc.code, "error": exc.message}
        except (KeyError, TypeError, ValueError):
            return {"status": "error", "code": "invalid_request", "error": "Invalid tool arguments."}
        except Exception:
            logger.exception("Unhandled MCP tool failure: %s", tool_name)
            return {
                "status": "error",
                "code": "operation_failed",
                "error": "The operation failed without exposing internal details.",
            }

    def _verify_token(self, request: dict) -> bool:
        """Verify per-session token if configured.

        Token is passed in the JSON-RPC request as params._token or in
        a top-level _token field.
        """
        if self._session_token is None:
            return True
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}
        token = request.get("_token") or params.get("_token")
        return isinstance(token, str) and secrets.compare_digest(token, self._session_token)

    def _dispatch_request(self, request: dict) -> Optional[dict]:
        """Dispatch one MCP JSON-RPC request; notifications return no response."""
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request"},
            }
        request_id = request.get("id")
        is_notification = "id" not in request

        def response(*, result=None, error=None) -> Optional[dict]:
            if is_notification:
                return None
            payload = {"jsonrpc": "2.0", "id": request_id}
            if error is not None:
                payload["error"] = error
            else:
                payload["result"] = result
            return payload

        if not self._verify_token(request):
            return response(error={"code": -32600, "message": "Invalid session token"})

        method = request.get("method", "")
        params = request.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return response(error={"code": -32600, "message": "Invalid Request"})

        if method == "initialize":
            requested_version = params.get("protocolVersion")
            if isinstance(requested_version, str) and len(requested_version) <= 32:
                self._protocol_version = requested_version
            return response(
                result={
                    "protocolVersion": self._protocol_version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "sezam", "version": "0.1.0"},
                    "instructions": (
                        "Use Sezam SSH tools instead of requesting passwords or private keys. "
                        "Tier 1 operations require local human approval."
                    ),
                }
            )
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return response(result={})
        if method == "tools/list":
            return response(result={"tools": self.get_tools()})
        if method == "tools/call":
            result = self.handle_tool_call(
                params.get("name", ""),
                params.get("arguments", {}),
            )
            return response(
                result={
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, ensure_ascii=False),
                        }
                    ],
                    "isError": result.get("status") == "error",
                }
            )
        return response(error={"code": -32601, "message": f"Unknown method: {method}"})

    def run_stdio(self) -> None:
        """Run MCP server on stdin/stdout (JSON-RPC style).

        Simple protocol for integration with Claude Code and other MCP clients.
        """
        self._running = True
        while self._running:
            # Review 1141a20 H7: a line is read up to MAX_LINE; the rest of a
            # longer one is skipped instead of held in memory.
            line = sys.stdin.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE and not line.endswith("\n"):
                while line and not line.endswith("\n"):
                    line = sys.stdin.readline(MAX_LINE + 1)
                sys.stdout.write(json.dumps(_TOO_LARGE_ERROR) + "\n")
                sys.stdout.flush()
                continue
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
                response = self._dispatch_request(request)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                sys.stderr.write("Invalid JSON request.\n")
            except Exception:
                logger.exception("Unhandled MCP stdio request failure")
                sys.stderr.write("MCP request failed.\n")

    def run_socket(self, socket_path: str, group: Optional[str] = None) -> None:
        """Run MCP server on a Unix socket (Linux/Mac) or named pipe (Windows).

        Spec 7.3: Filesystem permissions (0o600) restrict access to current user.
        Each connection is served on its own thread, its requests in order.
        Each connection reads newline-delimited JSON-RPC messages.

        Args:
            socket_path: Path for the Unix socket or named pipe.
            group: Also let this OS group connect (L2 broker).
        """
        if sys.platform == "win32":
            self._run_named_pipe(socket_path, group)
        else:
            self._run_unix_socket(socket_path, group)

    # Review a159e97: the socket and the pipe served one client at a time, so
    # a client that connected and stayed (or sent nothing) held back every
    # other one. Each connection now has its own thread.
    # Review 1141a20 M-AI3: and the calls of different connections run side
    # by side. A dispatch lock put them in one line, so one agent's slow
    # request, command or Tier 1 call waiting for the owner held back every
    # other client. The vault database keeps a transaction to its thread
    # (VaultDB._settle_transaction) and the managers lock their own state.
    _PIPE_UNLIMITED_INSTANCES = 255

    def _run_unix_socket(self, socket_path: str, group: Optional[str] = None) -> None:
        """Run on a Unix domain socket with 0o600 permissions (0o660 for
        ``group``) in a directory owned by us that nobody else can write."""
        path = Path(socket_path)
        self._server_socket = bind_unix_socket(path, group)
        self._server_socket.listen(16)
        self._server_socket.settimeout(1.0)  # Allow periodic check for shutdown
        self._running = True

        logger.info("MCP socket server listening on %s", socket_path)

        try:
            # Review 1141a20 H7: EMFILE ended this loop, and an agent with
            # unlimited connections took every descriptor the brake needs.
            serve_listener(
                self._server_socket, lambda: self._running, self._new_admission(group),
                self._serve_socket_client, "sezam-mcp", peers=bool(group),
            )
        finally:
            self._server_socket.close()
            # Clean up socket file
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass

    def _serve_socket_client(self, conn: socket.socket) -> None:
        logger.info("MCP client connected")
        try:
            self._handle_socket_connection(conn)
        except Exception as e:
            logger.error("Error handling MCP connection: %s", e)
        finally:
            conn.close()
            logger.info("MCP client disconnected")

    def _run_named_pipe(self, pipe_name: str, group: Optional[str] = None) -> None:
        """Run on a Windows named pipe.

        Named pipe path format: \\\\.\\pipe\\sezam_mcp
        Pipe security: explicit DACL granting only the current user's SID,
        FILE_FLAG_FIRST_PIPE_INSTANCE on the first instance (refuses a name
        another process already holds) and PIPE_REJECT_REMOTE_CLIENTS. The
        next instance is created before a connected one is handed to its
        thread or closed, so the name is never free for another process.
        Repeated connect failures back off and eventually stop instead of
        spinning.
        """
        import ctypes

        from . import winpipe

        buffer_size = 65536
        kernel32 = winpipe.load_kernel32()
        security = winpipe.OwnerOnlySecurity(group)

        if not pipe_name.startswith("\\\\.\\pipe\\"):
            pipe_name = f"\\\\.\\pipe\\{pipe_name}"
        self._pipe_name = pipe_name

        def create(first: bool):
            flags = winpipe.PIPE_ACCESS_DUPLEX
            if first:
                flags |= winpipe.FILE_FLAG_FIRST_PIPE_INSTANCE
            handle = kernel32.CreateNamedPipeW(
                pipe_name,
                flags,
                winpipe.PIPE_TYPE_BYTE | winpipe.PIPE_READMODE_BYTE
                | winpipe.PIPE_WAIT | winpipe.PIPE_REJECT_REMOTE_CLIENTS,
                self._PIPE_UNLIMITED_INSTANCES,
                buffer_size,
                buffer_size,
                0,
                ctypes.byref(security.attributes),
            )
            if handle in (None, 0, winpipe.INVALID_HANDLE_VALUE):
                logger.error(
                    "Failed to create named pipe %s (error %d); another process "
                    "may already own this name", pipe_name, ctypes.get_last_error(),
                )
                return None
            return handle

        self._running = True
        logger.info("MCP named pipe server listening on %s", pipe_name)
        admission = self._new_admission(group)
        failures = 0
        try:
            handle = create(first=True)
            while handle is not None:
                connected = kernel32.ConnectNamedPipe(handle, None)
                if not self._running:
                    kernel32.CloseHandle(handle)
                    break
                if not connected and ctypes.get_last_error() != winpipe.ERROR_PIPE_CONNECTED:
                    failures += 1
                    if failures >= self._MAX_PIPE_CONNECT_FAILURES:
                        kernel32.CloseHandle(handle)
                        logger.error(
                            "ConnectNamedPipe failed %d times in a row; stopping", failures
                        )
                        break
                    time.sleep(min(0.1 * (2 ** (failures - 1)), 5.0))
                    following = create(first=False)
                    kernel32.CloseHandle(handle)
                    handle = following
                    continue
                failures = 0
                following = create(first=False)
                self._start_pipe_client(kernel32, handle, buffer_size, admission, group)
                handle = following
                # Review 1141a20 H7: a failed instance (handles exhausted)
                # ended the server; it is retried. While no client holds an
                # instance it must be the first one again (no squatting).
                delay = 0.0
                while handle is None and self._running:
                    delay = min(max(2 * delay, 0.05), ACCEPT_BACKOFF_MAX)
                    time.sleep(delay)
                    handle = create(first=len(admission) == 0)
        finally:
            security.close()

    def _start_pipe_client(self, kernel32, handle, buffer_size: int, admission, group) -> None:
        from . import winpipe

        peer = winpipe.pipe_client_sid(handle) if group else None
        slot = admission.admit(peer, lambda: None)
        if slot is None:
            kernel32.DisconnectNamedPipe(handle)
            kernel32.CloseHandle(handle)
            return

        def run() -> None:
            try:
                self._serve_pipe_client(kernel32, handle, buffer_size)
            finally:
                admission.release(slot)

        try:
            threading.Thread(target=run, name="sezam-mcp-client", daemon=True).start()
        except RuntimeError:  # no thread left: drop this connection
            admission.release(slot)
            kernel32.DisconnectNamedPipe(handle)
            kernel32.CloseHandle(handle)
            logger.warning("MCP: no thread for a connection; dropped")
            time.sleep(0.05)

    @staticmethod
    def _new_admission(group: Optional[str]) -> Admission:
        """Review 1141a20 H7: at most MCP_MAX_CONNECTIONS agents' connections,
        MCP_MAX_PEER_CONNECTIONS from one OS user on a group socket; more are
        refused instead of taking descriptors the brake needs."""
        return Admission(
            MCP_MAX_CONNECTIONS, MCP_MAX_PEER_CONNECTIONS if group else None, evict=False
        )

    def _serve_pipe_client(self, kernel32, pipe_handle, buffer_size: int) -> None:
        logger.info("MCP pipe client connected")
        try:
            self._handle_pipe_connection(kernel32, pipe_handle, buffer_size)
        except Exception as e:
            logger.error("Error handling MCP pipe connection: %s", e)
        finally:
            kernel32.DisconnectNamedPipe(pipe_handle)
            kernel32.CloseHandle(pipe_handle)
            logger.info("MCP pipe client disconnected")
            if not self._running:
                self._wake_pipe()

    def _wake_pipe(self) -> None:
        """Return the pipe loop from its ConnectNamedPipe() after a stop."""
        name = getattr(self, "_pipe_name", None)
        if name:
            try:
                open(name, "r+b", buffering=0).close()
            except OSError:
                pass

    def _handle_socket_connection(self, conn: socket.socket) -> None:
        """Handle a single Unix socket connection.

        Reads newline-delimited JSON-RPC messages.
        """
        conn.settimeout(300)  # 5 min idle timeout
        buffer = b""

        while self._running:
            try:
                data = conn.recv(65536)
                if not data:
                    break
                buffer += data
                if len(buffer) > MAX_LINE and b"\n" not in buffer:
                    conn.sendall(_TOO_LARGE)
                    break

                # Process complete lines
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line_str = line.decode("utf-8").strip()
                    if not line_str:
                        continue

                    try:
                        request = json.loads(line_str)
                        response = self._dispatch_request(request)
                        if response is not None:
                            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                    except json.JSONDecodeError:
                        error_resp = {
                            "id": None,
                            "error": {"code": -32700, "message": "Parse error"},
                        }
                        conn.sendall((json.dumps(error_resp) + "\n").encode("utf-8"))

            except socket.timeout:
                break
            except (ConnectionResetError, BrokenPipeError):
                break

    def _handle_pipe_connection(self, kernel32, pipe_handle, buffer_size: int) -> None:
        """Handle a single Windows named pipe connection."""
        import ctypes
        import ctypes.wintypes

        buffer = b""
        read_buf = ctypes.create_string_buffer(buffer_size)
        bytes_read = ctypes.wintypes.DWORD(0)

        while self._running:
            success = kernel32.ReadFile(
                pipe_handle,
                read_buf,
                buffer_size,
                ctypes.byref(bytes_read),
                None,
            )

            if not success or bytes_read.value == 0:
                break

            buffer += read_buf.raw[: bytes_read.value]
            if len(buffer) > MAX_LINE and b"\n" not in buffer:
                kernel32.WriteFile(
                    pipe_handle, _TOO_LARGE, len(_TOO_LARGE),
                    ctypes.byref(ctypes.wintypes.DWORD(0)), None,
                )
                break

            # Process complete lines
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line_str = line.decode("utf-8").strip()
                if not line_str:
                    continue

                try:
                    request = json.loads(line_str)
                    response = self._dispatch_request(request)
                    if response is not None:
                        response_bytes = (json.dumps(response) + "\n").encode("utf-8")
                        bytes_written = ctypes.wintypes.DWORD(0)
                        kernel32.WriteFile(
                            pipe_handle,
                            response_bytes,
                            len(response_bytes),
                            ctypes.byref(bytes_written),
                            None,
                        )
                except json.JSONDecodeError:
                    error_resp = {
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    }
                    resp_bytes = (json.dumps(error_resp) + "\n").encode("utf-8")
                    bw = ctypes.wintypes.DWORD(0)
                    kernel32.WriteFile(pipe_handle, resp_bytes, len(resp_bytes), ctypes.byref(bw), None)

    def stop(self) -> None:
        """Stop the MCP server."""
        self._running = False
        self._approval.clear_all()
        self._broker.close()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        self._wake_pipe()

    @staticmethod
    def generate_session_token() -> str:
        """Generate a cryptographically random session token."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def default_socket_path() -> str:
        """Return the default socket/pipe path for the current platform."""
        if sys.platform == "win32":
            return "\\\\.\\pipe\\sezam_mcp"
        else:
            from .control import configured_run_dir

            return str(configured_run_dir() / "sezam_mcp.sock")
