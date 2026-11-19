"""SSH operations for MCP agents without exposing vault credentials."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import posixpath
import stat
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

import paramiko

from .redact import RedactingStream, Redactor


DEFAULT_CONNECT_TIMEOUT = 15
DEFAULT_COMMAND_TIMEOUT = 60
MAX_COMMAND_TIMEOUT = 3600
MAX_COMMAND_BYTES = 4096
MAX_STDIN_BYTES = 4096
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TRANSFER_BYTES = 512 * 1024 * 1024
MAX_SESSIONS = 8
SESSION_IDLE_TIMEOUT = 15 * 60
# One approval never grants an unbounded shell.
SESSION_MAX_LIFETIME = 60 * 60
CUT_OFF_MESSAGE = "The SSH connection was cut off ('sezam ai off' or lock)."


class SSHBrokerError(Exception):
    """A safe-to-return SSH broker error."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class SSHCredentials:
    host: str
    port: int
    username: str
    password: Optional[str]
    private_key: Optional[str]
    passphrase: Optional[str]
    host_key_sha256: Optional[str]
    use_ssh_agent: bool
    # "AI SSH CA" entry (field ssh_ca): private_key is a CA key that only
    # 'sezam ssh-agent' uses, to certify ephemeral keys (TODO section 3).
    ssh_ca: bool = False
    cert_ttl_minutes: Optional[str] = None
    source_address: Optional[str] = None

    @classmethod
    def from_entry(cls, entry: dict) -> "SSHCredentials":
        fields = {
            _normalise_key(field["key"]): str(field.get("value", ""))
            for field in entry.get("fields", [])
        }

        host = _first(fields, "host", "hostname", "server", "address")
        username = _first(fields, "username", "user", "login")
        if not host or not username:
            raise SSHBrokerError(
                "invalid_entry", "SSH entry must contain host and username fields."
            )
        if any(char.isspace() for char in host) or "\x00" in host:
            raise SSHBrokerError("invalid_entry", "SSH host is invalid.")

        port_text = _first(fields, "port") or "22"
        try:
            port = int(port_text)
        except ValueError as exc:
            raise SSHBrokerError("invalid_entry", "SSH port must be a number.") from exc
        if not 1 <= port <= 65535:
            raise SSHBrokerError("invalid_entry", "SSH port must be between 1 and 65535.")

        password = _first(fields, "password", "ssh_password")
        private_key = _first(
            fields, "private_key", "privatekey", "ssh_private_key", "ssh_key"
        )
        passphrase = _first(fields, "passphrase", "key_passphrase")
        host_key_sha256 = _first(
            fields, "host_key_sha256", "host_fingerprint", "ssh_fingerprint"
        )
        use_ssh_agent = (_first(fields, "use_ssh_agent", "ssh_agent") or "").lower() in {
            "1", "true", "yes", "on"
        }

        if not password and not private_key and not use_ssh_agent:
            raise SSHBrokerError(
                "invalid_entry",
                "SSH entry must contain password or private_key, or explicitly enable use_ssh_agent.",
            )

        if host_key_sha256:
            host_key_sha256 = _normalise_fingerprint(host_key_sha256)

        return cls(
            host=host,
            port=port,
            username=username,
            password=password,
            private_key=private_key,
            passphrase=passphrase,
            host_key_sha256=host_key_sha256,
            use_ssh_agent=use_ssh_agent,
            ssh_ca=(_first(fields, "ssh_ca") or "").lower() in {"1", "true", "yes", "on"},
            cert_ttl_minutes=_first(fields, "cert_ttl_minutes"),
            source_address=_first(fields, "source_address"),
        )


class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected_fingerprint: str):
        self._expected = expected_fingerprint

    def missing_host_key(self, client, hostname, key) -> None:
        actual = _fingerprint(key)
        if not hmac.compare_digest(actual, self._expected):
            raise paramiko.BadHostKeyException(hostname, key, key)


@dataclass
class _Session:
    client: paramiko.SSHClient
    channel: paramiko.Channel
    owner: str
    entry_id: str
    created_at: float
    last_used_at: float
    max_lifetime: float
    # The entry's secrets never reach the agent through the output.
    stdout_filter: RedactingStream
    stderr_filter: RedactingStream


class SSHManager:
    """Owns SSH clients, interactive channels, and SFTP transfers."""

    def __init__(
        self,
        *,
        max_sessions: int = MAX_SESSIONS,
        session_idle_timeout: int = SESSION_IDLE_TIMEOUT,
        session_max_lifetime: int = SESSION_MAX_LIFETIME,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        max_transfer_bytes: int = MAX_TRANSFER_BYTES,
        transfer_root: Optional[Path] = None,
    ):
        self._max_sessions = max_sessions
        self._session_idle_timeout = session_idle_timeout
        self._session_max_lifetime = session_max_lifetime
        self._transfer_root = transfer_root
        self._max_output_bytes = max_output_bytes
        self._max_transfer_bytes = max_transfer_bytes
        self._sessions: dict[str, _Session] = {}
        # Clients of a running execute/upload/download: the kill switch
        # cuts them too, not only the interactive sessions.
        self._running: set = set()
        self._cut_generation = 0
        # The broker's kill switch, read once a client is connected.
        self.cut_check: Optional[Callable[[], bool]] = None
        self._lock = threading.RLock()
        self._reaper_thread: Optional[threading.Thread] = None

    def execute(
        self,
        entry: dict,
        command: str,
        *,
        timeout: int = DEFAULT_COMMAND_TIMEOUT,
        pty: bool = False,
        stdin: Optional[str] = None,
    ) -> dict:
        if not isinstance(command, str) or not command or "\x00" in command:
            raise SSHBrokerError("invalid_request", "command must be a non-empty string.")
        if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
            raise SSHBrokerError("invalid_request", "command is too large.")
        if stdin is not None and (
            not isinstance(stdin, str) or len(stdin.encode("utf-8")) > MAX_STDIN_BYTES
        ):
            raise SSHBrokerError("invalid_request", "stdin is too large.")
        timeout = _bounded_int(timeout, 1, MAX_COMMAND_TIMEOUT, "timeout")

        with self._running_client(entry) as client:
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise SSHBrokerError("connection_failed", "SSH connection is not active.")
            channel = transport.open_session(timeout=timeout)
            channel.settimeout(min(timeout, 30))
            if pty:
                channel.get_pty()
            channel.exec_command(command)
            if stdin is not None:
                channel.sendall(stdin.encode("utf-8"))
            channel.shutdown_write()
            stdout, stderr, truncated = self._read_command(channel, timeout)
            exit_code = channel.recv_exit_status()
            redactor = Redactor.for_entry(entry)
            stdout = redactor.redact(stdout, truncated=truncated)
            stderr = redactor.redact(stderr, truncated=truncated)
            return {
                "status": "ok",
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": exit_code,
                "truncated": truncated,
            }

    @contextmanager
    def _running_client(self, entry: dict) -> Iterator[paramiko.SSHClient]:
        """A connected client for one execute/upload/download, cut by
        ``close_all``: the operation then fails with ``cut_off`` instead of
        returning what it produced (also when the cut came while connecting)."""
        with self._lock:
            generation = self._cut_generation
        client = self._connect(SSHCredentials.from_entry(entry))
        with self._lock:
            self._running.add(client)
            if generation != self._cut_generation:
                client.sezam_cut_off = True
        # A cut before the generation was read (review 7c10379).
        if self.cut_check is not None and self.cut_check():
            client.sezam_cut_off = True
        try:
            if getattr(client, "sezam_cut_off", False):
                raise SSHBrokerError("cut_off", CUT_OFF_MESSAGE)
            yield client
        except Exception:
            if getattr(client, "sezam_cut_off", False):
                raise SSHBrokerError("cut_off", CUT_OFF_MESSAGE) from None
            raise
        else:
            if getattr(client, "sezam_cut_off", False):
                raise SSHBrokerError("cut_off", CUT_OFF_MESSAGE)
        finally:
            with self._lock:
                self._running.discard(client)
            client.close()

    def open_session(
        self,
        entry: dict,
        *,
        owner: str,
        term: str = "xterm-256color",
        width: int = 120,
        height: int = 40,
        max_lifetime: Optional[float] = None,
    ) -> dict:
        """Open an interactive shell; it is closed after ``max_lifetime``
        seconds (the entry's max_session_minutes) whatever its activity."""
        if not term or len(term) > 128 or any(c in term for c in "\r\n\x00"):
            raise SSHBrokerError("invalid_request", "Invalid terminal type.")
        width = _bounded_int(width, 20, 1000, "width")
        height = _bounded_int(height, 5, 500, "height")

        with self._lock:
            self._cleanup_expired_locked()
            if len(self._sessions) >= self._max_sessions:
                raise SSHBrokerError("session_limit", "Maximum SSH session count reached.")

        client = self._connect(SSHCredentials.from_entry(entry))
        try:
            channel = client.invoke_shell(term=term, width=width, height=height)
            channel.settimeout(0.0)
            now = time.monotonic()
            session_id = secrets_token()
            redactor = Redactor.for_entry(entry)
            session = _Session(
                client=client,
                channel=channel,
                owner=owner,
                entry_id=entry["id"],
                created_at=now,
                last_used_at=now,
                max_lifetime=(
                    self._session_max_lifetime if max_lifetime is None else max_lifetime
                ),
                stdout_filter=RedactingStream(redactor),
                stderr_filter=RedactingStream(redactor),
            )
            with self._lock:
                if len(self._sessions) >= self._max_sessions:
                    raise SSHBrokerError(
                        "session_limit", "Maximum SSH session count reached."
                    )
                self._sessions[session_id] = session
                self._ensure_reaper_locked()
            return {"status": "ok", "session_id": session_id}
        except Exception:
            client.close()
            raise

    def write_session(self, session_id: str, data: str, *, owner: str) -> dict:
        if not isinstance(data, str) or len(data.encode("utf-8")) > 1024 * 1024:
            raise SSHBrokerError("invalid_request", "Session input is too large.")
        session = self._get_session(session_id, owner)
        if session.channel.closed:
            self.close_session(session_id, owner=owner)
            raise SSHBrokerError("session_closed", "SSH session is closed.")
        encoded = data.encode("utf-8")
        session.channel.sendall(encoded)
        session.last_used_at = time.monotonic()
        return {"status": "ok", "bytes_written": len(encoded)}

    def read_session(
        self,
        session_id: str,
        *,
        owner: str,
        max_bytes: int = 65536,
        wait_ms: int = 0,
    ) -> dict:
        max_bytes = _bounded_int(max_bytes, 1, self._max_output_bytes, "max_bytes")
        wait_ms = _bounded_int(wait_ms, 0, 5000, "wait_ms")
        session = self._get_session(session_id, owner)
        deadline = time.monotonic() + wait_ms / 1000
        stdout = bytearray()
        stderr = bytearray()

        while True:
            progressed = False
            if session.channel.recv_ready() and len(stdout) < max_bytes:
                stdout.extend(session.channel.recv(min(65536, max_bytes - len(stdout))))
                progressed = True
            remaining = max_bytes - len(stdout) - len(stderr)
            if session.channel.recv_stderr_ready() and remaining > 0:
                stderr.extend(session.channel.recv_stderr(min(65536, remaining)))
                progressed = True
            if progressed or time.monotonic() >= deadline or session.channel.closed:
                break
            time.sleep(0.02)

        channel = session.channel
        # At the end of the stream nothing more can complete a held tail. A
        # closed channel may still hold buffered output, so it is not the end yet.
        final = (
            (bool(channel.closed) or channel.exit_status_ready())
            and not channel.recv_ready()
            and not channel.recv_stderr_ready()
        )
        out = session.stdout_filter.feed(bytes(stdout), final=final)
        err = session.stderr_filter.feed(bytes(stderr), final=final)
        return {
            "status": "ok",
            "stdout": out.decode("utf-8", errors="replace"),
            "stderr": err.decode("utf-8", errors="replace"),
            "closed": bool(session.channel.closed),
            "exit_code": session.channel.exit_status if session.channel.exit_status_ready() else None,
        }

    def resize_session(
        self, session_id: str, *, owner: str, width: int, height: int
    ) -> dict:
        width = _bounded_int(width, 20, 1000, "width")
        height = _bounded_int(height, 5, 500, "height")
        session = self._get_session(session_id, owner)
        session.channel.resize_pty(width=width, height=height)
        session.last_used_at = time.monotonic()
        return {"status": "ok"}

    def session_entry_id(self, session_id: str, *, owner: str) -> str:
        return self._get_session(session_id, owner).entry_id

    def session_age(self, session_id: str, *, owner: str) -> float:
        """Seconds since the session was opened."""
        return time.monotonic() - self._get_session(session_id, owner).created_at

    def close_session(self, session_id: str, *, owner: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.owner != owner:
                raise SSHBrokerError("session_not_found", "SSH session not found.")
            del self._sessions[session_id]
        _close_session(session)
        return {"status": "ok"}

    def upload(
        self,
        entry: dict,
        local_path: str,
        remote_path: str,
        *,
        recursive: bool = False,
        overwrite: bool = False,
        local_root: Optional[Path] = None,
        protected: Iterable[Path] = (),
        remote_root: Optional[str] = None,
    ) -> dict:
        root = self._local_root(local_root)
        source = _confine_local_path(root, local_path, protected)
        try:
            source_mode = os.lstat(source).st_mode
        except OSError:
            raise SSHBrokerError("local_not_found", "Local source does not exist.") from None
        if stat.S_ISDIR(source_mode) and not recursive:
            raise SSHBrokerError("recursive_required", "recursive=true is required for directories.")
        remote_path = confine_remote_path(remote_root, remote_path)

        with self._running_client(entry) as client:
            with client.open_sftp() as sftp:
                if remote_root is not None:
                    _require_no_remote_links(sftp, remote_root, remote_path)
                transferred = self._upload_path(
                    sftp, source, remote_path, recursive=recursive, overwrite=overwrite
                )
            return {"status": "ok", **transferred}

    def download(
        self,
        entry: dict,
        remote_path: str,
        local_path: str,
        *,
        recursive: bool = False,
        overwrite: bool = False,
        local_root: Optional[Path] = None,
        protected: Iterable[Path] = (),
        remote_root: Optional[str] = None,
    ) -> dict:
        remote_path = confine_remote_path(remote_root, remote_path)
        root = self._local_root(local_root)
        target = _confine_local_path(root, local_path, protected)

        with self._running_client(entry) as client:
            with client.open_sftp() as sftp:
                if remote_root is not None:
                    _require_no_remote_links(sftp, remote_root, remote_path)
                transferred = self._download_path(
                    sftp, remote_path, root, target, recursive=recursive, overwrite=overwrite
                )
            return {"status": "ok", **transferred}

    def _local_root(self, local_root: Optional[Path]) -> Path:
        """The entry's local_root policy, or the default transfer directory."""
        if local_root is None:
            root = self._transfer_root or default_transfer_root()
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            return root
        try:
            mode = os.lstat(local_root).st_mode
        except OSError:
            raise SSHBrokerError("local_root_missing", "The entry's local_root does not exist.") from None
        if not stat.S_ISDIR(mode):
            raise SSHBrokerError("local_root_missing", "The entry's local_root is not a directory.")
        return local_root

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def session_summaries(self) -> list[dict]:
        """Open sessions for the owner's overview: entry, agent, age."""
        now = time.monotonic()
        with self._lock:
            sessions = list(self._sessions.values())
        return [
            {
                "entry_id": s.entry_id,
                "agent": s.owner,
                "open_seconds": int(now - s.created_at),
                "idle_seconds": int(now - s.last_used_at),
            }
            for s in sessions
        ]

    def close_all(self) -> None:
        """Kill switch: every interactive session and every running
        execute/upload/download (they fail with ``cut_off``)."""
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            running = list(self._running)
            self._cut_generation += 1
            for client in running:
                client.sezam_cut_off = True
        for session in sessions:
            _close_session(session)
        for client in running:
            with suppress(Exception):
                client.close()

    def running_count(self) -> int:
        with self._lock:
            return len(self._running)

    def _connect(self, credentials: SSHCredentials) -> paramiko.SSHClient:
        if credentials.ssh_ca:
            # A CA key never authenticates itself; it only certifies
            # short-lived keys in 'sezam ssh-agent'.
            raise SSHBrokerError(
                "invalid_entry",
                "This entry holds an SSH CA key; only 'sezam ssh-agent' uses it.",
            )
        client = paramiko.SSHClient()
        if credentials.host_key_sha256:
            # A pinned fingerprint is authoritative: never consult known_hosts,
            # so the policy always runs during key exchange — before any
            # credential is sent to the server.
            client.set_missing_host_key_policy(
                _PinnedHostKeyPolicy(credentials.host_key_sha256)
            )
        else:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = _load_private_key(credentials.private_key, credentials.passphrase)
        try:
            client.connect(
                hostname=credentials.host,
                port=credentials.port,
                username=credentials.username,
                password=credentials.password,
                pkey=pkey,
                allow_agent=credentials.use_ssh_agent,
                look_for_keys=False,
                timeout=DEFAULT_CONNECT_TIMEOUT,
                banner_timeout=DEFAULT_CONNECT_TIMEOUT,
                auth_timeout=DEFAULT_CONNECT_TIMEOUT,
            )
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(30)
            if credentials.host_key_sha256:
                actual = _fingerprint(transport.get_remote_server_key()) if transport else ""
                if not hmac.compare_digest(actual, credentials.host_key_sha256):
                    raise SSHBrokerError("host_key_mismatch", "SSH host key does not match the pinned fingerprint.")
            return client
        except SSHBrokerError:
            client.close()
            raise
        except paramiko.AuthenticationException as exc:
            client.close()
            raise SSHBrokerError("authentication_failed", "SSH authentication failed.") from exc
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise SSHBrokerError("host_key_mismatch", "SSH host key verification failed.") from exc
        except paramiko.SSHException as exc:
            client.close()
            raise SSHBrokerError("connection_failed", "SSH connection failed securely.") from exc
        except OSError as exc:
            client.close()
            raise SSHBrokerError("connection_failed", "Could not reach the SSH server.") from exc

    def _read_command(self, channel: paramiko.Channel, timeout: int) -> tuple[bytes, bytes, bool]:
        deadline = time.monotonic() + timeout
        stdout = bytearray()
        stderr = bytearray()
        truncated = False
        while True:
            progressed = False
            if channel.recv_ready():
                chunk = channel.recv(65536)
                progressed = True
                if len(stdout) + len(stderr) < self._max_output_bytes:
                    room = self._max_output_bytes - len(stdout) - len(stderr)
                    stdout.extend(chunk[:room])
                    truncated |= len(chunk) > room
                else:
                    truncated = True
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                progressed = True
                if len(stdout) + len(stderr) < self._max_output_bytes:
                    room = self._max_output_bytes - len(stdout) - len(stderr)
                    stderr.extend(chunk[:room])
                    truncated |= len(chunk) > room
                else:
                    truncated = True
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() >= deadline:
                channel.close()
                raise SSHBrokerError("timeout", "SSH command timed out.")
            if not progressed:
                time.sleep(0.01)
        return bytes(stdout), bytes(stderr), truncated

    def _get_session(self, session_id: str, owner: str) -> _Session:
        with self._lock:
            self._cleanup_expired_locked()
            session = self._sessions.get(session_id)
            if session is None or session.owner != owner:
                raise SSHBrokerError("session_not_found", "SSH session not found.")
            # Only agent input (write/resize) counts as activity: polling the
            # output must not keep an idle shell alive.
            return session

    def _ensure_reaper_locked(self) -> None:
        if self._reaper_thread is not None and self._reaper_thread.is_alive():
            return
        self._reaper_thread = threading.Thread(
            target=self._reap_idle_sessions,
            name="sezam-ssh-session-reaper",
            daemon=True,
        )
        self._reaper_thread.start()

    def _reap_idle_sessions(self) -> None:
        shortest = min(self._session_idle_timeout, self._session_max_lifetime)
        interval = min(30.0, max(0.25, shortest / 4))
        while True:
            time.sleep(interval)
            with self._lock:
                self._cleanup_expired_locked()
                if not self._sessions:
                    self._reaper_thread = None
                    return

    def _cleanup_expired_locked(self) -> None:
        now = time.monotonic()
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if now - session.last_used_at > self._session_idle_timeout
            or now - session.created_at > session.max_lifetime
        ]
        for session_id in expired:
            _close_session(self._sessions.pop(session_id))

    def _upload_path(self, sftp, source: Path, remote_path: str, *, recursive: bool, overwrite: bool) -> dict:
        files = 0
        total = 0
        source_stat = os.lstat(source)
        if _is_link(source_stat):
            raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
        if not stat.S_ISDIR(source_stat.st_mode):
            with _open_local_source(source) as handle:
                size = os.fstat(handle.fileno()).st_size
                self._check_transfer_total(size)
                _ensure_remote_parent(sftp, remote_path)
                _check_remote_target(sftp, remote_path, overwrite)
                sftp.putfo(handle, remote_path, file_size=size)
            return {"files": 1, "bytes": size}

        base = source.resolve()
        _ensure_remote_directory(sftp, remote_path)
        for root, directories, filenames in os.walk(source, followlinks=False):
            root_path = Path(root)
            for name in list(directories):
                child = root_path / name
                if _path_is_link(child):
                    raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
                _require_within(child, base)
                relative = child.relative_to(source).as_posix()
                _ensure_remote_directory(sftp, posixpath.join(remote_path, relative))
            for name in filenames:
                child = root_path / name
                _require_within(child, base)
                with _open_local_source(child) as handle:
                    size = os.fstat(handle.fileno()).st_size
                    total += size
                    self._check_transfer_total(total)
                    relative = child.relative_to(source).as_posix()
                    destination = posixpath.join(remote_path, relative)
                    _check_remote_target(sftp, destination, overwrite)
                    sftp.putfo(handle, destination, file_size=size)
                files += 1
        return {"files": files, "bytes": total}

    def _download_path(
        self, sftp, remote_path: str, root: Path, target: Path, *, recursive: bool, overwrite: bool
    ) -> dict:
        try:
            attrs = sftp.lstat(remote_path)
        except OSError as exc:
            raise SSHBrokerError("remote_not_found", "Remote source does not exist.") from exc
        if stat.S_ISLNK(attrs.st_mode):
            raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
        if stat.S_ISREG(attrs.st_mode):
            self._check_transfer_total(attrs.st_size)
            _ensure_local_tree(root, target.parent)
            with _open_local_target(target, overwrite) as handle:
                sftp.getfo(remote_path, handle)
            return {"files": 1, "bytes": attrs.st_size}
        if not stat.S_ISDIR(attrs.st_mode):
            raise SSHBrokerError("unsupported_type", "Remote source is not a regular file or directory.")
        if not recursive:
            raise SSHBrokerError("recursive_required", "recursive=true is required for directories.")

        files = 0
        total = 0
        _ensure_local_tree(root, target)
        base = root.resolve()
        pending = [(remote_path, target)]
        while pending:
            remote_dir, local_dir = pending.pop()
            for child in sftp.listdir_attr(remote_dir):
                _validate_remote_child_name(child.filename)
                child_remote = posixpath.join(remote_dir, child.filename)
                child_local = local_dir / child.filename
                if stat.S_ISLNK(child.st_mode):
                    raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
                if stat.S_ISDIR(child.st_mode):
                    _ensure_local_dir(child_local)
                    _require_within(child_local, base)
                    pending.append((child_remote, child_local))
                elif stat.S_ISREG(child.st_mode):
                    total += child.st_size
                    self._check_transfer_total(total)
                    _require_within(child_local, base)
                    with _open_local_target(child_local, overwrite) as handle:
                        sftp.getfo(child_remote, handle)
                    files += 1
                else:
                    raise SSHBrokerError("unsupported_type", "Remote tree contains an unsupported file type.")
        return {"files": files, "bytes": total}

    def _check_transfer_total(self, total: int) -> None:
        if total > self._max_transfer_bytes:
            raise SSHBrokerError("transfer_too_large", "Transfer exceeds the configured size limit.")


def secrets_token() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


def _normalise_key(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def _first(fields: dict[str, str], *names: str) -> Optional[str]:
    for name in names:
        value = fields.get(name)
        if value:
            return value
    return None


def _normalise_fingerprint(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("sha256:"):
        value = value[7:]
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except ValueError as exc:
        raise SSHBrokerError("invalid_entry", "Invalid SSH host key fingerprint.") from exc
    if len(raw) != 32:
        raise SSHBrokerError("invalid_entry", "SSH host key fingerprint must be SHA-256.")
    return "SHA256:" + base64.b64encode(raw).decode("ascii").rstrip("=")


def _fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _load_private_key(value: Optional[str], passphrase: Optional[str]) -> Optional[paramiko.PKey]:
    if not value:
        return None
    errors = []
    for key_type in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_type.from_private_key(io.StringIO(value), password=passphrase)
        except (paramiko.SSHException, ValueError) as exc:
            errors.append(exc)
    raise SSHBrokerError("invalid_entry", "Stored SSH private key or passphrase is invalid.")


def _bounded_int(value: Any, minimum: int, maximum: int, name: str) -> int:
    if isinstance(value, bool):
        raise SSHBrokerError("invalid_request", f"{name} must be an integer.")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise SSHBrokerError("invalid_request", f"{name} must be an integer.") from exc
    if not minimum <= result <= maximum:
        raise SSHBrokerError(
            "invalid_request", f"{name} must be between {minimum} and {maximum}."
        )
    return result


def default_transfer_root() -> Path:
    """Only directory the MCP SSH tools may read from or write to locally."""
    configured = os.environ.get("SEZAM_MCP_TRANSFER_DIR")
    return Path(configured).expanduser() if configured else Path.home() / "SezamTransfers"


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
# Never a valid MCP transfer location, whatever the policy says.
_PROTECTED_HOME_DIRS = (".ssh", ".gnupg", ".sezam", ".aws", ".kube", ".config/gcloud")


def protected_local_paths(extra: Iterable[Path] = ()) -> list[Path]:
    home = Path.home()
    return [*(home / name for name in _PROTECTED_HOME_DIRS), *extra]


def _norm(path: Path) -> Path:
    return Path(os.path.normcase(os.path.abspath(path)))


def _overlaps(a: Path, b: Path) -> bool:
    """True if one path equals the other or lies inside it."""
    variants_a = {_norm(a), _norm(a.resolve())}
    variants_b = {_norm(b), _norm(b.resolve())}
    return any(x == y or y in x.parents or x in y.parents for x in variants_a for y in variants_b)


def validate_local_root(value: Any, protected: Iterable[Path] = ()) -> Path:
    """Validate an entry's ``local_root`` policy value (fail closed).

    It must be an absolute directory path that is neither the home directory,
    one of its ancestors, a filesystem root, nor overlapping the vault or a
    credential directory (``~/.ssh`` and similar).
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SSHBrokerError("policy_invalid", "local_root policy must be a non-empty string.")
    root = Path(value).expanduser()
    if not root.is_absolute():
        raise SSHBrokerError("policy_invalid", "local_root policy must be an absolute path.")
    root = Path(os.path.abspath(root))
    home = _norm(Path.home())
    for candidate in {_norm(root), _norm(root.resolve())}:
        if candidate == home or candidate in home.parents or candidate.parent == candidate:
            raise SSHBrokerError(
                "policy_invalid",
                "local_root must not be the home directory, one of its ancestors or a filesystem root.",
            )
    for path in protected_local_paths(protected):
        if _overlaps(root, path):
            raise SSHBrokerError(
                "policy_invalid", "local_root must not overlap the vault or a credential directory."
            )
    return root


def _confine_local_path(root: Path, local_path: str, protected: Iterable[Path] = ()) -> Path:
    """Map an agent-supplied local_path into the transfer root.

    Relative paths are relative to the root; anything resolving outside it
    (``~/.ssh/id_*``, the vault DB, ``~/.bashrc``) is refused, and so is any
    symbolic link below the root or any path overlapping a protected one.
    """
    if not isinstance(local_path, str) or not local_path or "\x00" in local_path:
        raise SSHBrokerError("invalid_request", "local_path must be a non-empty string.")
    root = Path(os.path.abspath(root))
    candidate = Path(local_path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        raise SSHBrokerError(
            "local_path_denied", f"local_path must be inside the transfer directory {root}."
        ) from None
    current = root
    for part in relative.parts:
        current = current / part
        if _path_is_link(current):
            raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
    resolved = candidate.resolve()
    if resolved != root.resolve() and root.resolve() not in resolved.parents:
        raise SSHBrokerError(
            "local_path_denied", f"local_path must be inside the transfer directory {root}."
        )
    for path in protected_local_paths(protected):
        if _overlaps(resolved, path):
            raise SSHBrokerError(
                "local_path_denied", "local_path overlaps the vault or a credential directory."
            )
    return resolved


_REPARSE_TAG_NAME_SURROGATE = 0x20000000


def _is_link(st: os.stat_result) -> bool:
    """True for a symlink or any Windows name-surrogate reparse point.

    Directory junctions and other mount points redirect like a symlink but
    lstat() reports them as plain directories (S_ISLNK is False), so the
    reparse attribute and tag must be checked too.
    """
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = getattr(st, "st_file_attributes", 0)
    if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return bool(getattr(st, "st_reparse_tag", 0) & _REPARSE_TAG_NAME_SURROGATE)
    return False


def _path_is_link(path: Path) -> bool:
    try:
        return _is_link(os.lstat(path))
    except FileNotFoundError:
        return False


def _require_within(path: Path, base: Path) -> None:
    """Refuse a path that, once every link is resolved, leaves ``base``."""
    resolved = path.resolve()
    if resolved != base and base not in resolved.parents:
        raise SSHBrokerError("symlink_denied", "Path leaves the transfer directory.")


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _open_local_source(path: Path):
    """Open a local regular file for reading without following symlinks.

    O_NOFOLLOW refuses a symlink as the last component where the OS has it;
    comparing lstat() before with fstat() after the open catches a swap on
    every platform.
    """
    try:
        before = os.lstat(path)
    except OSError:
        raise SSHBrokerError("local_not_found", "Local source does not exist.") from None
    if _is_link(before):
        raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
    if not stat.S_ISREG(before.st_mode):
        raise SSHBrokerError("unsupported_type", "Local source is not a regular file or directory.")
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY)
    except OSError:
        raise SSHBrokerError("symlink_denied", "Local source could not be opened safely.") from None
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or not _same_file(before, after):
            raise SSHBrokerError("symlink_denied", "Local source changed while it was opened.")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _open_local_target(path: Path, overwrite: bool):
    """Create or replace a local download target as an owner-only (0600) file.

    A symlink at the target is refused, never followed; a new file is created
    with O_EXCL so nothing can be planted between the check and the open.
    """
    flags = os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW | _O_BINARY
    try:
        before: Optional[os.stat_result] = os.lstat(path)
    except FileNotFoundError:
        before = None
    if before is not None:
        if _is_link(before):
            raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
        if not overwrite:
            raise SSHBrokerError("destination_exists", "Local destination already exists.")
        if not stat.S_ISREG(before.st_mode):
            raise SSHBrokerError("unsupported_type", "Local destination is not a regular file.")
    else:
        flags |= os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise SSHBrokerError("destination_exists", "Local destination already exists.") from None
    except OSError:
        raise SSHBrokerError("symlink_denied", "Local destination could not be opened safely.") from None
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or (before is not None and not _same_file(before, after)):
            raise SSHBrokerError("symlink_denied", "Local destination changed while it was opened.")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        os.ftruncate(fd, 0)
        return os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise


def _ensure_local_dir(path: Path) -> None:
    """Create an owner-only directory; an existing symlink is never entered."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if _is_link(st):
        raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
    if not stat.S_ISDIR(st.st_mode):
        raise SSHBrokerError("unsupported_type", "Local destination is not a directory.")


def _ensure_local_tree(root: Path, directory: Path) -> None:
    current = root.resolve()
    for part in Path(directory).relative_to(current).parts:
        current = current / part
        _ensure_local_dir(current)


def _validate_remote_child_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise SSHBrokerError("unsafe_remote_name", "Remote directory contains an unsafe name.")


def _validate_remote_path(path: str) -> None:
    if not isinstance(path, str) or not path or "\x00" in path or "\n" in path or "\r" in path:
        raise SSHBrokerError("invalid_request", "Invalid remote path.")


def validate_remote_root(value: Any) -> str:
    """Validate an entry's ``remote_root`` policy value (fail closed).

    An absolute POSIX directory without ``..``, returned normalised
    (``/var/www/./site/`` -> ``/var/www/site``).
    """
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or any(c in value for c in "\x00\r\n\\")
    ):
        raise SSHBrokerError("policy_invalid", "remote_root policy must be an absolute POSIX path.")
    if ".." in value.split("/"):
        raise SSHBrokerError("policy_invalid", "remote_root policy must not contain '..'.")
    return "/" + posixpath.normpath(value).lstrip("/")


def confine_remote_path(root: Optional[str], path: str) -> str:
    """Map an agent-supplied remote path into the entry's ``remote_root``.

    Without a root the path is only checked for control characters. With
    one, any ``..`` component is refused, a relative path is taken relative
    to the root and the normalised result must be the root or lie below it.
    """
    _validate_remote_path(path)
    if root is None:
        return path
    if "\\" in path or ".." in path.split("/"):
        raise SSHBrokerError("remote_path_denied", f"Remote path must stay inside {root}.")
    candidate = path if path.startswith("/") else posixpath.join(root, path)
    candidate = "/" + posixpath.normpath(candidate).lstrip("/")
    if candidate != root and not candidate.startswith(root.rstrip("/") + "/"):
        raise SSHBrokerError("remote_path_denied", f"Remote path must stay inside {root}.")
    return candidate


def _require_no_remote_links(sftp, root: str, path: str) -> None:
    """Refuse a remote path that passes through a symbolic link below the
    root (``<root>/link -> /etc``); components that do not exist yet end
    the walk."""
    current = root
    for part in [p for p in path[len(root):].split("/") if p]:
        current = posixpath.join(current, part)
        try:
            attrs = sftp.lstat(current)
        except OSError:
            return
        if stat.S_ISLNK(attrs.st_mode):
            raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")


def _check_remote_target(sftp, path: str, overwrite: bool) -> None:
    """An existing remote target is replaced only with ``overwrite`` and
    never when it is a symbolic link (the write would follow it)."""
    try:
        attrs = sftp.lstat(path)
    except OSError:
        return
    if stat.S_ISLNK(attrs.st_mode):
        raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
    if not overwrite:
        raise SSHBrokerError("destination_exists", "Remote destination already exists.")


def _ensure_remote_parent(sftp, path: str) -> None:
    parent = posixpath.dirname(path)
    if parent:
        _ensure_remote_directory(sftp, parent)


def _ensure_remote_directory(sftp, path: str) -> None:
    if not path or path == "/":
        return
    current = "/" if path.startswith("/") else ""
    for part in [part for part in path.split("/") if part]:
        current = posixpath.join(current, part) if current else part
        try:
            attrs = sftp.lstat(current)
            if not stat.S_ISDIR(attrs.st_mode):
                raise SSHBrokerError("destination_exists", "Remote destination is not a directory.")
        except OSError:
            sftp.mkdir(current)


def _close_session(session: _Session) -> None:
    try:
        session.channel.close()
    finally:
        session.client.close()
