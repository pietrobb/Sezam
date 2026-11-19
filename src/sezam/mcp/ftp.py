"""FTP/FTPS transfers for the AI broker (AI broker TODO, section 6).

For hostings without SSH. TLS is mandatory by default:

* ``ftps_mode: explicit`` (default) - ``AUTH TLS`` before ``USER``/``PASS``,
  then ``PBSZ 0`` + ``PROT P`` so the data channel is encrypted as well;
* ``ftps_mode: implicit`` - TLS from the first byte (port 990 by default).

The server certificate is verified (``ssl.create_default_context()``, host
name included); ``tls_ca_cert`` in the entry (PEM) trusts that CA or
self-signed certificate instead of the system store. If TLS cannot be set
up the connection fails before the password is sent - there is never a
fallback to plain FTP. Plain FTP needs the explicit entry field
``allow_plain_ftp: true``, and every result then carries a warning that the
password crossed the network unencrypted.

Remote paths share the transfer policies of the SSH tools: ``remote_root``
confinement, ``local_root`` and the protected local paths, the size limit,
symlink refusal and timeouts. Errors are ``SSHBrokerError`` so the broker
reports them the same way.
"""

from __future__ import annotations

import ftplib
import os
import posixpath
import socket
import ssl
import stat
import threading
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

from .ssh import (
    DEFAULT_CONNECT_TIMEOUT,
    MAX_TRANSFER_BYTES,
    SSHBrokerError,
    _confine_local_path,
    _ensure_local_tree,
    _first,
    _is_link,
    _normalise_key,
    _open_local_source,
    _open_local_target,
    _path_is_link,
    _require_within,
    _validate_remote_child_name,
    confine_remote_path,
    default_transfer_root,
)

DEFAULT_OPERATION_TIMEOUT = 60
MAX_LIST_ENTRIES = 10_000
PLAIN_FTP_WARNING = (
    "Plain FTP (allow_plain_ftp): the password and all data crossed the "
    "network unencrypted."
)
_TRUE = {"true", "1", "yes", "on"}


def _clean(value: str) -> bool:
    return not any(c in value for c in "\r\n\x00")


@dataclass(frozen=True)
class FTPCredentials:
    host: str
    port: int
    username: str
    password: str
    mode: str  # "explicit" | "implicit" | "plain"
    ca_pem: Optional[str] = None

    def __repr__(self) -> str:  # never the password
        return f"FTPCredentials({self.username}@{self.host}:{self.port}, {self.mode})"

    @property
    def encrypted(self) -> bool:
        return self.mode != "plain"

    @classmethod
    def from_entry(cls, entry: dict) -> "FTPCredentials":
        fields = {
            _normalise_key(field["key"]): str(field.get("value", ""))
            for field in entry.get("fields", [])
        }
        host = _first(fields, "host", "hostname", "server", "address")
        username = _first(fields, "username", "user", "login")
        password = _first(fields, "password", "ftp_password")
        if not host or not username or not password:
            raise SSHBrokerError(
                "invalid_entry", "FTP entry must contain host, username and password fields."
            )
        if any(char.isspace() for char in host) or "\x00" in host:
            raise SSHBrokerError("invalid_entry", "FTP host is invalid.")
        if not _clean(username) or not _clean(password):
            raise SSHBrokerError("invalid_entry", "FTP username or password contains a line break.")

        plain = fields.get("allow_plain_ftp", "").strip().lower()
        mode_text = fields.get("ftps_mode", "").strip().lower()
        if plain in _TRUE:
            if mode_text:
                raise SSHBrokerError(
                    "invalid_entry", "allow_plain_ftp cannot be combined with ftps_mode."
                )
            mode = "plain"
        elif plain not in ("", "false", "0", "no", "off"):
            raise SSHBrokerError("invalid_entry", "allow_plain_ftp must be true or false.")
        elif mode_text in ("", "explicit"):
            mode = "explicit"
        elif mode_text == "implicit":
            mode = "implicit"
        else:
            raise SSHBrokerError("invalid_entry", "ftps_mode must be explicit or implicit.")

        port_text = _first(fields, "port") or ("990" if mode == "implicit" else "21")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise SSHBrokerError("invalid_entry", "FTP port must be a number.") from exc
        if not 1 <= port <= 65535:
            raise SSHBrokerError("invalid_entry", "FTP port must be between 1 and 65535.")
        ca_pem = _first(fields, "tls_ca_cert", "ftps_ca_cert") if mode != "plain" else None
        return cls(host, port, username, password, mode, ca_pem)


class _FTPS(ftplib.FTP_TLS):
    """Explicit FTPS whose data channels resume the control channel's TLS
    session (servers such as vsftpd and ProFTPD require that)."""

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            session = getattr(self.sock, "session", None)
            conn = self.context.wrap_socket(conn, server_hostname=self.host, session=session)
        return conn, size


class _ImplicitFTPS(_FTPS):
    """FTPS with TLS from the first byte (``ftps_mode: implicit``)."""

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        self.host, self.port = host, port
        if timeout != -999:
            self.timeout = timeout
        sock = socket.create_connection((host, port), self.timeout)
        self.af = sock.family
        try:
            self.sock = self.context.wrap_socket(sock, server_hostname=host)
        except BaseException:
            sock.close()
            raise
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome


def _tls_context(ca_pem: Optional[str]) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    except (ssl.SSLError, ValueError) as exc:
        raise SSHBrokerError("invalid_entry", "tls_ca_cert is not a valid PEM certificate.") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class FTPManager:
    """FTP/FTPS operations for the MCP broker. A fresh connection per call."""

    def __init__(
        self,
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        operation_timeout: float = DEFAULT_OPERATION_TIMEOUT,
        max_transfer_bytes: int = MAX_TRANSFER_BYTES,
        transfer_root: Optional[Path] = None,
    ):
        self._connect_timeout = connect_timeout
        self._operation_timeout = operation_timeout
        self._max_transfer_bytes = max_transfer_bytes
        self._transfer_root = transfer_root
        self._lock = threading.Lock()
        self._open: set = set()
        # The broker's kill switch, read once the connection stands and again
        # after login: a cut while connecting found no socket, one before the
        # connection was registered found nothing (review 7c10379).
        self.cut_check: Optional[Callable[[], bool]] = None

    def _check_cut(self, ftp) -> None:
        if getattr(ftp, "sezam_cut_off", False) or (self.cut_check is not None and self.cut_check()):
            ftp.sezam_cut_off = True
            raise SSHBrokerError("cut_off", "The FTP connection was cut off ('sezam ai off' or lock).")

    def close_all(self) -> None:
        """Kill switch: cut every connection still running (a transfer in
        progress fails instead of finishing)."""
        with self._lock:
            connections = list(self._open)
        for ftp in connections:
            ftp.sezam_cut_off = True
            sock = getattr(ftp, "sock", None)
            if sock is not None:
                with suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
            with suppress(Exception):
                ftp.close()

    def active_count(self) -> int:
        with self._lock:
            return len(self._open)

    # ── connection ──

    @contextmanager
    def _connect(self, credentials: FTPCredentials) -> Iterator[ftplib.FTP]:
        if credentials.mode == "plain":
            ftp: ftplib.FTP = ftplib.FTP(timeout=self._connect_timeout)
        else:
            cls = _ImplicitFTPS if credentials.mode == "implicit" else _FTPS
            ftp = cls(context=_tls_context(credentials.ca_pem), timeout=self._connect_timeout)
        with self._lock:
            self._open.add(ftp)
        try:
            try:
                ftp.connect(credentials.host, credentials.port)
                if credentials.mode == "explicit":
                    # Before USER/PASS; a refusal or a bad certificate ends
                    # here, the password is never sent.
                    ftp.auth()
            except ssl.SSLCertVerificationError as exc:
                raise SSHBrokerError(
                    "tls_verify_failed", "The FTP server's TLS certificate could not be verified."
                ) from exc
            except ftplib.error_perm as exc:
                raise SSHBrokerError(
                    "tls_unavailable",
                    "The FTP server does not offer TLS (AUTH TLS refused); plain FTP needs allow_plain_ftp.",
                ) from exc
            except ssl.SSLError as exc:
                raise SSHBrokerError("tls_failed", "TLS handshake with the FTP server failed.") from exc
            except (socket.timeout, TimeoutError) as exc:
                raise SSHBrokerError("timeout", "FTP connection timed out.") from exc
            except (OSError, EOFError, ftplib.Error) as exc:
                raise SSHBrokerError("connection_failed", "Could not connect to the FTP server.") from exc
            self._check_cut(ftp)  # before the password is sent
            try:
                ftp.login(credentials.username, credentials.password)
            except ftplib.error_perm as exc:
                raise SSHBrokerError("auth_failed", "FTP login failed.") from exc
            except (OSError, EOFError, ftplib.Error) as exc:
                raise SSHBrokerError("connection_failed", "FTP login failed.") from exc
            try:
                if credentials.encrypted:
                    ftp.prot_p()
                ftp.sock.settimeout(self._operation_timeout)
            except (OSError, EOFError, ftplib.Error) as exc:
                raise SSHBrokerError("tls_failed", "Could not protect the FTP data channel.") from exc
            self._check_cut(ftp)
            yield ftp
        except BaseException as exc:
            if getattr(ftp, "sezam_cut_off", False):
                raise SSHBrokerError(
                    "cut_off", "The FTP connection was cut off ('sezam ai off' or lock)."
                ) from exc
            if isinstance(exc, SSHBrokerError):
                raise
            if isinstance(exc, ftplib.error_perm):
                raise SSHBrokerError("ftp_refused", _reply(exc)) from exc
            if isinstance(exc, (socket.timeout, TimeoutError)):
                raise SSHBrokerError("timeout", "FTP operation timed out.") from exc
            if isinstance(exc, (OSError, EOFError, ftplib.Error)):
                raise SSHBrokerError("ftp_error", _reply(exc)) from exc
            raise
        finally:
            with self._lock:
                self._open.discard(ftp)
            with suppress(Exception):
                ftp.close()

    @staticmethod
    def _result(credentials: FTPCredentials, **values) -> dict:
        result = {"status": "ok", **values}
        if not credentials.encrypted:
            result["warning"] = PLAIN_FTP_WARNING
        return result

    def _local_root(self, local_root: Optional[Path]) -> Path:
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

    def _check_total(self, total: int) -> None:
        if total > self._max_transfer_bytes:
            raise SSHBrokerError("transfer_too_large", "Transfer exceeds the configured size limit.")

    # ── operations ──

    def list(self, entry: dict, remote_path: str, *, remote_root: Optional[str] = None) -> dict:
        credentials = FTPCredentials.from_entry(entry)
        path = confine_remote_path(remote_root, remote_path)
        with self._connect(credentials) as ftp:
            _require_no_links(ftp, remote_root, path)
            entries = []
            for name, kind, facts in _children(ftp, path):
                if len(entries) >= MAX_LIST_ENTRIES:
                    return self._result(credentials, path=path, entries=entries, truncated=True)
                item = {"name": name, "type": kind}
                if facts.get("size", "").isdigit():
                    item["size"] = int(facts["size"])
                if facts.get("modify"):
                    item["modify"] = facts["modify"]
                entries.append(item)
        return self._result(credentials, path=path, entries=entries, truncated=False)

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
        credentials = FTPCredentials.from_entry(entry)
        root = self._local_root(local_root)
        source = _confine_local_path(root, local_path, protected)
        try:
            source_stat = os.lstat(source)
        except OSError:
            raise SSHBrokerError("local_not_found", "Local source does not exist.") from None
        if _is_link(source_stat):
            raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
        is_dir = stat.S_ISDIR(source_stat.st_mode)
        if is_dir and not recursive:
            raise SSHBrokerError("recursive_required", "recursive=true is required for directories.")
        path = confine_remote_path(remote_root, remote_path)

        with self._connect(credentials) as ftp:
            _require_no_links(ftp, remote_root, path)
            if not is_dir:
                with _open_local_source(source) as handle:
                    size = os.fstat(handle.fileno()).st_size
                    self._check_total(size)
                    _ensure_remote_parent(ftp, path)
                    _check_target(ftp, path, overwrite)
                    ftp.storbinary(f"STOR {path}", handle, callback=lambda _block: _stop_if_cut(ftp))
                return self._result(credentials, files=1, bytes=size)

            files = total = 0
            base = source.resolve()
            _ensure_remote_dir(ftp, path)
            for directory, dirnames, filenames in os.walk(source, followlinks=False):
                current = Path(directory)
                for name in dirnames:
                    child = current / name
                    if _path_is_link(child):
                        raise SSHBrokerError("symlink_denied", "Symbolic links are not transferred.")
                    _require_within(child, base)
                    _ensure_remote_dir(ftp, posixpath.join(path, child.relative_to(source).as_posix()))
                for name in filenames:
                    child = current / name
                    _require_within(child, base)
                    with _open_local_source(child) as handle:
                        total += os.fstat(handle.fileno()).st_size
                        self._check_total(total)
                        target = posixpath.join(path, child.relative_to(source).as_posix())
                        _check_target(ftp, target, overwrite)
                        ftp.storbinary(f"STOR {target}", handle, callback=lambda _block: _stop_if_cut(ftp))
                    files += 1
        return self._result(credentials, files=files, bytes=total)

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
        credentials = FTPCredentials.from_entry(entry)
        path = confine_remote_path(remote_root, remote_path)
        root = self._local_root(local_root)
        target = _confine_local_path(root, local_path, protected)

        with self._connect(credentials) as ftp:
            _require_no_links(ftp, remote_root, path)
            kind = _remote_kind(ftp, path)
            if kind is None:
                raise SSHBrokerError("remote_not_found", "Remote source does not exist.")
            if kind == "file":
                _ensure_local_tree(root, target.parent)
                size = self._retrieve(ftp, path, target, overwrite, 0)
                return self._result(credentials, files=1, bytes=size)
            if kind != "dir":
                raise SSHBrokerError("unsupported_type", "Remote source is not a regular file or directory.")
            if not recursive:
                raise SSHBrokerError("recursive_required", "recursive=true is required for directories.")

            files = total = 0
            _ensure_local_tree(root, target)
            base = root.resolve()
            pending = [(path, target)]
            while pending:
                remote_dir, local_dir = pending.pop()
                for name, child_kind, _facts in list(_children(ftp, remote_dir)):
                    _validate_remote_child_name(name)
                    child_remote = posixpath.join(remote_dir, name)
                    child_local = local_dir / name
                    if child_kind == "dir":
                        _ensure_local_tree(root, child_local)
                        _require_within(child_local, base)
                        pending.append((child_remote, child_local))
                    elif child_kind == "file":
                        _require_within(child_local, base)
                        total += self._retrieve(ftp, child_remote, child_local, overwrite, total)
                        files += 1
                    else:
                        raise SSHBrokerError(
                            "unsupported_type", "Remote tree contains an unsupported file type."
                        )
        return self._result(credentials, files=files, bytes=total)

    def _retrieve(self, ftp, path: str, target: Path, overwrite: bool, so_far: int) -> int:
        """RETR into an owner-only local file, stopping at the size limit or
        at the kill switch (nothing of a cut download is kept)."""
        received = 0

        with _open_local_target(target, overwrite) as handle:
            def write(chunk: bytes) -> None:
                nonlocal received
                _stop_if_cut(ftp)
                received += len(chunk)
                self._check_total(so_far + received)
                handle.write(chunk)

            try:
                ftp.retrbinary(f"RETR {path}", write)
            except BaseException as exc:
                if isinstance(exc, SSHBrokerError) or getattr(ftp, "sezam_cut_off", False):
                    handle.truncate(0)
                raise
        return received

    def delete(self, entry: dict, remote_path: str, *, remote_root: Optional[str] = None) -> dict:
        """Delete one file, or one empty directory (never recursively)."""
        credentials = FTPCredentials.from_entry(entry)
        path = confine_remote_path(remote_root, remote_path)
        if remote_root is not None and path == remote_root:
            raise SSHBrokerError("remote_path_denied", "remote_root itself cannot be deleted.")
        with self._connect(credentials) as ftp:
            _require_no_links(ftp, remote_root, path)
            kind = _remote_kind(ftp, path)
            if kind == "file":
                ftp.delete(path)
            elif kind == "dir":
                ftp.rmd(path)
            elif kind is None:
                raise SSHBrokerError("remote_not_found", "Remote path does not exist.")
            else:
                raise SSHBrokerError("unsupported_type", "Remote path is not a file or directory.")
        return self._result(credentials, deleted=path, type=kind)

    def mkdir(self, entry: dict, remote_path: str, *, remote_root: Optional[str] = None) -> dict:
        credentials = FTPCredentials.from_entry(entry)
        path = confine_remote_path(remote_root, remote_path)
        with self._connect(credentials) as ftp:
            _require_no_links(ftp, remote_root, path)
            _ensure_remote_dir(ftp, path)
        return self._result(credentials, created=path)

    def rename(
        self,
        entry: dict,
        remote_path: str,
        new_remote_path: str,
        *,
        overwrite: bool = False,
        remote_root: Optional[str] = None,
    ) -> dict:
        credentials = FTPCredentials.from_entry(entry)
        source = confine_remote_path(remote_root, remote_path)
        target = confine_remote_path(remote_root, new_remote_path)
        if remote_root is not None and remote_root in (source, target):
            raise SSHBrokerError("remote_path_denied", "remote_root itself cannot be renamed.")
        with self._connect(credentials) as ftp:
            _require_no_links(ftp, remote_root, source)
            _require_no_links(ftp, remote_root, target)
            if _remote_kind(ftp, source) not in ("file", "dir"):
                raise SSHBrokerError("remote_not_found", "Remote source does not exist.")
            _check_target(ftp, target, overwrite)
            ftp.rename(source, target)
        return self._result(credentials, renamed=source, to=target)


# ── remote helpers ──


def _stop_if_cut(ftp) -> None:
    """Review 7c10379 (R7-H): close_all() shuts the control connection only;
    a server that keeps the data channel going let a transfer run to its
    end after 'sezam ai off'. Every block now checks the cut."""
    if getattr(ftp, "sezam_cut_off", False):
        raise SSHBrokerError("cut_off", "The FTP connection was cut off ('sezam ai off' or lock).")


def _reply(exc: BaseException) -> str:
    """Server reply text for the agent: one line, bounded, no control chars."""
    text = " ".join(str(exc).split())[:200]
    return f"FTP server refused: {text}" if text else "FTP operation failed."


def _unsupported(exc: ftplib.error_perm) -> bool:
    return str(exc)[:3] in ("500", "501", "502", "504")


def _kind_of(facts_type: str) -> str:
    value = facts_type.strip().lower()
    if value in ("file", "dir"):
        return value
    return "dir" if value in ("cdir", "pdir") else "other"


def _remote_kind(ftp, path: str) -> Optional[str]:
    """'file', 'dir', 'other' (a type the server reports for links, devices,
    ...) or None if absent. MLST (RFC 3659); servers without it (vsftpd)
    are asked with SIZE and CWD."""
    try:
        reply = ftp.sendcmd(f"MLST {path}")
    except ftplib.error_perm as exc:
        if _unsupported(exc):
            return _kind_without_mlst(ftp, path)
        return None
    for line in reply.splitlines()[1:]:
        facts = line.strip().split(" ", 1)[0]
        for fact in facts.split(";"):
            key, _, value = fact.partition("=")
            if key.strip().lower() == "type":
                return _kind_of(value)
    return "other"


def _kind_without_mlst(ftp, path: str) -> Optional[str]:
    try:
        ftp.voidcmd("TYPE I")
        ftp.size(path)
        return "file"
    except ftplib.error_perm:
        pass
    try:
        here = ftp.pwd()
        ftp.cwd(path)
    except ftplib.error_perm:
        return None
    ftp.cwd(here)
    return "dir"


def _children(ftp, path: str) -> Iterator[tuple[str, str, dict]]:
    """(name, kind, facts) of a directory's entries: MLSD, or NLST plus a
    per-entry type query on servers without it."""
    try:
        listing = list(ftp.mlsd(path, facts=["type", "size", "modify"]))
    except ftplib.error_perm as exc:
        if not _unsupported(exc):
            raise
        listing = None
    if listing is not None:
        for name, facts in listing:
            if facts.get("type", "").lower() in ("cdir", "pdir") or name in (".", ".."):
                continue
            yield name, _kind_of(facts.get("type", "")), facts
        return
    for raw in ftp.nlst(path):
        name = posixpath.basename(raw.rstrip("/"))
        if name in ("", ".", ".."):
            continue
        _validate_remote_child_name(name)
        yield name, _remote_kind(ftp, posixpath.join(path, name)) or "other", {}


def _require_no_links(ftp, root: Optional[str], path: str) -> None:
    """Below ``remote_root`` every existing component must be a directory
    (the last one a file or directory). A server that reports a symbolic
    link as such (``type=OS.unix=slink``) is refused; many servers report
    the link target's type instead, there only their own chroot holds."""
    if root is None:
        return
    current = root
    parts = [p for p in path[len(root):].split("/") if p]
    for index, part in enumerate(parts):
        current = posixpath.join(current, part)
        kind = _remote_kind(ftp, current)
        if kind is None:
            return
        if kind == "other" or (kind == "file" and index < len(parts) - 1):
            raise SSHBrokerError("symlink_denied", "Remote path is not a plain file or directory.")


def _check_target(ftp, path: str, overwrite: bool) -> None:
    kind = _remote_kind(ftp, path)
    if kind is None:
        return
    if kind != "file":
        raise SSHBrokerError("destination_exists", "Remote destination is not a regular file.")
    if not overwrite:
        raise SSHBrokerError("destination_exists", "Remote destination already exists.")


def _ensure_remote_parent(ftp, path: str) -> None:
    parent = posixpath.dirname(path)
    if parent and parent != "/":
        _ensure_remote_dir(ftp, parent)


def _ensure_remote_dir(ftp, path: str) -> None:
    if not path or path == "/":
        return
    current = "/" if path.startswith("/") else ""
    for part in [p for p in path.split("/") if p]:
        current = posixpath.join(current, part) if current else part
        kind = _remote_kind(ftp, current)
        if kind is None:
            ftp.mkd(current)
        elif kind != "dir":
            raise SSHBrokerError("destination_exists", "Remote destination is not a directory.")
