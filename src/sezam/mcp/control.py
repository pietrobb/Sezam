"""Control channel of a running broker (AI broker TODO, section 1).

Every ``mcp-serve`` process listens on its own owner-only endpoint: the
Unix socket ``~/.sezam/run/control-<pid>.sock`` (0600 in the private 0700
run directory) or the Windows named pipe ``\\\\.\\pipe\\sezam_control_<pid>``
(owner-only DACL, first instance, no remote clients). Several servers may
run at once, so clients send to every endpoint they find.

One JSON line in, one JSON line out, ``{"command": ...}``:

* ``ai_off`` -- no authentication: anyone who can reach the endpoint may
  pull the brake.
* ``status`` -- kill switch, lock state and the number of SSH sessions.
* ``lock`` -- lock the vault and wipe its keys.

``ai_on`` is never accepted here: turning AI access on needs the master
password in the CLI or GUI. Clients must not trust a reply on its own; the
CLI re-reads the persisted state after ``ai_off``.

A broker running as its own OS user for a group of agents (``--group``,
isolation level L2) also listens on a brake endpoint ``brake-<pid>.sock``
(``0660``, that group) / pipe ``sezam_control_brake_<pid>`` (owner + group
DACL) that accepts only ``ai_off`` and ``status``: the group may stop the
broker but never lock or unlock it. ``SEZAM_RUN_DIR`` points both sides at
a shared run directory (e.g. ``/run/sezam-broker``).
"""

from __future__ import annotations

import dataclasses
import errno
import json
import logging
import os
import socket
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from ..vault import ai_access

logger = logging.getLogger(__name__)

COMMANDS = frozenset({"ai_off", "status", "lock"})
BRAKE_COMMANDS = frozenset({"ai_off", "status"})
MAX_MESSAGE = 4096
CLIENT_TIMEOUT = 2.0
PIPE_PREFIX = "sezam_control_"
SOCKET_PREFIX = "control-"
BRAKE_SOCKET_PREFIX = "brake-"
RUN_DIR_ENV = "SEZAM_RUN_DIR"
_PIPE_ROOT = "\\\\.\\pipe\\"
_ERROR_PIPE_BUSY = 231
_PIPE_UNLIMITED_INSTANCES = 255
# Review 1141a20 H7: bounds of one endpoint (see Admission).
MAX_CONNECTIONS = 32
MAX_PEER_CONNECTIONS = 4
ACCEPT_BACKOFF_MAX = 1.0
_PIPE_POLL = 0.01

Handlers = dict[str, Callable[[], dict]]


def configured_run_dir() -> Path:
    """``$SEZAM_RUN_DIR`` (shared run directory of an L2 broker) or
    ``~/.sezam/run``."""
    shared = os.environ.get(RUN_DIR_ENV)
    return Path(shared) if shared else Path.home() / ".sezam" / "run"


def run_dir() -> Path:
    return configured_run_dir()


def _brake_pipe_prefix() -> str:
    return f"{PIPE_PREFIX}brake_"


def endpoint(pid: Optional[int] = None) -> str:
    """This process's control endpoint."""
    pid = os.getpid() if pid is None else pid
    if sys.platform == "win32":
        return f"{_PIPE_ROOT}{PIPE_PREFIX}{pid}"
    return str(run_dir() / f"{SOCKET_PREFIX}{pid}.sock")


def brake_endpoint(pid: Optional[int] = None) -> str:
    """This process's brake endpoint (group access, ai_off/status only)."""
    pid = os.getpid() if pid is None else pid
    if sys.platform == "win32":
        return f"{_PIPE_ROOT}{_brake_pipe_prefix()}{pid}"
    return str(run_dir() / f"{BRAKE_SOCKET_PREFIX}{pid}.sock")


def brokers() -> list[list[str]]:
    """Endpoints of every running broker in reach: per broker its control
    endpoint first, then its brake endpoint (the one a group member can
    open when the control endpoint belongs to another user)."""
    try:
        if sys.platform == "win32":
            names, root, suffix = os.listdir(_PIPE_ROOT), _PIPE_ROOT, ""
            kinds = (_brake_pipe_prefix(), PIPE_PREFIX)
        else:
            directory = run_dir()
            names = [p.name for p in directory.glob("*.sock")]
            root, suffix = str(directory) + os.sep, ".sock"
            kinds = (BRAKE_SOCKET_PREFIX, SOCKET_PREFIX)
    except OSError:
        return []
    found: dict[str, list[tuple[int, str]]] = {}
    for name in names:
        if not name.endswith(suffix):
            continue
        # The brake prefix is checked first: on Windows it extends the
        # control prefix.
        for rank, prefix in ((1, kinds[0]), (0, kinds[1])):
            if name.startswith(prefix):
                key = name[len(prefix): len(name) - len(suffix)]
                found.setdefault(key, []).append((rank, root + name))
                break
    return [[path for _, path in sorted(paths)] for _, paths in sorted(found.items())]


def group_id(name: str) -> int:
    import grp

    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        raise OSError(f"Unknown group {name!r}") from None


def prepare_socket_path(path: Path, gid: Optional[int] = None) -> None:
    """Make ``path`` safe to bind a Unix socket on (fail closed).

    The parent directory is created 0o700; an existing one must be a real
    directory (not a symlink) owned by us that nobody else can write to
    (so not /tmp), otherwise another local user could replace the socket.
    With ``gid`` (a shared L2 broker) the directory is given that group and
    mode 0o750 so the group can reach sockets in it, still not write there.
    A leftover socket is removed; any other file there is refused.
    """
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        pass
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode):
        raise PermissionError(f"Socket directory {parent} is not a directory.")
    if info.st_uid != os.getuid():
        raise PermissionError(f"Socket directory {parent} is not owned by the current user.")
    if info.st_mode & 0o022:
        raise PermissionError(f"Socket directory {parent} is writable by other users.")
    if gid is not None:
        if info.st_gid != gid:
            os.chown(parent, -1, gid)
        os.chmod(parent, 0o750)
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(existing.st_mode):
        raise PermissionError(f"{path} exists and is not a socket.")
    path.unlink()


def bind_unix_socket(path: Path, group: Optional[str] = None) -> socket.socket:
    """Bind a Unix socket on ``path``: 0o600, or 0o660 with ``group``. There
    is no moment at which it is open to anyone else."""
    gid = None if group is None else group_id(group)
    prepare_socket_path(path, gid)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Bound with our own primary group first; the shared group only
        # once the mode is right.
        old_umask = os.umask(0o177)
        try:
            sock.bind(str(path))
        finally:
            os.umask(old_umask)
        if gid is None:
            os.chmod(str(path), 0o600)
        else:
            os.chown(str(path), -1, gid)
            os.chmod(str(path), 0o660)
    except BaseException:
        sock.close()
        raise
    return sock


def handle_request(handlers: Handlers, raw: bytes) -> dict:
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"status": "error", "code": "bad_request"}
    command = request.get("command") if isinstance(request, dict) else None
    if command == "ai_on":
        return {
            "status": "error",
            "code": "not_allowed",
            "message": "AI access is turned on only with the master password ('sezam ai on').",
        }
    handler = handlers.get(command) if isinstance(command, str) else None
    if handler is None:
        return {"status": "error", "code": "unknown_command"}
    try:
        return handler()
    except Exception:
        logger.exception("Control command %s failed", command)
        return {"status": "error", "code": "internal_error"}


def _encode(message: dict) -> bytes:
    return (json.dumps(message, sort_keys=True) + "\n").encode("utf-8")


def _read_line(read: Callable[[int], bytes]) -> bytes:
    data = b""
    while b"\n" not in data and len(data) <= MAX_MESSAGE:
        chunk = read(MAX_MESSAGE)
        if not chunk:
            break
        data += chunk
    return data.split(b"\n", 1)[0][:MAX_MESSAGE]


# Review c78fd19 R13-11: a Windows pipe names its client only once data was
# read (ImpersonateNamedPipeClient), so a group pipe admits a connection
# under this key (all such connections together get one user's bound) and
# moves it to the real SID after the first read (Admission.identify).
UNIDENTIFIED = "?unidentified"


class _Slot:
    __slots__ = ("peer", "cut")

    def __init__(self, peer, cut: Callable[[], None]):
        self.peer = peer
        self.cut = cut


class Admission:
    """The connections one endpoint holds at once, oldest first.

    Review 1141a20 H7: every connection got its own thread without any
    bound, so a peer that opened connections and sent nothing (or a byte now
    and then) used up the process's file descriptors or threads; the accept
    loop then died on EMFILE and the brake stopped answering. An endpoint
    now holds at most ``total`` connections, and with ``per_peer`` at most
    that many from one OS user (uid / SID; peer None counts only towards
    ``total``). Over a bound either the newcomer is refused (``evict``
    False: long-lived sessions) or the oldest connection of that user, else
    of the endpoint, is cut (``evict`` True: the control channel, one line
    each way, so a brake request is never stuck behind idle connections).
    """

    def __init__(self, total: int, per_peer: Optional[int], evict: bool):
        self.total = total
        self.per_peer = per_peer
        self.evict = evict
        self._lock = threading.Lock()
        self._open: list[_Slot] = []

    def admit(self, peer, cut: Callable[[], None]) -> Optional[_Slot]:
        with self._lock:
            victim = None
            mine = (
                [slot for slot in self._open if slot.peer == peer]
                if self.per_peer is not None and peer is not None else []
            )
            if self.per_peer is not None and len(mine) >= self.per_peer:
                victim = mine[0]
            elif len(self._open) >= self.total:
                victim = self._open[0]
            if victim is not None:
                if not self.evict:
                    return None
                self._open.remove(victim)
            slot = _Slot(peer, cut)
            self._open.append(slot)
        if victim is not None:
            victim.cut()
        return slot

    def identify(self, slot: _Slot, peer) -> bool:
        """Move an admitted ``slot`` (admitted as UNIDENTIFIED) to the user
        it turned out to be. False when that user cannot be told, the slot
        was already cut, or (``evict`` False) the user is at ``per_peer``;
        with ``evict`` the user's oldest connection is cut instead."""
        victim = None
        with self._lock:
            if peer is None or slot not in self._open:
                return False
            mine = [s for s in self._open if s is not slot and s.peer == peer]
            if self.per_peer is not None and len(mine) >= self.per_peer:
                if not self.evict:
                    return False
                victim = mine[0]
                self._open.remove(victim)
            slot.peer = peer
        if victim is not None:
            victim.cut()
        return True

    def release(self, slot: _Slot) -> None:
        with self._lock:
            if slot in self._open:
                self._open.remove(slot)

    def __len__(self) -> int:
        with self._lock:
            return len(self._open)


def unix_peer(conn: socket.socket) -> Optional[int]:
    """The uid of the process at the other end of a Unix socket (Linux),
    None where the platform does not tell."""
    import struct

    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    try:
        _pid, uid, _gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        )
    except OSError:
        return None
    return uid


def serve_listener(
    listener: socket.socket,
    running: Callable[[], bool],
    admission: Admission,
    handle: Callable[[socket.socket], None],
    name: str,
    peers: bool = False,
) -> None:
    """Accept on ``listener`` until ``running()`` is false; each admitted
    connection is handled on its own thread and closed afterwards.

    Review 1141a20 H7: an OSError from accept() (EMFILE, ENFILE, ENOBUFS,
    ECONNABORTED...) ended the loop for good, as did a thread that could not
    be started. Now only a stop ends it; errors back off and retry, and the
    pending connections wait in the backlog until descriptors are free.
    """
    delay = 0.0
    while running():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError as exc:
            if not running():
                return
            delay = min(max(2 * delay, 0.05), ACCEPT_BACKOFF_MAX)
            logger.warning("%s: accept failed (%s); retrying in %.2fs", name, exc, delay)
            time.sleep(delay)
            continue
        delay = 0.0
        _start_connection(conn, admission, handle, name, unix_peer(conn) if peers else None)


def _start_connection(conn, admission: Admission, handle, name: str, peer) -> None:
    def cut() -> None:
        try:
            conn.shutdown(socket.SHUT_RDWR)  # wakes a recv() blocked on it
        except OSError:
            pass

    slot = admission.admit(peer, cut)
    if slot is None:
        conn.close()
        return

    def run() -> None:
        try:
            with conn:
                handle(conn)
        except Exception:
            logger.debug("%s: connection failed", name, exc_info=True)
        finally:
            admission.release(slot)

    try:
        threading.Thread(target=run, name=f"{name}-client", daemon=True).start()
    except RuntimeError:  # no thread left (TasksMax, memory): drop this one
        admission.release(slot)
        conn.close()
        logger.warning("%s: no thread for a connection; dropped", name)
        time.sleep(0.05)


class OwnerOnlyServer:
    """Stream endpoint only the current user can reach, served on
    background threads: a Unix socket (0600, private run directory) or a
    Windows named pipe (owner-only DACL, first instance, no remote clients).

    Each connection gets its own thread, so a client that connects and
    sends nothing cannot hold back anyone else. Subclasses implement
    ``_serve_connection(read, write)``.

    With ``group`` the endpoint is shared with that OS group as well: the
    socket is ``0660`` with that group in a ``0750`` run directory of that
    group, the pipe DACL adds the group's SID (connect, read, write; no new
    pipe instances).
    """

    thread_name = "sezam-endpoint"
    buffer_size = MAX_MESSAGE
    # Per-read timeout of a Unix connection; None keeps it open while idle.
    io_timeout: Optional[float] = CLIENT_TIMEOUT
    # Whole time from accept to the last byte; None for long-lived sessions.
    # A peer that trickles a byte now and then is cut at it too.
    connection_deadline: Optional[float] = None
    max_connections = MAX_CONNECTIONS
    # From one OS user, on an endpoint shared with a group.
    max_peer_connections = MAX_PEER_CONNECTIONS
    evict_oldest = False

    def __init__(self, path: str, group: Optional[str] = None):
        self.path = path
        self.group = group
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._admission = Admission(
            self.max_connections,
            self.max_peer_connections if group else None,
            self.evict_oldest,
        )
        self._pipes_open = 0
        self._pipes_lock = threading.Lock()

    def start(self) -> None:
        """Bind and start serving; raises if the endpoint cannot be owned."""
        self._running = True
        if sys.platform == "win32":
            from . import winpipe

            self._kernel32 = winpipe.load_kernel32()
            self._kernel32.FlushFileBuffers.argtypes = [winpipe.wt.HANDLE]
            self._security = winpipe.OwnerOnlySecurity(self.group)
            first = self._new_pipe()
            self._thread = threading.Thread(
                target=self._serve_pipe, args=(first,), name=self.thread_name, daemon=True
            )
        else:
            self._bind_unix()
            self._thread = threading.Thread(
                target=self._serve_unix, name=self.thread_name, daemon=True
            )
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if sys.platform == "win32":
            # Wake the ConnectNamedPipe() the server thread is blocked in.
            try:
                open(self.path, "r+b", buffering=0).close()
            except OSError:
                pass
        elif self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(5)
        if sys.platform == "win32":
            self._security.close()
        else:
            try:
                if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                    os.unlink(self.path)
            except OSError:
                pass

    # ── Unix socket ──

    def _bind_unix(self) -> None:
        sock = bind_unix_socket(Path(self.path), self.group)
        sock.listen(16)
        sock.settimeout(0.5)  # closing a socket does not wake accept() on Linux
        self._sock = sock

    def _serve_unix(self) -> None:
        serve_listener(
            self._sock, lambda: self._running, self._admission, self._handle_unix,
            self.thread_name, peers=bool(self.group),
        )

    def _handle_unix(self, conn: socket.socket) -> None:
        try:
            if self.connection_deadline is None:
                conn.settimeout(self.io_timeout)
                read = conn.recv
            else:
                end = time.monotonic() + self.connection_deadline

                def read(size: int) -> bytes:
                    left = end - time.monotonic()
                    if left <= 0:
                        return b""
                    conn.settimeout(left if self.io_timeout is None else min(left, self.io_timeout))
                    return conn.recv(size)

            self._serve_connection(read, conn.sendall)
        except OSError:
            pass

    def _serve_connection(
        self, read: Callable[[int], bytes], write: Callable[[bytes], None]
    ) -> None:
        raise NotImplementedError

    # ── Windows named pipe ──

    def _create_pipe(self, *, first: bool):
        import ctypes

        from . import winpipe

        flags = winpipe.PIPE_ACCESS_DUPLEX
        if first:
            flags |= winpipe.FILE_FLAG_FIRST_PIPE_INSTANCE
        handle = self._kernel32.CreateNamedPipeW(
            self.path,
            flags,
            winpipe.PIPE_TYPE_BYTE | winpipe.PIPE_READMODE_BYTE
            | winpipe.PIPE_WAIT | winpipe.PIPE_REJECT_REMOTE_CLIENTS,
            _PIPE_UNLIMITED_INSTANCES,
            self.buffer_size,
            self.buffer_size,
            0,
            ctypes.byref(self._security.attributes),
        )
        if handle in (None, 0, winpipe.INVALID_HANDLE_VALUE):
            raise OSError(f"Cannot create pipe {self.path} (error {ctypes.get_last_error()})")
        return handle

    def _new_pipe(self):
        """The next listening instance. Whenever none of ours is open it is
        created as the first instance, so the name is never joined after
        another process took it over."""
        with self._pipes_lock:
            first = self._pipes_open == 0
        handle = self._create_pipe(first=first)
        with self._pipes_lock:
            self._pipes_open += 1
        return handle

    def _close_pipe(self, handle) -> None:
        self._kernel32.CloseHandle(handle)
        with self._pipes_lock:
            self._pipes_open -= 1

    def _serve_pipe(self, handle) -> None:
        """Review 1141a20 H7: a pipe instance that could not be created and a
        thread that could not be started ended this loop for good; now only
        a stop does, the rest backs off and retries."""
        import ctypes

        from . import winpipe

        k = self._kernel32
        delay = 0.0
        while self._running:
            if handle is None:
                try:
                    handle = self._new_pipe()
                except OSError as exc:
                    delay = min(max(2 * delay, 0.05), ACCEPT_BACKOFF_MAX)
                    logger.warning("Pipe %s: %s; retrying in %.2fs", self.path, exc, delay)
                    time.sleep(delay)
                    continue
                delay = 0.0
            connected = k.ConnectNamedPipe(handle, None) or (
                ctypes.get_last_error() == winpipe.ERROR_PIPE_CONNECTED
            )
            if not self._running:
                break
            # The next instance exists before this one is handed off or
            # closed, so the name is never released while we run.
            try:
                following = self._new_pipe()
            except OSError as exc:
                logger.warning("Pipe %s: %s", self.path, exc)
                following = None
            if not connected:
                self._close_pipe(handle)
                time.sleep(0.05)
            else:
                self._start_pipe_connection(handle)
            handle = following
        if handle is not None:
            self._close_pipe(handle)

    def _start_pipe_connection(self, handle) -> None:
        from . import winpipe

        k = self._kernel32
        cut = threading.Event()
        slot = self._admission.admit(UNIDENTIFIED if self.group else None, cut.set)
        if slot is None:
            k.DisconnectNamedPipe(handle)
            self._close_pipe(handle)
            return

        def identify() -> bool:
            return self._admission.identify(slot, winpipe.pipe_client_sid(handle))

        def run() -> None:
            try:
                self._handle_pipe(handle, cut, identify if self.group else None)
            finally:
                self._admission.release(slot)

        try:
            threading.Thread(target=run, name=f"{self.thread_name}-client", daemon=True).start()
        except RuntimeError:  # no thread left: drop this connection
            self._admission.release(slot)
            k.DisconnectNamedPipe(handle)
            self._close_pipe(handle)
            logger.warning("%s: no thread for a connection; dropped", self.thread_name)
            time.sleep(0.05)

    def _handle_pipe(
        self, handle, cut: threading.Event, identify: Optional[Callable[[], bool]] = None
    ) -> None:
        import ctypes
        import ctypes.wintypes as wt

        from . import winpipe

        k = self._kernel32
        buffer = ctypes.create_string_buffer(self.buffer_size)
        bounded = self.connection_deadline is not None or self.evict_oldest
        end = None if self.connection_deadline is None else time.monotonic() + self.connection_deadline
        unidentified = [True] if identify is not None else []

        def wait_readable() -> int:
            """Bytes waiting; 0 once the connection is cut, past its
            deadline or closed. ReadFile() itself would block for good."""
            while not cut.is_set() and (end is None or time.monotonic() < end):
                available = winpipe.bytes_available(k, handle)
                if available is None:
                    return 0
                if available:
                    return available
                time.sleep(_PIPE_POLL)
            return 0

        def read(size: int) -> bytes:
            if bounded:
                available = wait_readable()
                if not available:
                    return b""
                size = min(size, available)
            got = wt.DWORD(0)
            if not k.ReadFile(
                handle, buffer, min(size, self.buffer_size), ctypes.byref(got), None
            ):
                return b""
            if unidentified and got.value:
                # A client of unknown user is refused, over its user's bound
                # refused or (evict) let in with that user's oldest cut.
                if not identify():
                    return b""
                unidentified.clear()
            return buffer.raw[: got.value]

        def write(data: bytes) -> None:
            while data:
                written = wt.DWORD(0)
                if not k.WriteFile(handle, data, len(data), ctypes.byref(written), None):
                    raise OSError("pipe write failed")
                data = data[written.value:]

        try:
            self._serve_connection(read, write)
            if bounded:
                # Until the client has read the reply and closed its end;
                # FlushFileBuffers() would wait for good on one that never
                # reads.
                wait_readable()
            else:
                k.FlushFileBuffers(handle)
        except OSError:
            pass
        finally:
            k.DisconnectNamedPipe(handle)
            self._close_pipe(handle)


class ControlServer(OwnerOnlyServer):
    """A broker's control endpoint: one JSON line in, one JSON line out."""

    thread_name = "sezam-control"
    connection_deadline = CLIENT_TIMEOUT
    evict_oldest = True

    def __init__(
        self, handlers: Handlers, path: Optional[str] = None, group: Optional[str] = None
    ):
        allowed = BRAKE_COMMANDS if group else COMMANDS
        if not set(handlers) <= allowed:
            raise ValueError(f"Unsupported control commands: {sorted(set(handlers) - allowed)}")
        self._handlers = dict(handlers)
        super().__init__(path or endpoint(), group)

    def _serve_connection(
        self, read: Callable[[int], bytes], write: Callable[[bytes], None]
    ) -> None:
        write(_encode(handle_request(self._handlers, _read_line(read))))


class ControlEndpoints:
    """A broker's owner-only control endpoint and, with ``group``, its brake
    endpoint for that group (``ai_off`` and ``status`` only)."""

    def __init__(self, handlers: Handlers, group: Optional[str] = None):
        self.servers = [ControlServer(handlers)]
        if group:
            brake = {name: handlers[name] for name in BRAKE_COMMANDS if name in handlers}
            self.servers.append(ControlServer(brake, brake_endpoint(), group))

    def start(self) -> None:
        started = []
        try:
            for server in self.servers:
                server.start()
                started.append(server)
        except BaseException:
            for server in started:
                server.stop()
            raise

    def stop(self) -> None:
        for server in self.servers:
            server.stop()


# ── Client ──


_BUSY = object()


def _exchange(path: str, payload: bytes):
    if sys.platform == "win32":
        deadline = time.monotonic() + CLIENT_TIMEOUT
        while True:
            try:
                pipe = open(path, "r+b", buffering=0)
                break
            except OSError as exc:
                # open() reports ERROR_PIPE_BUSY (every instance taken, the
                # next one not yet created) as EINVAL without a winerror.
                busy = getattr(exc, "winerror", None) == _ERROR_PIPE_BUSY or exc.errno == errno.EINVAL
                if busy and time.monotonic() < deadline:
                    time.sleep(0.02)
                    continue
                return None
        with pipe:
            pipe.write(payload)
            line = _read_line(pipe.read)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(CLIENT_TIMEOUT)
        with sock:
            try:
                sock.connect(path)
            except ConnectionRefusedError:
                # Left behind by a broker that died: nobody listens there.
                try:
                    if stat.S_ISSOCK(os.lstat(path).st_mode):
                        os.unlink(path)
                except OSError:
                    pass
                return None
            except BlockingIOError:
                return _BUSY  # backlog full
            except OSError:
                return None
            sock.sendall(payload)
            line = _read_line(sock.recv)
    if not line:
        return _BUSY  # cut before the reply: the endpoint was full
    try:
        reply = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return reply if isinstance(reply, dict) else None


def send(path: str, command: str, timeout: float = CLIENT_TIMEOUT) -> Optional[dict]:
    """Send one command; None if nobody answered within ``timeout``."""
    result: list = []

    end = time.monotonic() + timeout

    def run() -> None:
        # A full endpoint cuts its oldest connection: try again until the
        # time is up (review 1141a20 H7).
        while True:
            try:
                reply = _exchange(path, _encode({"command": command}))
            except Exception:
                logger.debug("Control endpoint %s did not answer", path, exc_info=True)
                reply = _BUSY
            if reply is not _BUSY:
                result.append(reply)
                return
            if time.monotonic() >= end:
                return
            time.sleep(0.02)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    return result[0] if result else None


def send_all(command: str, timeout: float = CLIENT_TIMEOUT) -> list[tuple[str, Optional[dict]]]:
    """Send ``command`` to every running broker in parallel, through the
    first of its endpoints that answers."""
    found = brokers()
    replies: dict[int, tuple[str, Optional[dict]]] = {}

    def run(index: int, paths: list[str]) -> None:
        for path in paths:
            reply = send(path, command, timeout)
            replies[index] = (path, reply)
            if reply is not None:
                return

    workers = [
        threading.Thread(target=run, args=(i, paths), daemon=True) for i, paths in enumerate(found)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(2 * timeout + 0.5)
    return [replies.get(i, (paths[0], None)) for i, paths in enumerate(found)]


@dataclass(frozen=True)
class BrakeResult:
    state: "ai_access.AIAccessState"
    stopped: int  # running brokers that persisted ai_off themselves
    unanswered: int  # brokers that did not; their watcher closes sessions
    # Why the 'off' is not anchored on the sync server; None when it is, or
    # when nothing needs it (no server, or a running broker anchors it).
    unanchored: Optional[str] = None


def pull_brake(vault, source: str) -> BrakeResult:
    """Turn AI access off everywhere ('sezam ai off', GUI, tray).

    Every running broker is told first (in-memory flag, close sessions,
    persist, audit). A reply is not trusted on its own: unless one broker
    persisted it and the vault now reads off, the switch is written here.
    Then, on an unlocked vault, the new 'off' is anchored on the sync server
    (R14-M3). Never needs a password; ``vault`` may be locked.
    """
    from ..vault import ai_access
    from .remote_policy import ServerAnchor

    replies = send_all("ai_off")
    stopped = sum(
        1 for _, reply in replies if reply and reply.get("status") == "ok" and reply.get("persisted")
    )
    state = ai_access.read_state(vault)
    if not stopped or state.enabled:
        state = ai_access.disable(vault, source)
    unanchored = None
    if ai_access.anchor_expected(vault):
        if vault.is_unlocked:
            try:
                ServerAnchor(vault, {}).anchor_off(state.epoch)
            except Exception as exc:
                logger.warning("The AI 'off' was not anchored on the sync server", exc_info=True)
                unanchored = str(exc) or type(exc).__name__
        elif not stopped:  # a broker that saved it anchors it from its unlocked vault
            unanchored = "the vault is locked"
    return BrakeResult(state, stopped, len(replies) - stopped, unanchored)


def brake_then_unlock(vault, source: str, unlock: Optional[Callable[[], None]]) -> BrakeResult:
    """R17-N3: the brake over the still locked vault, the unlock only after it.

    An unlock writes, so it waits for the vault's write lock; with another
    program holding it the unlock raised VaultBusy and the brake was never
    pulled. Here the unlock (for the audit record, written by the unlock, and
    the server anchor) comes after the switch is off, and whatever it raises
    only leaves the 'off' unanchored.
    """
    return anchor_after_brake(vault, pull_brake(vault, source), unlock)


def unlock_after_brake(vault, result: BrakeResult, unlock: Optional[Callable[[], None]]) -> BrakeResult:
    """Unlock (if asked) after the brake; a failure only leaves it unanchored."""
    if unlock is not None and not vault.is_unlocked:
        try:
            unlock()
        except Exception as exc:
            logger.warning("Unlocking after the AI brake failed; the switch is off", exc_info=True)
            why = f"the vault could not be unlocked after the brake: {exc or type(exc).__name__}"
            return dataclasses.replace(result, unanchored=result.unanchored and why)
    return result


def anchor_after_brake(vault, result: BrakeResult, unlock: Optional[Callable[[], None]]) -> BrakeResult:
    """Unlock (if asked) and anchor an 'off' the brake left unanchored."""
    from .remote_policy import ServerAnchor

    result = unlock_after_brake(vault, result, unlock)
    if result.unanchored is None or not vault.is_unlocked:
        return result
    try:
        ServerAnchor(vault, {}).anchor_off(result.state.epoch)
    except Exception as exc:
        logger.warning("The AI 'off' was not anchored on the sync server", exc_info=True)
        return dataclasses.replace(result, unanchored=str(exc) or type(exc).__name__)
    return dataclasses.replace(result, unanchored=None)


def broker_handlers(broker, lock: Callable[[], None]) -> Handlers:
    """Control commands of a running MCP broker."""

    def ai_off() -> dict:
        state = broker.disable_ai("control")
        return {
            "status": "ok",
            "ai_access": "off",
            "persisted": state is not None,
            "epoch": None if state is None else state.epoch,
        }

    def status() -> dict:
        return {"status": "ok", "pid": os.getpid(), **broker.status()}

    def do_lock() -> dict:
        lock()
        return {"status": "ok", "locked": True}

    return {"ai_off": ai_off, "status": status, "lock": do_lock}
