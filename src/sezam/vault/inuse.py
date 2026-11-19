"""Cross-process "vault in use" lock (lockout review M7).

Every open VaultDB (desktop app, CLI command, MCP server) holds a shared
lock on ``sezam.db.inuse``. Replacing the database file (snapshot restore)
needs the exclusive lock, so it cannot pull the file out from under a
process that still reads and writes the old one. The lock is advisory and
released by the OS when the process ends, so a crash never leaves it stuck.

Where the file system has no locks (some NFS/SMB/FUSE mounts), opening used to
fail outright. Each holder then leaves a marker file
``sezam.db.inuse.<sh|ex>.<host>.<pid>.<token>`` instead; markers of dead
processes on this host are cleared (review 688edcb, low).

Review e4cd15a S3: a marker left by a crash on another machine, by a process
whose pid was reused, or under a former hostname blocked restores forever.
A holder now touches its marker every MARKER_HEARTBEAT_SECONDS, and a marker
not touched for MARKER_STALE_SECONDS (by the file server's clock) is cleared
whoever left it. The "in use" error names the marker files, and a machine
whose locks work still honours markers other machines left.

Review 526419e S1: a holder that slept past MARKER_STALE_SECONDS had its
marker cleared and, on waking, went on writing into a vault another machine
was restoring. A holder whose marker is gone now refuses every statement
(fail closed) and never puts the marker back; a restore that cleared a marker
waits MARKER_SETTLE_SECONDS so a write that just passed the check lands first.
Markers are refreshed by writing to them, never by utime(): on SMB utime()
stamps this machine's clock, a write the file server's.
"""

from __future__ import annotations

import errno
import logging
import os
import re
import secrets
import socket
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class VaultInUse(RuntimeError):
    """Another process holds the vault open (or is replacing it)."""


class _LocksUnsupported(Exception):
    """The file system refuses file locks altogether."""


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.LockFileEx.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_Overlapped),
    ]
    _kernel32.LockFileEx.restype = wintypes.BOOL
    _kernel32.UnlockFileEx.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(_Overlapped),
    ]
    _kernel32.UnlockFileEx.restype = wintypes.BOOL
    _LOCKFILE_FAIL_IMMEDIATELY = 0x1
    _LOCKFILE_EXCLUSIVE_LOCK = 0x2
    # ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED: the share has no locks.
    _WIN_LOCKS_UNSUPPORTED = {1, 50}
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    def _try_lock(fd: int, exclusive: bool) -> bool:
        flags = _LOCKFILE_FAIL_IMMEDIATELY | (_LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0)
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        if _kernel32.LockFileEx(handle, flags, 0, 1, 0, ctypes.byref(_Overlapped())):
            return True
        if ctypes.get_last_error() in _WIN_LOCKS_UNSUPPORTED:
            raise _LocksUnsupported()
        return False

    def _unlock(fd: int) -> None:
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        _kernel32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(_Overlapped()))

    def _pid_alive(pid: int) -> bool:
        # os.kill(pid, 0) would terminate the process on Windows.
        handle = _kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() == 5  # access denied: it exists
        try:
            code = wintypes.DWORD()
            ok = _kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return not ok or code.value == 259  # STILL_ACTIVE
        finally:
            _kernel32.CloseHandle(handle)

else:
    import fcntl

    _POSIX_LOCKS_UNSUPPORTED = {
        errno.ENOLCK, errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        errno.ENOSYS, errno.EINVAL,
    }

    def _try_lock(fd: int, exclusive: bool) -> bool:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError as exc:
            if exc.errno in _POSIX_LOCKS_UNSUPPORTED:
                raise _LocksUnsupported() from exc
            raise
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True


_HOST = re.sub(r"[^A-Za-z0-9-]", "_", socket.gethostname()) or "host"
MARKER_HEARTBEAT_SECONDS = 30.0
MARKER_STALE_SECONDS = 600.0
MARKER_SETTLE_SECONDS = 1.0
# A live holder on this host that just woke refreshes its marker within one
# heartbeat (review d150605 N6).
MARKER_WAKE_GRACE_SECONDS = MARKER_HEARTBEAT_SECONDS + 10.0


def lock_path(db_path: str | Path) -> Path:
    db_path = Path(db_path)
    return db_path.with_name(db_path.name + ".inuse")


def _stamp(path: Path, *, create: bool) -> None:
    """Bump the mtime by a write, which the file server stamps with its clock."""
    flags = os.O_WRONLY | os.O_TRUNC | (os.O_CREAT if create else 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, str(time.time_ns()).encode())
    finally:
        os.close(fd)


class InUseLock:
    """Shared (open vault) or exclusive (replace vault) hold on one database."""

    def __init__(self, db_path: str | Path):
        self.path = lock_path(db_path)
        self._fd: int | None = None
        self._marker: Path | None = None
        self._heartbeat_stop: threading.Event | None = None
        self._lost = False
        self._cleared_stale = False

    @property
    def held(self) -> bool:
        return self._fd is not None or self._marker is not None

    @staticmethod
    def _busy(exclusive: bool, blockers: list[Path] = ()) -> VaultInUse:
        text = (
            "The vault is open in another Sezam program (desktop app, MCP "
            "server or another command). Lock or close it and try again."
            if exclusive
            else "The vault is being restored by another Sezam command; try again."
        )
        if blockers:
            text += (
                " It is marked in use by " + ", ".join(str(b) for b in blockers)
                + "; if no Sezam program runs on that machine any more, delete "
                f"{'that file' if len(blockers) == 1 else 'those files'} (cleared "
                f"by itself {int(MARKER_STALE_SECONDS // 60)} minutes after it stops)."
            )
        return VaultInUse(text)

    def ensure_held(self) -> None:
        """VaultInUse once the marker this holder relies on is gone (fail closed)."""
        marker = self._marker
        if marker is not None and not self._lost:
            try:
                marker.stat()
            except FileNotFoundError:
                self._lose(marker)
            except OSError:
                pass
        if self._lost:
            raise VaultInUse(
                "This program lost its hold on the vault: its in-use marker was "
                "cleared while it was paused (asleep longer than "
                f"{int(MARKER_STALE_SECONDS // 60)} minutes), and another machine "
                "may have restored the vault since. Nothing more is saved here; "
                "close the vault and reopen it."
            )

    def _lose(self, marker: Path) -> None:
        if not self._lost:
            self._lost = True
            logger.warning(
                "Vault-in-use marker %s was removed by another process; "
                "refusing further writes", marker,
            )
        stop = self._heartbeat_stop
        if stop is not None:
            stop.set()

    def acquire(self, *, exclusive: bool, timeout: float) -> None:
        """Take the lock, waiting up to ``timeout`` seconds; VaultInUse if not."""
        if self.held:
            return
        self._lost = False
        self._cleared_stale = False
        self._take(exclusive, timeout)
        if exclusive and self._cleared_stale:
            # A holder whose marker was just cleared may be mid-write.
            time.sleep(MARKER_SETTLE_SECONDS)

    def _take(self, exclusive: bool, timeout: float) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + timeout
        blockers: list[Path] = []
        while True:
            try:
                if _try_lock(fd, exclusive):
                    # A machine without locks on the same share leaves markers.
                    blockers = self._blockers(exclusive)
                    if not blockers:
                        break
                    _unlock(fd)
            except _LocksUnsupported:
                os.close(fd)
                self._acquire_marker(exclusive, deadline)
                return
            if time.monotonic() >= deadline:
                os.close(fd)
                raise self._busy(exclusive, blockers)
            time.sleep(0.05)
        self._fd = fd

    def _fs_now(self) -> float:
        """The file server's clock (marker ages from another host's clock skew)."""
        clock = self.path.with_name(self.path.name + "-clock")
        try:
            _stamp(clock, create=True)
            return os.stat(clock).st_mtime
        except OSError:
            return time.time()

    @staticmethod
    def _refreshed(marker: Path, mtime: float) -> bool:
        """Whether the holder touches ``marker`` within MARKER_WAKE_GRACE_SECONDS."""
        deadline = time.monotonic() + MARKER_WAKE_GRACE_SECONDS
        while time.monotonic() < deadline:
            time.sleep(0.1)
            try:
                if marker.stat().st_mtime != mtime:
                    return True
            except FileNotFoundError:
                return False
        return False

    def _others(self, exclusive: bool) -> list[tuple[str, Path]]:
        """(kind 'sh'/'ex', path) of the live markers that block this holder.

        Review d150605 N6: after a sleep the first command on the machine
        cleared the marker of the desktop app still running there (its age
        past MARKER_STALE_SECONDS, the heartbeat not run yet), and the app
        then refused every write. A shared open leaves shared markers alone
        (they do not block it); a stale marker of a live process on this host
        is cleared only if its heartbeat does not refresh it, so a reused pid
        still does not block for good.
        """
        found = []
        prefix = self.path.name + "."
        now = None
        for marker in self.path.parent.glob(prefix + "*"):
            if marker == self._marker:
                continue
            parts = marker.name[len(prefix):].split(".")
            if len(parts) != 4 or parts[0] not in ("sh", "ex") or not parts[2].isdigit():
                continue
            if parts[1] == _HOST and not _pid_alive(int(parts[2])):
                marker.unlink(missing_ok=True)  # left by a crashed process
                continue
            if not exclusive and parts[0] == "sh":
                continue
            try:
                mtime = marker.stat().st_mtime
            except FileNotFoundError:
                continue
            if now is None:
                now = self._fs_now()
            if now - mtime > MARKER_STALE_SECONDS and not (
                parts[1] == _HOST and self._refreshed(marker, mtime)
            ):
                # No heartbeat: a crash elsewhere, a reused pid, a renamed host.
                logger.warning("Clearing stale vault-in-use marker %s", marker)
                marker.unlink(missing_ok=True)
                self._cleared_stale = True
                continue
            found.append((parts[0], marker))
        return found

    def _blockers(self, exclusive: bool) -> list[Path]:
        return [path for _, path in self._others(exclusive)]

    def _heartbeat(self, marker: Path, stop: threading.Event) -> None:
        while not stop.wait(MARKER_HEARTBEAT_SECONDS):
            try:
                _stamp(marker, create=False)  # never re-creates a cleared marker
            except FileNotFoundError:
                self._lose(marker)
                return
            except OSError:
                pass

    def _acquire_marker(self, exclusive: bool, deadline: float) -> None:
        logger.warning(
            "File locks are not supported in %s; marking the vault as in use "
            "with marker files instead.", self.path.parent,
        )
        kind = "ex" if exclusive else "sh"
        while True:
            blockers = self._blockers(exclusive)
            if not blockers:
                self._marker = self.path.with_name(
                    f"{self.path.name}.{kind}.{_HOST}.{os.getpid()}.{secrets.token_hex(4)}"
                )
                os.close(os.open(self._marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
                # Two holders may have looked at the same moment: re-check.
                blockers = self._blockers(exclusive)
                if not blockers:
                    stop = threading.Event()
                    self._heartbeat_stop = stop
                    threading.Thread(
                        target=self._heartbeat, args=(self._marker, stop),
                        name="sezam-inuse-heartbeat", daemon=True,
                    ).start()
                    return
                self._marker.unlink(missing_ok=True)
                self._marker = None
            if time.monotonic() >= deadline:
                raise self._busy(exclusive, blockers)
            time.sleep(0.05 + secrets.randbelow(50) / 1000)  # jitter: no lockstep retries

    def release(self) -> None:
        stop, self._heartbeat_stop = self._heartbeat_stop, None
        if stop is not None:
            stop.set()
        marker, self._marker = self._marker, None
        if marker is not None:
            marker.unlink(missing_ok=True)
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            _unlock(fd)
        finally:
            os.close(fd)
