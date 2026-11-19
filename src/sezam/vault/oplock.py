"""Exclusive cross-process lock for sync and key changes (review d615826 H4).

Nothing ordered a push, pull or full resync in one process (the GUI,
'mcp-serve', a CLI command) against a password change, a rotation taken over
or a re-key in another. Each now holds ``sezam.db.sync`` exclusively: the OS
file lock orders processes, a per-path RLock the threads of one process, and
a nested hold (a push inside a re-key or a pull) is free. Where the file
system has no locks, only the threads of this process are ordered.
"""

from __future__ import annotations

import functools
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from .inuse import _LocksUnsupported, _try_lock, _unlock

DEFAULT_TIMEOUT = 120.0


class VaultBusy(RuntimeError):
    """Another Sezam program is syncing or changing the vault's keys."""


_BUSY = "Another Sezam program is syncing or changing the vault keys; try again shortly."
_guard = threading.Lock()
_slots: dict[str, list] = {}  # lock path → [RLock, depth, fd]


def lock_path(db_path: str | Path) -> Path:
    db_path = Path(db_path)
    return db_path.with_name(db_path.name + ".sync")


@contextmanager
def exclusive(db_path: str | Path, *, timeout: Optional[float] = None) -> Iterator[None]:
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    path = lock_path(db_path)
    key = os.path.normcase(str(path.resolve()))
    with _guard:
        slot = _slots.setdefault(key, [threading.RLock(), 0, None])
    if not slot[0].acquire(timeout=timeout):
        raise VaultBusy(_BUSY)
    try:
        if slot[1] == 0:
            slot[2] = _take(path, timeout)
        slot[1] += 1
        try:
            yield
        finally:
            slot[1] -= 1
            if slot[1] == 0:
                fd, slot[2] = slot[2], None
                if fd is not None:
                    try:
                        _unlock(fd)
                    finally:
                        os.close(fd)
    finally:
        slot[0].release()


def held(method):
    """Run a method of an object with ``_db`` (Vault, SyncClient) under the lock.

    A database without a file (a test double) has no other process to order.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        path = getattr(self._db, "path", None)
        if path is None:
            return method(self, *args, **kwargs)
        with exclusive(path):
            return method(self, *args, **kwargs)

    return wrapper


def _take(path: Path, timeout: float) -> Optional[int]:
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while not _try_lock(fd, True):
            if time.monotonic() >= deadline:
                raise VaultBusy(_BUSY)
            time.sleep(0.05)
    except _LocksUnsupported:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise
    return fd
