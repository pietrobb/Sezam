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
_slots: dict[str, list] = {}  # lock path → [RLock, depth, fd, owner thread, explicit depth]


def lock_path(db_path: str | Path) -> Path:
    db_path = Path(db_path)
    return db_path.with_name(db_path.name + ".sync")


def _key(db_path: str | Path) -> str:
    path = str(db_path)
    return _resolved_key(path) if os.path.isabs(path) else _resolved_key.__wrapped__(path)


@functools.lru_cache(maxsize=256)
def _resolved_key(db_path: str) -> str:
    # Asked for on every write (INV-6, R15-P5); resolving the path each time cost more than the lock.
    return os.path.normcase(str(lock_path(db_path).resolve()))


class Unlocked(RuntimeError):
    """A pending batch, key change or revocation queue written without the lock."""


def held_here(db_path: str | Path) -> bool:
    """This thread holds the lock of ``db_path``."""
    slot = _slots.get(_key(db_path))
    return slot is not None and slot[1] > 0 and slot[3] == threading.get_ident()


def _held_by_caller(db_path: str | Path) -> bool:
    """Held here by a caller, not only by VaultDB for one statement or
    transaction (``implicit``)."""
    slot = _slots.get(_key(db_path))
    return slot is not None and slot[4] > 0 and slot[3] == threading.get_ident()


def require(db) -> None:
    """INV-6 (docs/ROOT_CAUSE_PLAN.md, review 8bc70f7 H3): the account-level
    state another process reads and rewrites (a re-key batch, a key change
    journal, the revocation queue, an org recovery body, the last key epoch
    the server took) is written only under the vault lock. Checked where it
    is written, so a caller that forgets the lock fails on its first write
    instead of a hand-kept list of callers missing it. A database without a
    file (a test double), like ``held``, has no other process to order.

    R15-P5: the hold VaultDB takes for every write itself does not count;
    the operation reading and rewriting this state holds it end to end."""
    path = getattr(db, "path", None)
    if path is not None and not _held_by_caller(path):
        raise Unlocked(
            "Internal error: the vault's pending sync state was about to be changed "
            "without the vault lock; nothing was changed."
        )


@contextmanager
def exclusive(
    db_path: str | Path, *, timeout: Optional[float] = None, implicit: bool = False
) -> Iterator[None]:
    """``implicit``: VaultDB's own hold for one write (INV-6, R15-P5)."""
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    path = lock_path(db_path)
    key = _key(db_path)
    with _guard:
        slot = _slots.setdefault(key, [threading.RLock(), 0, None, None, 0])
    if not slot[0].acquire(timeout=timeout):
        raise VaultBusy(_BUSY)
    try:
        if slot[1] == 0:
            slot[2] = _take(path, timeout)
            slot[3] = threading.get_ident()
        slot[1] += 1
        slot[4] += 0 if implicit else 1
        try:
            yield
        finally:
            slot[4] -= 0 if implicit else 1
            slot[1] -= 1
            if slot[1] == 0:
                fd, slot[2], slot[3] = slot[2], None, None
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
