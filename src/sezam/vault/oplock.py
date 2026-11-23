"""Exclusive cross-process lock for sync and key changes (review d615826 H4).

Nothing ordered a push, pull or full resync in one process (the GUI,
'mcp-serve', a CLI command) against a password change, a rotation taken over
or a re-key in another. Each now holds ``sezam.db.sync`` exclusively: the OS
file lock orders processes, a per-path RLock the threads of one process, and
a nested hold (a push inside a re-key or a pull) is free. Where the file
system has no locks, only the threads of this process are ordered.

R16-M3: a second file, ``sezam.db.write``, orders writes (VaultDB takes it
for each write and transaction, INV-6). A holder of the sync lock holds it
too, except while it waits for the server (``network``).
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
_slots: dict[str, list] = {}  # lock path → [RLock, depth, fd, owner thread]

# R16-M3 (regression of 3e17d5f): two locks. SYNC orders the operations that
# read, send and rewrite the account's sync state (a caller's hold); WRITE
# orders single writes and read-then-write edits (VaultDB takes it for every
# write). A SYNC holder gives WRITE up while it waits for the server, so a
# push no longer holds every other process's writes through its requests.
# Order: SYNC before WRITE.
SYNC, WRITE = ".sync", ".write"


def lock_path(db_path: str | Path, kind: str = SYNC) -> Path:
    db_path = Path(db_path)
    return db_path.with_name(db_path.name + kind)


def _key(db_path: str | Path, kind: str) -> str:
    path = str(db_path)
    return _resolved_key(path, kind) if os.path.isabs(path) else _resolved_key.__wrapped__(path, kind)


@functools.lru_cache(maxsize=256)
def _resolved_key(db_path: str, kind: str) -> str:
    # Asked for on every write (INV-6, R15-P5); resolving the path each time cost more than the lock.
    return os.path.normcase(str(lock_path(db_path, kind).resolve()))


class Unlocked(RuntimeError):
    """A pending batch, key change or revocation queue written without the lock."""


def _mine(slot: Optional[list]) -> bool:
    return slot is not None and slot[1] > 0 and slot[3] == threading.get_ident()


def held_here(db_path: str | Path) -> bool:
    """This thread holds the write lock of ``db_path``."""
    return _mine(_slots.get(_key(db_path, WRITE)))


def holds_sync(db_path: str | Path) -> bool:
    """This thread holds the sync lock (a caller's hold, not VaultDB's own)."""
    return _mine(_slots.get(_key(db_path, SYNC)))


def require(db) -> None:
    """INV-6 (docs/ROOT_CAUSE_PLAN.md, review 8bc70f7 H3): the account-level
    state another process reads and rewrites (a re-key batch, a key change
    journal, the revocation queue, an org recovery body, the last key epoch
    the server took) is written only under the vault lock. Checked where it
    is written, so a caller that forgets the lock fails on its first write
    instead of a hand-kept list of callers missing it. A database without a
    file (a test double), like ``held``, has no other process to order.

    R15-P5: the hold VaultDB takes for every write itself does not count;
    the operation reading and rewriting this state holds the sync lock end
    to end."""
    path = getattr(db, "path", None)
    if path is not None and not holds_sync(path):
        raise Unlocked(
            "Internal error: the vault's pending sync state was about to be changed "
            "without the vault lock; nothing was changed."
        )


def _slot(db_path: str | Path, kind: str) -> list:
    with _guard:
        return _slots.setdefault(_key(db_path, kind), [threading.RLock(), 0, None, None])


def _enter(slot: list, path: Path, timeout: float) -> None:
    if not slot[0].acquire(timeout=timeout):
        raise VaultBusy(_BUSY)
    try:
        if slot[1] == 0:
            slot[2] = _take(path, timeout)
            slot[3] = threading.get_ident()
        slot[1] += 1
    except BaseException:
        slot[0].release()
        raise


def _leave(slot: list) -> None:
    try:
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


@contextmanager
def exclusive(
    db_path: str | Path, *, timeout: Optional[float] = None, implicit: bool = False
) -> Iterator[None]:
    """The sync lock and the write lock; ``implicit``: the write lock alone
    (VaultDB's own hold for one write, INV-6 R15-P5, or an edit's, R16-M1)."""
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    write = _slot(db_path, WRITE)
    sync = None
    if not implicit:
        sync = _slot(db_path, SYNC)
        # A thread holding the write lock alone that waited for the sync lock
        # would wait for a sync holder that waits for the write lock after
        # its request: it does not wait.
        wait = 0 if _mine(write) and not _mine(sync) else timeout
        _enter(sync, lock_path(db_path, SYNC), wait)
    try:
        _enter(write, lock_path(db_path, WRITE), timeout)
        try:
            yield
        finally:
            if _mine(write):  # not taken back after a request (network): already given up
                _leave(write)
    finally:
        if sync is not None:
            _leave(sync)


@contextmanager
def network(db) -> Iterator[None]:
    """R16-M3: a sync holder waiting for the server gives the write lock up
    (taken back after), so other processes' writes do not wait for the
    network. Inside a transaction, or without the sync lock (an edit's
    read-then-write), it keeps it."""
    path = getattr(db, "path", None)
    in_transaction = getattr(db, "in_own_transaction", None)
    write = None if path is None else _slots.get(_key(path, WRITE))
    if (
        write is None or not _mine(write) or not holds_sync(path)
        or (in_transaction is not None and in_transaction())
    ):
        yield
        return
    depth = write[1]
    for _ in range(depth):
        _leave(write)
    try:
        yield
    finally:
        _enter(write, lock_path(path, WRITE), DEFAULT_TIMEOUT)
        for _ in range(depth - 1):
            _enter(write, lock_path(path, WRITE), DEFAULT_TIMEOUT)


def _locked(method, implicit: bool):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        path = getattr(self._db, "path", None)
        if path is None:
            return method(self, *args, **kwargs)
        with exclusive(path, implicit=implicit):
            return method(self, *args, **kwargs)

    return wrapper


def held(method):
    """Run a method of an object with ``_db`` (Vault, SyncClient) under the
    sync lock (and the write lock outside its requests).

    A database without a file (a test double) has no other process to order.
    """
    return _locked(method, implicit=False)


def writes(method):
    """Run a method under the write lock alone: an edit that reads a row and
    writes the next version of it (R16-M1). It never waits for the network."""
    return _locked(method, implicit=True)


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
