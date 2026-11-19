"""Review 688edcb, low: a vault on a file system without file locks.

The M7 "vault in use" lock called flock/LockFileEx unconditionally. On a mount
that has no locks (some NFS/SMB/FUSE setups) the call fails with ENOLCK or
EOPNOTSUPP (ERROR_NOT_SUPPORTED on Windows), and the vault could not be opened
at all. Now holders leave marker files instead, with the same rules: open
vaults share, a restore excludes, a crashed holder does not block.
"""

from __future__ import annotations

import errno
import os
import re
import socket

import pytest

from sezam.vault import inuse
from sezam.vault.db import VaultDB
from sezam.vault.inuse import InUseLock, VaultInUse


@pytest.fixture
def no_file_locks(monkeypatch):
    if os.name == "nt":
        import ctypes

        monkeypatch.setattr(inuse._kernel32, "LockFileEx", lambda *a: False)
        monkeypatch.setattr(ctypes, "get_last_error", lambda: 50)  # ERROR_NOT_SUPPORTED
    else:
        def refuse(fd, op):
            raise OSError(errno.ENOLCK, "No locks available")

        monkeypatch.setattr(inuse.fcntl, "flock", refuse)


def _markers(db_path):
    return sorted(p.name.split(".")[3] for p in db_path.parent.glob("sezam.db.inuse.*"))


def test_vault_opens_without_file_locks_and_markers_keep_the_rules(tmp_path, no_file_locks):
    db_path = tmp_path / "sezam.db"
    first, second = VaultDB(db_path), VaultDB(db_path)
    first.open()  # failed before: OSError(ENOLCK) / VaultInUse after 10 s
    second.open()
    assert _markers(db_path) == ["sh", "sh"]

    restore = InUseLock(db_path)
    with pytest.raises(VaultInUse, match="open in another"):
        restore.acquire(exclusive=True, timeout=0)
    first.close()
    second.close()
    assert _markers(db_path) == []

    restore.acquire(exclusive=True, timeout=0)
    with pytest.raises(VaultInUse, match="being restored"):
        VaultDB(db_path)._in_use.acquire(exclusive=False, timeout=0.1)
    restore.release()
    reopened = VaultDB(db_path)
    reopened.open()
    reopened.close()


def test_marker_of_a_dead_process_does_not_block(tmp_path, no_file_locks, monkeypatch):
    db_path = tmp_path / "sezam.db"
    host = re.sub(r"[^A-Za-z0-9-]", "_", socket.gethostname())
    stale = tmp_path / f"sezam.db.inuse.ex.{host}.999999.dead"
    stale.write_bytes(b"")
    monkeypatch.setattr(inuse, "_pid_alive", lambda pid: pid != 999999, raising=False)
    db = VaultDB(db_path)
    db.open()
    assert not stale.exists()
    db.close()
    # A marker of another host is not judged by local pids: it still counts.
    remote = tmp_path / "sezam.db.inuse.sh.otherhost.999999.live"
    remote.write_bytes(b"")
    with pytest.raises(VaultInUse):
        InUseLock(db_path).acquire(exclusive=True, timeout=0)
