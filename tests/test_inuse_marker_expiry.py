"""Review e4cd15a S3: the marker-file "vault in use" lock (21b7beb).

Markers were only cleared for dead pids on this host, so a crash on another
machine sharing the vault, a pid the OS reused, or a renamed host left a
marker that blocked every restore for good, and the error did not say which
file it was. A machine whose file locks work ignored markers altogether and
could replace a vault another machine (without locks) had open.
"""

from __future__ import annotations

import os
import re
import socket
import time

import pytest

from sezam.vault import inuse
from sezam.vault.inuse import InUseLock, VaultInUse
from tests.test_inuse_without_file_locks import no_file_locks  # noqa: F401  (fixture)

HOST = re.sub(r"[^A-Za-z0-9-]", "_", socket.gethostname())


def _marker(tmp_path, name: str, age_s: float = 0.0):
    path = tmp_path / f"sezam.db.inuse.{name}"
    path.write_bytes(b"")
    if age_s:
        then = time.time() - age_s
        os.utime(path, (then, then))
    return path


STALE = getattr(inuse, "MARKER_STALE_SECONDS", 600) + 60


@pytest.mark.parametrize("name", [
    "sh.otherhost.4242.crashed",  # a crash on another machine
    "sh.{host}.{pid}.reused",  # our pid now belongs to someone else
    "ex.formername.{pid}.renamed",  # this host before a rename
])
def test_marker_without_heartbeat_expires(tmp_path, no_file_locks, name, monkeypatch):  # noqa: F811
    # The pid is filled in here, not in the test id: pytest-xdist workers
    # have different pids and refuse to run when their test ids differ.
    name = name.format(host=HOST, pid=os.getpid())
    monkeypatch.setattr(inuse, "MARKER_WAKE_GRACE_SECONDS", 0.3, raising=False)
    stale = _marker(tmp_path, name, age_s=STALE)
    lock = InUseLock(tmp_path / "sezam.db")
    lock.acquire(exclusive=True, timeout=0)  # blocked forever before
    assert not stale.exists()
    lock.release()


def test_busy_error_names_the_marker_file(tmp_path, no_file_locks):  # noqa: F811
    live = _marker(tmp_path, "sh.otherhost.4242.live")
    with pytest.raises(VaultInUse) as info:
        InUseLock(tmp_path / "sezam.db").acquire(exclusive=True, timeout=0)
    assert str(live) in str(info.value) and "delete" in str(info.value)
    assert live.exists()


def test_holder_keeps_its_marker_fresh(tmp_path, no_file_locks, monkeypatch):  # noqa: F811
    monkeypatch.setattr(inuse, "MARKER_HEARTBEAT_SECONDS", 0.05, raising=False)
    holder = InUseLock(tmp_path / "sezam.db")
    holder.acquire(exclusive=False, timeout=0)
    marker = holder._marker
    old = time.time() - STALE
    os.utime(marker, (old, old))
    deadline = time.monotonic() + 5
    while marker.stat().st_mtime < time.time() - 60 and time.monotonic() < deadline:
        time.sleep(0.05)
    with pytest.raises(VaultInUse):  # the heartbeat kept the holder visible
        InUseLock(tmp_path / "sezam.db").acquire(exclusive=True, timeout=0)
    holder.release()
    assert not marker.exists()


@pytest.mark.parametrize("held,exclusive,blocked", [
    ("sh", True, True),  # a restore does not replace a vault open elsewhere
    ("ex", False, True),  # nor does a program open one being restored
    ("sh", False, False),  # open vaults share
])
def test_working_locks_honour_markers_of_other_machines(tmp_path, held, exclusive, blocked):
    _marker(tmp_path, f"{held}.otherhost.4242.nolocks")
    lock = InUseLock(tmp_path / "sezam.db")
    if blocked:
        with pytest.raises(VaultInUse, match="otherhost"):
            lock.acquire(exclusive=exclusive, timeout=0)
        assert not lock.held
    else:
        lock.acquire(exclusive=exclusive, timeout=0)
        assert lock.held
        lock.release()
