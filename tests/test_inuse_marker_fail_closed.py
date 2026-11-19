"""Review 526419e S1: a holder that slept lost its marker and went on writing.

On a share without file locks a process asleep for more than
MARKER_STALE_SECONDS has its marker cleared by another machine, which may then
restore the vault. On waking, the heartbeat only logged the missing marker and
the process kept writing into a database that was being replaced: its writes
were lost. A holder now fails closed once its marker is gone, and never puts it
back. Marker ages were also measured with utime(), which stamps the file with
this machine's clock on SMB, so a machine whose clock ran ahead cleared the
marker of a live holder; the file server's own write stamp is used instead.
"""

from __future__ import annotations

import os
import threading
import time
from unittest.mock import Mock

import pytest

from sezam.vault import inuse
from sezam.vault.db import VaultDB
from sezam.vault.inuse import InUseLock, VaultInUse
from tests.test_inuse_without_file_locks import no_file_locks  # noqa: F401  (fixture)


def _open(tmp_path) -> VaultDB:
    db = VaultDB(tmp_path / "sezam.db")
    db.open()
    db.execute("CREATE TABLE t (v INTEGER)")
    return db


def test_holder_whose_marker_was_cleared_stops_writing(tmp_path, no_file_locks, monkeypatch):  # noqa: F811
    monkeypatch.setattr(inuse, "MARKER_HEARTBEAT_SECONDS", 3600)
    db = _open(tmp_path)
    try:
        marker = db._in_use._marker
        db.execute("INSERT INTO t VALUES (1)")
        # The holder is asleep: no heartbeat may have the marker open while
        # another machine removes it (Windows otherwise refuses the unlink).
        db._in_use._heartbeat_stop.set()
        marker.unlink()
        wake = Mock(spec=threading.Event)
        wake.wait.side_effect = [False, True]
        db._in_use._heartbeat(marker, wake)
        assert db._in_use._lost
        with pytest.raises(VaultInUse, match="reopen"):
            db.execute("INSERT INTO t VALUES (2)")
        assert not marker.exists()  # the heartbeat did not put it back
    finally:
        db.close()
    check = VaultDB(tmp_path / "sezam.db", hold_in_use=False)
    check.open()
    try:
        assert [r["v"] for r in check.fetchall("SELECT v FROM t")] == [1]
    finally:
        check.close()


def test_write_right_after_wake_is_refused(tmp_path, no_file_locks):  # noqa: F811
    db = _open(tmp_path)  # default heartbeat: it does not run during the test
    try:
        db._in_use._marker.unlink()
        with pytest.raises(VaultInUse):
            db.execute("INSERT INTO t VALUES (1)")
    finally:
        db.close()


def test_a_client_clock_ahead_does_not_clear_a_live_marker(tmp_path, no_file_locks, monkeypatch):  # noqa: F811
    holder = InUseLock(tmp_path / "sezam.db")
    holder.acquire(exclusive=False, timeout=0)
    try:
        real_utime = os.utime

        def utime_ahead(path, times=None, **kw):  # SMB keeps the client's time
            if times is None and "ns" not in kw:
                ahead = time.time() + inuse.MARKER_STALE_SECONDS * 2
                times = (ahead, ahead)
            return real_utime(path, times, **kw)

        monkeypatch.setattr(inuse.os, "utime", utime_ahead)
        with pytest.raises(VaultInUse):
            InUseLock(tmp_path / "sezam.db").acquire(exclusive=True, timeout=0)
        assert holder._marker.exists()
    finally:
        holder.release()
