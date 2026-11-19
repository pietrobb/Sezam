"""Review d150605 N6: after a sleep, a command on the same machine broke the app.

On a share without file locks the desktop app's marker is older than
MARKER_STALE_SECONDS right after the machine wakes (its heartbeat has not run
yet). The first Sezam command on that machine cleared it, and the app, still
running, then refused every write ("lost its hold on the vault").
"""

from __future__ import annotations

import os
import threading
import time

import pytest

from sezam.vault import inuse
from sezam.vault.inuse import InUseLock, VaultInUse
from tests.test_inuse_without_file_locks import no_file_locks  # noqa: F401  (fixture)

ASLEEP = inuse.MARKER_STALE_SECONDS + 60


def _app_just_woke(tmp_path) -> InUseLock:
    app = InUseLock(tmp_path / "sezam.db")
    app.acquire(exclusive=False, timeout=0)
    then = time.time() - ASLEEP
    os.utime(app._marker, (then, then))
    return app


def test_a_command_after_wake_leaves_the_app_its_marker(tmp_path, no_file_locks):  # noqa: F811
    app = _app_just_woke(tmp_path)
    try:
        command = InUseLock(tmp_path / "sezam.db")
        command.acquire(exclusive=False, timeout=0)
        command.release()
        assert app._marker.exists()
        app.ensure_held()  # the app goes on saving
    finally:
        app.release()


def test_a_restore_after_wake_waits_for_the_apps_heartbeat(
    tmp_path, no_file_locks, monkeypatch  # noqa: F811
):
    monkeypatch.setattr(inuse, "MARKER_WAKE_GRACE_SECONDS", 3.0, raising=False)
    app = _app_just_woke(tmp_path)
    try:
        monkeypatch.setattr(inuse, "MARKER_HEARTBEAT_SECONDS", 0.1)
        app._heartbeat_stop.set()  # restart the heartbeat on the short interval
        stop = threading.Event()
        app._heartbeat_stop = stop
        threading.Thread(
            target=app._heartbeat, args=(app._marker, stop), daemon=True
        ).start()
        with pytest.raises(VaultInUse):
            InUseLock(tmp_path / "sezam.db").acquire(exclusive=True, timeout=0)
        assert app._marker.exists()
        app.ensure_held()
    finally:
        app.release()


def test_a_reused_pid_on_this_host_still_expires(tmp_path, no_file_locks, monkeypatch):  # noqa: F811
    monkeypatch.setattr(inuse, "MARKER_WAKE_GRACE_SECONDS", 0.3, raising=False)
    host = inuse._HOST
    stale = tmp_path / f"sezam.db.inuse.sh.{host}.{os.getpid()}.reused"
    stale.write_bytes(b"")
    then = time.time() - ASLEEP
    os.utime(stale, (then, then))
    lock = InUseLock(tmp_path / "sezam.db")
    lock.acquire(exclusive=True, timeout=0)
    assert not stale.exists()
    lock.release()
