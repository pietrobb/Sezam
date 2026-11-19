"""Run blocking server calls off the Qt GUI thread.

All calls share one worker thread, so they never race on the shared
SyncClient session or the vault database, and results are delivered back on
the GUI thread through a queued signal. A callback whose owner widget has
already been deleted (dialog closed, vault auto-locked) is dropped.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

import shiboken6
from PySide6.QtCore import QObject, QThread, Signal, Slot

_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sezam-net")


class _Bridge(QObject):
    done = Signal(object, object, object)

    def __init__(self):
        super().__init__()
        self.active = 0  # submitted and not yet delivered (GUI thread only)
        self.done.connect(self._deliver)

    @Slot(object, object, object)
    def _deliver(self, target, result, error):
        self.active -= 1
        owner, on_success, on_error = target
        if not shiboken6.isValid(owner):
            return
        if error is None:
            on_success(result)
        elif on_error is not None:
            on_error(error)


_bridge: Optional[_Bridge] = None
# Started QThread workers that use the unlocked vault (GUI thread only).
_threads: list[QThread] = []


def track(thread: QThread) -> None:
    """Count a started worker as busy until it finishes.

    Review a159e97: the autolock waited only for run_in_background calls, so
    it zeroed the keys under a running import, server connect or Argon2
    upgrade and closed the dialog that owned the thread.
    """
    _threads.append(thread)


def busy() -> bool:
    """A background call is still running (review 526419e S7: the autolock
    waits for it rather than lock the vault under a member re-key)."""
    _threads[:] = [t for t in _threads if shiboken6.isValid(t) and t.isRunning()]
    return bool(_threads) or (_bridge is not None and _bridge.active > 0)


def run_in_background(
    owner: QObject,
    fn: Callable[[], Any],
    on_success: Callable[[Any], None],
    on_error: Optional[Callable[[Exception], None]] = None,
):
    """Run ``fn`` on the network thread; call back on the GUI thread.

    Must be called from the GUI thread (the bridge lives there).
    Returns the Future, mainly for tests.
    """
    global _bridge
    if _bridge is None:
        _bridge = _Bridge()
    bridge = _bridge
    bridge.active += 1
    target = (owner, on_success, on_error)

    def job():
        try:
            result = fn()
        except Exception as exc:
            bridge.done.emit(target, None, exc)
            return
        bridge.done.emit(target, result, None)

    return _EXECUTOR.submit(job)
