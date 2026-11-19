import os
import sys

import pytest

# A modal Qt dialog nobody closes is failed after this long (idea #10).
MODAL_LIMIT_SECONDS = 10.0


class ModalWatchdog:
    """Close a modal Qt dialog that stays open longer than ``limit`` seconds.

    Tests run with real windows: a QMessageBox a test did not patch waits for
    a click that never comes and stalls the whole run. The check runs in the
    modal's own event loop, closes it and records it, so the test fails
    instead. Dialogs a test closes itself (QTimer.singleShot) are untouched.
    """

    def __init__(self, limit: float = MODAL_LIMIT_SECONDS, interval_ms: int = 250):
        from PySide6.QtCore import QTimer

        self.limit = limit
        self.stuck: list[str] = []
        self._open_since: dict[int, float] = {}
        self._timer = QTimer()
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self.check)

    def start(self) -> "ModalWatchdog":
        self._timer.start()
        return self

    def stop(self) -> None:
        self._timer.stop()

    def check(self) -> None:
        import time

        from PySide6.QtWidgets import QApplication

        modal = QApplication.activeModalWidget()
        if modal is None:
            self._open_since.clear()
            return
        opened = self._open_since.setdefault(id(modal), time.monotonic())
        if time.monotonic() - opened < self.limit:
            return
        self.stuck.append(f"{type(modal).__name__} {modal.windowTitle()!r}")
        self._open_since.pop(id(modal), None)
        modal.reject() if hasattr(modal, "reject") else modal.close()


@pytest.fixture(autouse=True)
def _no_stuck_qt_modal():
    """Fail (not hang) a test that leaves a modal Qt dialog open."""
    if "PySide6.QtWidgets" not in sys.modules:
        yield
        return
    from PySide6.QtWidgets import QApplication

    _app = QApplication.instance() or QApplication(sys.argv)
    watchdog = ModalWatchdog().start()
    yield
    watchdog.stop()
    if watchdog.stuck:
        pytest.fail(
            "A modal dialog waited for a click and was closed by the test watchdog: "
            + ", ".join(watchdog.stuck)
        )


@pytest.fixture(autouse=True)
def _no_live_timers_in_leftover_windows():
    """A window a test leaves behind keeps its timers: an autolock fired
    minutes later inside another test's event processing and opened the
    unlock dialog there. Timers of windows the test created are stopped."""
    def top_level() -> list:
        if "PySide6.QtWidgets" not in sys.modules:
            return []
        from PySide6.QtWidgets import QApplication

        return QApplication.topLevelWidgets()

    def address(widget) -> int:
        # id() of a temporary wrapper is reused once it is freed, so a window
        # this test created could match one from before and keep its timers.
        from shiboken6 import Shiboken

        return Shiboken.getCppPointer(widget)[0]

    before = {address(w) for w in top_level()}
    yield
    left = [w for w in top_level() if address(w) not in before]
    if not left:
        return
    from PySide6.QtCore import QTimer

    for widget in left:
        for timer in widget.findChildren(QTimer):
            timer.stop()


@pytest.fixture(autouse=True)
def _private_control_endpoints(tmp_path_factory, monkeypatch):
    """Keep tests away from the control endpoints of a real running
    mcp-serve: 'sezam lock' / 'sezam ai off' in a test must never reach it."""
    from sezam.mcp import control, ssh_agent

    run = tmp_path_factory.mktemp("run")
    os.chmod(run, 0o700)
    monkeypatch.setattr(control, "run_dir", lambda: run)
    monkeypatch.setattr(control, "PIPE_PREFIX", f"sezam_test_control_{os.getpid()}_{run.name}_")
    monkeypatch.setattr(
        ssh_agent, "PIPE_PREFIX", f"sezam_test_agent_{os.getpid()}_{run.name}_"
    )
    # Nor the user's real known_hosts: a test writes this file when it needs one.
    known_hosts = run / "known_hosts"
    monkeypatch.setattr(ssh_agent, "known_hosts_path", lambda: str(known_hosts))


@pytest.fixture(autouse=True)
def _keep_pytest_dumpable(monkeypatch):
    """In-process 'mcp-serve' / 'ssh-agent' runs must not make the whole
    pytest process non-dumpable; test_ai_s4a_hardening checks the real call
    in child processes."""
    from sezam.mcp import hardening

    monkeypatch.setattr(hardening, "_LINUX", False)
