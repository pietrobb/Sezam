"""A window one test leaves behind must not lock (and prompt) inside a later one.

test_gui_full left MainWindows alive with a running 7- and 15-minute autolock.
Minutes later the lock fired during an unrelated test's event processing and
opened the unlock dialog there; the modal watchdog then failed whichever test
happened to be running. conftest stops the timers of windows a test leaves.
"""

import pytest

pytest.importorskip("PySide6")

_left = []


def test_a_window_is_left_with_a_running_autolock(tmp_path):
    from PySide6.QtWidgets import QApplication

    from sezam.gui.main_window import MainWindow

    QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "vault.db")
    window._reset_autolock()
    assert window._autolock_timer.isActive()
    _left.append(window)


def test_the_next_test_finds_its_timers_stopped():
    assert _left, "runs after the test above"
    assert not _left[0]._autolock_timer.isActive()
