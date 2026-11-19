"""Idea #10: a modal dialog no test closes fails the test, not the whole run.

The tests open real windows. A QMessageBox a test forgot to patch waited for
a click forever and stalled a full pytest run for minutes; the conftest
watchdog closes such a dialog and fails the test that left it open.
"""

import sys
import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from tests.conftest import ModalWatchdog  # noqa: E402


def test_a_message_box_nobody_closes_is_closed_and_reported():
    _app = QApplication.instance() or QApplication(sys.argv)
    watchdog = ModalWatchdog(limit=0.5, interval_ms=50).start()
    started = time.monotonic()
    try:
        QMessageBox.warning(None, "Stuck", "Nobody clicks this.")
    finally:
        watchdog.stop()
    assert time.monotonic() - started < 5
    assert watchdog.stuck == ["QMessageBox 'Stuck'"]
