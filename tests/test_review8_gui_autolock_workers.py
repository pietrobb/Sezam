"""Review a159e97 (core, medium): GUI worker threads were not covered by the autolock.

The autolock waited only for calls made through run_in_background. The
import, server-connect and Argon2-upgrade dialogs run their own QThread on the
window's unlocked vault, so the autolock zeroed the keys under them and
rejected the dialog that owned the running thread.
"""

from __future__ import annotations

import threading

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402

from sezam.crypto.kdf import Argon2Params  # noqa: E402
from sezam.gui import argon2_upgrade_dialog  # noqa: E402
from tests.test_review_desktop_gui import qapp, vault, window  # noqa: E402,F401


def test_autolock_waits_for_a_running_argon2_upgrade(window, monkeypatch):  # noqa: F811
    release = threading.Event()
    seen = []

    def slow_upgrade(upgraded, password, params):
        seen.append(upgraded.is_unlocked)
        release.wait(5)
        seen.append(upgraded.is_unlocked)

    monkeypatch.setattr(argon2_upgrade_dialog, "upgrade_vault_kdf", slow_upgrade)
    dialog = argon2_upgrade_dialog.Argon2UpgradeDialog(
        Argon2Params(time_cost=1), Argon2Params(time_cost=2), window._vault, window
    )
    dialog.show()
    dialog._password_input.setText("pw")
    dialog._do_upgrade()
    worker = dialog._worker
    try:
        for _ in range(100):
            if seen:
                break
            QTest.qWait(10)
        window._reset_autolock()
        window._autolock_timer.timeout.emit()
        assert window._vault is not None  # not locked under the upgrade
        assert window._autolock_timer.isActive()
    finally:
        release.set()
    assert worker.wait(5000)
    QCoreApplication.processEvents()
    assert seen == [True, True]
    window._autolock_timer.timeout.emit()
    assert window._vault is None  # locks once the worker is done
