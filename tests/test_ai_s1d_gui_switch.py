"""AI broker TODO section 1 (S1d): GUI switch for AI access.

The main window and the tray show the kill switch (green ON / red OFF).
Turning it off never asks for anything, works while the window is locked
and reaches running brokers; turning it on always asks for the master
password, even when the window is unlocked.
"""

import sys
import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from sezam.crypto.kdf import Argon2Params  # noqa: E402
from sezam.mcp import control  # noqa: E402
from sezam.mcp.approval import ApprovalManager  # noqa: E402
from sezam.mcp.broker import MCPBroker  # noqa: E402
from sezam.vault import ai_access  # noqa: E402
from sezam.vault.crud import Vault  # noqa: E402

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "s1d-master-password"


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication(sys.argv)


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield v
    if v.is_unlocked:
        v.lock()


@pytest.fixture
def window(qapp, vault, tmp_path, monkeypatch):
    from sezam.gui.main_window import MainWindow

    prompts = []
    warnings = []
    answers = []

    def get_text(*args, **kwargs):
        prompts.append(args[2] if len(args) > 2 else kwargs)
        return answers.pop(0) if answers else ("", False)

    monkeypatch.setattr(QInputDialog, "getText", staticmethod(get_text))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: warnings.append(a[2])))
    w = MainWindow(tmp_path)
    w._vault = vault
    monkeypatch.setattr(w, "_show_unlock", lambda: None)
    w.prompts, w.warnings, w.answers = prompts, warnings, answers
    yield w
    w._tray.hide()
    w.deleteLater()


def _settle(window, seconds=5.0):
    switch = window._ai_switch
    deadline = time.monotonic() + seconds
    while switch.worker is not None and time.monotonic() < deadline:
        switch.worker.join(0.05)
        QCoreApplication.processEvents()
    QCoreApplication.processEvents()
    assert switch.worker is None, "AI switch job did not finish"


def _state(tmp_path):
    return ai_access.read_state(Vault(tmp_path))


def _ai_actions(tmp_path):
    v = Vault(tmp_path)
    v.unlock(PASSWORD)
    try:
        rows = v.db.fetchall("SELECT action FROM audit_log ORDER BY rowid")
        return [r["action"] for r in rows if r["action"].startswith("ai_")]
    finally:
        v.lock()


def test_window_and_tray_show_the_switch(window):
    switch = window._ai_switch
    assert switch.button.text() == "AI access: ON"
    assert switch.tray_action in window._tray.contextMenu().actions()
    assert switch.tray_action.text() == "Turn AI access OFF"


def test_turning_off_needs_no_password_and_stops_running_brokers(window, vault, tmp_path):
    broker = MCPBroker(vault, ApprovalManager())
    server = control.ControlServer(
        control.broker_handlers(broker, lambda: None), control.endpoint(pid=4_200_001)
    )
    server.start()
    try:
        window._ai_switch.button.click()
        _settle(window)
    finally:
        server.stop()

    assert window.prompts == []
    assert broker._ai_off is True
    assert _state(tmp_path) == ai_access.AIAccessState(False, 1)  # the broker persisted it
    assert window._ai_switch.button.text() == "AI access: OFF"
    assert window._ai_switch.tray_action.text() == "Turn AI access on..."
    assert "1 running MCP server(s) stopped" in window._ai_switch.last_message
    vault.lock()
    assert _ai_actions(tmp_path) == ["ai_off"]


def test_turning_off_works_while_the_window_is_locked(window, vault, tmp_path):
    window.lock_vault()
    assert window._vault is None

    window._ai_switch.tray_action.trigger()
    _settle(window)

    assert window.prompts == []
    assert _state(tmp_path) == ai_access.AIAccessState(False, 1)
    assert _ai_actions(tmp_path) == ["ai_off"]  # queued, written at this unlock


def test_turning_on_always_asks_for_the_master_password(window, vault, tmp_path):
    ai_access.disable(Vault(tmp_path), "test")
    window._ai_switch.refresh()
    assert window._ai_switch.button.text() == "AI access: OFF"
    assert vault.is_unlocked  # an unlocked window is not enough

    window._ai_switch.button.click()  # cancelled
    _settle(window)
    assert len(window.prompts) == 1 and _state(tmp_path).enabled is False

    window.answers.append(("wrong password", True))
    window._ai_switch.button.click()
    _settle(window)
    assert _state(tmp_path).enabled is False
    assert window.warnings and "Wrong master password" in window.warnings[-1]

    window.answers.append((PASSWORD, True))
    window._ai_switch.tray_action.trigger()
    _settle(window)
    assert len(window.prompts) == 3
    assert _state(tmp_path) == ai_access.AIAccessState(True, 1)
    assert window._ai_switch.button.text() == "AI access: ON"
    vault.lock()
    assert _ai_actions(tmp_path)[-1] == "ai_on"


def test_switch_follows_changes_made_elsewhere(window, tmp_path):
    ai_access.disable(Vault(tmp_path), "cli")
    window._ai_switch.refresh()
    assert window._ai_switch.button.text() == "AI access: OFF"
