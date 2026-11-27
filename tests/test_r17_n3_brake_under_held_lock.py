"""R17-N3 (review c02cc47): the AI kill switch works while another program writes.

Since R15-P5 every write takes ``sezam.db.write`` and an unlock writes. ``sezam ai
off`` with a CLI session (and the GUI switch with an unlocked window) unlocked
first, for the audit record and the server anchor: with the write lock held
elsewhere the unlock raised VaultBusy (a RuntimeError, past ``except
ValueError``) and the brake was never pulled. The brake now comes first, over
the locked vault (``db.brake()`` does not wait for the write lock); the unlock
only afterwards, and nothing it raises takes the brake back.
"""

from __future__ import annotations

import subprocess
import sys
import time
from contextlib import contextmanager

import pytest

from sezam.mcp import control
from sezam.vault import ai_access, oplock
from sezam.vault.crud import Vault
from tests.test_ai_s1a_kill_switch import PASSWORD, _run, env  # noqa: F401  (fixture)

HOLDER = (
    "import sys\n"
    "from sezam.vault import oplock\n"
    "with oplock.exclusive(sys.argv[1]):\n"
    "    print('held', flush=True)\n"
    "    sys.stdin.read()\n"
)


@contextmanager
def _another_program_writes(path):
    """Another process (a sync, say) holds the vault's sync and write locks."""
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(Vault(path).db.path)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        yield
    finally:
        holder.stdin.close()
        holder.wait(30)


@pytest.fixture
def quick(env, monkeypatch):  # noqa: F811
    monkeypatch.setattr(oplock, "DEFAULT_TIMEOUT", 2.0)  # VaultBusy after 2 s, not 120 s
    monkeypatch.setattr(control, "send_all", lambda *a, **k: [])  # no broker running
    return env


def _session_kek(path) -> bytearray:
    vault = Vault(path)
    vault.unlock(PASSWORD)
    try:
        return bytearray(vault._dek_mgr._kek)
    finally:
        vault.lock()


def test_cli_ai_off_with_a_session_brakes_while_another_program_writes(quick, monkeypatch):
    from sezam import cli

    kek = _session_kek(quick)
    monkeypatch.setattr(cli, "_load_session", lambda: bytearray(kek))
    assert ai_access.read_state(Vault(quick)).enabled
    with _another_program_writes(quick):
        result = _run("ai", "off")
        assert not ai_access.read_state(Vault(quick)).enabled, result.output
    assert result.exit_code == 0, result.output
    assert "AI access is OFF" in result.output
    assert _run("ai", "status").output.startswith("AI access: OFF")


def test_the_gui_switch_brakes_while_another_program_writes(quick, monkeypatch):
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication, QWidget

    from sezam.gui import ai_switch

    QApplication.instance() or QApplication(sys.argv)
    monkeypatch.setattr(ai_switch.QMessageBox, "warning", lambda *a, **k: None)
    kek = _session_kek(quick)  # the window is unlocked
    parent = QWidget()
    switch = ai_switch.AIAccessSwitch(quick, lambda: kek, parent)
    try:
        with _another_program_writes(quick):
            switch.turn_off()
            deadline = time.monotonic() + 30
            while switch.worker is not None and time.monotonic() < deadline:
                switch.worker.join(0.05)
                QCoreApplication.processEvents()
            QCoreApplication.processEvents()
            assert switch.worker is None
            assert not ai_access.read_state(Vault(quick)).enabled, switch.last_message
        assert switch.last_message.startswith("AI access is OFF"), switch.last_message
    finally:
        switch._timer.stop()
        parent.deleteLater()


def test_the_brake_itself_never_waits_for_the_write_lock(quick):
    with _another_program_writes(quick):
        started = time.monotonic()
        result = control.pull_brake(Vault(quick), "cli")
        assert not result.state.enabled
        assert not ai_access.read_state(Vault(quick)).enabled
        assert time.monotonic() - started < 10
