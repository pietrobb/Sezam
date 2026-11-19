"""Regression tests for desktop GUI review items 32-34 (HEAD 2c7e809)."""

import sys

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication, QEvent, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402
from shiboken6 import isValid  # noqa: E402

from sezam.crypto.kdf import Argon2Params  # noqa: E402
from sezam.vault.crud import Vault  # noqa: E402

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "TestHeslo123!"
TOTP_SEED = "JBSWY3DPEHPK3PXP"


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

    w = MainWindow(tmp_path)
    w._vault = vault
    unlock_calls = []
    monkeypatch.setattr(w, "_show_unlock", lambda: unlock_calls.append(True))
    w.unlock_calls = unlock_calls
    yield w
    w._tray.hide()
    w.deleteLater()


def _flush_deletes():
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    QCoreApplication.processEvents()


# -- 32: auto-lock closes and frees dialogs ----------------------------------

def test_lock_during_dialog_rejects_and_frees_it(window, vault):
    from sezam.gui.entry_dialog import EntryDialog

    node = vault.create_node("Servers")
    entry_id = vault.create_entry(
        node, "SSH", [{"key": "password", "value": "s3cret", "sensitive": True}]
    )
    dialog = EntryDialog(vault, node, entry=vault.read_entry(entry_id), parent=window)
    QTimer.singleShot(50, window.lock_vault)

    accepted = window._run_dialog(dialog)

    assert accepted is False
    assert window._vault is None
    assert not vault.is_unlocked
    _flush_deletes()
    assert not isValid(dialog), "dialog with secrets must be deallocated"
    # The unlock prompt is deferred until the dialog's loop has unwound.
    QCoreApplication.processEvents()
    assert window.unlock_calls == [True]


def test_lock_rejects_nested_dialogs(window):
    outer = QDialog(window)
    inner = QDialog(outer)
    outer.show()
    inner.show()

    window.lock_vault()

    assert not outer.isVisible()
    assert not inner.isVisible()


def test_unlock_prompt_not_stacked(qapp, tmp_path, monkeypatch):
    from sezam.gui import main_window

    created = []

    class FakeUnlock:
        def __init__(self, *args):
            created.append(self)
            self.vault = None

        def exec(self):
            w._show_unlock()  # e.g. global hotkey while the prompt is open
            return 0

        def deleteLater(self):
            pass

    monkeypatch.setattr(main_window, "UnlockDialog", FakeUnlock)
    w = main_window.MainWindow(tmp_path)
    monkeypatch.setattr(w, "_quit", lambda: None)
    w._show_unlock()
    assert len(created) == 1
    assert w._unlock_showing is False
    w._tray.hide()


# -- 33: tray icon is visible and close does not orphan the process ---------

def test_tray_has_icon(window):
    assert not window._tray.icon().isNull()
    assert not window.windowIcon().isNull()


def test_close_without_tray_quits(window, monkeypatch):
    from sezam.gui import main_window
    from PySide6.QtGui import QCloseEvent

    quits = []
    monkeypatch.setattr(window, "_quit", lambda: quits.append(True))
    monkeypatch.setattr(
        main_window.QSystemTrayIcon, "isSystemTrayAvailable", staticmethod(lambda: False)
    )
    event = QCloseEvent()
    window.closeEvent(event)
    assert event.isAccepted()
    assert quits == [True]


# -- 34a: TOTP copy never yields the seed -----------------------------------

def test_totp_copy_emits_code_not_seed(qapp, monkeypatch):
    from sezam.gui import entry_detail

    monkeypatch.setattr(entry_detail, "time_remaining", lambda *a, **k: 20)
    fw = entry_detail.FieldWidget("totp", TOTP_SEED, sensitive=True, field_type="totp")
    copied = []
    fw.copy_requested.connect(copied.append)
    fw._do_copy()
    assert len(copied) == 1
    assert copied[0] != TOTP_SEED
    assert copied[0].isdigit()


def test_invalid_totp_copy_emits_nothing(qapp, monkeypatch):
    from sezam.gui import entry_detail

    monkeypatch.setattr(entry_detail, "time_remaining", lambda *a, **k: 20)
    seed = "not a base32 seed !!!"
    fw = entry_detail.FieldWidget("totp", seed, sensitive=True, field_type="totp")
    copied = []
    fw.copy_requested.connect(copied.append)
    fw._do_copy()
    assert copied == []


def test_totp_copy_near_rollover_does_not_block(qapp, monkeypatch):
    from sezam.gui import entry_detail

    monkeypatch.setattr(entry_detail, "time_remaining", lambda *a, **k: 1)
    monkeypatch.setattr(
        "time.sleep", lambda *_: pytest.fail("GUI thread must not sleep")
    )
    fw = entry_detail.FieldWidget("totp", TOTP_SEED, sensitive=True, field_type="totp")
    copied = []
    fw.copy_requested.connect(copied.append)
    fw._do_copy()
    assert copied == []  # deferred to the next period, not emitted synchronously


# -- 34b: "Inherit" clears an explicit tier ---------------------------------

def test_update_entry_inherit_tier_clears_tier(vault):
    node = vault.create_node("N")
    entry_id = vault.create_entry(node, "E", [{"key": "k", "value": "v"}], tier=2)
    vault.update_entry(entry_id, name="E2")
    assert vault.read_entry(entry_id)["tier"] == 2  # tier=None keeps it
    vault.update_entry(entry_id, inherit_tier=True)
    assert vault.read_entry(entry_id)["tier"] is None
    with pytest.raises(ValueError):
        vault.update_entry(entry_id, tier=1, inherit_tier=True)


def test_entry_dialog_inherit_clears_tier(qapp, vault):
    from sezam.gui.entry_dialog import EntryDialog

    node = vault.create_node("N")
    entry_id = vault.create_entry(node, "E", [{"key": "k", "value": "v"}], tier=2)
    dialog = EntryDialog(vault, node, entry=vault.read_entry(entry_id))
    dialog._tier_combo.setCurrentIndex(0)  # "Inherit"
    dialog._save()
    assert vault.read_entry(entry_id)["tier"] is None
