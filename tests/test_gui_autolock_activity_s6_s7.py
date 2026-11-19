"""Review 526419e S6+S7: the desktop autolock.

S6: the idle timer was reset only by clicks in the main window's tree, so
typing a long note in a dialog counted as idle and the autolock closed the
dialog with the text in it. S7: the autolock also fired while a member
revocation ran in the background and cut its re-key off, and the message then
said the re-key "stays pending" while nothing was pending.
"""

from __future__ import annotations

import threading

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QDialog, QLineEdit, QVBoxLayout  # noqa: E402

from tests.test_integration_client_server import _client, server  # noqa: E402,F401
from tests.test_review_desktop_gui import qapp, vault, window  # noqa: E402,F401
from tests.test_revoke_second_member_8b import _admin_with_two_members  # noqa: E402
from sezam.vault import pending_states


def test_typing_in_a_dialog_keeps_the_vault_unlocked(window):  # noqa: F811
    window._autolock_ms = 2000
    window._reset_autolock()
    dialog = QDialog(window)
    field = QLineEdit(dialog)
    QVBoxLayout(dialog).addWidget(field)
    dialog.show()
    QTest.qWait(700)
    QTest.keyClicks(field, "a long note")
    assert window._autolock_timer.remainingTime() > 1800
    dialog.close()


def test_autolock_waits_for_a_background_call(window):  # noqa: F811
    from sezam.gui.background import run_in_background

    release = threading.Event()
    done = []
    run_in_background(window, lambda: release.wait(5), done.append)
    try:
        window._reset_autolock()
        window._autolock_timer.timeout.emit()
        assert window._vault is not None  # not locked under the call
        assert window._autolock_timer.isActive()
    finally:
        release.set()
    for _ in range(100):
        QCoreApplication.processEvents()
        if done:
            break
        QTest.qWait(20)
    assert done
    window._autolock_timer.timeout.emit()
    assert window._vault is None  # locks once the call is over


def test_a_rekey_cut_off_is_not_reported_as_pending(server, tmp_path, monkeypatch):  # noqa: F811
    from sezam.vault.revocation import RekeyPending, queued_revocations, revoke_member

    url, db = server
    admin, bob_id, _carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)

    def locked_midway(user_id):
        raise RuntimeError("Vault is locked")

    monkeypatch.setattr(admin, "rekey_after_revocation", locked_midway)
    with pytest.raises(RekeyPending) as info:
        revoke_member(admin, _client(admin, url), bob_id)
    assert "stays pending" not in str(info.value)
    assert (pending_states.rekey_batch(admin.db) or None) in (None, {})
    assert queued_revocations(admin) == [bob_id]  # the next push re-keys
