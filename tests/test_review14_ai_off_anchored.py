"""Review 8bc70f7 R14-M3 (last part): 'sezam ai off' and the GUI switch
anchored nothing on the sync server; only a running broker did.

With no mcp-serve running, an agent under the owner's OS user saved the rows
of a sealed 'on', waited for 'sezam ai off' (or the GUI switch) and wrote
them back. The server still held the anchor from before the brake, so the
next broker took the old 'on'. The brake now anchors its own 'off' epoch
when the vault is unlocked, and says so when it cannot.
"""

from __future__ import annotations

import sys
import time

import pytest

from sezam.mcp import broker as broker_mod
from sezam.mcp import control
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_ai_switch_replay_h6 import _copy_rows, _write_rows
from tests.test_review13_ai_switch_anchor import (
    _allowed,
    _broker,
    _code,
    _stop,
    laptop,  # noqa: F401  (fixture)
)


@pytest.fixture(autouse=True)
def _no_running_brokers(monkeypatch):
    monkeypatch.setattr(broker_mod, "ANCHOR_WAIT_SECONDS", 2)
    monkeypatch.setattr(control, "send_all", lambda *a, **k: [])


def _anchored_on(vault) -> dict:
    """AI on with its anchor home made (one broker run), then no broker."""
    first = _broker(vault)
    assert _allowed(first)
    _stop(first)
    first.remote_policy._thread.join(30)  # gone: it must not anchor the brake
    assert not first.remote_policy._thread.is_alive()
    return _copy_rows(vault)  # the agent's copy of the sealed 'on'


def _refused(broker) -> str:
    return _code(lambda: broker.vault_list(""))


def test_ai_off_with_no_broker_running_is_anchored(laptop):  # noqa: F811
    saved = _anchored_on(laptop)
    result = control.pull_brake(laptop, "cli")
    _write_rows(laptop, saved)
    assert ai_access.read_state(laptop).enabled  # on disk: the replayed copy
    second = _broker(laptop)
    try:
        assert _refused(second) == "ai_disabled"
    finally:
        _stop(second)
    assert result.stopped == 0 and result.unanchored is None


def test_a_brake_on_a_locked_vault_says_it_is_not_anchored(laptop):  # noqa: F811
    _anchored_on(laptop)
    result = control.pull_brake(Vault(laptop.path), "cli")
    assert not ai_access.read_state(laptop).enabled
    assert result.unanchored == "the vault is locked"


def test_an_unreachable_server_does_not_hold_back_the_brake(laptop, monkeypatch):  # noqa: F811
    _anchored_on(laptop)
    real = SyncClient._request

    def blocked(self, method, path, *args, **kwargs):
        if path.startswith("/api/ai-anchor"):
            raise ConnectionError("blocked by the agent")
        return real(self, method, path, *args, **kwargs)

    monkeypatch.setattr(SyncClient, "_request", blocked)
    result = control.pull_brake(laptop, "cli")
    assert not ai_access.read_state(laptop).enabled
    assert "blocked by the agent" in result.unanchored


def test_put_anchor_on_a_locked_vault_sends_nothing(laptop, monkeypatch):  # noqa: F811
    """_put_anchor: the MAC and the signature need the unlocked vault."""
    from sezam.mcp import remote_policy

    _anchored_on(laptop)
    home = ai_access.anchor_home(laptop)
    sent = []
    monkeypatch.setattr(remote_policy, "_authed", lambda *a, **k: sent.append(a))
    locked = Vault(laptop.path)
    with pytest.raises(ai_access.AnchorUnverifiable):
        remote_policy._put_anchor(locked, None, home, 5)
    assert sent == []
    remote_policy._put_anchor(laptop, None, home, 5)
    assert sent and sent[0][3]["epoch"] == 5 and len(sent[0][3]["signature"]) == 128


def test_a_vault_on_no_server_needs_no_anchor(tmp_path):
    from tests.test_integration_client_server import _vault

    vault = _vault(tmp_path / "alone", "solo")
    try:
        assert control.pull_brake(vault, "cli").unanchored is None
    finally:
        vault.lock()


def test_the_gui_anchors_a_locked_window_brake_once_it_is_unlocked(laptop, monkeypatch):  # noqa: F811
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication, QWidget

    from sezam.gui.ai_switch import AIAccessSwitch

    QApplication.instance() or QApplication(sys.argv)
    saved = _anchored_on(laptop)
    kek = {"value": None}  # the window is locked
    parent = QWidget()
    switch = AIAccessSwitch(laptop.path, lambda: kek["value"], parent)

    def settle():
        deadline = time.monotonic() + 15
        while switch.worker is not None and time.monotonic() < deadline:
            switch.worker.join(0.05)
            QCoreApplication.processEvents()
        QCoreApplication.processEvents()
        assert switch.worker is None

    try:
        switch.turn_off()
        settle()
        assert "Not anchored on the sync server yet" in switch.last_message
        kek["value"] = bytearray(laptop._dek_mgr._kek)  # the window is unlocked
        switch.refresh()
        settle()
        assert "is now anchored on the sync server" in switch.last_message
        _write_rows(laptop, saved)
        second = _broker(laptop)
        assert _refused(second) == "ai_disabled"
        _stop(second)
    finally:
        switch._timer.stop()
        parent.deleteLater()
