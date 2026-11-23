"""AI access switch for the main window and the tray (AI broker TODO S1d).

Same rule as the CLI: turning AI access off never asks for anything and
works while the vault is locked; turning it on always asks for the master
password, even when the window is unlocked. The state is re-read every few
seconds so a change from the CLI or a running broker shows up.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QPushButton, QWidget

from ..mcp import control
from ..vault import ai_access
from ..vault.crud import Vault
from .styles import COLORS

logger = logging.getLogger(__name__)

REFRESH_MS = 5000
ANCHOR_RETRY_SECONDS = 30.0


class AIAccessSwitch(QObject):
    """Toolbar button + tray action showing and flipping the kill switch."""

    _finished = Signal(str, object, object)  # kind, result, error

    def __init__(
        self,
        vault_path: Path,
        current_kek: Callable[[], Optional[bytearray]],
        parent: QWidget,
    ):
        super().__init__(parent)
        self._vault_path = Path(vault_path)
        self._current_kek = current_kek
        self._parent = parent
        self.worker: Optional[threading.Thread] = None
        self.last_message = ""
        # R14-M3: an 'off' pulled while the window was locked could not be
        # anchored on the sync server; it is, once the window is unlocked.
        self._unanchored_epoch: Optional[int] = None
        self._anchor_retry_at = 0.0

        self.button = QPushButton()
        self.button.setFixedWidth(150)
        self.button.clicked.connect(self.toggle)
        self.tray_action = QAction(self)
        self.tray_action.triggered.connect(self.toggle)
        self._finished.connect(self._on_finished)

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def _vault_exists(self) -> bool:
        return (self._vault_path / "sezam.db").exists()

    def state(self) -> Optional[ai_access.AIAccessState]:
        if not self._vault_exists():
            return None
        return ai_access.read_state(Vault(self._vault_path))

    def refresh(self) -> None:
        state = self.state()
        busy = self.worker is not None and self.worker.is_alive()
        if state is None:
            self.button.setText("AI access: -")
            self.button.setEnabled(False)
            self.tray_action.setText("AI access: no vault")
            self.tray_action.setEnabled(False)
            return
        self.button.setEnabled(not busy)
        self.tray_action.setEnabled(not busy)
        color = COLORS["success"] if state.enabled else COLORS["error"]
        self.button.setText(f"AI access: {'ON' if state.enabled else 'OFF'}")
        self.button.setToolTip(
            "Click to turn AI access off (no password)." if state.enabled
            else "Click to turn AI access on (master password)."
        )
        self.button.setStyleSheet(
            f"color: {color}; border: 1px solid {color}; font-weight: bold;"
        )
        self.tray_action.setText(
            "Turn AI access OFF" if state.enabled else "Turn AI access on..."
        )
        if (
            self._unanchored_epoch is not None and not busy and not state.enabled
            and time.monotonic() >= self._anchor_retry_at and self._current_kek() is not None
        ):
            self._anchor_again(self._unanchored_epoch)

    def _anchor_again(self, epoch: int) -> None:
        kek = bytearray(self._current_kek())

        def job():
            from ..mcp.remote_policy import ServerAnchor

            vault = Vault(self._vault_path)
            try:
                vault.unlock_with_kek(kek)
                ServerAnchor(vault, {}).anchor_off(epoch)
                return epoch
            finally:
                vault.lock()
                kek[:] = b"\x00" * len(kek)

        self._start("anchor", job)

    def toggle(self) -> None:
        state = self.state()
        if state is None:
            return
        if state.enabled:
            self.turn_off()
        else:
            self.turn_on()

    def turn_off(self) -> None:
        """The brake: no password, also while locked."""
        kek = self._current_kek()
        kek = None if kek is None else bytearray(kek)

        def job():
            vault = Vault(self._vault_path)
            try:
                if kek is not None:
                    try:
                        vault.unlock_with_kek(kek)  # audit at once, not at the next unlock
                    except ValueError:
                        pass
                return control.pull_brake(vault, "gui")
            finally:
                vault.lock()
                if kek is not None:
                    kek[:] = b"\x00" * len(kek)

        self._start("off", job)

    def turn_on(self) -> None:
        """Always asks for the master password, whatever the lock state."""
        password, ok = QInputDialog.getText(
            self._parent,
            "Turn AI access on",
            "Master password (required to turn AI access on):",
            QLineEdit.Password,
        )
        if not ok or not password:
            return

        def job(password=password):
            vault = Vault(self._vault_path)
            try:
                vault.unlock(password)
                return ai_access.enable(vault, "gui")
            finally:
                vault.lock()

        self._start("on", job)

    def _start(self, kind: str, job) -> None:
        if self.worker is not None and self.worker.is_alive():
            return

        def run():
            try:
                result = job()
            except Exception as exc:
                self._finished.emit(kind, None, exc)
                return
            self._finished.emit(kind, result, None)

        self.button.setEnabled(False)
        self.tray_action.setEnabled(False)
        self.worker = threading.Thread(target=run, name=f"sezam-ai-{kind}", daemon=True)
        self.worker.start()

    def _on_finished(self, kind: str, result, error) -> None:
        self.worker = None
        if kind == "anchor":
            if error is not None:
                logger.warning("Anchoring the AI 'off' on the sync server failed", exc_info=error)
                self._anchor_retry_at = time.monotonic() + ANCHOR_RETRY_SECONDS
            elif self._unanchored_epoch == result:
                self._unanchored_epoch = None
                self._show(f"AI access 'off' (epoch {result}) is now anchored on the sync server.")
            self.refresh()
            return
        self.refresh()
        if error is not None:
            if kind == "on" and isinstance(error, ValueError):
                self.last_message = "Wrong master password: AI access stays off."
            else:
                logger.error("Turning AI access %s failed", kind, exc_info=error)
                self.last_message = f"Turning AI access {kind} failed: {error}"
            QMessageBox.warning(self._parent, "AI access", self.last_message)
            return
        if kind == "off":
            self.last_message = f"AI access is OFF (epoch {result.state.epoch})."
            if result.stopped:
                self.last_message += f" {result.stopped} running MCP server(s) stopped."
            if result.unanswered:
                self.last_message += (
                    f" {result.unanswered} did not answer; they close their sessions within seconds."
                )
            if result.unanchored:
                self._unanchored_epoch = result.state.epoch
                self._anchor_retry_at = 0.0
                self.last_message += (
                    f" Not anchored on the sync server yet ({result.unanchored}); "
                    "it is once the vault is unlocked here."
                )
        else:
            self._unanchored_epoch = None
            self.last_message = f"AI access is ON (epoch {result.epoch})."
            try:
                waits = ai_access.anchor_expected(Vault(self._vault_path))
            except Exception:
                waits = True
            if waits:  # R16-L6: say what AI tools wait for
                self.last_message += (
                    " AI tools work once the sync server confirms the switch; if that server "
                    "is gone for good, run 'sezam ai on --server-gone'."
                )
        self._show(self.last_message)

    def _show(self, message: str) -> None:
        self.last_message = message
        status_bar = getattr(self._parent, "statusBar", None)
        if status_bar is not None:
            status_bar().showMessage(message, 10_000)
