"""Unlock dialog — master password prompt with Argon2id spinner."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from ..vault.crud import Vault

logger = logging.getLogger(__name__)


class UnlockWorker(QThread):
    """Background thread for Argon2id key derivation."""

    finished = Signal(object)  # Vault or Exception

    def __init__(self, vault_path: Path, password: str):
        super().__init__()
        self._vault_path = vault_path
        self._password = password
        self.notice: Optional[str] = None

    def run(self):
        try:
            vault = Vault(self._vault_path)
            vault.unlock(self._password)
            # Review 526419e V5: while the password is known, the server
            # learns this vault's org recovery (or the user hears it lacks it).
            from ..vault.org_recovery_server import register_while_password_known

            try:
                self.notice = register_while_password_known(vault, self._password)
            except Exception:  # never blocks the unlock
                logger.debug("Org recovery check failed", exc_info=True)
            self.finished.emit(vault)
        except Exception as e:
            self.finished.emit(e)


class UnlockDialog(QDialog):
    """Master password unlock dialog."""

    def __init__(self, vault_path: Path, parent=None):
        super().__init__(parent)
        self._vault_path = vault_path
        self.vault: Optional[Vault] = None
        self._worker: Optional[UnlockWorker] = None

        self.setWindowTitle("Sezam — Unlock")
        self.setFixedSize(380, 220)
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        self._title = QLabel("Sezam")
        self._title.setAlignment(Qt.AlignCenter)
        self._title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e0e0e0;")
        layout.addWidget(self._title)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Master password")
        self._password_input.setEchoMode(QLineEdit.Password)
        self._password_input.setStyleSheet(
            "background: #16213e; border: 1px solid #2a2a3e; border-radius: 6px; "
            "padding: 8px 12px; color: #e0e0e0; font-size: 14px;"
        )
        self._password_input.returnPressed.connect(self._unlock)
        layout.addWidget(self._password_input)

        self._unlock_btn = QPushButton("Unlock")
        self._unlock_btn.setStyleSheet(
            "background: #0f3460; color: #e0e0e0; border: none; border-radius: 6px; "
            "padding: 8px; font-size: 14px;"
        )
        self._unlock_btn.clicked.connect(self._unlock)
        layout.addWidget(self._unlock_btn)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # Indeterminate
        self._progress.setVisible(False)
        self._progress.setStyleSheet("QProgressBar { border: none; background: #16213e; height: 4px; }")
        layout.addWidget(self._progress)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        self._error_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._error_label)

        self.setStyleSheet("QDialog { background: #1a1a2e; }")

    def _unlock(self):
        password = self._password_input.text()
        if not password:
            return

        self._unlock_btn.setEnabled(False)
        self._password_input.setEnabled(False)
        self._progress.setVisible(True)
        self._error_label.setText("")

        self._worker = UnlockWorker(self._vault_path, password)
        self._worker.finished.connect(self._on_unlock_result)
        self._worker.start()

    def _on_unlock_result(self, result):
        self._progress.setVisible(False)
        self._unlock_btn.setEnabled(True)
        self._password_input.setEnabled(True)

        if isinstance(result, Vault):
            self.vault = result
            if self._worker is not None and self._worker.notice:
                QMessageBox.information(self, "Org Recovery", self._worker.notice)
            self.accept()
        else:
            self._error_label.setText("Wrong master password")
            self._password_input.selectAll()
            self._password_input.setFocus()
