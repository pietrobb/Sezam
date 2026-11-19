"""Settings dialog — auto-lock, clipboard, Argon2id params, server URL."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)


if TYPE_CHECKING:
    from ..vault.crud import Vault


class SettingsDialog(QDialog):
    """Application settings."""

    server_connect_requested = Signal()
    security_settings_saved = Signal(int, int)

    def __init__(self, vault: Optional[Vault] = None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self.setWindowTitle("Nastavenia")
        self.setFixedSize(440, 340)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        form = QFormLayout()

        self._autolock_spin = QSpinBox()
        self._autolock_spin.setRange(1, 120)
        autolock_minutes = int(vault.db.get_meta("autolock_minutes") or 15) if vault else 15
        self._autolock_spin.setValue(autolock_minutes)
        self._autolock_spin.setSuffix(" min")
        form.addRow("Auto-lock po:", self._autolock_spin)

        self._clipboard_spin = QSpinBox()
        self._clipboard_spin.setRange(5, 120)
        clipboard_seconds = int(vault.db.get_meta("clipboard_clear_seconds") or 15) if vault else 15
        self._clipboard_spin.setValue(clipboard_seconds)
        self._clipboard_spin.setSuffix(" sec")
        form.addRow("Schranku vymazat:", self._clipboard_spin)

        # Server URL display row
        server_row = QHBoxLayout()
        self._server_input = QLineEdit()
        self._server_input.setPlaceholderText("https://sezam.example.com")
        self._server_input.setReadOnly(True)
        if vault:
            existing_url = vault.db.get_meta("server_url") or ""
            if existing_url:
                self._server_input.setText(existing_url)
        server_row.addWidget(self._server_input, 1)

        self._connect_btn = QPushButton("Pripojit k serveru")
        self._connect_btn.setProperty("cssClass", "accent")
        self._connect_btn.clicked.connect(self._on_connect_server)
        server_row.addWidget(self._connect_btn)

        form.addRow("Server:", server_row)

        layout.addLayout(form)
        layout.addStretch()

        save_btn = QPushButton("Ulozit")
        save_btn.clicked.connect(self._save)
        layout.addWidget(save_btn)

    def _save(self) -> None:
        autolock_minutes = self._autolock_spin.value()
        clipboard_seconds = self._clipboard_spin.value()
        if self._vault:
            self._vault.db.set_meta("autolock_minutes", str(autolock_minutes))
            self._vault.db.set_meta("clipboard_clear_seconds", str(clipboard_seconds))
            self._vault.db.conn.commit()
        self.security_settings_saved.emit(autolock_minutes, clipboard_seconds)
        self.accept()

    def _on_connect_server(self) -> None:
        self.server_connect_requested.emit()
        self.accept()
