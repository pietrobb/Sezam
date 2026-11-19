"""First run wizard — create vault with master password.

Spec 7.1: "Vitajte v Sezame. Vytvorte si master heslo."
+ varovanie o nenávratnej strate + Argon2id benchmark.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from ..crypto.kdf import benchmark_argon2
from ..password import estimate_strength
from ..vault.crud import Vault


class CreateVaultWorker(QThread):
    """Background thread for vault creation (Argon2id benchmark + derivation)."""

    finished = Signal(object)

    def __init__(self, vault_path: Path, password: str):
        super().__init__()
        self._path = vault_path
        self._password = password

    def run(self):
        try:
            params = benchmark_argon2(target_seconds=1.0)
            vault = Vault.create(self._path, self._password, params)
            self.finished.emit(vault)
        except Exception as e:
            self.finished.emit(e)


class WizardDialog(QDialog):
    """First-run vault creation wizard."""

    def __init__(self, vault_path: Path, parent=None):
        super().__init__(parent)
        self._vault_path = vault_path
        self.vault: Optional[Vault] = None
        self._worker: Optional[CreateVaultWorker] = None

        self.setWindowTitle("Sezam — Setup")
        self.setFixedSize(420, 380)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Welcome to Sezam")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #e0e0e0;")
        layout.addWidget(title)

        warning = QLabel("Create your master password.\nForgotten password = permanent data loss.")
        warning.setAlignment(Qt.AlignCenter)
        warning.setStyleSheet("color: #f39c12; font-size: 13px;")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        layout.addSpacing(8)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Master password")
        self._password_input.setEchoMode(QLineEdit.Password)
        self._password_input.textChanged.connect(self._on_password_changed)
        self._password_input.setStyleSheet(
            "background: #16213e; border: 1px solid #2a2a3e; border-radius: 6px; "
            "padding: 8px 12px; color: #e0e0e0; font-size: 14px;"
        )
        layout.addWidget(self._password_input)

        self._strength_label = QLabel("")
        self._strength_label.setStyleSheet("font-size: 12px;")
        layout.addWidget(self._strength_label)

        self._confirm_input = QLineEdit()
        self._confirm_input.setPlaceholderText("Confirm password")
        self._confirm_input.setEchoMode(QLineEdit.Password)
        self._confirm_input.setStyleSheet(
            "background: #16213e; border: 1px solid #2a2a3e; border-radius: 6px; "
            "padding: 8px 12px; color: #e0e0e0; font-size: 14px;"
        )
        layout.addWidget(self._confirm_input)

        self._create_btn = QPushButton("Create Vault")
        self._create_btn.setStyleSheet(
            "background: #0f3460; color: #e0e0e0; border: none; border-radius: 6px; "
            "padding: 10px; font-size: 14px;"
        )
        self._create_btn.clicked.connect(self._create)
        layout.addWidget(self._create_btn)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        layout.addWidget(self._progress)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #a0a0b0; font-size: 12px;")
        self._status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._status_label)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: #e74c3c; font-size: 12px;")
        self._error_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._error_label)

        self.setStyleSheet("QDialog { background: #1a1a2e; }")

    def _on_password_changed(self, text):
        if text:
            s = estimate_strength(text)
            colors = {0: "#e74c3c", 1: "#e74c3c", 2: "#f39c12", 3: "#2ecc71", 4: "#2ecc71"}
            self._strength_label.setText(f"{s['label']} ({s['entropy_bits']} bits)")
            self._strength_label.setStyleSheet(f"font-size: 12px; color: {colors[s['score']]};")
        else:
            self._strength_label.setText("")

    def _create(self):
        password = self._password_input.text()
        confirm = self._confirm_input.text()

        if not password:
            self._error_label.setText("Password cannot be empty")
            return
        if password != confirm:
            self._error_label.setText("Passwords do not match")
            return

        self._error_label.setText("")
        self._create_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText("Benchmarking Argon2id and creating vault...")

        self._worker = CreateVaultWorker(self._vault_path, password)
        self._worker.finished.connect(self._on_created)
        self._worker.start()

    def _on_created(self, result):
        self._progress.setVisible(False)
        self._create_btn.setEnabled(True)

        if isinstance(result, Vault):
            self.vault = result
            self._status_label.setText("Vault created!")
            self.accept()
        else:
            self._error_label.setText(str(result))
            self._status_label.setText("")
