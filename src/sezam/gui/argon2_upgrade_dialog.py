"""Argon2id parameter upgrade dialog.

Spec 9.5: After a successful unlock, if current Argon2 params are weaker
than recommended, prompt the user to upgrade. On accept, re-derive KEK
with new params and re-wrap all DEKs.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from .background import track as track_worker
from ..crypto.kdf import Argon2Params
from ..vault.crud import Vault
from .styles import COLORS


class _UpgradeWorker(QThread):
    """Background thread for Argon2id re-derivation and DEK re-wrap."""

    finished = Signal(object)  # None on success, Exception on failure

    def __init__(
        self,
        vault: Vault,
        password: str,
        new_params: Argon2Params,
    ):
        super().__init__()
        self._vault = vault
        self._password = password
        self._new_params = new_params

    def run(self):
        try:
            upgrade_vault_kdf(self._vault, self._password, self._new_params)
            self.finished.emit(None)
        except Exception as e:
            self.finished.emit(e)


def upgrade_vault_kdf(vault: Vault, password: str, new_params: Argon2Params) -> None:
    """Upgrade Argon2 params through the verified password-rotation path.

    ``Vault.change_password`` verifies the typed password against the active
    KEK (a typo is rejected instead of becoming the new password), re-wraps
    org recovery and bumps key_epoch. When connected, one push carries the
    DEK rewrap, the epoch and the new key material (applied together by the
    server); if it fails, the next sync resends it from the local journal.
    """
    db = vault.db
    client = None
    server_url = db.get_meta("server_url")
    if server_url:
        from ..vault.sync_client import SyncClient

        client = SyncClient(db, server_url, vault.keypair, db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        client.prepare_key_change()  # fail before any local change

    auth_proof = vault.change_password(password, password, new_params=new_params)
    try:
        if client is not None:
            client.push()
    finally:
        auth_proof[:] = b"\x00" * len(auth_proof)


class Argon2UpgradeDialog(QDialog):
    """Dialog offering to upgrade Argon2id parameters to recommended values.

    Shows a comparison of current vs recommended params and requires
    the master password to proceed.
    """

    def __init__(
        self,
        current_params: Argon2Params,
        recommended_params: Argon2Params,
        vault: Vault,
        parent=None,
    ):
        super().__init__(parent)
        self._current = current_params
        self._recommended = recommended_params
        self._vault = vault
        self._worker: Optional[_UpgradeWorker] = None

        self.setWindowTitle("Security Upgrade Available")
        self.setFixedSize(480, 380)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # Title
        title = QLabel("Stronger Key Derivation Available")
        title.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {COLORS['text']};"
        )
        layout.addWidget(title)

        # Explanation
        explanation = QLabel(
            "Your vault is using weaker Argon2id parameters than currently "
            "recommended. Upgrading increases resistance to brute-force attacks."
        )
        explanation.setWordWrap(True)
        explanation.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        layout.addWidget(explanation)

        # Comparison table
        comparison = QLabel(self._build_comparison_text())
        comparison.setStyleSheet(
            f"background: {COLORS['bg_card']}; border-radius: 8px; "
            f"padding: 12px; font-family: 'Cascadia Code', monospace; "
            f"font-size: 12px; color: {COLORS['text']};"
        )
        layout.addWidget(comparison)

        # Password field
        pw_label = QLabel("Enter master password to upgrade:")
        pw_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(pw_label)

        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("Master password")
        self._password_input.setEchoMode(QLineEdit.Password)
        self._password_input.returnPressed.connect(self._do_upgrade)
        layout.addWidget(self._password_input)

        # Progress
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # Indeterminate
        self._progress.setVisible(False)
        self._progress.setFixedHeight(4)
        layout.addWidget(self._progress)

        # Status label
        self._status_label = QLabel("")
        self._status_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 12px;")
        self._status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._status_label)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        skip_btn = QPushButton("Skip for Now")
        skip_btn.clicked.connect(self.reject)
        btn_row.addWidget(skip_btn)

        btn_row.addStretch()

        self._upgrade_btn = QPushButton("Upgrade Security")
        self._upgrade_btn.setProperty("cssClass", "accent")
        self._upgrade_btn.clicked.connect(self._do_upgrade)
        btn_row.addWidget(self._upgrade_btn)

        layout.addLayout(btn_row)

    def _build_comparison_text(self) -> str:
        """Build a text comparison of current vs recommended params."""
        def _mem_str(kb: int) -> str:
            return f"{kb // 1024} MB"

        lines = [
            f"{'Parameter':<16} {'Current':>10} {'Recommended':>14}",
            f"{'─' * 42}",
            f"{'Time cost':<16} {self._current.time_cost:>10} {self._recommended.time_cost:>14}",
            f"{'Memory':<16} {_mem_str(self._current.memory_cost):>10} {_mem_str(self._recommended.memory_cost):>14}",
            f"{'Parallelism':<16} {self._current.parallelism:>10} {self._recommended.parallelism:>14}",
        ]
        return "\n".join(lines)

    def _do_upgrade(self):
        """Start the Argon2id parameter upgrade."""
        password = self._password_input.text()
        if not password:
            self._status_label.setText("Enter your master password")
            return

        self._upgrade_btn.setEnabled(False)
        self._password_input.setEnabled(False)
        self._progress.setVisible(True)
        self._status_label.setText("")

        self._worker = _UpgradeWorker(
            vault=self._vault,
            password=password,
            new_params=self._recommended,
        )
        self._worker.finished.connect(self._on_upgrade_result)
        self._worker.start()
        track_worker(self._worker)

    def _on_upgrade_result(self, result):
        """Handle upgrade completion."""
        self._progress.setVisible(False)
        self._upgrade_btn.setEnabled(True)
        self._password_input.setEnabled(True)

        if result is None:
            QMessageBox.information(
                self,
                "Upgrade Complete",
                "Argon2id parameters have been upgraded.\n"
                "All encryption keys have been re-wrapped with the stronger derivation.",
            )
            self.accept()
        else:
            self._status_label.setText(f"Upgrade failed: {result}")
            self._password_input.selectAll()
            self._password_input.setFocus()
