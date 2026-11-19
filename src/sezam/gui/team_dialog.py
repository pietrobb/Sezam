"""Team admin panel — user list, invitations, audit log, shares.

Spec 7.1: GUI admin panel for team management.
"""

from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .background import run_in_background
from .styles import COLORS


class TeamDialog(QDialog):
    """Team administration dialog with tabs for users, audit log, and shares."""

    def __init__(self, vault=None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._server_client = None
        self.setWindowTitle("Team Administration")
        self.setMinimumSize(820, 560)
        self.resize(900, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(
            f"background: {COLORS['bg_panel']}; "
            f"border-bottom: 1px solid {COLORS['border']};"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)

        title = QLabel("Team Administration")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet(f"color: {COLORS['text']};")
        header_layout.addWidget(title)
        header_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(80)
        close_btn.clicked.connect(self.accept)
        header_layout.addWidget(close_btn)

        layout.addWidget(header)

        # Tab widget
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background: {COLORS['bg']};
            }}
            QTabBar::tab {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text_secondary']};
                padding: 10px 24px;
                border: none;
                border-bottom: 2px solid transparent;
                font-size: 13px;
            }}
            QTabBar::tab:selected {{
                color: {COLORS['text']};
                border-bottom: 2px solid {COLORS['accent']};
            }}
            QTabBar::tab:hover {{
                color: {COLORS['text']};
                background: {COLORS['bg_hover']};
            }}
        """)
        layout.addWidget(self._tabs, 1)

        self._setup_users_tab()
        self._setup_audit_tab()
        self._setup_shares_tab()
        self._setup_org_recovery_tab()

        # Load data
        self._refresh_users()
        self._refresh_audit()
        self._refresh_shares()

    def _get_server_client(self):
        """Return one authenticated client for the configured server."""
        if self._server_client is not None:
            return self._server_client
        server_url = self._vault.db.get_meta("server_url")
        user_id = self._vault.db.get_meta("user_id")
        if not server_url or not user_id:
            raise RuntimeError("This vault is not connected to a server")
        from ..vault.sync_client import SyncClient

        self._server_client = SyncClient(
            self._vault.db, server_url, self._vault.keypair, user_id
        )
        # A refused re-key is rebased on the pulled objects (needs the DEKs).
        self._server_client.set_dek_manager(self._vault.dek_mgr)
        self._server_client.authenticate()
        return self._server_client

    # ---- Users Tab ----

    def _setup_users_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Action bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(8)

        invite_btn = QPushButton("Invite Colleague")
        invite_btn.setProperty("cssClass", "accent")
        invite_btn.clicked.connect(self._invite_colleague)
        action_bar.addWidget(invite_btn)

        approve_btn = QPushButton("Approve Selected")
        approve_btn.clicked.connect(self._approve_user)
        action_bar.addWidget(approve_btn)

        share_btn = QPushButton("Share Folder…")
        share_btn.clicked.connect(self._grant_folder)
        action_bar.addWidget(share_btn)

        revoke_btn = QPushButton("Revoke Access")
        revoke_btn.setStyleSheet(
            f"QPushButton {{ color: {COLORS['error']}; }} "
            f"QPushButton:hover {{ background: {COLORS['error']}; color: white; }}"
        )
        revoke_btn.clicked.connect(self._revoke_user)
        action_bar.addWidget(revoke_btn)

        # Review 526419e S4: only 'sezam push' finished the revocation queue.
        finish_btn = QPushButton("Finish Re-keys")
        finish_btn.setToolTip(
            "Send the re-keys of revoked members and settle the sync conflicts they wait for"
        )
        finish_btn.clicked.connect(self._finish_rekeys)
        action_bar.addWidget(finish_btn)

        action_bar.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_users)
        action_bar.addWidget(refresh_btn)

        layout.addLayout(action_bar)

        # Users table
        self._users_table = QTableWidget()
        self._users_table.setColumnCount(5)
        self._users_table.setHorizontalHeaderLabels(
            ["Name", "Status", "Fingerprint", "Role", "Joined"]
        )
        self._users_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._users_table.setSelectionMode(QTableWidget.SingleSelection)
        self._users_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._users_table.setAlternatingRowColors(True)
        self._users_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self._users_table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLORS['bg']};
                gridline-color: {COLORS['border']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
            QTableWidget::item {{
                padding: 6px 12px;
            }}
            QTableWidget::item:selected {{
                background: {COLORS['bg_selected']};
                color: white;
            }}
            QHeaderView::section {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text_secondary']};
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                padding: 8px 12px;
                border: none;
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        layout.addWidget(self._users_table, 1)

        self._tabs.addTab(tab, "Users")

    # ---- Audit Log Tab ----

    def _setup_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Filter bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(8)

        filter_bar.addWidget(QLabel("Actor:"))
        self._audit_actor_filter = QComboBox()
        self._audit_actor_filter.setMinimumWidth(150)
        self._audit_actor_filter.addItem("All", "")
        filter_bar.addWidget(self._audit_actor_filter)

        filter_bar.addWidget(QLabel("Action:"))
        self._audit_action_filter = QComboBox()
        self._audit_action_filter.setMinimumWidth(120)
        self._audit_action_filter.addItem("All", "")
        for action in ("read", "write", "delete", "approve", "deny", "share", "rekey"):
            self._audit_action_filter.addItem(action, action)
        filter_bar.addWidget(self._audit_action_filter)

        filter_bar.addWidget(QLabel("Since:"))
        self._audit_date_filter = QComboBox()
        self._audit_date_filter.setMinimumWidth(120)
        self._audit_date_filter.addItem("All time", "0")
        self._audit_date_filter.addItem("Last hour", "3600000")
        self._audit_date_filter.addItem("Last 24h", "86400000")
        self._audit_date_filter.addItem("Last 7 days", "604800000")
        self._audit_date_filter.addItem("Last 30 days", "2592000000")
        filter_bar.addWidget(self._audit_date_filter)

        filter_bar.addStretch()

        filter_apply_btn = QPushButton("Apply Filters")
        filter_apply_btn.clicked.connect(self._refresh_audit)
        filter_bar.addWidget(filter_apply_btn)

        layout.addLayout(filter_bar)

        # Audit table
        self._audit_table = QTableWidget()
        self._audit_table.setColumnCount(4)
        self._audit_table.setHorizontalHeaderLabels(
            ["Timestamp", "Actor", "Action", "Record ID"]
        )
        self._audit_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._audit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._audit_table.setAlternatingRowColors(True)
        self._audit_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self._audit_table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLORS['bg']};
                gridline-color: {COLORS['border']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
            QTableWidget::item {{
                padding: 6px 12px;
            }}
            QTableWidget::item:selected {{
                background: {COLORS['bg_selected']};
                color: white;
            }}
            QHeaderView::section {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text_secondary']};
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                padding: 8px 12px;
                border: none;
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        layout.addWidget(self._audit_table, 1)

        self._tabs.addTab(tab, "Audit Log")

    # ---- Shares Tab ----

    def _setup_shares_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Action bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(8)

        revoke_share_btn = QPushButton("Revoke Selected Share")
        revoke_share_btn.setStyleSheet(
            f"QPushButton {{ color: {COLORS['error']}; }} "
            f"QPushButton:hover {{ background: {COLORS['error']}; color: white; }}"
        )
        revoke_share_btn.clicked.connect(self._revoke_share)
        action_bar.addWidget(revoke_share_btn)

        action_bar.addStretch()

        refresh_shares_btn = QPushButton("Refresh")
        refresh_shares_btn.clicked.connect(self._refresh_shares)
        action_bar.addWidget(refresh_shares_btn)

        layout.addLayout(action_bar)

        # Shares table
        self._shares_table = QTableWidget()
        self._shares_table.setColumnCount(5)
        self._shares_table.setHorizontalHeaderLabels(
            ["Share ID", "Created By", "State", "Expires", "Created"]
        )
        self._shares_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._shares_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._shares_table.setAlternatingRowColors(True)
        self._shares_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )
        self._shares_table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLORS['bg']};
                gridline-color: {COLORS['border']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
            QTableWidget::item {{
                padding: 6px 12px;
            }}
            QTableWidget::item:selected {{
                background: {COLORS['bg_selected']};
                color: white;
            }}
            QHeaderView::section {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text_secondary']};
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                padding: 8px 12px;
                border: none;
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        layout.addWidget(self._shares_table, 1)

        self._tabs.addTab(tab, "Active Shares")

    # ---- Org Recovery Tab ----

    def _setup_org_recovery_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Description
        desc = QLabel(
            "Shamir Secret Sharing — rozdelenie kluča obnovy medzi "
            "dôveryhodných držiteľov. Na obnovu je potrebný minimálny "
            "počet kusov (prah)."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        layout.addWidget(desc)

        # Threshold spinner
        threshold_row = QHBoxLayout()
        threshold_row.setSpacing(8)
        threshold_label = QLabel("Prah (minimum kusov):")
        threshold_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px;")
        threshold_row.addWidget(threshold_label)
        self._threshold_spin = QSpinBox()
        self._threshold_spin.setMinimum(2)
        self._threshold_spin.setMaximum(255)
        self._threshold_spin.setValue(3)
        self._threshold_spin.setFixedWidth(80)
        threshold_row.addWidget(self._threshold_spin)
        threshold_row.addStretch()
        layout.addLayout(threshold_row)

        # Total shares spinner
        total_row = QHBoxLayout()
        total_row.setSpacing(8)
        total_label = QLabel("Celkový počet kusov:")
        total_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px;")
        total_row.addWidget(total_label)
        self._total_spin = QSpinBox()
        self._total_spin.setMinimum(2)
        self._total_spin.setMaximum(255)
        self._total_spin.setValue(5)
        self._total_spin.setFixedWidth(80)
        total_row.addWidget(self._total_spin)
        total_row.addStretch()
        layout.addLayout(total_row)

        # Generate button
        gen_btn = QPushButton("Nastaviť Org Recovery")
        gen_btn.setProperty("cssClass", "accent")
        gen_btn.setFixedWidth(220)
        gen_btn.clicked.connect(self._setup_org_recovery)
        layout.addWidget(gen_btn)

        # Shares display area
        self._shares_display = QTextEdit()
        self._shares_display.setReadOnly(True)
        self._shares_display.setPlaceholderText(
            "Tu sa zobrazia kusy kľúča obnovy po vygenerovaní..."
        )
        self._shares_display.setStyleSheet(f"""
            QTextEdit {{
                background: {COLORS['bg']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 8px;
            }}
        """)
        layout.addWidget(self._shares_display, 1)

        # Print button (hidden until shares generated)
        self._print_shares_btn = QPushButton("Vytlačiť kusy")
        self._print_shares_btn.setFixedWidth(160)
        self._print_shares_btn.setVisible(False)
        self._print_shares_btn.clicked.connect(self._print_shares)
        layout.addWidget(self._print_shares_btn)

        self._tabs.addTab(tab, "Org Recovery")

    @Slot()
    def _setup_org_recovery(self):
        """Generate Shamir shares for organizational recovery."""
        if not self._vault or not self._vault.is_unlocked:
            QMessageBox.warning(self, "Chyba", "Trezor je zamknutý.")
            return

        threshold = self._threshold_spin.value()
        total = self._total_spin.value()

        if total < threshold:
            QMessageBox.warning(
                self, "Chyba",
                "Celkový počet kusov musí byť >= prah."
            )
            return

        # Lockout review N4: a new setup voids every share handed out before.
        replace = self._vault.org_recovery_configured()
        message = f"Nastaviť Org Recovery s prahom {threshold} z {total}?"
        if replace:
            message += (
                "\n\nPOZOR: Org Recovery je už nastavený. Nové nastavenie "
                "zneplatní VŠETKY doterajšie kusy. Držitelia kľúča musia "
                "dostať nové kusy."
            )
        reply = QMessageBox.question(
            self,
            "Nahradiť Org Recovery" if replace else "Potvrdiť nastavenie",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        from ..vault.org_recovery_server import (
            OrgRecoveryNotReplaced,
            OrgRecoveryOnServer,
            setup_and_register,
        )

        password = ""
        if self._vault.db.get_meta("server_url"):
            password, ok = QInputDialog.getText(
                self, "Org Recovery na serveri",
                "Heslo účtu (server si recovery kľúč zaregistruje):",
                QLineEdit.EchoMode.Password,
            )
            if not ok or not password:
                return
        try:
            # Review 526419e V5: a replacement the server refuses keeps the
            # old setup, so the shares handed out before keep working.
            try:
                setup = setup_and_register(
                    self._vault, password, threshold, total, replace=replace
                )
            except OrgRecoveryOnServer as on_server:
                # Review 526419e S2/S3: never replace the server's recovery
                # (web, another device, another admin) without asking.
                if on_server.other_admin:
                    text = (
                        "Org Recovery na serveri nastavil iný správca "
                        f"({on_server.other_admin}). Nové nastavenie zneplatní "
                        "VŠETKY jeho kusy. Dohodnite sa s ním. Ak jeho obnovu "
                        "ponecháte, po obnove vám reset povolí iný správca "
                        "(allow-key-reset).\n\nNahradiť jeho Org Recovery?"
                    )
                else:
                    text = (
                        "Org Recovery tohto účtu už je na serveri (nastavené na "
                        "webe alebo inom zariadení). Nové nastavenie zneplatní "
                        "VŠETKY jeho kusy.\n\nNahradiť ho?"
                    )
                if QMessageBox.question(
                    self, "Nahradiť Org Recovery", text,
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
                ) != QMessageBox.Yes:
                    return
                setup = setup_and_register(
                    self._vault, password, threshold, total, replace=True,
                    replace_other_admin=bool(on_server.other_admin),
                )
        except OrgRecoveryNotReplaced as e:
            QMessageBox.critical(
                self, "Org Recovery",
                f"Server nový recovery kľúč neprijal ({e}).\n"
                "Doterajšie nastavenie aj jeho kusy zostávajú platné.",
            )
            return
        except Exception as e:
            QMessageBox.critical(
                self, "Chyba",
                f"Nepodarilo sa nastaviť Org Recovery:\n{e}"
            )
            return
        shares = setup.shares
        self._report_registration(setup)

        # Display shares
        lines = []
        self._last_shares = []
        for idx, share_bytes in shares:
            hex_str = share_bytes.hex()
            lines.append(f"Kus {idx}/{total}: {idx}:{hex_str}")
            self._last_shares.append((idx, total, hex_str))

        self._shares_display.setPlainText("\n".join(lines))
        self._print_shares_btn.setVisible(True)

        QMessageBox.information(
            self,
            "Org Recovery nastavený",
            f"Vygenerovaných {total} kusov (prah: {threshold}).\n\n"
            "Každý kus odovzdajte jednej dôveryhodnej osobe.\n"
            "Tieto kusy sa znova nezobrazia po zatvorení okna!"
        )

    def _report_registration(self, setup):
        """Review e4cd15a #1: the server learns the recovery key (with proof of
        the current password), so after a Shamir recovery it takes the new
        password without another admin's key-reset grant."""
        if setup.registered is None:
            QMessageBox.information(
                self, "Org Recovery",
                "Trezor ešte nie je pripojený k serveru: recovery kľúč sa na "
                "serveri zaregistruje pri pripojení.",
            )
        elif not setup.registered:
            QMessageBox.warning(
                self, "Org Recovery",
                f"Server recovery kľúč zatiaľ nepozná ({setup.error}). Registráciu "
                "ponúkne znova ďalšie odomknutie; dovtedy obnova týmito kusmi "
                "potrebuje 'sezam allow-key-reset' od iného admina.",
            )

    @Slot()
    def _print_shares(self):
        """Print the generated shares."""
        if not hasattr(self, '_last_shares') or not self._last_shares:
            return

        from PySide6.QtPrintSupport import QPrinter, QPrintDialog
        from PySide6.QtGui import QTextDocument

        printer = QPrinter(QPrinter.HighResolution)
        dialog = QPrintDialog(printer, self)
        if dialog.exec() != QDialog.Accepted:
            return

        doc = QTextDocument()
        total = self._last_shares[0][1] if self._last_shares else "?"
        html = "<h2>Sezam Org Recovery — kusy kľúča obnovy</h2>"
        html += f"<p>Celkový počet: {total}</p>"
        for idx, tot, hex_str in self._last_shares:
            html += f"<p><b>Kus {idx}/{tot}:</b> <code>{idx}:{hex_str}</code></p>"
        html += f"<p style='color: gray; margin-top: 2em;'>Vytvorené: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        doc.setHtml(html)
        doc.print_(printer)

    # ---- Data Loading ----

    @Slot()
    def _refresh_users(self):
        """Reload the authoritative user list from the server."""
        self._users_table.setRowCount(0)

        if not self._vault or not self._vault.is_unlocked:
            return

        self._show_table_message(self._users_table, "Loading...")
        run_in_background(
            self,
            lambda: self._get_server_client().list_users(),
            self._show_users,
            lambda exc: self._show_table_message(self._users_table, f"Server unavailable: {exc}"),
        )

    @staticmethod
    def _show_table_message(table, text: str):
        table.setRowCount(1)
        table.setItem(0, 0, QTableWidgetItem(text))

    def _show_users(self, rows):
        self._users_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            name_item = QTableWidgetItem(row.get("username", ""))
            name_item.setData(Qt.UserRole, row.get("id", ""))
            self._users_table.setItem(i, 0, name_item)
            self._users_table.setItem(i, 1, self._status_item(row.get("status", "unknown")))
            fingerprint = row.get("key_fingerprint", "")
            self._users_table.setItem(i, 2, QTableWidgetItem(fingerprint))
            self._users_table.setItem(i, 3, QTableWidgetItem("Admin" if row.get("is_admin") else "Member"))
            created = row.get("created_at", 0)
            created_str = datetime.fromtimestamp(created / 1000).strftime("%Y-%m-%d") if created else "--"
            self._users_table.setItem(i, 4, QTableWidgetItem(created_str))

    def _status_item(self, status: str) -> QTableWidgetItem:
        """Create a colored status table item."""
        item = QTableWidgetItem(status)
        if status == "active":
            item.setForeground(Qt.GlobalColor.green)
        elif status == "pending":
            item.setForeground(Qt.GlobalColor.yellow)
        elif status in ("revoked", "suspended"):
            item.setForeground(Qt.GlobalColor.red)
        return item

    @Slot()
    def _refresh_audit(self):
        """Reload audit log with current filters."""
        self._audit_table.setRowCount(0)

        if not self._vault or not self._vault.is_unlocked:
            return

        # Read filter values
        actor_filter = self._audit_actor_filter.currentData() or None
        action_filter = self._audit_action_filter.currentData() or None
        since_filter = self._audit_date_filter.currentData() or "0"

        since_ms = None
        if since_filter and since_filter != "0":
            since_ms = int(time.time() * 1000) - int(since_filter)

        try:
            from ..vault.audit import AuditLog
            audit = AuditLog(self._vault.db)
            records = audit.get_records(
                actor_id=actor_filter if actor_filter else None,
                action=action_filter if action_filter else None,
                since=since_ms,
                limit=500,
            )
        except Exception:
            records = []

        self._audit_table.setRowCount(len(records))
        for i, record in enumerate(records):
            # Timestamp
            ts = record.get("timestamp", 0)
            ts_str = datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S") if ts else "--"
            self._audit_table.setItem(i, 0, QTableWidgetItem(ts_str))

            # Actor
            actor_id = record.get("actor_id", "")
            actor_short = actor_id[:12] + "..." if len(actor_id) > 12 else actor_id
            self._audit_table.setItem(i, 1, QTableWidgetItem(actor_short))

            # Action (color-coded)
            action = record.get("action", "")
            action_item = QTableWidgetItem(action)
            if action == "delete":
                action_item.setForeground(Qt.GlobalColor.red)
            elif action == "write":
                action_item.setForeground(Qt.GlobalColor.cyan)
            elif action == "read":
                action_item.setForeground(Qt.GlobalColor.green)
            elif action in ("approve", "share"):
                action_item.setForeground(Qt.GlobalColor.yellow)
            self._audit_table.setItem(i, 2, action_item)

            # Record ID
            rec_id = record.get("id", "")
            rec_short = rec_id[:12] + "..." if len(rec_id) > 12 else rec_id
            self._audit_table.setItem(i, 3, QTableWidgetItem(rec_short))

    @Slot()
    def _refresh_shares(self):
        """Reload authoritative active share links from the server."""
        self._shares_table.setRowCount(0)

        if not self._vault or not self._vault.is_unlocked:
            return

        self._show_table_message(self._shares_table, "Loading...")
        run_in_background(
            self,
            lambda: self._get_server_client().list_shares(),
            self._show_shares,
            lambda exc: self._show_table_message(self._shares_table, f"Server unavailable: {exc}"),
        )

    def _show_shares(self, rows):
        self._shares_table.setRowCount(0)
        if not rows:
            self._shares_table.setRowCount(1)
            self._shares_table.setItem(0, 0, QTableWidgetItem("No active shares"))
            for col in range(1, 5):
                self._shares_table.setItem(0, col, QTableWidgetItem(""))
            return

        self._shares_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            share_item = QTableWidgetItem(str(row.get("id", "")))
            share_item.setData(Qt.UserRole, row.get("id", ""))
            self._shares_table.setItem(i, 0, share_item)
            self._shares_table.setItem(i, 1, QTableWidgetItem(str(row.get("created_by", ""))))
            state = "Locked" if row.get("is_locked") else f"{row.get('view_count', 0)}/{row.get('max_views', 0)} views"
            self._shares_table.setItem(i, 2, QTableWidgetItem(state))

            expires = row.get("expires_at")
            exp_str = datetime.fromtimestamp(expires / 1000).strftime("%Y-%m-%d %H:%M") if expires else "--"
            self._shares_table.setItem(i, 3, QTableWidgetItem(exp_str))

            created = row.get("created_at", 0)
            created_str = datetime.fromtimestamp(created / 1000).strftime("%Y-%m-%d %H:%M") if created else "--"
            self._shares_table.setItem(i, 4, QTableWidgetItem(created_str))

    # ---- Actions ----

    @Slot()
    def _invite_colleague(self):
        """Create and display a server-backed invitation link."""
        if not self._vault or not self._vault.is_unlocked:
            QMessageBox.warning(self, "Error", "Vault is locked.")
            return

        server_url = (self._vault.db.get_meta("server_url") or "").rstrip("/")
        run_in_background(
            self,
            lambda: self._get_server_client().create_invitation(),
            lambda response: self._show_invitation(server_url, response),
            lambda exc: QMessageBox.critical(self, "Invitation Failed", str(exc)),
        )

    def _show_invitation(self, server_url: str, response: dict):
        from urllib.parse import quote

        try:
            token = response["invitation_token"]
            expires_at = response["expires_at"]
        except (KeyError, TypeError) as exc:
            QMessageBox.critical(self, "Invitation Failed", f"Malformed server response: {exc}")
            return
        invite_link = f"{server_url}/?invite={quote(token, safe='')}"
        if response.get("genesis_hash"):
            invite_link += f"#g={quote(response['genesis_hash'], safe='')}"
        expires_text = datetime.fromtimestamp(expires_at / 1000).strftime("%Y-%m-%d %H:%M")
        msg = QMessageBox(self)
        msg.setWindowTitle("Invitation Link")
        msg.setText("Share this link with your colleague:")
        msg.setDetailedText(invite_link)
        msg.setStandardButtons(QMessageBox.Ok)

        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(invite_link)
        msg.setInformativeText(
            f"Copied to clipboard.\n\n{invite_link}\n\nExpires: {expires_text}."
        )
        msg.exec()

    @Slot()
    def _approve_user(self):
        """Approve the selected pending user."""
        row = self._users_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Info", "Select a user to approve.")
            return

        status_item = self._users_table.item(row, 1)
        if status_item and status_item.text() != "pending":
            QMessageBox.information(self, "Info", "Only pending users can be approved.")
            return

        name_item = self._users_table.item(row, 0)
        user_name = name_item.text() if name_item else "?"
        user_id = name_item.data(Qt.UserRole) if name_item else None
        if not user_id:
            QMessageBox.warning(self, "Error", "The selected row is not a server user.")
            return

        reply = QMessageBox.question(
            self,
            "Approve User",
            f"Approve user '{user_name}' for vault access?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            def approved(_result):
                QMessageBox.information(self, "Approved", f"User '{user_name}' has been approved.")
                self._refresh_users()

            run_in_background(
                self,
                lambda: self._get_server_client().approve_user(user_id),
                approved,
                lambda exc: QMessageBox.critical(self, "Approval Failed", str(exc)),
            )

    @Slot()
    def _grant_folder(self):
        """Share a top-level folder with the selected approved member."""
        row = self._users_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Info", "Select a member to share a folder with.")
            return
        status_item = self._users_table.item(row, 1)
        if status_item is None or status_item.text() != "active":
            QMessageBox.information(self, "Info", "Only approved members can be given access.")
            return
        name_item = self._users_table.item(row, 0)
        user_name = name_item.text() if name_item else "?"
        user_id = name_item.data(Qt.UserRole) if name_item else None
        if not user_id:
            QMessageBox.warning(self, "Error", "The selected row is not a server user.")
            return

        folders = self._vault.list_nodes()
        if not folders:
            QMessageBox.information(self, "Info", "There is no folder to share.")
            return
        labels = [f"{n['name']}  ({n['id'][-6:]})" for n in folders]
        label, ok = QInputDialog.getItem(
            self, "Share Folder", f"Folder to share with '{user_name}':", labels, 0, False
        )
        if not ok:
            return
        folder = folders[labels.index(label)]
        level, ok = QInputDialog.getItem(
            self, "Share Folder", "Access:", ["read", "write"], 0, False
        )
        if not ok:
            return

        self._run_grant(user_id, user_name, folder, level, None)

    def _run_grant(self, user_id, user_name, folder, level, confirmed_fingerprint):
        vault = self._vault
        from ..vault.revocation import MemberKeyUnconfirmed, grant_member

        def failed(exc):
            if not isinstance(exc, MemberKeyUnconfirmed):
                QMessageBox.critical(self, "Sharing Failed", str(exc))
                return
            # First share with this member: the key is only what the server says.
            reply = QMessageBox.question(
                self,
                "Confirm Member Key",
                f"Key fingerprint of '{user_name}':\n\n{exc.fingerprint}\n\n"
                "Does it match the fingerprint the member's device shows?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                self._run_grant(user_id, user_name, folder, level, exc.fingerprint)

        run_in_background(
            self,
            lambda: grant_member(
                vault, self._get_server_client(), user_id, folder["id"], level,
                confirm_fingerprint=lambda fp: fp == confirmed_fingerprint,
            ),
            lambda _result: QMessageBox.information(
                self, "Shared", f"'{user_name}' now has {level} access to '{folder['name']}'."
            ),
            failed,
        )

    @Slot()
    def _revoke_user(self):
        """Revoke access for the selected user."""
        row = self._users_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Info", "Select a user to revoke.")
            return

        name_item = self._users_table.item(row, 0)
        user_name = name_item.text() if name_item else "?"
        user_id = name_item.data(Qt.UserRole) if name_item else None
        if not user_id:
            QMessageBox.warning(self, "Error", "The selected row is not a server user.")
            return

        reply = QMessageBox.question(
            self,
            "Revoke Access",
            f"Revoke access for '{user_name}'?\n\n"
            "The server revokes the member at once; the folders they could open "
            "are then re-keyed.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            vault = self._vault

            from ..vault.revocation import RekeyPending, revoke_member

            def revoke():
                revoke_member(vault, self._get_server_client(), user_id)

            def revoked(_result):
                QMessageBox.information(self, "Revoked", f"Access revoked for '{user_name}'.")
                self._refresh_users()

            def failed(exc):
                if isinstance(exc, RekeyPending):
                    QMessageBox.warning(
                        self, "Re-key Pending",
                        f"{exc}\n\n'Finish Re-keys' sends it and settles what it waits for.",
                    )
                    self._refresh_users()
                    return
                QMessageBox.critical(
                    self,
                    "Revocation Failed",
                    f"Revocation was not confirmed by the server. Any completed re-key remains pending for retry.\n\n{exc}",
                )

            run_in_background(self, revoke, revoked, failed)

    @Slot()
    def _finish_rekeys(self):
        """What 'sezam push' does for revoked members (review 526419e S4): send
        the pending re-key, re-key every queued member whose folders are free,
        and offer to settle the conflicts the others wait for."""
        from ..vault.revocation import blocked_message, push_with_queued_revocations

        vault = self._vault
        rekeyed: dict[str, int] = {}  # over the rounds after settling conflicts

        def run():
            return push_with_queued_revocations(vault, self._get_server_client())

        def finished(result):
            rekeyed.update(result.get("rekeyed") or {})
            blocked = result.get("blocked") or {}
            waiting = sorted({oid for ids in blocked.values() for oid in ids})
            if waiting and self._settle_conflicts(waiting):
                run_in_background(self, run, finished, failed)
                return
            lines = [
                f"Re-keyed {count} folder(s) after revoking user {user_id}."
                for user_id, count in rekeyed.items()
            ]
            lines += [blocked_message(user_id, ids) for user_id, ids in blocked.items()]
            lines += [
                f"The re-key of revoked user {user_id} waits: {reason}"
                for user_id, reason in (result.get("too_large") or {}).items()
            ]
            if result.get("conflicts"):
                lines.append(f"The push left {len(result['conflicts'])} conflict(s).")
            QMessageBox.information(
                self, "Re-keys", "\n".join(lines) or "No member re-key is waiting."
            )
            self._refresh_users()

        def failed(exc):
            QMessageBox.critical(self, "Re-key Failed", str(exc))

        run_in_background(self, run, finished, failed)

    def _settle_conflicts(self, object_ids: list[str]) -> bool:
        """Ask which copy to keep for each conflict; True when any was settled."""
        client = self._get_server_client()
        settled = False
        for object_id in object_ids:
            box = QMessageBox(self)
            box.setWindowTitle("Sync Conflict")
            box.setText(
                f"Item {object_id} was changed here and on another device. A member "
                "re-key waits until you choose which copy to keep."
            )
            keep_local = box.addButton("Keep This Device's Copy", QMessageBox.AcceptRole)
            keep_server = box.addButton("Take the Server's Copy", QMessageBox.DestructiveRole)
            box.addButton("Later", QMessageBox.RejectRole)
            box.exec()
            clicked = box.clickedButton()
            keep = "local" if clicked is keep_local else "server" if clicked is keep_server else None
            if keep is None:
                continue
            try:
                client.resolve_conflict(object_id, keep)
            except (KeyError, RuntimeError) as exc:
                QMessageBox.warning(self, "Sync Conflict", str(exc))
                continue
            settled = True
        return settled

    @Slot()
    def _revoke_share(self):
        """Revoke the selected share link."""
        row = self._shares_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Info", "Select a share to revoke.")
            return

        reply = QMessageBox.question(
            self,
            "Revoke Share",
            "Revoke this share link? It will no longer be accessible.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            share_item = self._shares_table.item(row, 0)
            share_id = share_item.data(Qt.UserRole) if share_item else None
            if not share_id:
                QMessageBox.warning(self, "Error", "The selected row is not a server share.")
                return
            def revoked(_result):
                QMessageBox.information(self, "Revoked", f"Share '{share_id}' has been revoked.")
                self._refresh_shares()

            run_in_background(
                self,
                lambda: self._get_server_client().revoke_share(share_id),
                revoked,
                lambda exc: QMessageBox.critical(self, "Share Revocation Failed", str(exc)),
            )
