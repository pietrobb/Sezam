"""Main window — tree, search, detail panel, systray, hotkey.

Spec 7.1: Systray -> Ctrl+Alt+V -> password -> search bar -> copy -> auto-clear 15s.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QEvent, Qt, QTimer, Signal, Slot
from PySide6.QtGui import (
    QColor,
    QFont,
    QIcon,
    QKeySequence,
    QPainter,
    QPixmap,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSystemTrayIcon,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..vault.crud import Vault
from .ai_switch import AIAccessSwitch
from .unlock_dialog import UnlockDialog
from .wizard_dialog import WizardDialog
from .background import busy as background_busy
from .background import run_in_background
from .entry_detail import EntryDetailWidget
from .entry_dialog import EntryDialog, NodeDialog
from .settings_dialog import SettingsDialog
from .server_connect_dialog import ServerConnectDialog
from .team_dialog import TeamDialog
from .styles import COLORS

logger = logging.getLogger(__name__)


AUTOLOCK_MS = 15 * 60 * 1000  # 15 min
AUTOLOCK_RETRY_MS = 5 * 1000  # while a background server call still runs
# Review 526419e S6: input anywhere in the app (a dialog too) is activity.
_ACTIVITY_EVENTS = (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.Wheel)
CLIPBOARD_CLEAR_MS = 15 * 1000  # 15s


def app_icon() -> QIcon:
    """Sezam icon drawn in code (the repo ships no icon assets)."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(COLORS["accent"]))
        painter.drawRoundedRect(0, 0, size, size, size * 0.2, size * 0.2)
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", max(6, int(size * 0.5)), QFont.Bold))
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "S")
        painter.end()
        icon.addPixmap(pixmap)
    return icon


class MainWindow(QMainWindow):
    """Sezam desktop main window."""

    vault_unlocked = Signal()
    vault_locked = Signal()

    def __init__(self, vault_path: Path):
        super().__init__()
        self._vault_path = vault_path
        self._vault: Optional[Vault] = None
        self._unlock_showing = False
        self._autolock_ms = AUTOLOCK_MS
        self._clipboard_clear_ms = CLIPBOARD_CLEAR_MS
        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setSingleShot(True)
        self._clipboard_timer.timeout.connect(self._clear_clipboard)
        self._clipboard_remaining = 0
        self._clipboard_owned: Optional[str] = None
        self._clipboard_countdown_timer = QTimer(self)
        self._clipboard_countdown_timer.setInterval(1000)
        self._clipboard_countdown_timer.timeout.connect(self._update_clipboard_countdown)
        self._autolock_timer = QTimer(self)
        self._autolock_timer.setSingleShot(True)
        self._autolock_timer.timeout.connect(self._autolock_fired)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)
        self._share_notification_timer = QTimer(self)
        self._share_notification_timer.setInterval(60 * 1000)
        self._share_notification_timer.timeout.connect(self._poll_share_notifications)
        self._notification_client = None
        self._notification_poll_running = False

        self.setWindowTitle("Sezam")
        self.setMinimumSize(960, 640)
        self.resize(1100, 720)

        self._setup_ui()
        self._setup_tray()
        self._setup_shortcuts()

        self.vault_unlocked.connect(self._on_unlocked)
        self.vault_locked.connect(self._on_locked)

    # -- UI Setup --

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ---- Toolbar ----
        toolbar = QWidget()
        toolbar.setFixedHeight(52)
        toolbar.setStyleSheet(f"background: {COLORS['bg_panel']}; border-bottom: 1px solid {COLORS['border']};")
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(16, 0, 16, 0)
        tb.setSpacing(12)

        logo = QLabel("Sezam")
        logo.setFont(QFont("Segoe UI", 15, QFont.Bold))
        logo.setStyleSheet(f"color: {COLORS['accent']}; letter-spacing: 1px;")
        tb.addWidget(logo)

        tb.addSpacing(16)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search entries...  (Ctrl+F)")
        self._search_input.setClearButtonEnabled(True)
        self._search_input.setMaximumWidth(420)
        self._search_input.setMinimumHeight(36)
        self._search_input.textChanged.connect(self._on_search)
        tb.addWidget(self._search_input, 1)

        self._deep_search_cb = QCheckBox("Search in values")
        self._deep_search_cb.setToolTip("Also search inside decrypted field values (slower)")
        self._deep_search_cb.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        self._deep_search_cb.toggled.connect(self._on_deep_search_toggled)
        tb.addWidget(self._deep_search_cb)

        tb.addSpacing(8)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        tb.addWidget(self._status_label)

        tb.addStretch()

        # Kill switch: off without a password (also while locked), on only
        # with the master password.
        self._ai_switch = AIAccessSwitch(self._vault_path, self._current_kek, self)
        tb.addWidget(self._ai_switch.button)

        lock_btn = QPushButton("Lock")
        lock_btn.setProperty("cssClass", "accent")
        lock_btn.setFixedWidth(80)
        lock_btn.clicked.connect(self.lock_vault)
        tb.addWidget(lock_btn)

        main_layout.addWidget(toolbar)

        # ---- Content area ----
        content = QWidget()
        content.setStyleSheet(f"background: {COLORS['bg']};")
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # -- Left sidebar --
        sidebar = QWidget()
        sidebar.setFixedWidth(300)
        sidebar.setStyleSheet(f"background: {COLORS['bg_panel']};")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(0)

        # Sidebar action buttons
        btn_bar = QWidget()
        btn_bar.setFixedHeight(44)
        btn_bar.setStyleSheet(f"background: {COLORS['bg_panel']}; border-bottom: 1px solid {COLORS['border']};")
        bb = QHBoxLayout(btn_bar)
        bb.setContentsMargins(8, 6, 8, 6)
        bb.setSpacing(6)

        sidebar_btn_style = (
            "padding: 5px 10px; font-size: 12px;"
        )

        add_folder_btn = QPushButton("+ Folder")
        add_folder_btn.setToolTip("Create new folder (Ctrl+Shift+N)")
        add_folder_btn.setStyleSheet(sidebar_btn_style)
        add_folder_btn.clicked.connect(lambda: self._new_folder(None))
        bb.addWidget(add_folder_btn)

        add_entry_btn = QPushButton("+ Entry")
        add_entry_btn.setToolTip("Create new entry (Ctrl+N)")
        add_entry_btn.setStyleSheet(sidebar_btn_style)
        add_entry_btn.clicked.connect(lambda: self._new_entry(None))
        bb.addWidget(add_entry_btn)

        bb.addStretch()

        more_btn = QPushButton("More")
        more_btn.setToolTip("Team, Import, Export, Server, Settings")
        more_btn.setStyleSheet(sidebar_btn_style)
        more_menu = QMenu(more_btn)
        more_menu.addAction("Team", self._show_team)
        more_menu.addAction("Import", self._show_import_wizard)
        more_menu.addAction("Export", self._show_export_dialog)
        more_menu.addAction("Server", self._show_server_connect)
        more_menu.addSeparator()
        more_menu.addAction("Settings", self._show_settings)
        more_btn.setMenu(more_menu)
        bb.addWidget(more_btn)

        sb_layout.addWidget(btn_bar)

        # Tree (with drag-and-drop for re-key, spec 7.1)
        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setRootIsDecorated(True)
        self._tree.setAnimated(True)
        self._tree.setIndentation(20)
        self._tree.setDragEnabled(True)
        self._tree.setAcceptDrops(True)
        self._tree.setDropIndicatorShown(True)
        self._tree.setDragDropMode(QAbstractItemView.InternalMove)
        self._tree.setDefaultDropAction(Qt.MoveAction)
        self._tree.itemClicked.connect(self._on_tree_item_clicked)
        self._tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        # Override the default drop behaviour so we can intercept and re-encrypt
        self._tree.dropEvent = self._on_tree_drop
        sb_layout.addWidget(self._tree)

        content_layout.addWidget(sidebar)

        # -- Detail panel --
        self._detail = EntryDetailWidget()
        self._detail.field_copied.connect(self._on_field_copied)
        self._detail.edit_requested.connect(self._edit_entry)
        self._detail.delete_requested.connect(self._delete_entry)
        content_layout.addWidget(self._detail, 1)

        main_layout.addWidget(content, 1)

        # ---- Status bar ----
        self._statusbar_label = QLabel("  Locked")
        self.statusBar().addWidget(self._statusbar_label)

    def _setup_tray(self):
        self._tray = QSystemTrayIcon(self)
        # A tray icon without an icon is invisible on every platform.
        icon = app_icon()
        self._tray.setIcon(icon)
        self.setWindowIcon(icon)
        self._tray.setToolTip("Sezam")
        tray_menu = QMenu()
        tray_menu.addAction("Show", self._show_and_focus)
        tray_menu.addAction("Lock", self.lock_vault)
        tray_menu.addAction(self._ai_switch.tray_action)
        tray_menu.addSeparator()
        tray_menu.addAction("Quit", self._quit)
        self._tray.setContextMenu(tray_menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+F"), self, self._focus_search)
        QShortcut(QKeySequence("Ctrl+L"), self, self.lock_vault)
        QShortcut(QKeySequence("Ctrl+N"), self, lambda: self._new_entry(None))
        QShortcut(QKeySequence("Ctrl+Shift+N"), self, lambda: self._new_folder(None))
        QShortcut(QKeySequence("Escape"), self, self._escape_pressed)

    # -- Vault lifecycle --

    def check_or_create_vault(self):
        db_path = self._vault_path / "sezam.db"
        if not db_path.exists():
            wizard = WizardDialog(self._vault_path, self)
            accepted = wizard.exec()
            vault = wizard.vault
            wizard.deleteLater()  # drop the master password widgets
            if accepted:
                self._vault = vault
                self.vault_unlocked.emit()
            else:
                self._quit()
        else:
            self._show_unlock()

    def _show_unlock(self):
        if self._unlock_showing or self._vault is not None:
            return
        self._unlock_showing = True
        dialog = UnlockDialog(self._vault_path, self)
        try:
            accepted = dialog.exec()
            vault = dialog.vault
        finally:
            self._unlock_showing = False
            dialog.deleteLater()  # drop the master password widget
        if accepted:
            self._vault = vault
            self.vault_unlocked.emit()
        else:
            self._quit()

    def _run_dialog(self, dialog: QDialog) -> bool:
        """Run a modal vault dialog and free it afterwards.

        Dialogs parented to the main window would otherwise live (with any
        passwords, secrets or Shamir shares in their widgets) for the whole
        process lifetime. Deleting only after exec() returned is safe even
        when a lock rejected the dialog from inside its own event loop.
        """
        try:
            return bool(dialog.exec()) and self._vault is not None
        finally:
            dialog.deleteLater()

    def _close_open_dialogs(self) -> None:
        """Hide every open dialog (entry edit, Shamir shares, message boxes)."""
        for dialog in self.findChildren(QDialog):
            if dialog.isVisible():
                dialog.reject()

    def _current_kek(self) -> Optional[bytearray]:
        if self._vault is not None and self._vault.is_unlocked:
            return self._vault.current_kek
        return None

    @Slot()
    def lock_vault(self):
        if self._vault is None:
            return  # already locked (the unlock dialog may be showing)
        # Secrets on screen must disappear with the keys.
        self._close_open_dialogs()
        if self._vault.is_unlocked:
            self._vault.lock()
        self._vault = None
        self._tree.clear()
        self._detail.clear()
        self._autolock_timer.stop()
        self._share_notification_timer.stop()
        self._notification_client = None
        self.vault_locked.emit()
        self._statusbar_label.setText("  Locked")
        # Defer: when the lock fires inside a dialog's exec(), that nested loop
        # must unwind (and the dialog be freed) before the unlock prompt opens.
        QTimer.singleShot(0, self._show_unlock)

    @Slot()
    def _on_unlocked(self):
        count = self._rebuild_tree()
        self._statusbar_label.setText(f"  Unlocked  |  {count} entries")
        self._load_security_settings()
        self._reset_autolock()
        self._search_input.setFocus()
        if self._vault.db.get_meta("server_url") and self._vault.db.get_meta("user_id"):
            self._share_notification_timer.start()
            QTimer.singleShot(0, self._poll_share_notifications)
        # Check Argon2 params after unlock (spec 9.5)
        QTimer.singleShot(500, self._check_argon2_upgrade)

    @Slot()
    def _on_locked(self):
        self._statusbar_label.setText("  Locked")

    def _load_security_settings(self):
        if not self._vault:
            return
        autolock_minutes = int(self._vault.db.get_meta("autolock_minutes") or 15)
        clipboard_seconds = int(
            self._vault.db.get_meta("clipboard_clear_seconds") or 15
        )
        self._apply_security_settings(autolock_minutes, clipboard_seconds)

    @Slot(int, int)
    def _apply_security_settings(self, autolock_minutes, clipboard_seconds):
        self._autolock_ms = autolock_minutes * 60 * 1000
        self._clipboard_clear_ms = clipboard_seconds * 1000
        if self._vault and self._vault.is_unlocked:
            self._reset_autolock()

    def _reset_autolock(self):
        self._autolock_timer.start(self._autolock_ms)

    def eventFilter(self, obj, event):
        # Review 526419e S6: typing a long note in a dialog never reached the
        # main window, so the autolock closed the dialog with the text in it.
        if event.type() in _ACTIVITY_EVENTS and self._autolock_timer.isActive():
            self._reset_autolock()
        return super().eventFilter(obj, event)

    @Slot()
    def _autolock_fired(self):
        # Review 526419e S7: a lock under a background server call (a member
        # revocation and its re-key) cut the re-key off; it waits for the call.
        if background_busy():
            self._autolock_timer.start(AUTOLOCK_RETRY_MS)
            return
        self.lock_vault()

    # -- Tree --

    def _rebuild_tree(self) -> int:
        self._tree.clear()
        if not self._vault or not self._vault.is_unlocked:
            return 0

        root_id = self._vault.db.get_meta("root_node_id")
        count = self._populate_tree_node(None, root_id)
        self._tree.expandAll()
        return count

    def _populate_tree_node(self, parent_item, node_id: str) -> int:
        nodes = self._vault.list_nodes(node_id)
        entries = self._vault.list_entries(node_id)
        count = 0

        for node in nodes:
            item = QTreeWidgetItem()
            item.setText(0, f"  {node['name']}")
            item.setData(0, Qt.UserRole, {"type": "node", "id": node["id"]})
            item.setFont(0, QFont("Segoe UI", 12, QFont.DemiBold))
            if parent_item:
                parent_item.addChild(item)
            else:
                self._tree.addTopLevelItem(item)
            count += self._populate_tree_node(item, node["id"])

        for entry in entries:
            item = QTreeWidgetItem()
            item.setText(0, f"  {entry['name']}")
            item.setData(0, Qt.UserRole, {"type": "entry", "id": entry["id"]})
            item.setFont(0, QFont("Segoe UI", 11))
            if parent_item:
                parent_item.addChild(item)
            else:
                self._tree.addTopLevelItem(item)
            count += 1

        return count

    @Slot(QTreeWidgetItem, int)
    def _on_tree_item_clicked(self, item, column):
        self._reset_autolock()
        data = item.data(0, Qt.UserRole)
        if not data:
            return
        if data["type"] == "entry":
            try:
                entry = self._vault.read_entry(data["id"])
                self._detail.show_entry(entry)
            except Exception as e:
                self._statusbar_label.setText(f"  Error: {e}")
        elif data["type"] == "node":
            self._detail.show_folder(data["id"], self._vault)

    def _on_tree_context_menu(self, pos):
        item = self._tree.itemAt(pos)
        menu = QMenu(self)
        if item:
            data = item.data(0, Qt.UserRole)
            if data and data["type"] == "node":
                menu.addAction("New Entry here", lambda: self._new_entry(data["id"]))
                menu.addAction("New Subfolder", lambda: self._new_folder(data["id"]))
                menu.addSeparator()
                menu.addAction("Rename Folder", lambda: self._rename_node(data["id"]))
                menu.addAction("Delete Folder", lambda: self._delete_node(data["id"]))
            elif data and data["type"] == "entry":
                menu.addAction("Edit", lambda: self._edit_entry(data["id"]))
                menu.addSeparator()
                menu.addAction("Delete", lambda: self._delete_entry(data["id"]))
        else:
            menu.addAction("New Folder", lambda: self._new_folder(None))
            menu.addAction("New Entry", lambda: self._new_entry(None))
        menu.addSeparator()
        menu.addAction("Restore Deleted…", self._restore_deleted)
        menu.exec(self._tree.mapToGlobal(pos))

    # -- Drag-and-Drop (spec 7.1 — re-key transaction) --

    def _on_tree_drop(self, event):
        """Handle drag-and-drop on tree — move entry/node with re-encryption."""
        if not self._vault or not self._vault.is_unlocked:
            event.ignore()
            return

        dragged_item = self._tree.currentItem()
        if dragged_item is None:
            event.ignore()
            return

        dragged_data = dragged_item.data(0, Qt.UserRole)
        if not dragged_data:
            event.ignore()
            return

        # Determine the drop target
        target_item = self._tree.itemAt(event.position().toPoint())

        # Resolve target node id
        if target_item is None:
            # Dropped on empty area — move to root
            target_node_id = self._vault.db.get_meta("root_node_id")
            target_name = "Root"
        else:
            target_data = target_item.data(0, Qt.UserRole)
            if not target_data:
                event.ignore()
                return
            if target_data["type"] == "node":
                target_node_id = target_data["id"]
                target_name = target_item.text(0).strip()
            elif target_data["type"] == "entry":
                # Dropped on an entry — use the entry's parent folder
                parent_item = target_item.parent()
                if parent_item:
                    parent_data = parent_item.data(0, Qt.UserRole)
                    target_node_id = parent_data["id"]
                    target_name = parent_item.text(0).strip()
                else:
                    target_node_id = self._vault.db.get_meta("root_node_id")
                    target_name = "Root"
            else:
                event.ignore()
                return

        dragged_name = dragged_item.text(0).strip()
        dragged_type = dragged_data["type"]
        dragged_id = dragged_data["id"]

        # Confirmation dialog
        reply = QMessageBox.question(
            self,
            "Move with Re-encryption",
            f'Moving "{dragged_name}" to "{target_name}" will '
            f"re-encrypt with the target folder's DEK. Continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            event.ignore()
            return

        try:
            if dragged_type == "entry":
                self._vault.move_entry(dragged_id, target_node_id)
            elif dragged_type == "node":
                self._vault.move_node(dragged_id, target_node_id)

            count = self._rebuild_tree()
            self._statusbar_label.setText(
                f'  Moved "{dragged_name}" to "{target_name}"  |  {count} entries'
            )
        except ValueError as e:
            QMessageBox.warning(self, "Move Failed", str(e))
        except Exception as e:
            self._statusbar_label.setText(f"  Move failed: {e}")

        # Always ignore the default drop so Qt doesn't also rearrange items
        event.ignore()

    # -- CRUD --

    def _new_entry(self, node_id: str = None):
        if not self._vault or not self._vault.is_unlocked:
            return
        if node_id is None:
            item = self._tree.currentItem()
            if item:
                data = item.data(0, Qt.UserRole)
                if data and data["type"] == "node":
                    node_id = data["id"]
            if node_id is None:
                node_id = self._vault.db.get_meta("root_node_id")

        dialog = EntryDialog(self._vault, node_id, parent=self)
        if self._run_dialog(dialog):
            count = self._rebuild_tree()
            self._statusbar_label.setText(f"  Entry created  |  {count} entries")

    def _edit_entry(self, entry_id: str):
        if not self._vault or not self._vault.is_unlocked:
            return
        try:
            entry = self._vault.read_entry(entry_id)
            dialog = EntryDialog(self._vault, entry["node_id"], entry=entry, parent=self)
            if self._run_dialog(dialog):
                self._rebuild_tree()
                self._detail.show_entry(self._vault.read_entry(entry_id))
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to edit entry: {e}")
            self._statusbar_label.setText(f"  Error: {e}")

    def _delete_entry(self, entry_id: str):
        if not self._vault:
            return
        reply = QMessageBox.question(
            self, "Delete Entry",
            "Are you sure you want to delete this entry?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._vault.delete_entry(entry_id)
            count = self._rebuild_tree()
            self._detail.clear()
            self._statusbar_label.setText(
                f"  Entry deleted  |  {count} entries  |  right-click → Restore Deleted…"
            )

    def _new_folder(self, parent_id: str = None):
        if not self._vault or not self._vault.is_unlocked:
            return
        if parent_id is None:
            item = self._tree.currentItem()
            if item:
                data = item.data(0, Qt.UserRole)
                if data and data["type"] == "node":
                    parent_id = data["id"]
        dialog = NodeDialog(self._vault, parent_id, parent=self)
        if self._run_dialog(dialog):
            self._rebuild_tree()

    def _rename_node(self, node_id: str):
        if not self._vault or not self._vault.is_unlocked:
            return
        current_name = ""
        # Find current name from tree
        for i in range(self._tree.topLevelItemCount()):
            found = self._find_tree_item(self._tree.topLevelItem(i), node_id)
            if found:
                current_name = found.text(0).strip()
                break
        new_name, ok = QInputDialog.getText(
            self, "Rename Folder", "New name:", text=current_name
        )
        if ok and new_name.strip():
            try:
                self._vault.rename_node(node_id, new_name.strip())
                self._rebuild_tree()
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to rename: {e}")

    def _find_tree_item(self, item, node_id: str):
        data = item.data(0, Qt.UserRole)
        if data and data.get("id") == node_id:
            return item
        for i in range(item.childCount()):
            found = self._find_tree_item(item.child(i), node_id)
            if found:
                return found
        return None

    def _delete_node(self, node_id: str):
        if not self._vault:
            return
        reply = QMessageBox.question(
            self, "Delete Folder",
            "Delete this folder and everything inside it?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self._vault.delete_node(node_id)
            self._rebuild_tree()
            self._detail.clear()
            self._statusbar_label.setText("  Folder deleted  |  right-click → Restore Deleted…")

    def _restore_deleted(self):
        """Pick a deleted folder or entry and bring it back (lockout review M2)."""
        if not self._vault or not self._vault.is_unlocked:
            return
        from ..vault.trash import TrashError, list_trash, restore_entry, restore_node

        items = list_trash(self._vault)
        if not items:
            QMessageBox.information(self, "Restore Deleted", "Trash is empty.")
            return
        labels = []
        for item in items:
            extra = f" ({item['entries']} entries)" if item["type"] == "folder" else ""
            labels.append(f"{item['type']}: /{item['path']}  {item['name']}{extra}")
        choice, ok = QInputDialog.getItem(
            self, "Restore Deleted", "Deleted item:", labels, 0, False
        )
        if not ok:
            return
        item = items[labels.index(choice)]
        try:
            if item["type"] == "folder":
                restore_node(self._vault, item["id"])
            else:
                restore_entry(self._vault, item["id"])
        except (KeyError, TrashError) as e:
            QMessageBox.warning(self, "Restore Deleted", str(e))
            return
        count = self._rebuild_tree()
        self._statusbar_label.setText(f"  Restored {item['name']}  |  {count} entries")

    def _show_settings(self):
        dialog = SettingsDialog(vault=self._vault, parent=self)
        dialog.server_connect_requested.connect(self._show_server_connect)
        dialog.security_settings_saved.connect(self._apply_security_settings)
        self._run_dialog(dialog)

    def _show_server_connect(self):
        """Show the server connection dialog."""
        if not self._vault or not self._vault.is_unlocked:
            return
        # CLI sessions never hold the master password; the dialog asks for it.
        dialog = ServerConnectDialog(vault=self._vault, password="", parent=self)
        if self._run_dialog(dialog):
            count = self._rebuild_tree()
            self._statusbar_label.setText(
                f"  Pripojeny k serveru  |  {count} entries"
            )

    def _show_team(self):
        if not self._vault or not self._vault.is_unlocked:
            return
        dialog = TeamDialog(vault=self._vault, parent=self)
        self._run_dialog(dialog)

    def _show_import_wizard(self):
        if not self._vault or not self._vault.is_unlocked:
            return
        from .import_wizard import ImportWizardDialog
        dialog = ImportWizardDialog(vault=self._vault, parent=self)
        if self._run_dialog(dialog):
            count = self._rebuild_tree()
            self._statusbar_label.setText(f"  Import complete  |  {count} entries")

    def _show_export_dialog(self):
        if not self._vault or not self._vault.is_unlocked:
            return

        formats = {
            "Encrypted backup": ("backup", "Sezam Backup (*.db)"),
            "Plaintext CSV": ("csv", "CSV Files (*.csv)"),
            "Bitwarden JSON": ("bitwarden", "JSON Files (*.json)"),
        }
        choice, accepted = QInputDialog.getItem(
            self,
            "Export Vault",
            "Format:",
            list(formats),
            0,
            False,
        )
        if not accepted:
            return
        fmt, file_filter = formats[choice]

        if fmt != "backup":
            reply = QMessageBox.warning(
                self,
                "Plaintext Export",
                "This export contains ALL vault secrets in plaintext. "
                "Anyone with the file can read your passwords. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        default_name = {
            "backup": "sezam-backup.db",
            "csv": "sezam-export.csv",
            "bitwarden": "sezam-bitwarden.json",
        }[fmt]
        dest, _ = QFileDialog.getSaveFileName(
            self,
            "Export Vault",
            str(Path.home() / default_name),
            file_filter,
        )
        if not dest:
            return

        try:
            if fmt == "backup":
                self._vault.db.backup(dest)
            else:
                from ..cli import _export_bitwarden, _export_csv, export_incomplete_message

                if fmt == "csv":
                    skipped = _export_csv(self._vault, dest)
                else:
                    skipped = _export_bitwarden(self._vault, dest)
                incomplete = export_incomplete_message(dest, skipped)
                if incomplete:
                    self._statusbar_label.setText("  Export INCOMPLETE")
                    QMessageBox.warning(self, "Export Incomplete", incomplete)
                    return
            self._statusbar_label.setText(f"  Export saved to {dest}")
            QMessageBox.information(self, "Export Complete", f"Export saved to:\n{dest}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    # -- Search --

    @Slot(bool)
    def _on_deep_search_toggled(self, checked):
        """Re-run current search when deep search checkbox is toggled."""
        text = self._search_input.text()
        if text.strip():
            self._on_search(text)

    @Slot(str)
    def _on_search(self, text):
        self._reset_autolock()
        if not text.strip() or not self._vault:
            self._rebuild_tree()
            return

        deep = self._deep_search_cb.isChecked()
        if deep:
            results = self._vault.deep_search(text)
        else:
            results = self._vault.search(text)

        self._tree.clear()
        for r in results:
            item = QTreeWidgetItem()
            path_display = f"{r['path']}/" if r['path'] else ""
            matched = ""
            if r.get("matched_field"):
                matched = f"  [{r['matched_field']}]"
            item.setText(0, f"  {r['name']}    {path_display}{matched}")
            item.setData(0, Qt.UserRole, {"type": "entry", "id": r["entry_id"]})
            self._tree.addTopLevelItem(item)
        mode = " (deep)" if deep else ""
        self._statusbar_label.setText(f"  {len(results)} results{mode} for \"{text}\"")

    # -- Clipboard --

    @Slot(str)
    def _on_field_copied(self, value):
        clipboard = QApplication.clipboard()
        clipboard.setText(value)
        # Remember only what we wrote; the timer clears it only if it is
        # still there, so a newer copy from another app survives.
        self._clipboard_owned = value
        clipboard_seconds = self._clipboard_clear_ms // 1000
        self._clipboard_remaining = clipboard_seconds
        self._clipboard_timer.start(self._clipboard_clear_ms)
        self._clipboard_countdown_timer.start()
        self._statusbar_label.setText(
            f"  Copied to clipboard  |  clearing in {clipboard_seconds}s"
        )
        self._tray.setToolTip(
            f"Sezam \u2014 Clipboard clears in {clipboard_seconds}s"
        )

    def _update_clipboard_countdown(self):
        self._clipboard_remaining -= 1
        if self._clipboard_remaining > 0:
            self._statusbar_label.setText(f"  Clipboard clearing in {self._clipboard_remaining}s")
            self._tray.setToolTip(f"Sezam \u2014 Clipboard clears in {self._clipboard_remaining}s")
        else:
            self._clipboard_countdown_timer.stop()

    def _clear_clipboard(self):
        owned, self._clipboard_owned = self._clipboard_owned, None
        self._clipboard_timer.stop()
        self._clipboard_countdown_timer.stop()
        self._tray.setToolTip("Sezam")
        if owned is None:
            return
        clipboard = QApplication.clipboard()
        if clipboard.text() != owned:
            self._statusbar_label.setText("  Clipboard changed elsewhere \u2014 left as is")
            return
        clipboard.clear()
        self._statusbar_label.setText("  Clipboard cleared")

    # -- Shortcuts --

    def _focus_search(self):
        self._search_input.setFocus()
        self._search_input.selectAll()

    def _escape_pressed(self):
        if self._search_input.hasFocus() and self._search_input.text():
            self._search_input.clear()
        else:
            self._tree.setFocus()

    # -- Tray --

    def _poll_share_notifications(self):
        if not self._vault or not self._vault.is_unlocked:
            return
        server_url = self._vault.db.get_meta("server_url")
        user_id = self._vault.db.get_meta("user_id")
        if not server_url or not user_id or self._notification_poll_running:
            return

        vault = self._vault
        client = self._notification_client

        def poll():
            # Runs on the network thread: a slow or dead server must not
            # freeze the window on every timer tick.
            nonlocal client
            if client is None:
                from ..vault.sync_client import SyncClient

                client = SyncClient(vault.db, server_url, vault.keypair, user_id)
            return client, client.poll_share_notifications()

        def failed(_exc):
            self._notification_poll_running = False
            self._notification_client = None

        self._notification_poll_running = True
        run_in_background(
            self, poll, lambda result: self._show_share_notifications(vault, *result), failed
        )

    def _show_share_notifications(self, vault, client, notifications):
        self._notification_poll_running = False
        if vault is not self._vault or not vault.is_unlocked:
            return  # locked (or re-unlocked) while the poll was in flight
        self._notification_client = client
        for notification in notifications:
            share_id = str(notification.get("share_id", ""))
            label = f"{share_id[:12]}..." if len(share_id) > 12 else share_id
            self._tray.showMessage(
                "Secure Share viewed",
                f"Share {label} was viewed.",
                QSystemTrayIcon.MessageIcon.Information,
                10_000,
            )

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._show_and_focus()

    def _show_and_focus(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()
        if self._vault and self._vault.is_unlocked:
            self._search_input.setFocus()

    def show_and_activate(self):
        """Public method for global hotkey to bring up the window.

        Spec 7.1: Ctrl+Alt+V global hotkey shows and focuses the vault window.
        If locked, shows the unlock dialog.
        """
        self._show_and_focus()
        if not self._vault or not self._vault.is_unlocked:
            self._show_unlock()

    # -- Argon2 upgrade (spec 9.5) --

    def _check_argon2_upgrade(self):
        """Check if current Argon2id parameters are weaker than recommended.

        Spec 9.5: After successful unlock, compare current params with
        recommended defaults. If weaker, offer to upgrade.
        """
        if not self._vault or not self._vault.is_unlocked:
            return

        try:
            from ..crypto.kdf import Argon2Params
            current_params = Argon2Params.from_dict(
                self._vault.db.get_meta_json("argon2_params")
            )
            recommended = Argon2Params()  # Default: time=3, mem=256MB, par=4

            # Check if current params are weaker
            needs_upgrade = (
                current_params.time_cost < recommended.time_cost
                or current_params.memory_cost < recommended.memory_cost
                or current_params.parallelism < recommended.parallelism
            )

            if not needs_upgrade:
                return

            # Show upgrade dialog
            from .argon2_upgrade_dialog import Argon2UpgradeDialog
            dialog = Argon2UpgradeDialog(
                current_params=current_params,
                recommended_params=recommended,
                vault=self._vault,
                parent=self,
            )
            self._run_dialog(dialog)

        except Exception:
            # An optional upgrade offer must not break unlock, but say why it was skipped.
            logger.warning("Argon2 upgrade check failed", exc_info=True)

    # -- Window events --

    def closeEvent(self, event):
        # Hide to tray only when the tray icon is really there to bring the
        # window back (and to Quit); otherwise closing would leave an
        # invisible, unlocked process behind.
        if QSystemTrayIcon.isSystemTrayAvailable() and self._tray.isVisible():
            event.ignore()
            self.hide()
            return
        event.accept()
        self._quit()

    def _quit(self):
        # A pending secret must not outlive the app (the timer dies with it).
        self._clear_clipboard()
        if self._vault and self._vault.is_unlocked:
            self._vault.lock()
        QApplication.quit()
