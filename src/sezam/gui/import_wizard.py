"""Import Wizard GUI — import entries from various password manager formats.

Spec 10.1: Format selection, file picker, preview, tier assignment,
conflict handling, progress bar.

Supported formats:
  - CSV (Sezam format)
  - KeePass (.kdbx)
  - Bitwarden (JSON)
  - 1Password (1PIF / CSV)
  - Plaintext (one entry per line: name:username:password)
"""

from __future__ import annotations

import json
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .background import track as track_worker
from ..importers import import_entry
from .styles import COLORS


# ── Format definitions ──

FORMATS = {
    "csv": {
        "label": "CSV (Sezam format)",
        "extensions": "CSV Files (*.csv)",
        "description": "Sezam CSV with columns: folder, name, field_key, field_value, sensitive, tier",
    },
    "keepass": {
        "label": "KeePass (.kdbx)",
        "extensions": "KeePass Files (*.kdbx)",
        "description": "KeePass .kdbx database file (requires pykeepass)",
    },
    "bitwarden": {
        "label": "Bitwarden (JSON)",
        "extensions": "JSON Files (*.json)",
        "description": "Bitwarden JSON export file",
    },
    "onepassword": {
        "label": "1Password (.1pux)",
        "extensions": "1Password Export Files (*.1pux)",
        "description": "1Password .1pux export archive",
    },
    "plaintext": {
        "label": "Plaintext",
        "extensions": "Text Files (*.txt);;All Files (*)",
        "description": "Simple format: one entry per line as name:username:password",
    },
}


# ── Preview parsers ──

def _parse_csv_preview(file_path: str) -> list[dict]:
    """Parse Sezam CSV and return list of preview entries (grouped like the import)."""
    from ..importers.csv_import import read_csv_entries

    return [
        {
            "folder": item["folder"],
            "name": item["name"],
            "fields_count": len(item["fields"]),
            "field_keys": ", ".join(f["key"] for f in item["fields"]),
            "tier": item["tier"],
        }
        for item in read_csv_entries(file_path)
    ]


def _parse_bitwarden_preview(file_path: str) -> list[dict]:
    """Parse Bitwarden JSON and return preview entries."""
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)

    folders: dict[Optional[str], str] = {}
    for folder in data.get("folders", []):
        folders[folder.get("id")] = folder.get("name", "")

    results = []
    for item in data.get("items", []):
        if item.get("type", 1) != 1:
            continue
        login = item.get("login", {})
        field_keys = []
        if login.get("username"):
            field_keys.append("username")
        if login.get("password"):
            field_keys.append("password")
        if login.get("uris"):
            field_keys.append("url")
        if login.get("totp"):
            field_keys.append("totp")
        if item.get("notes"):
            field_keys.append("notes")
        for cf in item.get("fields", []):
            field_keys.append(cf.get("name", "field"))

        results.append({
            "folder": folders.get(item.get("folderId"), ""),
            "name": item.get("name", "Untitled"),
            "fields_count": len(field_keys),
            "field_keys": ", ".join(field_keys),
            "tier": None,
        })
    return results


def _parse_plaintext_preview(file_path: str) -> list[dict]:
    """Parse plaintext file (name:username:password per line)."""
    results = []
    with open(file_path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            name = parts[0].strip() if parts else f"Entry {line_num}"
            field_keys = []
            if len(parts) > 1 and parts[1].strip():
                field_keys.append("username")
            if len(parts) > 2 and parts[2].strip():
                field_keys.append("password")
            results.append({
                "folder": "",
                "name": name,
                "fields_count": len(field_keys),
                "field_keys": ", ".join(field_keys) or "name only",
                "tier": None,
            })
    return results


# ── Import worker ──

class _ImportWorker(QThread):
    """Background import thread."""

    progress = Signal(int, int)  # current, total
    finished = Signal(int, str)  # count, error_message

    def __init__(
        self,
        vault,
        file_path: str,
        format_id: str,
        tier: Optional[int],
        conflict_mode: str,
        keepass_password: Optional[str] = None,
    ):
        super().__init__()
        self._vault = vault
        self._file_path = file_path
        self._format_id = format_id
        self._tier = tier
        self._conflict_mode = conflict_mode
        self._keepass_password = keepass_password

    def run(self):
        try:
            from ..vault.snapshots import take_snapshot

            take_snapshot(self._vault.db, "import")
            count = 0
            if self._format_id == "csv":
                from ..importers.csv_import import import_csv
                count = import_csv(
                    self._vault, self._file_path, self._tier, self._conflict_mode
                )
            elif self._format_id == "keepass":
                from ..importers.keepass import import_keepass
                count = import_keepass(
                    self._vault,
                    self._file_path,
                    password=self._keepass_password,
                    tier=self._tier,
                    conflict_mode=self._conflict_mode,
                )
            elif self._format_id == "bitwarden":
                from ..importers.bitwarden import import_bitwarden
                count = import_bitwarden(
                    self._vault, self._file_path, self._tier, self._conflict_mode
                )
            elif self._format_id == "onepassword":
                count = self._import_onepassword()
            elif self._format_id == "plaintext":
                count = self._import_plaintext()

            self.finished.emit(count, "")
        except Exception as e:
            self.finished.emit(0, str(e))

    def _import_onepassword(self) -> int:
        """Import the canonical 1Password .1pux export."""
        from ..cli import _import_1password

        return _import_1password(
            self._vault,
            self._file_path,
            tier=self._tier,
            conflict_mode=self._conflict_mode,
        )

    def _import_plaintext(self) -> int:
        """Import plaintext format: name:username:password per line."""
        count = 0
        claimed: set[str] = set()
        root_id = self._vault.db.get_meta("root_node_id")

        with open(self._file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":", 2)
                name = parts[0].strip()
                if not name:
                    continue

                fields = []
                sort_order = 0
                if len(parts) > 1 and parts[1].strip():
                    fields.append({
                        "key": "username",
                        "value": parts[1].strip(),
                        "sensitive": False,
                        "sort_order": sort_order,
                    })
                    sort_order += 1
                if len(parts) > 2 and parts[2].strip():
                    fields.append({
                        "key": "password",
                        "value": parts[2].strip(),
                        "sensitive": True,
                        "sort_order": sort_order,
                    })
                    sort_order += 1

                if not fields:
                    # At minimum create with the name
                    fields.append({
                        "key": "name",
                        "value": name,
                        "sensitive": False,
                        "sort_order": 0,
                    })

                if import_entry(
                    self._vault,
                    root_id,
                    name,
                    fields,
                    self._tier,
                    self._conflict_mode,
                    claimed=claimed,
                ):
                    count += 1

        return count

    def _ensure_folder(self, folder_path: str) -> str:
        """Create folder hierarchy if needed, return leaf node ID."""
        if not folder_path:
            return self._vault.db.get_meta("root_node_id")

        parts = [p for p in folder_path.split("/") if p]
        current_node = self._vault.db.get_meta("root_node_id")

        for part in parts:
            children = self._vault.list_nodes(current_node)
            found = None
            for child in children:
                if child["name"].lower() == part.lower():
                    found = child["id"]
                    break
            if found is None:
                found = self._vault.create_node(part, current_node)
            current_node = found

        return current_node


# ── Main wizard dialog ──

class ImportWizardDialog(QDialog):
    """Multi-step import wizard with format selection, file picker,
    preview, and progress.
    """

    def __init__(self, vault=None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._file_path: Optional[str] = None
        self._preview_entries: list[dict] = []
        self._worker: Optional[_ImportWorker] = None
        self._imported_count = 0

        self.setWindowTitle("Import Entries")
        self.setMinimumSize(720, 520)
        self.resize(800, 580)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(
            f"background: {COLORS['bg_panel']}; "
            f"border-bottom: 1px solid {COLORS['border']};"
        )
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(20, 0, 20, 0)
        self._title_label = QLabel("Import Entries")
        self._title_label.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {COLORS['text']};"
        )
        h_layout.addWidget(self._title_label)
        h_layout.addStretch()
        main_layout.addWidget(header)

        # Stacked pages
        self._stack = QStackedWidget()
        main_layout.addWidget(self._stack, 1)

        self._setup_page_format()
        self._setup_page_preview()
        self._setup_page_progress()

        # Footer with navigation buttons
        footer = QWidget()
        footer.setFixedHeight(56)
        footer.setStyleSheet(
            f"background: {COLORS['bg_panel']}; "
            f"border-top: 1px solid {COLORS['border']};"
        )
        f_layout = QHBoxLayout(footer)
        f_layout.setContentsMargins(20, 0, 20, 0)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self.reject)
        f_layout.addWidget(self._cancel_btn)

        f_layout.addStretch()

        self._back_btn = QPushButton("Back")
        self._back_btn.setVisible(False)
        self._back_btn.clicked.connect(self._go_back)
        f_layout.addWidget(self._back_btn)

        self._next_btn = QPushButton("Next")
        self._next_btn.setProperty("cssClass", "accent")
        self._next_btn.clicked.connect(self._go_next)
        f_layout.addWidget(self._next_btn)

        main_layout.addWidget(footer)

    # ---- Page 1: Format Selection + File Picker ----

    def _setup_page_format(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Format selection
        fmt_label = QLabel("Select import format:")
        fmt_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 14px; font-weight: 600;")
        layout.addWidget(fmt_label)

        self._format_combo = QComboBox()
        for fmt_id, fmt_info in FORMATS.items():
            self._format_combo.addItem(fmt_info["label"], fmt_id)
        self._format_combo.currentIndexChanged.connect(self._on_format_changed)
        layout.addWidget(self._format_combo)

        self._format_desc = QLabel(FORMATS["csv"]["description"])
        self._format_desc.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        self._format_desc.setWordWrap(True)
        layout.addWidget(self._format_desc)

        layout.addSpacing(8)

        # File picker
        file_label = QLabel("Select file to import:")
        file_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 14px; font-weight: 600;")
        layout.addWidget(file_label)

        file_row = QHBoxLayout()
        self._file_input = QLineEdit()
        self._file_input.setPlaceholderText("No file selected")
        self._file_input.setReadOnly(True)
        file_row.addWidget(self._file_input, 1)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        layout.addSpacing(8)

        # KeePass password (only shown for KeePass format)
        self._keepass_pw_label = QLabel("KeePass master password:")
        self._keepass_pw_label.setVisible(False)
        self._keepass_pw_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px;")
        layout.addWidget(self._keepass_pw_label)

        self._keepass_pw_input = QLineEdit()
        self._keepass_pw_input.setPlaceholderText("KeePass password")
        self._keepass_pw_input.setEchoMode(QLineEdit.Password)
        self._keepass_pw_input.setVisible(False)
        layout.addWidget(self._keepass_pw_input)

        # Tier assignment
        tier_row = QHBoxLayout()
        tier_label = QLabel("Default tier for imported entries:")
        tier_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px;")
        tier_row.addWidget(tier_label)

        self._tier_combo = QComboBox()
        self._tier_combo.addItem("Tier 0 (Auto — AI reads freely)", 0)
        self._tier_combo.addItem("Tier 1 (Approval — AI needs consent)", 1)
        self._tier_combo.addItem("Tier 2 (Deny — AI cannot see)", 2)
        self._tier_combo.setCurrentIndex(1)  # Default tier 1
        tier_row.addWidget(self._tier_combo)
        layout.addLayout(tier_row)

        # Conflict handling
        conflict_row = QHBoxLayout()
        conflict_label = QLabel("On conflict (duplicate name):")
        conflict_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px;")
        conflict_row.addWidget(conflict_label)

        self._conflict_combo = QComboBox()
        self._conflict_combo.addItem("Skip existing", "skip")
        self._conflict_combo.addItem("Overwrite existing", "overwrite")
        self._conflict_combo.addItem("Create duplicate", "duplicate")
        conflict_row.addWidget(self._conflict_combo)
        layout.addLayout(conflict_row)

        layout.addStretch()
        self._stack.addWidget(page)

    # ---- Page 2: Preview ----

    def _setup_page_preview(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        self._preview_label = QLabel("Preview: 0 entries to import")
        self._preview_label.setStyleSheet(
            f"color: {COLORS['text']}; font-size: 14px; font-weight: 600;"
        )
        layout.addWidget(self._preview_label)

        self._preview_table = QTableWidget()
        self._preview_table.setColumnCount(4)
        self._preview_table.setHorizontalHeaderLabels(
            ["Folder", "Name", "Fields", "Tier"]
        )
        self._preview_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._preview_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._preview_table.setAlternatingRowColors(True)
        self._preview_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._preview_table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLORS['bg']};
                gridline-color: {COLORS['border']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
            QTableWidget::item {{
                padding: 4px 8px;
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
                padding: 8px;
                border: none;
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        layout.addWidget(self._preview_table, 1)

        self._stack.addWidget(page)

    # ---- Page 3: Progress / Results ----

    def _setup_page_progress(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.setAlignment(Qt.AlignCenter)

        self._progress_title = QLabel("Importing entries...")
        self._progress_title.setStyleSheet(
            f"color: {COLORS['text']}; font-size: 16px; font-weight: 600;"
        )
        self._progress_title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._progress_title)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # Indeterminate
        self._progress_bar.setFixedWidth(400)
        layout.addWidget(self._progress_bar, alignment=Qt.AlignCenter)

        self._progress_status = QLabel("")
        self._progress_status.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 13px;"
        )
        self._progress_status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._progress_status)

        self._stack.addWidget(page)

    # ---- Navigation ----

    def _go_next(self):
        current = self._stack.currentIndex()

        if current == 0:
            # Validate format page
            if not self._file_path:
                QMessageBox.warning(self, "No File", "Please select a file to import.")
                return

            fmt_id = self._format_combo.currentData()
            if fmt_id == "keepass" and not self._keepass_pw_input.text():
                QMessageBox.warning(self, "Password Required", "Enter the KeePass master password.")
                return

            # Parse preview
            self._load_preview()
            if not self._preview_entries:
                QMessageBox.warning(self, "No Entries", "No entries found in the selected file.")
                return

            self._stack.setCurrentIndex(1)
            self._back_btn.setVisible(True)
            self._title_label.setText("Import Preview")

        elif current == 1:
            # Start import
            self._start_import()
            self._stack.setCurrentIndex(2)
            self._back_btn.setVisible(False)
            self._next_btn.setVisible(False)
            self._cancel_btn.setVisible(False)
            self._title_label.setText("Importing...")

    def _go_back(self):
        current = self._stack.currentIndex()
        if current > 0:
            self._stack.setCurrentIndex(current - 1)
            self._back_btn.setVisible(current - 1 > 0)
            self._title_label.setText("Import Entries")

    # ---- Format change ----

    @Slot(int)
    def _on_format_changed(self, index):
        fmt_id = self._format_combo.currentData()
        if fmt_id and fmt_id in FORMATS:
            self._format_desc.setText(FORMATS[fmt_id]["description"])

        # Show/hide KeePass password field
        is_keepass = fmt_id == "keepass"
        self._keepass_pw_label.setVisible(is_keepass)
        self._keepass_pw_input.setVisible(is_keepass)

        # Clear file selection when format changes
        self._file_path = None
        self._file_input.clear()

    # ---- File picker ----

    def _browse_file(self):
        fmt_id = self._format_combo.currentData()
        extensions = FORMATS.get(fmt_id, {}).get("extensions", "All Files (*)")

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Import File", "", extensions
        )
        if file_path:
            self._file_path = file_path
            self._file_input.setText(file_path)

    # ---- Preview ----

    def _load_preview(self):
        """Parse the selected file and populate the preview table."""
        fmt_id = self._format_combo.currentData()

        try:
            if fmt_id == "csv":
                self._preview_entries = _parse_csv_preview(self._file_path)
            elif fmt_id == "bitwarden":
                self._preview_entries = _parse_bitwarden_preview(self._file_path)
            elif fmt_id == "onepassword":
                self._preview_entries = [{
                    "folder": "(1Password)",
                    "name": "Preview not available for .1pux archives",
                    "fields_count": 0,
                    "field_keys": "Will be determined during import",
                    "tier": None,
                }]
            elif fmt_id == "plaintext":
                self._preview_entries = _parse_plaintext_preview(self._file_path)
            elif fmt_id == "keepass":
                # For KeePass, we cannot preview without opening the DB
                # Show a placeholder
                self._preview_entries = [{
                    "folder": "(KeePass)",
                    "name": "Preview not available for encrypted databases",
                    "fields_count": 0,
                    "field_keys": "Will be determined during import",
                    "tier": None,
                }]
            else:
                self._preview_entries = []
        except Exception as e:
            QMessageBox.warning(self, "Parse Error", f"Failed to parse file: {e}")
            self._preview_entries = []
            return

        # Populate table
        default_tier = self._tier_combo.currentData()
        self._preview_table.setRowCount(len(self._preview_entries))
        for i, entry in enumerate(self._preview_entries):
            self._preview_table.setItem(i, 0, QTableWidgetItem(entry.get("folder", "")))
            self._preview_table.setItem(i, 1, QTableWidgetItem(entry.get("name", "")))
            self._preview_table.setItem(
                i, 2, QTableWidgetItem(entry.get("field_keys", ""))
            )
            tier = entry.get("tier")
            tier_str = str(tier) if tier is not None else str(default_tier)
            self._preview_table.setItem(i, 3, QTableWidgetItem(f"Tier {tier_str}"))

        self._preview_label.setText(f"Preview: {len(self._preview_entries)} entries to import")

    # ---- Import execution ----

    def _start_import(self):
        """Kick off the background import."""
        fmt_id = self._format_combo.currentData()
        tier = self._tier_combo.currentData()
        conflict = self._conflict_combo.currentData()
        keepass_pw = self._keepass_pw_input.text() if fmt_id == "keepass" else None

        self._progress_bar.setRange(0, 0)  # Indeterminate
        self._progress_status.setText("Starting import...")

        self._worker = _ImportWorker(
            vault=self._vault,
            file_path=self._file_path,
            format_id=fmt_id,
            tier=tier,
            conflict_mode=conflict,
            keepass_password=keepass_pw,
        )
        self._worker.finished.connect(self._on_import_finished)
        self._worker.start()
        track_worker(self._worker)

    @Slot(int, str)
    def _on_import_finished(self, count: int, error: str):
        """Handle import completion."""
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(100)
        self._imported_count = count

        if error:
            self._progress_title.setText("Import Failed")
            self._progress_status.setText(f"Error: {error}")
            self._progress_status.setStyleSheet(f"color: {COLORS['error']}; font-size: 13px;")
            self._cancel_btn.setVisible(True)
            self._cancel_btn.setText("Close")
        else:
            self._progress_title.setText("Import Complete")
            self._progress_status.setText(f"Successfully imported {count} entries.")
            self._progress_status.setStyleSheet(
                f"color: {COLORS['success']}; font-size: 13px;"
            )
            # Show done button
            self._cancel_btn.setVisible(True)
            self._cancel_btn.setText("Done")
            self._cancel_btn.clicked.disconnect()
            self._cancel_btn.clicked.connect(self.accept)
