"""Dialogs for creating/editing entries and nodes."""

from __future__ import annotations


from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..password import generate_password
from ..vault.crud import Vault


class EntryDialog(QDialog):
    """Create or edit an entry."""

    def __init__(self, vault: Vault, node_id: str, entry: dict = None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._node_id = node_id
        self._entry = entry
        self._field_rows: list[dict] = []

        self.setWindowTitle("Edit Entry" if entry else "New Entry")
        self.setMinimumSize(500, 400)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # Name
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name:"))
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Entry name")
        if entry:
            self._name_input.setText(entry["name"])
        name_row.addWidget(self._name_input)
        layout.addLayout(name_row)

        # Tier
        tier_row = QHBoxLayout()
        tier_row.addWidget(QLabel("Tier:"))
        self._tier_combo = QComboBox()
        self._tier_combo.addItems(["Inherit", "0 — Free", "1 — On request", "2 — Secret"])
        if entry and entry.get("tier") is not None:
            self._tier_combo.setCurrentIndex(entry["tier"] + 1)
        tier_row.addWidget(self._tier_combo)
        layout.addLayout(tier_row)

        # Fields
        self._fields_container = QVBoxLayout()
        layout.addLayout(self._fields_container)

        if entry:
            for f in entry.get("fields", []):
                self._add_field_row(f["key"], f["value"], f.get("sensitive", False))
        else:
            self._add_field_row("", "")
            self._add_field_row("", "", sensitive=False)

        # Add field button
        add_btn = QPushButton("+ Add Field")
        add_btn.setStyleSheet("color: #a0a0b0; border: none; font-size: 13px;")
        add_btn.clicked.connect(lambda: self._add_field_row("", ""))
        layout.addWidget(add_btn)

        layout.addStretch()

        # Buttons
        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(
            "background: #0f3460; color: #e0e0e0; border: none; border-radius: 6px; padding: 8px 24px;"
        )
        save_btn.setDefault(True)
        save_btn.clicked.connect(self._save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        layout.addLayout(btn_row)

        self.setStyleSheet("QDialog { background: #1a1a2e; color: #e0e0e0; }")

    def _add_field_row(self, key: str = "", value: str = "", sensitive: bool = False):
        row = QHBoxLayout()

        key_input = QLineEdit(key)
        key_input.setPlaceholderText("Field name")
        key_input.setFixedWidth(140)
        row.addWidget(key_input)

        value_input = QLineEdit(value)
        value_input.setPlaceholderText("Value")
        if sensitive:
            value_input.setEchoMode(QLineEdit.Password)
        row.addWidget(value_input, 1)

        sensitive_cb = QCheckBox("Sensitive")
        sensitive_cb.setChecked(sensitive)
        sensitive_cb.toggled.connect(
            lambda checked: value_input.setEchoMode(
                QLineEdit.Password if checked else QLineEdit.Normal
            )
        )
        row.addWidget(sensitive_cb)

        # Generate password button
        gen_btn = QPushButton("Gen")
        gen_btn.setFixedWidth(40)
        gen_btn.setToolTip("Generate random password")
        gen_btn.clicked.connect(lambda: value_input.setText(generate_password()))
        row.addWidget(gen_btn)

        # Remove button
        remove_btn = QPushButton("X")
        remove_btn.setFixedWidth(30)
        row.addWidget(remove_btn)

        container = QWidget()
        container.setLayout(row)
        self._fields_container.addWidget(container)

        field_data = {
            "container": container,
            "key": key_input,
            "value": value_input,
            "sensitive": sensitive_cb,
        }
        self._field_rows.append(field_data)
        remove_btn.clicked.connect(lambda: self._remove_field(field_data))

    def _remove_field(self, field_data):
        field_data["container"].deleteLater()
        self._field_rows.remove(field_data)

    def _save(self):
        name = self._name_input.text().strip()
        if not name:
            return

        tier_idx = self._tier_combo.currentIndex()
        tier = None if tier_idx == 0 else tier_idx - 1

        fields = []
        for i, fr in enumerate(self._field_rows):
            key = fr["key"].text().strip()
            value = fr["value"].text()
            if not key:
                continue
            fields.append({
                "key": key,
                "value": value,
                "sensitive": fr["sensitive"].isChecked(),
                "sort_order": i,
            })

        try:
            if self._entry:
                self._vault.update_entry(
                    self._entry["id"],
                    name=name,
                    fields=fields,
                    tier=tier,
                    inherit_tier=tier is None,
                )
            else:
                self._vault.create_entry(self._node_id, name, fields, tier=tier)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save entry: {e}")
            return

        self.accept()


class NodeDialog(QDialog):
    """Create a new folder node."""

    def __init__(self, vault: Vault, parent_id: str = None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._parent_id = parent_id

        self.setWindowTitle("New Folder")
        self.setFixedSize(400, 180)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Folder name")
        self._name_input.setMinimumHeight(36)
        self._name_input.returnPressed.connect(self._save)
        layout.addWidget(self._name_input)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("Create")
        save_btn.setStyleSheet(
            "background: #0f3460; color: #e0e0e0; border: none; border-radius: 6px; padding: 8px 24px;"
        )
        save_btn.setDefault(True)
        save_btn.clicked.connect(self._save)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        layout.addLayout(btn_row)

        self.setStyleSheet("QDialog { background: #1a1a2e; color: #e0e0e0; }")

    def _save(self):
        name = self._name_input.text().strip()
        if not name:
            return
        try:
            self._vault.create_node(name, self._parent_id)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to create folder: {e}")
            return
        self.accept()
