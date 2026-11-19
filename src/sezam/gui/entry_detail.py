"""Entry detail widget — shows fields with show/hide, copy, TOTP countdown.

Spec 10.2: TOTP fields display code in large label with circular countdown
indicator (30s period), auto-refresh every second, wait for new code if <5s
remaining before copying.
"""

from __future__ import annotations

import logging
from PySide6.QtCore import Qt, QTimer, QRectF, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..totp import generate_totp, time_remaining
from .styles import COLORS

logger = logging.getLogger(__name__)


class TotpCountdownWidget(QWidget):
    """Circular countdown indicator for TOTP period.

    Draws an arc that depletes as the TOTP period counts down.
    Shows remaining seconds in the center.
    """

    def __init__(self, period: int = 30, parent=None):
        super().__init__(parent)
        self._period = period
        self._remaining = period
        self.setFixedSize(48, 48)

    def set_remaining(self, remaining: int):
        self._remaining = remaining
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = QRectF(4, 4, 40, 40)

        # Background circle
        bg_pen = QPen(QColor(COLORS['border']), 3)
        painter.setPen(bg_pen)
        painter.drawEllipse(rect)

        # Progress arc (depleting clockwise)
        fraction = self._remaining / self._period
        if fraction > 0:
            if self._remaining <= 5:
                arc_color = QColor(COLORS['warning'])
            else:
                arc_color = QColor(COLORS['success'])

            arc_pen = QPen(arc_color, 3)
            painter.setPen(arc_pen)
            # Qt uses 1/16th of a degree, starting from 3 o'clock, counter-clockwise
            start_angle = 90 * 16  # 12 o'clock
            span_angle = int(fraction * 360 * 16)
            painter.drawArc(rect, start_angle, span_angle)

        # Center text
        painter.setPen(QColor(COLORS['text']))
        font = QFont("Segoe UI", 11, QFont.Bold)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, str(self._remaining))

        painter.end()


class FieldWidget(QWidget):
    """Single field row — key, value, show/hide, copy."""

    copy_requested = Signal(str)

    def __init__(self, key: str, value: str, sensitive: bool, field_type: str = None):
        super().__init__()
        self._value = value
        self._sensitive = sensitive
        self._visible = not sensitive
        self._field_type = field_type
        self._is_totp = (field_type == "totp" or key.lower() in ("totp_secret", "totp", "otp"))

        self.setStyleSheet(f"""
            FieldWidget {{
                background: {COLORS['bg_card']};
                border-radius: 8px;
                padding: 4px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        if self._is_totp:
            self._setup_totp_layout(layout, key)
        else:
            self._setup_standard_layout(layout, key, sensitive)

    def _setup_standard_layout(self, layout, key: str, sensitive: bool):
        """Standard field layout: key, value, show/hide, copy."""
        # Key label
        self._key_label = QLabel(key)
        self._key_label.setFixedWidth(130)
        self._key_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;")
        layout.addWidget(self._key_label)

        # Value label
        self._value_label = QLabel()
        self._value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._value_label.setStyleSheet(f"color: {COLORS['text']}; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 14px;")
        self._value_label.setWordWrap(True)
        layout.addWidget(self._value_label, 1)

        # Show/Hide button
        if sensitive:
            self._toggle_btn = QPushButton("Show")
            self._toggle_btn.setFixedSize(64, 32)
            self._toggle_btn.clicked.connect(self._toggle)
            layout.addWidget(self._toggle_btn)

        # Copy button
        copy_btn = QPushButton("Copy")
        copy_btn.setFixedSize(64, 32)
        copy_btn.clicked.connect(self._do_copy)
        layout.addWidget(copy_btn)

        self._update_display()

    def _setup_totp_layout(self, layout, key: str):
        """TOTP field layout: key, large code, circular countdown, copy."""
        # Left: key label
        key_label = QLabel(key)
        key_label.setFixedWidth(130)
        key_label.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 12px; "
            f"font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;"
        )
        layout.addWidget(key_label)

        # Center: TOTP code in large font
        self._value_label = QLabel()
        self._value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._value_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(self._value_label, 1)

        # Circular countdown
        self._countdown_widget = TotpCountdownWidget(30)
        layout.addWidget(self._countdown_widget)

        # Show/Hide toggle (TOTP is sensitive by default)
        self._visible = False
        self._toggle_btn = QPushButton("Show")
        self._toggle_btn.setFixedSize(64, 32)
        self._toggle_btn.clicked.connect(self._toggle)
        layout.addWidget(self._toggle_btn)

        # Copy button
        copy_btn = QPushButton("Copy")
        copy_btn.setFixedSize(64, 32)
        copy_btn.clicked.connect(self._do_copy)
        layout.addWidget(copy_btn)

        # Timer for auto-refresh every second
        self._totp_timer = QTimer(self)
        self._totp_timer.setInterval(1000)
        self._totp_timer.timeout.connect(self._update_totp)
        self._totp_timer.start()

        self._update_display()

    def _update_display(self):
        if self._is_totp and self._visible:
            try:
                code = generate_totp(self._value)
                remaining = time_remaining()
                # Format code with a space in the middle for readability (e.g., "123 456")
                if len(code) == 6:
                    display_code = f"{code[:3]} {code[3:]}"
                else:
                    display_code = code
                self._value_label.setText(display_code)
                color = COLORS['success'] if remaining > 5 else COLORS['warning']
                self._value_label.setStyleSheet(
                    f"color: {color}; font-family: 'Cascadia Code', monospace; "
                    f"font-size: 26px; font-weight: bold; letter-spacing: 6px;"
                )
                # Update countdown widget
                if hasattr(self, '_countdown_widget'):
                    self._countdown_widget.set_remaining(remaining)
            except Exception:
                self._value_label.setText("Invalid TOTP secret")
                self._value_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 14px;")
        elif self._is_totp and not self._visible:
            self._value_label.setText("\u2022 \u2022 \u2022  \u2022 \u2022 \u2022")
            self._value_label.setStyleSheet(
                f"color: {COLORS['text_muted']}; font-size: 26px; letter-spacing: 6px;"
            )
            # Still update countdown even when hidden
            try:
                remaining = time_remaining()
                if hasattr(self, '_countdown_widget'):
                    self._countdown_widget.set_remaining(remaining)
            except Exception:
                logger.debug("TOTP countdown update failed", exc_info=True)
        elif self._visible:
            self._value_label.setText(self._value)
            self._value_label.setStyleSheet(f"color: {COLORS['text']}; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 14px;")
        else:
            self._value_label.setText("\u2022 \u2022 \u2022 \u2022 \u2022 \u2022 \u2022 \u2022")
            self._value_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px; letter-spacing: 2px;")

    def _toggle(self):
        self._visible = not self._visible
        self._update_display()
        if hasattr(self, '_toggle_btn'):
            self._toggle_btn.setText("Hide" if self._visible else "Show")

    def _update_totp(self):
        """Auto-refresh TOTP display every second."""
        if self._is_totp:
            self._update_display()

    def _do_copy(self):
        if not self._is_totp:
            self.copy_requested.emit(self._value)
            return
        remaining = time_remaining()
        if remaining < 5:
            # Wait for the next code without blocking the GUI thread.
            QTimer.singleShot(int((remaining + 0.1) * 1000), self, self._copy_totp_code)
        else:
            self._copy_totp_code()

    def _copy_totp_code(self):
        try:
            code = generate_totp(self._value)
        except Exception:
            # Never fall back to the value: for a TOTP field it is the seed.
            self._value_label.setText("Invalid TOTP secret")
            self._value_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 14px;")
            return
        self.copy_requested.emit(code)


class EntryDetailWidget(QWidget):
    """Entry detail panel — header + field cards."""

    field_copied = Signal(str)
    edit_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self._current_entry_id = None
        self.setStyleSheet(f"background: {COLORS['bg']};")

        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(24, 24, 24, 24)
        self._layout.setSpacing(0)

        # Empty state
        self._empty_state = QWidget()
        empty_layout = QVBoxLayout(self._empty_state)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_icon = QLabel("Select an entry from the sidebar")
        empty_icon.setAlignment(Qt.AlignCenter)
        empty_icon.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 15px;")
        empty_layout.addWidget(empty_icon)
        hint = QLabel("or press Ctrl+N to create a new one")
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px;")
        empty_layout.addWidget(hint)
        self._layout.addWidget(self._empty_state)

        # Header (hidden until entry selected)
        self._header = QWidget()
        self._header.setVisible(False)
        header_layout = QVBoxLayout(self._header)
        header_layout.setContentsMargins(0, 0, 0, 16)

        # Title row
        title_row = QHBoxLayout()
        self._name_label = QLabel()
        self._name_label.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self._name_label.setStyleSheet(f"color: {COLORS['text']};")
        title_row.addWidget(self._name_label)
        title_row.addStretch()

        edit_btn = QPushButton("Edit")
        edit_btn.setFixedSize(72, 34)
        edit_btn.clicked.connect(lambda: self.edit_requested.emit(self._current_entry_id) if self._current_entry_id else None)
        title_row.addWidget(edit_btn)

        del_btn = QPushButton("Delete")
        del_btn.setFixedSize(72, 34)
        del_btn.setStyleSheet(f"QPushButton {{ color: {COLORS['error']}; }} QPushButton:hover {{ background: {COLORS['error']}; color: white; }}")
        del_btn.clicked.connect(lambda: self.delete_requested.emit(self._current_entry_id) if self._current_entry_id else None)
        title_row.addWidget(del_btn)

        header_layout.addLayout(title_row)

        # Tags
        self._tags_label = QLabel("")
        self._tags_label.setStyleSheet(f"color: {COLORS['accent']}; font-size: 12px; margin-top: 2px;")
        self._tags_label.setWordWrap(True)
        header_layout.addWidget(self._tags_label)

        # Metadata
        self._meta_label = QLabel("")
        self._meta_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; margin-top: 4px;")
        header_layout.addWidget(self._meta_label)

        self._layout.addWidget(self._header)

        # Scroll area for fields
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setVisible(False)
        self._fields_widget = QWidget()
        self._fields_widget.setStyleSheet(f"background: {COLORS['bg']};")
        self._fields_layout = QVBoxLayout(self._fields_widget)
        self._fields_layout.setAlignment(Qt.AlignTop)
        self._fields_layout.setSpacing(6)
        self._fields_layout.setContentsMargins(0, 0, 0, 0)
        self._scroll.setWidget(self._fields_widget)
        self._layout.addWidget(self._scroll, 1)

    def show_entry(self, entry: dict):
        self._current_entry_id = entry.get("id")
        self._empty_state.setVisible(False)
        self._header.setVisible(True)
        self._scroll.setVisible(True)

        self._name_label.setText(entry.get("name", ""))

        tags = entry.get("tags", [])
        if tags:
            self._tags_label.setText("  ".join(f"#{t}" for t in tags))
            self._tags_label.setVisible(True)
        else:
            self._tags_label.setVisible(False)

        # Metadata line
        from datetime import datetime
        created = entry.get("created_at", 0)
        modified = entry.get("modified_at", 0)
        tier = entry.get("tier")
        parts = []
        if tier is not None:
            parts.append(f"Tier {tier}")
        if created:
            parts.append(f"Created {datetime.fromtimestamp(created/1000).strftime('%Y-%m-%d %H:%M')}")
        if modified and modified != created:
            parts.append(f"Modified {datetime.fromtimestamp(modified/1000).strftime('%Y-%m-%d %H:%M')}")
        parts.append(f"v{entry.get('version', 1)}")
        self._meta_label.setText("  |  ".join(parts))

        # Clear old fields
        while self._fields_layout.count():
            child = self._fields_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Add field widgets
        for f in entry.get("fields", []):
            fw = FieldWidget(
                f["key"],
                f["value"],
                f.get("sensitive", False),
                f.get("field_type"),
            )
            fw.copy_requested.connect(self.field_copied)
            self._fields_layout.addWidget(fw)

        self._fields_layout.addStretch()

    def show_folder(self, node_id: str, vault):
        """Show folder summary when a folder is clicked."""
        self._current_entry_id = None
        self._empty_state.setVisible(False)
        self._header.setVisible(True)
        self._scroll.setVisible(True)

        entries = vault.list_entries(node_id)
        children = vault.list_nodes(node_id)

        # Get folder name from tree
        self._name_label.setText("Folder")
        self._tags_label.setVisible(False)
        self._meta_label.setText(f"{len(children)} subfolders  |  {len(entries)} entries")

        while self._fields_layout.count():
            child = self._fields_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Show entries as simple list
        for e in entries:
            row = QLabel(f"  {e['name']}")
            row.setStyleSheet(f"color: {COLORS['text']}; font-size: 13px; padding: 8px 16px; background: {COLORS['bg_card']}; border-radius: 6px;")
            self._fields_layout.addWidget(row)

        if not entries and not children:
            empty = QLabel("Empty folder. Right-click to add entries.")
            empty.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 13px; padding: 16px;")
            self._fields_layout.addWidget(empty)

        self._fields_layout.addStretch()

    def clear(self):
        self._current_entry_id = None
        self._empty_state.setVisible(True)
        self._header.setVisible(False)
        self._scroll.setVisible(False)
        while self._fields_layout.count():
            child = self._fields_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
