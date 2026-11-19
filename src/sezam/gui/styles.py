"""Global stylesheet for Sezam desktop GUI — consistent dark theme."""

COLORS = {
    "bg": "#111118",
    "bg_panel": "#1a1a24",
    "bg_card": "#22222e",
    "bg_input": "#2a2a38",
    "bg_hover": "#303044",
    "bg_selected": "#3d5af1",
    "accent": "#3d5af1",
    "accent_hover": "#5b73f5",
    "accent_dim": "#2a3fb0",
    "text": "#e8e8ef",
    "text_secondary": "#9898a8",
    "text_muted": "#5a5a6a",
    "border": "#33333f",
    "success": "#34d399",
    "error": "#f87171",
    "warning": "#fbbf24",
    "sensitive": "#f97316",
}

GLOBAL_STYLE = f"""
QMainWindow {{
    background: {COLORS['bg']};
}}

QWidget {{
    color: {COLORS['text']};
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
    font-size: 13px;
}}

/* Tree */
QTreeWidget {{
    background: {COLORS['bg_panel']};
    border: none;
    outline: none;
    font-size: 13px;
    padding: 4px;
}}
QTreeWidget::item {{
    padding: 6px 10px;
    border-radius: 6px;
    margin: 1px 4px;
}}
QTreeWidget::item:hover {{
    background: {COLORS['bg_hover']};
}}
QTreeWidget::item:selected {{
    background: {COLORS['bg_selected']};
    color: white;
}}
QTreeWidget::branch {{
    background: {COLORS['bg_panel']};
}}

/* Buttons */
QPushButton {{
    background: {COLORS['bg_card']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13px;
    min-height: 20px;
}}
QPushButton:hover {{
    background: {COLORS['bg_hover']};
    border-color: {COLORS['accent']};
}}
QPushButton:pressed {{
    background: {COLORS['accent_dim']};
}}

/* Accent button */
QPushButton[cssClass="accent"] {{
    background: {COLORS['accent']};
    border: none;
    color: white;
    font-weight: 600;
}}
QPushButton[cssClass="accent"]:hover {{
    background: {COLORS['accent_hover']};
}}

/* Inputs */
QLineEdit {{
    background: {COLORS['bg_input']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 10px 14px;
    min-height: 16px;
    color: {COLORS['text']};
    font-size: 14px;
    selection-background-color: {COLORS['accent']};
}}
QLineEdit:focus {{
    border-color: {COLORS['accent']};
}}

/* Scrollbars */
QScrollBar:vertical {{
    background: {COLORS['bg_panel']};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {COLORS['border']};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {COLORS['text_muted']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar:horizontal {{
    height: 0px;
}}

/* Splitter */
QSplitter::handle {{
    background: {COLORS['border']};
    width: 1px;
}}

/* StatusBar */
QStatusBar {{
    background: {COLORS['bg']};
    color: {COLORS['text_muted']};
    font-size: 12px;
    border-top: 1px solid {COLORS['border']};
    padding: 2px 8px;
}}

/* ComboBox */
QComboBox {{
    background: {COLORS['bg_input']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px 12px;
    color: {COLORS['text']};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    color: {COLORS['text']};
    selection-background-color: {COLORS['accent']};
}}

/* CheckBox */
QCheckBox {{
    spacing: 6px;
    color: {COLORS['text_secondary']};
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    background: {COLORS['bg_input']};
}}
QCheckBox::indicator:checked {{
    background: {COLORS['accent']};
    border-color: {COLORS['accent']};
}}

/* SpinBox */
QSpinBox {{
    background: {COLORS['bg_input']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px;
    color: {COLORS['text']};
}}

/* MessageBox */
QMessageBox {{
    background: {COLORS['bg_panel']};
}}
QMessageBox QLabel {{
    color: {COLORS['text']};
}}

/* Menu */
QMenu {{
    background: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{
    padding: 8px 24px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background: {COLORS['accent']};
    color: white;
}}
QMenu::separator {{
    height: 1px;
    background: {COLORS['border']};
    margin: 4px 8px;
}}

/* ProgressBar */
QProgressBar {{
    background: {COLORS['bg_input']};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
}}
QProgressBar::chunk {{
    background: {COLORS['accent']};
    border-radius: 3px;
}}

/* ToolTip */
QToolTip {{
    background: {COLORS['bg_card']};
    color: {COLORS['text']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    padding: 6px 10px;
}}

/* Dialog */
QDialog {{
    background: {COLORS['bg_panel']};
}}

/* Label */
QLabel {{
    color: {COLORS['text']};
}}

/* FormLayout labels */
QFormLayout QLabel {{
    color: {COLORS['text_secondary']};
}}

/* ScrollArea */
QScrollArea {{
    background: transparent;
    border: none;
}}
"""
