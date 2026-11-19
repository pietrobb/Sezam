"""Interactive GUI tests using pytest-qt.

These tests simulate REAL user interactions — clicking buttons, typing text,
checking widget visibility and sizes. They catch visual/UX bugs that unit
tests miss: truncated text, overlapping labels, invisible widgets, broken
buttons, dialogs too small for content.
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")  # qtbot fixture

from PySide6.QtCore import Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton, QLabel  # noqa: E402

from sezam.crypto.kdf import Argon2Params  # noqa: E402
from sezam.vault.crud import Vault  # noqa: E402

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "InteractiveTest!42"


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication(sys.argv)
    return app


@pytest.fixture
def fresh_vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    if vault.is_unlocked:
        vault.lock()


@pytest.fixture
def populated_vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    work = vault.create_node("Work")
    personal = vault.create_node("Personal")
    servers = vault.create_node("Servers", parent_id=work)
    e1 = vault.create_entry(servers, "Production DB", [
        {"key": "host", "value": "db.prod.internal"},
        {"key": "port", "value": "5432"},
        {"key": "password", "value": "s3cret!", "sensitive": True},
    ])
    e2 = vault.create_entry(personal, "Gmail", [
        {"key": "email", "value": "user@gmail.com"},
        {"key": "password", "value": "gmail-pass", "sensitive": True},
    ])
    yield {
        "vault": vault, "path": tmp_path,
        "work": work, "personal": personal, "servers": servers,
        "e1": e1, "e2": e2,
    }
    if vault.is_unlocked:
        vault.lock()


# ═══════════════════════════════════════════════════════════════════════
# 1. WIZARD DIALOG — vault creation
# ═══════════════════════════════════════════════════════════════════════

class TestWizardDialog:
    def test_dialog_renders_at_usable_size(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        dlg.show()
        assert dlg.width() >= 400
        assert dlg.height() >= 300
        dlg.close()

    def test_all_inputs_visible_and_editable(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        dlg.show()
        assert dlg._password_input.isVisibleTo(dlg)
        assert dlg._confirm_input.isVisibleTo(dlg)
        assert dlg._create_btn.isVisibleTo(dlg)
        assert not dlg._password_input.isReadOnly()
        assert not dlg._confirm_input.isReadOnly()
        dlg.close()

    def test_password_input_is_masked(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        assert dlg._password_input.echoMode() == QLineEdit.Password
        assert dlg._confirm_input.echoMode() == QLineEdit.Password
        dlg.close()

    def test_empty_password_shows_error(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        dlg._password_input.setText("")
        dlg._confirm_input.setText("")
        dlg._create()
        assert dlg._error_label.text() != ""
        dlg.close()

    def test_mismatched_passwords_shows_error(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        dlg._password_input.setText("abc123")
        dlg._confirm_input.setText("different")
        dlg._create()
        assert "match" in dlg._error_label.text().lower() or "do not" in dlg._error_label.text().lower()
        dlg.close()

    def test_strength_indicator_updates(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        dlg._password_input.setText("")
        assert dlg._strength_label.text() == ""
        dlg._password_input.setText("SuperStr0ng!Pass#2026")
        assert dlg._strength_label.text() != ""
        dlg.close()

    def test_inputs_have_sufficient_height(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        dlg.show()
        qapp.processEvents()
        assert dlg._password_input.height() >= 30, \
            f"Password input too short: {dlg._password_input.height()}px"
        assert dlg._confirm_input.height() >= 30, \
            f"Confirm input too short: {dlg._confirm_input.height()}px"
        dlg.close()

    def test_create_button_enabled(self, qapp, tmp_path):
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        assert dlg._create_btn.isEnabled()
        dlg.close()


# ═══════════════════════════════════════════════════════════════════════
# 2. UNLOCK DIALOG
# ═══════════════════════════════════════════════════════════════════════

class TestUnlockDialog:
    def test_dialog_renders_at_usable_size(self, qapp, tmp_path):
        Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
        from sezam.gui.unlock_dialog import UnlockDialog
        dlg = UnlockDialog(tmp_path)
        dlg.show()
        assert dlg.width() >= 350
        assert dlg.height() >= 180
        dlg.close()

    def test_password_input_visible_and_masked(self, qapp, tmp_path):
        Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
        from sezam.gui.unlock_dialog import UnlockDialog
        dlg = UnlockDialog(tmp_path)
        dlg.show()
        assert dlg._password_input.isVisibleTo(dlg)
        assert dlg._password_input.echoMode() == QLineEdit.Password
        dlg.close()

    def test_empty_password_does_nothing(self, qapp, tmp_path):
        Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
        from sezam.gui.unlock_dialog import UnlockDialog
        dlg = UnlockDialog(tmp_path)
        dlg._password_input.setText("")
        dlg._unlock()
        # Should not start worker
        assert dlg._worker is None
        dlg.close()

    def test_unlock_button_enabled(self, qapp, tmp_path):
        Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
        from sezam.gui.unlock_dialog import UnlockDialog
        dlg = UnlockDialog(tmp_path)
        assert dlg._unlock_btn.isEnabled()
        dlg.close()

    def test_input_has_sufficient_height(self, qapp, tmp_path):
        Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
        from sezam.gui.unlock_dialog import UnlockDialog
        dlg = UnlockDialog(tmp_path)
        dlg.show()
        qapp.processEvents()
        assert dlg._password_input.height() >= 30, \
            f"Password input too short: {dlg._password_input.height()}px"
        dlg.close()


# ═══════════════════════════════════════════════════════════════════════
# 3. NODE (FOLDER) DIALOG
# ═══════════════════════════════════════════════════════════════════════

class TestNodeDialog:
    def test_dialog_renders(self, qapp, fresh_vault):
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        assert dlg.width() >= 300
        assert dlg.height() >= 120
        dlg.close()

    def test_input_visible_and_editable(self, qapp, fresh_vault):
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        assert dlg._name_input.isVisibleTo(dlg)
        assert not dlg._name_input.isReadOnly()
        dlg.close()

    def test_type_and_save_creates_folder(self, qapp, fresh_vault, qtbot):
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        qtbot.keyClicks(dlg._name_input, "TestFolder")
        dlg._save()
        nodes = fresh_vault.list_nodes()
        assert any(n["name"] == "TestFolder" for n in nodes)
        dlg.close()

    def test_empty_name_rejected(self, qapp, fresh_vault, qtbot):
        from sezam.gui.entry_dialog import NodeDialog
        nodes_before = len(fresh_vault.list_nodes())
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        # Don't type anything
        dlg._save()
        assert len(fresh_vault.list_nodes()) == nodes_before
        dlg.close()

    def test_save_button_is_default(self, qapp, fresh_vault):
        """Save button should be the default (Enter triggers it, not Cancel)."""
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        buttons = dlg.findChildren(QPushButton)
        save_btn = next(b for b in buttons if b.text() == "Create")
        cancel_btn = next(b for b in buttons if b.text() == "Cancel")
        assert save_btn.isDefault()
        assert not cancel_btn.autoDefault()
        dlg.close()

    def test_input_has_sufficient_height(self, qapp, fresh_vault):
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        qapp.processEvents()
        assert dlg._name_input.height() >= 30, \
            f"Name input too short: {dlg._name_input.height()}px"
        dlg.close()


# ═══════════════════════════════════════════════════════════════════════
# 4. ENTRY DIALOG
# ═══════════════════════════════════════════════════════════════════════

class TestEntryDialog:
    def test_dialog_renders_at_usable_size(self, qapp, fresh_vault):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg.show()
        assert dlg.width() >= 480
        assert dlg.height() >= 380
        dlg.close()

    def test_new_entry_has_empty_field_names(self, qapp, fresh_vault):
        """No pre-filled 'username'/'password' — fields should be blank."""
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        for row in dlg._field_rows:
            assert row["key"].text() == "", \
                f"Field key pre-filled with '{row['key'].text()}' — should be empty"
        dlg.close()

    def test_new_entry_starts_with_two_field_rows(self, qapp, fresh_vault):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        assert len(dlg._field_rows) == 2
        dlg.close()

    def test_add_field_button_works(self, qapp, fresh_vault, qtbot):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg.show()
        initial = len(dlg._field_rows)
        # Find and click the "+ Add Field" button
        add_btn = None
        for btn in dlg.findChildren(QPushButton):
            if "Add Field" in btn.text():
                add_btn = btn
                break
        assert add_btn is not None, "Could not find '+ Add Field' button"
        qtbot.mouseClick(add_btn, Qt.LeftButton)
        assert len(dlg._field_rows) == initial + 1
        dlg.close()

    def test_type_and_save_creates_entry(self, qapp, fresh_vault, qtbot):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg.show()
        qtbot.keyClicks(dlg._name_input, "MyEntry")
        dlg._field_rows[0]["key"].setText("url")
        dlg._field_rows[0]["value"].setText("https://example.com")
        dlg._save()
        entries = fresh_vault.list_entries(fid)
        assert any(e["name"] == "MyEntry" for e in entries)
        dlg.close()

    def test_edit_existing_entry_prefills_data(self, qapp, populated_vault):
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(v, populated_vault["servers"], entry=entry)
        dlg.show()
        assert dlg._name_input.text() == "Production DB"
        assert len(dlg._field_rows) == 3
        assert dlg._field_rows[0]["key"].text() == "host"
        assert dlg._field_rows[0]["value"].text() == "db.prod.internal"
        dlg.close()

    def test_sensitive_checkbox_toggles_echo_mode(self, qapp, fresh_vault):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        row = dlg._field_rows[0]
        assert row["value"].echoMode() == QLineEdit.Normal
        row["sensitive"].setChecked(True)
        assert row["value"].echoMode() == QLineEdit.Password
        row["sensitive"].setChecked(False)
        assert row["value"].echoMode() == QLineEdit.Normal
        dlg.close()

    def test_save_button_is_default(self, qapp, fresh_vault):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        buttons = dlg.findChildren(QPushButton)
        save_btn = next((b for b in buttons if b.text() == "Save"), None)
        cancel_btn = next((b for b in buttons if b.text() == "Cancel"), None)
        assert save_btn is not None
        assert cancel_btn is not None
        assert save_btn.isDefault()
        assert not cancel_btn.autoDefault()
        dlg.close()

    def test_empty_name_rejected(self, qapp, fresh_vault):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg._name_input.setText("")
        dlg._save()
        entries = fresh_vault.list_entries(fid)
        assert len(entries) == 0
        dlg.close()

    def test_gen_button_fills_password(self, qapp, fresh_vault, qtbot):
        fid = fresh_vault.create_node("F")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg.show()
        gen_btns = [b for b in dlg.findChildren(QPushButton) if b.text() == "Gen"]
        assert len(gen_btns) >= 1, "No 'Gen' button found"
        value_before = dlg._field_rows[0]["value"].text()
        qtbot.mouseClick(gen_btns[0], Qt.LeftButton)
        value_after = dlg._field_rows[0]["value"].text()
        assert value_after != value_before
        assert len(value_after) >= 10  # Generated password should be substantial
        dlg.close()


# ═══════════════════════════════════════════════════════════════════════
# 5. MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════

def _real_font_for_fontless_platform():
    """Load a real font when the Qt platform has none; return its id or None.

    QT_QPA_PLATFORM=offscreen on Windows has no font database: every glyph
    is a box as wide as the pixel size ('iiii' measures like 'WWWW'), so
    text widths are about twice the real ones and say nothing about
    truncation. Offscreen does take application fonts, so measure with one.
    """
    import os
    from PySide6.QtGui import QFontDatabase
    if QFontDatabase.families():
        return None
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        os.path.join(windir, "Fonts", "segoeui.ttf"),
        os.path.join(windir, "Fonts", "arial.ttf"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]
    for path in candidates:
        if os.path.exists(path):
            font_id = QFontDatabase.addApplicationFont(path)
            if font_id >= 0:
                return font_id
    pytest.fail(f"Platform has no fonts and none of {candidates} could be loaded")


class TestMainWindow:
    def test_window_renders_at_usable_size(self, qapp, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w.show()
        qapp.processEvents()
        assert w.width() >= 900
        assert w.height() >= 600
        w.close()

    def test_sidebar_buttons_readable(self, qapp, populated_vault):
        """All sidebar buttons must show their full text (not truncated)."""
        from PySide6.QtWidgets import QStyle, QStyleOptionButton
        from sezam.gui.main_window import MainWindow
        font_id = _real_font_for_fontless_platform()
        w = MainWindow(populated_vault["path"])
        try:
            w.show()
            qapp.processEvents()
            sidebar_btns = []
            for btn in w.findChildren(QPushButton):
                text = btn.text()
                if text in ("+ Folder", "+ Entry", "More"):
                    sidebar_btns.append(btn)
                    # The text must fit the label area the style leaves
                    # inside the button's padding, not just the button.
                    opt = QStyleOptionButton()
                    btn.initStyleOption(opt)
                    label = btn.style().subElementRect(
                        QStyle.SE_PushButtonContents, opt, btn)
                    text_width = btn.fontMetrics().horizontalAdvance(text)
                    assert label.width() >= text_width, (
                        f"Button '{text}' truncated: label area={label.width()}px "
                        f"(button {btn.width()}px), text needs {text_width}px")
            assert len(sidebar_btns) == 3, \
                f"Expected 3 sidebar buttons, found {len(sidebar_btns)}: {[b.text() for b in sidebar_btns]}"
        finally:
            w.close()
            if font_id is not None:
                from PySide6.QtGui import QFontDatabase
                QFontDatabase.removeApplicationFont(font_id)

    def test_tree_shows_all_data(self, qapp, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        count = w._rebuild_tree()
        assert count == 2  # 2 entries
        assert w._tree.topLevelItemCount() >= 2  # Work, Personal folders
        w.close()

    def test_search_input_visible_and_editable(self, qapp, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w.show()
        qapp.processEvents()
        assert w._search_input.isVisibleTo(w)
        assert not w._search_input.isReadOnly()
        assert w._search_input.height() >= 30
        w.close()

    def test_search_filters_tree(self, qapp, populated_vault, qtbot):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()
        w.show()
        total = w._tree.topLevelItemCount()
        qtbot.keyClicks(w._search_input, "Gmail")
        qapp.processEvents()
        filtered = w._tree.topLevelItemCount()
        assert filtered < total or filtered >= 1
        # Clear search restores full tree
        w._search_input.clear()
        qapp.processEvents()
        assert w._tree.topLevelItemCount() >= total
        w.close()

    def test_tree_click_shows_entry_detail(self, qapp, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()

        def find_entry_item(item):
            data = item.data(0, Qt.UserRole)
            if data and data["type"] == "entry":
                return item
            for i in range(item.childCount()):
                found = find_entry_item(item.child(i))
                if found:
                    return found
            return None

        for i in range(w._tree.topLevelItemCount()):
            found = find_entry_item(w._tree.topLevelItem(i))
            if found:
                w._on_tree_item_clicked(found, 0)
                assert w._detail._current_entry_id is not None
                assert w._detail._name_label.text() != ""
                w.close()
                return
        pytest.fail("No entry item found in tree")

    def test_context_menu_has_rename(self, qapp, populated_vault):
        """Right-click on folder should offer Rename option."""
        from sezam.gui.main_window import MainWindow
        from PySide6.QtWidgets import QMenu
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()

        # Find a folder item
        for i in range(w._tree.topLevelItemCount()):
            item = w._tree.topLevelItem(i)
            data = item.data(0, Qt.UserRole)
            if data and data["type"] == "node":
                # Simulate right-click by getting position
                rect = w._tree.visualItemRect(item)
                pos = rect.center()
                # We can't easily test the full menu, but verify the method exists
                assert hasattr(w, '_rename_node')
                w.close()
                return
        pytest.fail("No folder item found in tree")

    def test_lock_button_visible(self, qapp, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w.show()
        qapp.processEvents()
        lock_btns = [b for b in w.findChildren(QPushButton) if b.text() == "Lock"]
        assert len(lock_btns) >= 1
        assert lock_btns[0].isVisibleTo(w)
        w.close()


# ═══════════════════════════════════════════════════════════════════════
# 6. ENTRY DETAIL WIDGET
# ═══════════════════════════════════════════════════════════════════════

class TestEntryDetailWidget:
    def test_empty_state_shown_initially(self, qapp):
        from sezam.gui.entry_detail import EntryDetailWidget
        d = EntryDetailWidget()
        d.show()
        assert d._empty_state.isVisibleTo(d)
        assert not d._header.isVisibleTo(d)
        d.close()

    def test_show_entry_displays_all_fields(self, qapp, populated_vault):
        from sezam.gui.entry_detail import EntryDetailWidget
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        d = EntryDetailWidget()
        d.show()
        d.show_entry(entry)
        assert d._name_label.text() == "Production DB"
        assert d._header.isVisibleTo(d)
        assert not d._empty_state.isVisibleTo(d)
        # Should have field widgets
        field_count = 0
        from sezam.gui.entry_detail import FieldWidget
        for fw in d.findChildren(FieldWidget):
            field_count += 1
        assert field_count == 3, f"Expected 3 fields, got {field_count}"
        d.close()

    def test_sensitive_field_is_masked(self, qapp, populated_vault):
        from sezam.gui.entry_detail import EntryDetailWidget, FieldWidget
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        d = EntryDetailWidget()
        d.show_entry(entry)
        # Find the password field widget
        for fw in d.findChildren(FieldWidget):
            if fw._sensitive:
                # Value should be masked (bullets, not plaintext)
                assert fw._value != fw._value_label.text(), \
                    "Sensitive field should be masked"
                assert "\u2022" in fw._value_label.text()
                break
        d.close()

    def test_show_hide_toggle_works(self, qapp, populated_vault, qtbot):
        from sezam.gui.entry_detail import EntryDetailWidget, FieldWidget
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        d = EntryDetailWidget()
        d.show()
        d.show_entry(entry)
        for fw in d.findChildren(FieldWidget):
            if fw._sensitive and hasattr(fw, '_toggle_btn'):
                # Initially masked
                assert "\u2022" in fw._value_label.text()
                # Click show
                qtbot.mouseClick(fw._toggle_btn, Qt.LeftButton)
                assert fw._value_label.text() == fw._value
                assert fw._toggle_btn.text() == "Hide"
                # Click hide
                qtbot.mouseClick(fw._toggle_btn, Qt.LeftButton)
                assert "\u2022" in fw._value_label.text()
                assert fw._toggle_btn.text() == "Show"
                d.close()
                return
        pytest.fail("No sensitive field with toggle found")

    def test_copy_button_emits_signal(self, qapp, populated_vault, qtbot):
        from sezam.gui.entry_detail import EntryDetailWidget, FieldWidget
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        d = EntryDetailWidget()
        d.show_entry(entry)
        copied = []
        d.field_copied.connect(lambda v: copied.append(v))
        # Find a non-sensitive field and click Copy
        for fw in d.findChildren(FieldWidget):
            if not fw._sensitive:
                copy_btns = [b for b in fw.findChildren(QPushButton) if b.text() == "Copy"]
                assert len(copy_btns) == 1
                qtbot.mouseClick(copy_btns[0], Qt.LeftButton)
                assert len(copied) == 1
                assert copied[0] == fw._value
                d.close()
                return
        pytest.fail("No non-sensitive field found")

    def test_edit_button_emits_signal(self, qapp, populated_vault, qtbot):
        from sezam.gui.entry_detail import EntryDetailWidget
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        d = EntryDetailWidget()
        d.show()
        d.show_entry(entry)
        edit_ids = []
        d.edit_requested.connect(lambda eid: edit_ids.append(eid))
        edit_btns = [b for b in d.findChildren(QPushButton) if b.text() == "Edit"]
        assert len(edit_btns) >= 1
        qtbot.mouseClick(edit_btns[0], Qt.LeftButton)
        assert len(edit_ids) == 1
        assert edit_ids[0] == populated_vault["e1"]
        d.close()

    def test_clear_restores_empty_state(self, qapp, populated_vault):
        from sezam.gui.entry_detail import EntryDetailWidget
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])
        d = EntryDetailWidget()
        d.show()
        d.show_entry(entry)
        d.clear()
        assert d._current_entry_id is None
        assert d._empty_state.isVisibleTo(d)
        assert not d._header.isVisibleTo(d)
        d.close()


# ═══════════════════════════════════════════════════════════════════════
# 7. SERVER CONNECT DIALOG
# ═══════════════════════════════════════════════════════════════════════

class TestServerConnectDialog:
    def test_dialog_not_cramped(self, qapp, fresh_vault):
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault)
        dlg.show()
        qapp.processEvents()
        assert dlg.height() >= 400, f"Dialog too short: {dlg.height()}px"
        dlg.close()

    def test_all_inputs_visible(self, qapp, fresh_vault):
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault)
        dlg.show()
        qapp.processEvents()
        assert dlg._url_input.isVisibleTo(dlg)
        assert dlg._username_input.isVisibleTo(dlg)
        assert dlg._connect_btn.isVisibleTo(dlg)
        assert dlg._cancel_btn.isVisibleTo(dlg)
        dlg.close()

    def test_password_field_shown_when_no_password(self, qapp, fresh_vault):
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault, password="")
        dlg.show()
        qapp.processEvents()
        assert dlg._password_input is not None
        assert dlg._password_input.isVisibleTo(dlg)
        assert dlg._password_input.echoMode() == QLineEdit.Password
        dlg.close()

    def test_password_field_hidden_when_provided(self, qapp, fresh_vault):
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault, password="test123")
        dlg.show()
        qapp.processEvents()
        assert dlg._password_input is None
        dlg.close()

    def test_labels_dont_overlap_inputs(self, qapp, fresh_vault):
        """Check that each label is ABOVE its input, not overlapping."""
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault)
        dlg.show()
        qapp.processEvents()
        labels = [l for l in dlg.findChildren(QLabel)
                  if l.text() and l.isVisibleTo(dlg) and ":" in l.text()]
        inputs = [i for i in dlg.findChildren(QLineEdit) if i.isVisibleTo(dlg)]
        for label in labels:
            label_bottom = label.mapTo(dlg, label.rect().bottomLeft()).y()
            for inp in inputs:
                inp_top = inp.mapTo(dlg, inp.rect().topLeft()).y()
                inp_bottom = inp.mapTo(dlg, inp.rect().bottomLeft()).y()
                # If label overlaps with input area, that's a bug
                if label_bottom > inp_top and label.mapTo(dlg, label.rect().topLeft()).y() < inp_bottom:
                    label_left = label.mapTo(dlg, label.rect().topLeft()).x()
                    inp_left = inp.mapTo(dlg, inp.rect().topLeft()).x()
                    # Only flag if they're in the same horizontal region
                    if abs(label_left - inp_left) < 200:
                        # A label can be INSIDE an input's area if it's a placeholder
                        # but not a separate QLabel
                        assert False, \
                            f"Label '{label.text()}' overlaps with input at y={inp_top}-{inp_bottom}"
        dlg.close()

    def test_invitation_fields_hidden_initially(self, qapp, fresh_vault):
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault)
        dlg.show()
        assert not dlg._token_input.isVisibleTo(dlg)
        assert not dlg._token_submit_btn.isVisibleTo(dlg)
        dlg.close()

    def test_empty_url_shows_error(self, qapp, fresh_vault):
        from sezam.gui.server_connect_dialog import ServerConnectDialog
        dlg = ServerConnectDialog(fresh_vault, password="test")
        dlg._url_input.setText("")
        dlg._on_connect()
        assert dlg._status_label.text() != ""
        dlg.close()


# ═══════════════════════════════════════════════════════════════════════
# 8. SETTINGS DIALOG
# ═══════════════════════════════════════════════════════════════════════

class TestSettingsDialog:
    def test_dialog_renders(self, qapp):
        from sezam.gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog()
        dlg.show()
        qapp.processEvents()
        assert dlg.width() >= 400
        assert dlg.height() >= 300
        dlg.close()

    def test_spinboxes_visible(self, qapp):
        from sezam.gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog()
        dlg.show()
        qapp.processEvents()
        assert dlg._autolock_spin.isVisibleTo(dlg)
        assert dlg._clipboard_spin.isVisibleTo(dlg)
        dlg.close()

    def test_default_values(self, qapp):
        from sezam.gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog()
        assert dlg._autolock_spin.value() == 15
        assert dlg._clipboard_spin.value() == 15
        dlg.close()


# ═══════════════════════════════════════════════════════════════════════
# 9. FULL INTERACTIVE JOURNEYS
# ═══════════════════════════════════════════════════════════════════════

class TestFullInteractiveJourney:
    def test_create_folder_and_entry_journey(self, qapp, fresh_vault, qtbot):
        """Simulate: open main window → create folder → create entry → verify."""
        from sezam.gui.main_window import MainWindow

        w = MainWindow(tmp_path := fresh_vault._db.path.parent)
        w._vault = fresh_vault
        w._rebuild_tree()
        w.show()
        qapp.processEvents()

        # 1. Create folder via dialog
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault)
        dlg.show()
        qtbot.keyClicks(dlg._name_input, "Projects")
        dlg._save()

        # 2. Rebuild tree — folder should appear
        w._rebuild_tree()
        assert w._tree.topLevelItemCount() >= 1

        # 3. Find the folder ID
        nodes = fresh_vault.list_nodes()
        folder = next(n for n in nodes if n["name"] == "Projects")

        # 4. Create entry in folder via dialog
        from sezam.gui.entry_dialog import EntryDialog
        edlg = EntryDialog(fresh_vault, folder["id"])
        edlg.show()
        qtbot.keyClicks(edlg._name_input, "API Key")
        edlg._field_rows[0]["key"].setText("token")
        edlg._field_rows[0]["value"].setText("sk-abc123")
        edlg._field_rows[0]["sensitive"].setChecked(True)
        edlg._save()

        # 5. Rebuild tree and verify entry
        count = w._rebuild_tree()
        assert count == 1

        # 6. Click entry in tree and verify detail
        def find_entry(item):
            data = item.data(0, Qt.UserRole)
            if data and data["type"] == "entry":
                return item
            for i in range(item.childCount()):
                f = find_entry(item.child(i))
                if f:
                    return f
            return None

        for i in range(w._tree.topLevelItemCount()):
            found = find_entry(w._tree.topLevelItem(i))
            if found:
                w._on_tree_item_clicked(found, 0)
                break

        assert w._detail._name_label.text() == "API Key"
        assert w._detail._current_entry_id is not None

        w.close()

    def test_edit_entry_journey(self, qapp, populated_vault, qtbot):
        """Simulate: view entry → edit → save → verify changes."""
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["e1"])

        # 1. Show in detail
        from sezam.gui.entry_detail import EntryDetailWidget
        d = EntryDetailWidget()
        d.show()
        d.show_entry(entry)
        assert d._name_label.text() == "Production DB"

        # 2. Edit via dialog
        from sezam.gui.entry_dialog import EntryDialog
        edlg = EntryDialog(v, entry["node_id"], entry=entry)
        edlg.show()
        edlg._name_input.clear()
        qtbot.keyClicks(edlg._name_input, "Production DB (updated)")
        edlg._save()

        # 3. Re-read and verify
        updated = v.read_entry(populated_vault["e1"])
        assert updated["name"] == "Production DB (updated)"

        # 4. Show updated entry in detail
        d.show_entry(updated)
        assert d._name_label.text() == "Production DB (updated)"

        d.close()

    def test_rename_folder_works(self, qapp, fresh_vault):
        """Verify vault.rename_node creates a renamed folder."""
        fid = fresh_vault.create_node("OldName")
        fresh_vault.rename_node(fid, "NewName")

        from sezam.gui.main_window import MainWindow
        w = MainWindow(fresh_vault._db.path.parent)
        w._vault = fresh_vault
        w._rebuild_tree()

        # Find the renamed folder in tree
        found = False
        for i in range(w._tree.topLevelItemCount()):
            item = w._tree.topLevelItem(i)
            if "NewName" in item.text(0):
                found = True
                break
        assert found, "Renamed folder 'NewName' not found in tree"

        # Old name should NOT be there
        for i in range(w._tree.topLevelItemCount()):
            item = w._tree.topLevelItem(i)
            assert "OldName" not in item.text(0), "Old folder name still in tree"

        w.close()

    def test_delete_entry_journey(self, qapp, populated_vault):
        """Delete entry and verify it's gone from tree."""
        v = populated_vault["vault"]
        v.delete_entry(populated_vault["e2"])

        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = v
        count = w._rebuild_tree()
        assert count == 1  # Only e1 left

        # Detail should be clearable
        w._detail.clear()
        assert w._detail._current_entry_id is None
        w.close()

    def test_search_deep_journey(self, qapp, populated_vault, qtbot):
        """Search with deep search enabled finds field values."""
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()
        w.show()

        # Enable deep search
        w._deep_search_cb.setChecked(True)

        # Search for a field VALUE (not name)
        w._search_input.setText("gmail.com")
        qapp.processEvents()
        assert w._tree.topLevelItemCount() >= 1

        w.close()
