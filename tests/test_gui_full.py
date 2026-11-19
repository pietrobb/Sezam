"""Comprehensive GUI + vault integration test suite."""

import os
import shutil
import sys
from pathlib import Path

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault
from sezam.password import generate_password, generate_passphrase, estimate_strength

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
TEST_PASSWORD = "TestHeslo123!"


@pytest.fixture
def vault_env(tmp_path):
    vault = Vault.create(tmp_path, TEST_PASSWORD, FAST_PARAMS)
    # Populate with data
    servers = vault.create_node("Servers")
    hetzner = vault.create_node("Hetzner", parent_id=servers)
    ssh_id = vault.create_entry(hetzner, "SSH Root", [
        {"key": "host", "value": "1.2.3.4"},
        {"key": "username", "value": "root"},
        {"key": "password", "value": "secret!", "sensitive": True},
    ], tags=["ssh", "production"])
    clients = vault.create_node("Clients")
    client_id = vault.create_entry(clients, "Auto-Moto", [
        {"key": "url", "value": "https://example.com"},
        {"key": "password", "value": "klient123", "sensitive": True},
    ])
    yield {
        "vault": vault,
        "path": tmp_path,
        "servers_id": servers,
        "hetzner_id": hetzner,
        "ssh_id": ssh_id,
        "clients_id": clients,
        "client_id": client_id,
    }
    vault.lock()


# === FOLDER OPERATIONS ===

class TestFolderOps:
    def test_create_folder_at_root(self, vault_env):
        v = vault_env["vault"]
        fid = v.create_node("NewFolder")
        nodes = v.list_nodes()
        assert any(n["name"] == "NewFolder" for n in nodes)

    def test_create_subfolder(self, vault_env):
        v = vault_env["vault"]
        sid = v.create_node("SubFolder", parent_id=vault_env["servers_id"])
        children = v.list_nodes(vault_env["servers_id"])
        assert any(n["name"] == "SubFolder" for n in children)

    def test_list_nodes_sorted(self, vault_env):
        v = vault_env["vault"]
        v.create_node("Zebra")
        v.create_node("Alpha")
        nodes = v.list_nodes()
        names = [n["name"] for n in nodes]
        assert names == sorted(names, key=str.lower)

    def test_delete_folder(self, vault_env):
        v = vault_env["vault"]
        fid = v.create_node("ToDelete")
        v.db.execute("UPDATE nodes SET is_deleted = 1 WHERE id = ?", (fid,))
        nodes = v.list_nodes()
        assert not any(n["name"] == "ToDelete" for n in nodes)


# === ENTRY OPERATIONS ===

class TestEntryOps:
    def test_create_entry(self, vault_env):
        v = vault_env["vault"]
        eid = v.create_entry(vault_env["clients_id"], "NewEntry", [
            {"key": "user", "value": "test"},
        ])
        assert eid
        entries = v.list_entries(vault_env["clients_id"])
        assert any(e["name"] == "NewEntry" for e in entries)

    def test_read_entry_fields(self, vault_env):
        v = vault_env["vault"]
        entry = v.read_entry(vault_env["ssh_id"])
        assert entry["name"] == "SSH Root"
        assert len(entry["fields"]) == 3
        assert entry["fields"][2]["sensitive"] is True
        assert entry["fields"][2]["value"] == "secret!"

    def test_update_entry_name(self, vault_env):
        v = vault_env["vault"]
        v.update_entry(vault_env["ssh_id"], name="SSH Root (updated)")
        entry = v.read_entry(vault_env["ssh_id"])
        assert entry["name"] == "SSH Root (updated)"

    def test_update_entry_fields(self, vault_env):
        v = vault_env["vault"]
        v.update_entry(vault_env["ssh_id"], fields=[
            {"key": "host", "value": "5.6.7.8"},
            {"key": "password", "value": "newpass", "sensitive": True},
        ])
        entry = v.read_entry(vault_env["ssh_id"])
        assert len(entry["fields"]) == 2
        assert entry["fields"][0]["value"] == "5.6.7.8"
        assert entry["version"] == 2

    def test_update_creates_history(self, vault_env):
        v = vault_env["vault"]
        v.update_entry(vault_env["ssh_id"], name="v2")
        rows = v.db.fetchall(
            "SELECT * FROM entry_history WHERE entry_id = ?", (vault_env["ssh_id"],)
        )
        assert len(rows) == 1

    def test_delete_entry(self, vault_env):
        v = vault_env["vault"]
        eid = v.create_entry(vault_env["clients_id"], "Temp", [{"key": "x", "value": "y"}])
        v.delete_entry(eid)
        entries = v.list_entries(vault_env["clients_id"])
        assert not any(e["id"] == eid for e in entries)

    def test_deleted_entry_not_readable_in_list(self, vault_env):
        v = vault_env["vault"]
        eid = v.create_entry(vault_env["clients_id"], "Ghost", [{"key": "x", "value": "y"}])
        entries_before = len(v.list_entries(vault_env["clients_id"]))
        v.delete_entry(eid)
        entries_after = len(v.list_entries(vault_env["clients_id"]))
        assert entries_after == entries_before - 1

    def test_entry_with_tags(self, vault_env):
        v = vault_env["vault"]
        entry = v.read_entry(vault_env["ssh_id"])
        assert "ssh" in entry["tags"]
        assert "production" in entry["tags"]

    def test_entry_with_tier(self, vault_env):
        v = vault_env["vault"]
        eid = v.create_entry(vault_env["clients_id"], "Tier2", [
            {"key": "x", "value": "y"}
        ], tier=2)
        entry = v.read_entry(eid)
        assert entry["tier"] == 2

    def test_get_field_value(self, vault_env):
        v = vault_env["vault"]
        assert v.get_field_value(vault_env["ssh_id"], "host") == "1.2.3.4"
        assert v.get_field_value(vault_env["ssh_id"], "password") == "secret!"
        assert v.get_field_value(vault_env["ssh_id"], "nonexistent") is None


# === SEARCH ===

class TestSearch:
    def test_search_by_name(self, vault_env):
        results = vault_env["vault"].search("SSH")
        assert len(results) >= 1
        assert any("SSH" in r["name"] for r in results)

    def test_search_by_field_key(self, vault_env):
        results = vault_env["vault"].search("password")
        assert len(results) >= 2  # both entries have password field

    def test_search_case_insensitive(self, vault_env):
        r1 = vault_env["vault"].search("ssh")
        r2 = vault_env["vault"].search("SSH")
        assert len(r1) == len(r2)

    def test_search_empty(self, vault_env):
        assert vault_env["vault"].search("") == []

    def test_search_no_results(self, vault_env):
        assert vault_env["vault"].search("zzzznonexistent") == []


# === PATH RESOLUTION ===

class TestPathResolution:
    def test_resolve_folder(self, vault_env):
        node_id, name = vault_env["vault"].resolve_path("Servers/Hetzner")
        assert node_id == vault_env["hetzner_id"]
        assert name is None

    def test_find_entry_by_path(self, vault_env):
        entry = vault_env["vault"].find_entry_by_path("Servers/Hetzner/SSH Root")
        assert entry is not None
        assert entry["fields"][0]["value"] == "1.2.3.4"

    def test_find_nonexistent(self, vault_env):
        entry = vault_env["vault"].find_entry_by_path("No/Such/Path")
        assert entry is None


# === LOCK / UNLOCK ===

class TestLockUnlock:
    def test_lock_and_reopen(self, vault_env):
        v = vault_env["vault"]
        v.lock()
        v2 = Vault(vault_env["path"])
        v2.unlock(TEST_PASSWORD)
        entry = v2.read_entry(vault_env["ssh_id"])
        assert entry["name"] == "SSH Root"
        vault_env["vault"] = v2  # replace for cleanup

    def test_wrong_password(self, vault_env):
        v = vault_env["vault"]
        v.lock()
        v2 = Vault(vault_env["path"])
        with pytest.raises(ValueError, match="Wrong master password"):
            v2.unlock("wrong!")
        # Re-open for cleanup
        v3 = Vault(vault_env["path"])
        v3.unlock(TEST_PASSWORD)
        vault_env["vault"] = v3

    def test_operations_while_locked(self, vault_env):
        v = vault_env["vault"]
        v.lock()
        from sezam.vault.crud import VaultLocked
        with pytest.raises(VaultLocked):
            v.list_nodes()
        # Re-open
        v2 = Vault(vault_env["path"])
        v2.unlock(TEST_PASSWORD)
        vault_env["vault"] = v2


# === CHANGE PASSWORD ===

class TestChangePassword:
    def test_change_password_works(self, vault_env):
        v = vault_env["vault"]
        v.change_password(TEST_PASSWORD, "NewPassword!")
        v.lock()
        # Old fails
        v2 = Vault(vault_env["path"])
        with pytest.raises(ValueError):
            v2.unlock(TEST_PASSWORD)
        # New works
        v3 = Vault(vault_env["path"])
        v3.unlock("NewPassword!")
        entry = v3.read_entry(vault_env["ssh_id"])
        assert entry["name"] == "SSH Root"
        vault_env["vault"] = v3


# === EXPORT SAFETY ===

class TestExportSafety:
    @pytest.mark.parametrize("fmt", ["csv", "bitwarden"])
    def test_noninteractive_plaintext_export_requires_explicit_flag(
        self, monkeypatch, tmp_path, fmt
    ):
        import click
        from sezam import cli

        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
        monkeypatch.setattr(
            cli,
            "_open_vault",
            lambda: pytest.fail("vault must not open before explicit confirmation"),
        )

        with pytest.raises(click.ClickException, match="--confirm-plaintext"):
            cli.export.callback(str(tmp_path / "export"), fmt, False)

    def test_explicit_flag_allows_noninteractive_plaintext_export(
        self, monkeypatch, tmp_path, vault_env
    ):
        from sezam import cli

        exported = []
        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
        monkeypatch.setattr(cli, "_open_vault", lambda: vault_env["vault"])
        monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault: "verified")
        monkeypatch.setattr(
            cli,
            "_export_csv",
            lambda vault, dest: exported.append((vault, dest)) or {"folders": 0, "entries": 0},
        )

        dest = str(tmp_path / "confirmed.csv")
        cli.export.callback(dest, "csv", True)

        assert exported == [(vault_env["vault"], dest)]


# === GUI DIALOGS ===

class TestGUIDialogs:
    @pytest.fixture(autouse=True)
    def setup_app(self):
        if not hasattr(TestGUIDialogs, "_app"):
            QApplication = pytest.importorskip("PySide6.QtWidgets").QApplication
            TestGUIDialogs._app = QApplication.instance() or QApplication(sys.argv)
        yield

    def test_node_dialog_create(self, vault_env):
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(vault_env["vault"], parent_id=None)
        dlg._name_input.setText("DialogFolder")
        dlg._save()
        assert dlg.result()
        nodes = vault_env["vault"].list_nodes()
        assert any(n["name"] == "DialogFolder" for n in nodes)

    def test_node_dialog_empty_rejected(self, vault_env):
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(vault_env["vault"], parent_id=None)
        dlg._name_input.setText("")
        dlg._save()
        assert not dlg.result()

    def test_entry_dialog_create(self, vault_env):
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(vault_env["vault"], vault_env["clients_id"])
        dlg._name_input.setText("DialogEntry")
        dlg._field_rows[0]["key"].setText("test_key")
        dlg._field_rows[0]["value"].setText("test_val")
        dlg._save()
        assert dlg.result()
        entries = vault_env["vault"].list_entries(vault_env["clients_id"])
        assert any(e["name"] == "DialogEntry" for e in entries)

    def test_entry_dialog_empty_rejected(self, vault_env):
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(vault_env["vault"], vault_env["clients_id"])
        dlg._name_input.setText("")
        dlg._save()
        assert not dlg.result()

    def test_field_widget_sensitive_masked(self, vault_env):
        from sezam.gui.entry_detail import FieldWidget
        fw = FieldWidget("pwd", "secret", sensitive=True)
        assert fw._value_label.text() != "secret"
        assert "\u2022" in fw._value_label.text()

    def test_field_widget_toggle(self, vault_env):
        from sezam.gui.entry_detail import FieldWidget
        fw = FieldWidget("pwd", "secret", sensitive=True)
        fw._toggle()
        assert fw._value_label.text() == "secret"
        fw._toggle()
        assert "\u2022" in fw._value_label.text()

    def test_field_widget_copy_signal(self, vault_env):
        from sezam.gui.entry_detail import FieldWidget
        copied = []
        fw = FieldWidget("user", "admin", sensitive=False)
        fw.copy_requested.connect(lambda v: copied.append(v))
        fw._do_copy()
        assert copied == ["admin"]

    def test_main_window_tree(self, vault_env):
        from sezam.gui.main_window import MainWindow
        from PySide6.QtCore import Qt
        w = MainWindow(vault_env["path"])
        w._vault = vault_env["vault"]
        count = w._rebuild_tree()
        assert count >= 2  # at least SSH Root + Auto-Moto
        assert w._tree.topLevelItemCount() > 0

    def test_main_window_search(self, vault_env):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(vault_env["path"])
        w._vault = vault_env["vault"]
        w._rebuild_tree()
        w._on_search("SSH")
        assert w._tree.topLevelItemCount() >= 1
        w._on_search("")
        assert w._tree.topLevelItemCount() > 1  # restored

    def test_share_view_poll_delivers_sanitized_tray_notification(self, vault_env):
        from sezam.gui.main_window import MainWindow

        class FakeClient:
            def poll_share_notifications(self):
                return [{
                    "id": "01NOTIFICATION0000000000000",
                    "share_id": "share-id-visible-to-owner",
                    "viewed_at": 123,
                    "viewer_ip_hmac": "must-not-be-shown",
                }]

        class FakeTray:
            def __init__(self):
                self.messages = []

            def showMessage(self, *args):
                self.messages.append(args)

        vault_env["vault"].db.set_meta("server_url", "https://sync.invalid")
        vault_env["vault"].db.set_meta("user_id", "OWNER000000000000000000001")
        w = MainWindow(vault_env["path"])
        w._vault = vault_env["vault"]
        w._notification_client = FakeClient()
        w._tray = FakeTray()

        w._poll_share_notifications()

        import time
        from PySide6.QtWidgets import QApplication

        deadline = time.monotonic() + 5
        while not w._tray.messages and time.monotonic() < deadline:
            QApplication.processEvents()
            time.sleep(0.01)
        assert len(w._tray.messages) == 1
        title, message, *_ = w._tray.messages[0]
        assert title == "Secure Share viewed"
        assert "share-id-vis..." in message
        assert "must-not-be-shown" not in message
        assert w._share_notification_timer.interval() == 60_000

    def test_gui_plaintext_export_rejection_creates_nothing(
        self, vault_env, monkeypatch
    ):
        from PySide6.QtWidgets import QMessageBox
        from sezam.gui import main_window

        w = main_window.MainWindow(vault_env["path"])
        w._vault = vault_env["vault"]
        monkeypatch.setattr(
            main_window.QInputDialog,
            "getItem",
            lambda *args: ("Plaintext CSV", True),
        )
        monkeypatch.setattr(
            main_window.QMessageBox,
            "warning",
            lambda *args: QMessageBox.No,
        )
        monkeypatch.setattr(
            main_window.QFileDialog,
            "getSaveFileName",
            lambda *args: pytest.fail("file picker must not open after rejection"),
        )

        w._show_export_dialog()

    def test_gui_plaintext_export_writes_selected_file(
        self, vault_env, monkeypatch, tmp_path
    ):
        from PySide6.QtWidgets import QMessageBox
        from sezam.gui import main_window

        dest = tmp_path / "vault.csv"
        w = main_window.MainWindow(vault_env["path"])
        w._vault = vault_env["vault"]
        monkeypatch.setattr(
            main_window.QInputDialog,
            "getItem",
            lambda *args: ("Plaintext CSV", True),
        )
        monkeypatch.setattr(
            main_window.QMessageBox,
            "warning",
            lambda *args: QMessageBox.Yes,
        )
        monkeypatch.setattr(
            main_window.QFileDialog,
            "getSaveFileName",
            lambda *args: (str(dest), "CSV Files (*.csv)"),
        )
        monkeypatch.setattr(main_window.QMessageBox, "information", lambda *args: None)

        w._show_export_dialog()

        exported = dest.read_text(encoding="utf-8")
        assert "field_value" in exported
        assert "secret!" in exported

    def test_detail_shows_entry(self, vault_env):
        from sezam.gui.entry_detail import EntryDetailWidget
        d = EntryDetailWidget()
        entry = vault_env["vault"].read_entry(vault_env["ssh_id"])
        d.show_entry(entry)
        assert d._name_label.text() == "SSH Root"
        assert d._current_entry_id == vault_env["ssh_id"]
        # _header.isVisible() requires parent widget to be shown;
        # verify the state flag instead
        assert not d._empty_state.isVisibleTo(d)

    def test_detail_clear(self, vault_env):
        from sezam.gui.entry_detail import EntryDetailWidget
        d = EntryDetailWidget()
        d.show()  # must be shown for visibility checks
        d.clear()
        assert d._current_entry_id is None
        assert d._empty_state.isVisibleTo(d)
        assert not d._header.isVisibleTo(d)

    def test_settings_dialog(self, vault_env):
        from sezam.gui.settings_dialog import SettingsDialog
        dlg = SettingsDialog()
        dlg.show()
        assert dlg.isVisible()
        dlg.close()

    def test_security_settings_persist_and_drive_runtime_timers(self, vault_env):
        from sezam.gui.main_window import MainWindow
        from sezam.gui.settings_dialog import SettingsDialog

        vault = vault_env["vault"]
        saved = []
        dialog = SettingsDialog(vault=vault)
        dialog.security_settings_saved.connect(
            lambda minutes, seconds: saved.append((minutes, seconds))
        )
        dialog._autolock_spin.setValue(7)
        dialog._clipboard_spin.setValue(23)
        dialog._save()

        assert saved == [(7, 23)]
        assert vault.db.get_meta("autolock_minutes") == "7"
        assert vault.db.get_meta("clipboard_clear_seconds") == "23"
        reopened = SettingsDialog(vault=vault)
        assert reopened._autolock_spin.value() == 7
        assert reopened._clipboard_spin.value() == 23

        window = MainWindow(vault_env["path"])
        window._vault = vault
        window._load_security_settings()
        assert window._autolock_timer.interval() == 7 * 60 * 1000
        window._on_field_copied("secret")
        assert window._clipboard_timer.interval() == 23 * 1000
        assert window._clipboard_remaining == 23
        assert "clearing in 23s" in window._statusbar_label.text()


# === PASSWORD GENERATOR ===

class TestPasswordGen:
    def test_default_length(self):
        assert len(generate_password()) == 20

    def test_custom_length(self):
        assert len(generate_password(32)) == 32

    def test_no_symbols(self):
        pwd = generate_password(20, symbols=False)
        special = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
        assert not any(c in special for c in pwd)

    def test_passphrase(self):
        pp = generate_passphrase(5)
        assert len(pp.split("-")) == 5

    def test_strength_strong(self):
        s = estimate_strength(generate_password(24))
        assert s["score"] >= 3

    def test_strength_weak(self):
        s = estimate_strength("abc")
        assert s["score"] <= 1


# === BACKUP / INTEGRITY ===

class TestBackup:
    def test_backup_creates_file(self, vault_env):
        dest = vault_env["path"] / "backup.db"
        vault_env["vault"].db.backup(dest)
        assert dest.exists()
        assert dest.stat().st_size > 0

    def test_integrity_check(self, vault_env):
        assert vault_env["vault"].db.integrity_check()
