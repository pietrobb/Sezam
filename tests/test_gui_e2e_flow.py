"""End-to-end GUI flow tests — simulates real user interactions.

Tests the FULL lifecycle that a desktop user would go through:
  1. Create vault (WizardDialog)
  2. Unlock vault (UnlockDialog)
  3. Create folders
  4. Create entries with fields
  5. Read/display entries
  6. Edit entries
  7. Delete entries
  8. Delete folders
  9. Move entries between folders
  10. Search (name + deep)
  11. Lock → re-unlock → verify data persistence
  12. Wrong password handling

Each test uses a fresh vault in tmp_path to avoid interference.
"""

import sys
from pathlib import Path

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault, VaultLocked

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "E2eTestHeslo!99"


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _qt_app():
    """Ensure QApplication exists (singleton, needed for any widget)."""
    QApplication = pytest.importorskip("PySide6.QtWidgets").QApplication
    app = QApplication.instance() or QApplication(sys.argv)
    yield app


@pytest.fixture
def fresh_vault(tmp_path):
    """Create a brand-new vault and return it unlocked."""
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    if vault.is_unlocked:
        vault.lock()


@pytest.fixture
def populated_vault(tmp_path):
    """Vault with folders and entries for testing reads/edits/deletes."""
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    servers = vault.create_node("Servers")
    hetzner = vault.create_node("Hetzner", parent_id=servers)
    ssh_id = vault.create_entry(hetzner, "SSH Root", [
        {"key": "host", "value": "1.2.3.4"},
        {"key": "username", "value": "root"},
        {"key": "password", "value": "s3cret!", "sensitive": True},
    ])
    clients = vault.create_node("Clients")
    gmail_id = vault.create_entry(clients, "Gmail", [
        {"key": "email", "value": "user@gmail.com"},
        {"key": "password", "value": "gmailpass", "sensitive": True},
    ])
    yield {
        "vault": vault,
        "path": tmp_path,
        "servers": servers,
        "hetzner": hetzner,
        "clients": clients,
        "ssh_id": ssh_id,
        "gmail_id": gmail_id,
    }
    if vault.is_unlocked:
        vault.lock()


# ── 1. Vault Creation ────────────────────────────────────────────────────


class TestVaultCreation:
    def test_create_new_vault(self, tmp_path):
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        assert vault.is_unlocked
        root_id = vault.db.get_meta("root_node_id")
        assert root_id is not None
        vault.lock()

    def test_create_vault_db_exists(self, tmp_path):
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        vault.lock()
        assert (tmp_path / "sezam.db").exists()

    def test_wizard_dialog_creates_vault(self, tmp_path):
        from PySide6.QtCore import QEventLoop, QTimer
        from sezam.gui.wizard_dialog import WizardDialog
        dlg = WizardDialog(tmp_path)
        # Simulate filling in password
        dlg._password_input.setText(PASSWORD)
        dlg._confirm_input.setText(PASSWORD)
        dlg._create()
        # Wait for the background worker to finish
        loop = QEventLoop()
        dlg._worker.finished.connect(loop.quit)
        QTimer.singleShot(30000, loop.quit)
        loop.exec()
        assert dlg.vault is not None
        assert dlg.vault.is_unlocked
        dlg.vault.lock()


# ── 2. Unlock ─────────────────────────────────────────────────────────────


class TestUnlock:
    def test_unlock_correct_password(self, tmp_path):
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        vault.lock()
        v2 = Vault(tmp_path)
        v2.unlock(PASSWORD)
        assert v2.is_unlocked
        v2.lock()

    def test_unlock_wrong_password(self, tmp_path):
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        vault.lock()
        v2 = Vault(tmp_path)
        with pytest.raises(ValueError, match="Wrong master password"):
            v2.unlock("wrong_password")

    def test_unlock_dialog_worker(self, tmp_path):
        """Test that UnlockWorker correctly unlocks in a thread."""
        from PySide6.QtCore import QEventLoop, QTimer
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        vault.lock()

        from sezam.gui.unlock_dialog import UnlockWorker
        results = []
        worker = UnlockWorker(tmp_path, PASSWORD)
        worker.finished.connect(lambda r: results.append(r))
        worker.start()
        # Process events so the signal is delivered
        loop = QEventLoop()
        worker.finished.connect(loop.quit)
        QTimer.singleShot(10000, loop.quit)  # timeout
        loop.exec()

        assert len(results) == 1
        assert isinstance(results[0], Vault)
        assert results[0].is_unlocked

        # Verify the vault can actually be used from main thread
        # (tests check_same_thread=False fix)
        v = results[0]
        nodes = v.list_nodes()
        assert isinstance(nodes, list)
        v.lock()


# ── 3. Folder (Node) Operations ──────────────────────────────────────────


class TestFolderOps:
    def test_create_folder_at_root(self, fresh_vault):
        fid = fresh_vault.create_node("MyFolder")
        assert fid
        nodes = fresh_vault.list_nodes()
        assert any(n["name"] == "MyFolder" for n in nodes)

    def test_create_subfolder(self, fresh_vault):
        parent = fresh_vault.create_node("Parent")
        child = fresh_vault.create_node("Child", parent_id=parent)
        children = fresh_vault.list_nodes(parent)
        assert any(n["name"] == "Child" for n in children)

    def test_create_nested_3_levels(self, fresh_vault):
        l1 = fresh_vault.create_node("L1")
        l2 = fresh_vault.create_node("L2", parent_id=l1)
        l3 = fresh_vault.create_node("L3", parent_id=l2)
        assert fresh_vault.list_nodes(l2)
        names = [n["name"] for n in fresh_vault.list_nodes(l2)]
        assert "L3" in names

    def test_delete_folder(self, fresh_vault):
        fid = fresh_vault.create_node("ToDelete")
        fresh_vault.db.execute(
            "UPDATE nodes SET is_deleted = 1 WHERE id = ?", (fid,)
        )
        nodes = fresh_vault.list_nodes()
        assert not any(n["name"] == "ToDelete" for n in nodes)

    def test_delete_folder_tombstones_subtree_with_versions_and_audit(
        self, tmp_path, monkeypatch
    ):
        from PySide6.QtWidgets import QMessageBox

        from sezam.gui.main_window import MainWindow
        from sezam.vault.audit import AuditLog

        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        parent = vault.create_node("Parent")
        child = vault.create_node("Child", parent_id=parent)
        parent_entry = vault.create_entry(parent, "Parent entry", [{"key": "k", "value": "v"}])
        child_entry = vault.create_entry(child, "Child entry", [{"key": "k", "value": "v"}])
        root_id = vault.db.get_meta("root_node_id")
        vault.lock()

        vault = Vault(tmp_path)
        vault.unlock(PASSWORD)
        signing_pk = vault.keypair.signing_pk
        window = MainWindow(tmp_path)
        window._vault = vault
        monkeypatch.setattr(
            QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes
        )

        window._delete_node(parent)

        nodes = vault.db.fetchall(
            "SELECT id, version, is_deleted, EXISTS (SELECT 1 FROM outbox o WHERE o.object_id = nodes.id) AS queued FROM nodes WHERE id IN (?, ?)",
            (parent, child),
        )
        entries = vault.db.fetchall(
            "SELECT id, version, is_deleted, EXISTS (SELECT 1 FROM outbox o WHERE o.object_id = entries.id) AS queued FROM entries WHERE id IN (?, ?)",
            (parent_entry, child_entry),
        )
        assert {
            (row["id"], row["version"], row["queued"], row["is_deleted"])
            for row in nodes
        } == {(parent, 2, 1, 1), (child, 2, 1, 1)}
        assert {
            (row["id"], row["version"], row["queued"], row["is_deleted"])
            for row in entries
        } == {(parent_entry, 2, 1, 1), (child_entry, 2, 1, 1)}
        assert vault.db.fetchone(
            "SELECT is_deleted FROM nodes WHERE id = ?", (root_id,)
        )["is_deleted"] == 0

        audit_row = vault.db.fetchone(
            "SELECT id, action FROM audit_log ORDER BY timestamp DESC, rowid DESC LIMIT 1"
        )
        assert audit_row["action"] == "delete"
        assert AuditLog(vault.db).verify_record(audit_row["id"], signing_pk)

        window._vault = None
        window.close()
        vault.lock()

    def test_multiple_folders_at_root(self, fresh_vault):
        fresh_vault.create_node("Alpha")
        fresh_vault.create_node("Beta")
        fresh_vault.create_node("Gamma")
        nodes = fresh_vault.list_nodes()
        names = [n["name"] for n in nodes]
        assert "Alpha" in names
        assert "Beta" in names
        assert "Gamma" in names

    def test_rename_folder(self, fresh_vault):
        fid = fresh_vault.create_node("OldName")
        fresh_vault.rename_node(fid, "NewName")
        nodes = fresh_vault.list_nodes()
        names = [n["name"] for n in nodes]
        assert "NewName" in names
        assert "OldName" not in names

    def test_rename_folder_persists(self, tmp_path):
        v = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        fid = v.create_node("Before")
        v.rename_node(fid, "After")
        v.lock()
        v2 = Vault(tmp_path)
        v2.unlock(PASSWORD)
        nodes = v2.list_nodes()
        assert any(n["name"] == "After" for n in nodes)
        assert not any(n["name"] == "Before" for n in nodes)
        v2.lock()

    def test_folder_via_node_dialog(self, fresh_vault):
        """Test creating folder through the GUI dialog."""
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault, parent_id=None)
        dlg._name_input.setText("DialogFolder")
        dlg._save()
        nodes = fresh_vault.list_nodes()
        assert any(n["name"] == "DialogFolder" for n in nodes)

    def test_folder_dialog_empty_name_rejected(self, fresh_vault):
        from sezam.gui.entry_dialog import NodeDialog
        nodes_before = len(fresh_vault.list_nodes())
        dlg = NodeDialog(fresh_vault, parent_id=None)
        dlg._name_input.setText("")
        dlg._save()
        assert len(fresh_vault.list_nodes()) == nodes_before

    def test_folder_dialog_in_subfolder(self, fresh_vault):
        parent = fresh_vault.create_node("Parent")
        from sezam.gui.entry_dialog import NodeDialog
        dlg = NodeDialog(fresh_vault, parent_id=parent)
        dlg._name_input.setText("SubChild")
        dlg._save()
        children = fresh_vault.list_nodes(parent)
        assert any(n["name"] == "SubChild" for n in children)


# ── 4. Entry Operations ──────────────────────────────────────────────────


class TestEntryOps:
    def test_create_entry(self, fresh_vault):
        fid = fresh_vault.create_node("Folder")
        eid = fresh_vault.create_entry(fid, "MyEntry", [
            {"key": "url", "value": "https://example.com"},
            {"key": "user", "value": "admin"},
        ])
        assert eid
        entries = fresh_vault.list_entries(fid)
        assert any(e["name"] == "MyEntry" for e in entries)

    def test_create_entry_with_sensitive_field(self, fresh_vault):
        fid = fresh_vault.create_node("Folder")
        eid = fresh_vault.create_entry(fid, "Secret", [
            {"key": "password", "value": "hunter2", "sensitive": True},
        ])
        entry = fresh_vault.read_entry(eid)
        assert entry["fields"][0]["sensitive"] is True
        assert entry["fields"][0]["value"] == "hunter2"

    def test_read_entry(self, populated_vault):
        entry = populated_vault["vault"].read_entry(populated_vault["ssh_id"])
        assert entry["name"] == "SSH Root"
        assert len(entry["fields"]) == 3
        assert entry["fields"][0]["value"] == "1.2.3.4"

    def test_update_entry_name(self, populated_vault):
        v = populated_vault["vault"]
        v.update_entry(populated_vault["ssh_id"], name="SSH Root (updated)")
        entry = v.read_entry(populated_vault["ssh_id"])
        assert entry["name"] == "SSH Root (updated)"

    def test_update_entry_fields(self, populated_vault):
        v = populated_vault["vault"]
        v.update_entry(populated_vault["ssh_id"], fields=[
            {"key": "host", "value": "10.0.0.1"},
            {"key": "username", "value": "admin"},
        ])
        entry = v.read_entry(populated_vault["ssh_id"])
        assert len(entry["fields"]) == 2
        assert entry["fields"][0]["value"] == "10.0.0.1"

    def test_delete_entry(self, populated_vault):
        v = populated_vault["vault"]
        v.delete_entry(populated_vault["ssh_id"])
        entries = v.list_entries(populated_vault["hetzner"])
        assert not any(e["id"] == populated_vault["ssh_id"] for e in entries)

    def test_entry_via_dialog(self, fresh_vault):
        """Test creating entry through the GUI dialog."""
        fid = fresh_vault.create_node("Folder")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg._name_input.setText("DialogEntry")
        # New dialog should have empty fields (not pre-filled)
        assert dlg._field_rows[0]["key"].text() == ""
        assert dlg._field_rows[1]["key"].text() == ""
        # Fill in fields
        dlg._field_rows[0]["key"].setText("url")
        dlg._field_rows[0]["value"].setText("https://test.com")
        dlg._field_rows[1]["key"].setText("token")
        dlg._field_rows[1]["value"].setText("abc123")
        dlg._save()
        entries = fresh_vault.list_entries(fid)
        assert any(e["name"] == "DialogEntry" for e in entries)

    def test_entry_dialog_empty_name_rejected(self, fresh_vault):
        fid = fresh_vault.create_node("Folder")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        dlg._name_input.setText("")
        dlg._save()
        entries = fresh_vault.list_entries(fid)
        assert len(entries) == 0

    def test_entry_dialog_no_prefilled_fields(self, fresh_vault):
        """Verify new entry dialog has empty field names (not 'username'/'password')."""
        fid = fresh_vault.create_node("Folder")
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(fresh_vault, fid)
        for row in dlg._field_rows:
            assert row["key"].text() == "", \
                f"Field key should be empty, got '{row['key'].text()}'"

    def test_entry_dialog_edit_existing(self, populated_vault):
        v = populated_vault["vault"]
        entry = v.read_entry(populated_vault["ssh_id"])
        from sezam.gui.entry_dialog import EntryDialog
        dlg = EntryDialog(v, populated_vault["hetzner"], entry=entry)
        # Should show existing data
        assert dlg._name_input.text() == "SSH Root"
        assert len(dlg._field_rows) == 3
        # Modify and save
        dlg._name_input.setText("SSH Root v2")
        dlg._save()
        updated = v.read_entry(populated_vault["ssh_id"])
        assert updated["name"] == "SSH Root v2"


# ── 5. Move Operations ───────────────────────────────────────────────────


class TestMoveOps:
    def test_move_entry_between_folders(self, populated_vault):
        v = populated_vault["vault"]
        # Move SSH entry from Hetzner to Clients
        v.move_entry(populated_vault["ssh_id"], populated_vault["clients"])
        # Should not be in Hetzner anymore
        entries_hz = v.list_entries(populated_vault["hetzner"])
        assert not any(e["id"] == populated_vault["ssh_id"] for e in entries_hz)
        # Should be in Clients
        entries_cl = v.list_entries(populated_vault["clients"])
        assert any(e["id"] == populated_vault["ssh_id"] for e in entries_cl)

    def test_move_entry_data_preserved(self, populated_vault):
        v = populated_vault["vault"]
        v.move_entry(populated_vault["ssh_id"], populated_vault["clients"])
        entry = v.read_entry(populated_vault["ssh_id"])
        assert entry["name"] == "SSH Root"
        assert entry["fields"][0]["value"] == "1.2.3.4"

    def test_move_folder(self, populated_vault):
        v = populated_vault["vault"]
        # Move Hetzner folder to Clients
        v.move_node(populated_vault["hetzner"], populated_vault["clients"])
        children = v.list_nodes(populated_vault["clients"])
        assert any(n["id"] == populated_vault["hetzner"] for n in children)


# ── 6. Search ─────────────────────────────────────────────────────────────


class TestSearch:
    def test_search_by_name(self, populated_vault):
        results = populated_vault["vault"].search("SSH")
        assert len(results) >= 1
        assert any("SSH" in r["name"] for r in results)

    def test_search_by_field_key(self, populated_vault):
        results = populated_vault["vault"].search("email")
        assert len(results) >= 1

    def test_search_case_insensitive(self, populated_vault):
        r1 = populated_vault["vault"].search("gmail")
        r2 = populated_vault["vault"].search("Gmail")
        assert len(r1) == len(r2)
        assert len(r1) >= 1

    def test_search_no_results(self, populated_vault):
        results = populated_vault["vault"].search("xyznonexistent999")
        assert results == []

    def test_deep_search_finds_field_value(self, populated_vault):
        results = populated_vault["vault"].deep_search("gmail.com")
        assert len(results) >= 1

    def test_deep_search_finds_password_value(self, populated_vault):
        results = populated_vault["vault"].deep_search("s3cret!")
        assert len(results) >= 1

    def test_main_window_search(self, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()
        w._on_search("SSH")
        assert w._tree.topLevelItemCount() >= 1
        w._on_search("")
        # Should restore full tree
        assert w._tree.topLevelItemCount() >= 2


# ── 7. Lock → Re-unlock → Data Persistence ───────────────────────────────


class TestPersistence:
    def test_data_survives_lock_unlock(self, tmp_path):
        # Create vault with data
        v = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        fid = v.create_node("Persistent")
        eid = v.create_entry(fid, "SurvivesLock", [
            {"key": "secret", "value": "persisted!", "sensitive": True},
        ])
        v.lock()

        # Re-open
        v2 = Vault(tmp_path)
        v2.unlock(PASSWORD)
        nodes = v2.list_nodes()
        assert any(n["name"] == "Persistent" for n in nodes)
        entry = v2.read_entry(eid)
        assert entry["name"] == "SurvivesLock"
        assert entry["fields"][0]["value"] == "persisted!"
        v2.lock()

    def test_edits_persist_after_relock(self, tmp_path):
        v = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        fid = v.create_node("F")
        eid = v.create_entry(fid, "Original", [
            {"key": "k", "value": "v1"},
        ])
        v.update_entry(eid, name="Renamed", fields=[
            {"key": "k", "value": "v2"},
        ])
        v.lock()

        v2 = Vault(tmp_path)
        v2.unlock(PASSWORD)
        entry = v2.read_entry(eid)
        assert entry["name"] == "Renamed"
        assert entry["fields"][0]["value"] == "v2"
        v2.lock()

    def test_delete_persists_after_relock(self, tmp_path):
        v = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        fid = v.create_node("F")
        eid = v.create_entry(fid, "Temp", [{"key": "k", "value": "v"}])
        v.delete_entry(eid)
        v.lock()

        v2 = Vault(tmp_path)
        v2.unlock(PASSWORD)
        entries = v2.list_entries(fid)
        assert not any(e["id"] == eid for e in entries)
        v2.lock()

    def test_operations_on_locked_vault_fail(self, tmp_path):
        v = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        v.lock()
        with pytest.raises(VaultLocked):
            v.list_nodes()
        with pytest.raises(VaultLocked):
            v.create_node("Should fail")


# ── 8. Main Window Integration ────────────────────────────────────────────


class TestMainWindow:
    def test_rebuild_tree_shows_all_data(self, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        count = w._rebuild_tree()
        assert count == 2  # SSH Root + Gmail
        assert w._tree.topLevelItemCount() >= 2  # Servers + Clients folders

    def test_tree_item_click_shows_entry(self, populated_vault):
        from PySide6.QtCore import Qt
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()

        # Recursively find an entry item in the tree
        def find_entry(item):
            data = item.data(0, Qt.UserRole)
            if data and data["type"] == "entry":
                return item
            for i in range(item.childCount()):
                found = find_entry(item.child(i))
                if found:
                    return found
            return None

        for i in range(w._tree.topLevelItemCount()):
            found = find_entry(w._tree.topLevelItem(i))
            if found:
                w._on_tree_item_clicked(found, 0)
                assert w._detail._current_entry_id is not None
                return
        pytest.fail("No entry item found in tree")

    def test_new_folder_via_main_window(self, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()

        # Directly test vault create_node (what the dialog does)
        v = populated_vault["vault"]
        fid = v.create_node("NewViaMain")
        count = w._rebuild_tree()
        nodes = v.list_nodes()
        assert any(n["name"] == "NewViaMain" for n in nodes)

    def test_new_entry_via_main_window(self, populated_vault):
        from sezam.gui.main_window import MainWindow
        w = MainWindow(populated_vault["path"])
        w._vault = populated_vault["vault"]
        w._rebuild_tree()

        v = populated_vault["vault"]
        eid = v.create_entry(populated_vault["clients"], "NewEntry", [
            {"key": "test", "value": "value"},
        ])
        count = w._rebuild_tree()
        assert count == 3  # SSH Root + Gmail + NewEntry

    def test_detail_shows_and_clears(self, populated_vault):
        from sezam.gui.entry_detail import EntryDetailWidget
        v = populated_vault["vault"]
        d = EntryDetailWidget()

        entry = v.read_entry(populated_vault["ssh_id"])
        d.show_entry(entry)
        assert d._name_label.text() == "SSH Root"
        assert d._current_entry_id == populated_vault["ssh_id"]

        d.clear()
        assert d._current_entry_id is None


# ── 9. Full User Journey ─────────────────────────────────────────────────


class TestFullJourney:
    """Simulate a complete user session from scratch."""

    def test_complete_session(self, tmp_path):
        # 1. Create vault
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
        assert vault.is_unlocked

        # 2. Create folder structure
        work = vault.create_node("Work")
        personal = vault.create_node("Personal")
        servers = vault.create_node("Servers", parent_id=work)

        # 3. Add entries
        e1 = vault.create_entry(servers, "Production DB", [
            {"key": "host", "value": "db.prod.internal"},
            {"key": "port", "value": "5432"},
            {"key": "password", "value": "prod-secret", "sensitive": True},
        ])
        e2 = vault.create_entry(personal, "Gmail", [
            {"key": "email", "value": "me@gmail.com"},
            {"key": "password", "value": "gmail-pass", "sensitive": True},
        ])

        # 4. Verify we can read them
        entry1 = vault.read_entry(e1)
        assert entry1["name"] == "Production DB"
        assert entry1["fields"][2]["value"] == "prod-secret"
        assert entry1["fields"][2]["sensitive"] is True

        # 5. Edit entry
        vault.update_entry(e1, name="Production DB (primary)", fields=[
            {"key": "host", "value": "db.prod.internal"},
            {"key": "port", "value": "5432"},
            {"key": "password", "value": "new-secret", "sensitive": True},
            {"key": "notes", "value": "Updated 2026-03"},
        ])
        updated = vault.read_entry(e1)
        assert updated["name"] == "Production DB (primary)"
        assert len(updated["fields"]) == 4

        # 6. Search
        results = vault.search("Gmail")
        assert len(results) == 1
        results = vault.search("prod")
        assert len(results) >= 1
        results = vault.deep_search("gmail.com")
        assert len(results) >= 1

        # 7. Move entry to different folder
        vault.move_entry(e2, work)
        entries_personal = vault.list_entries(personal)
        assert not any(e["id"] == e2 for e in entries_personal)
        entries_work = vault.list_entries(work)
        assert any(e["id"] == e2 for e in entries_work)
        # Data still intact after move
        moved = vault.read_entry(e2)
        assert moved["fields"][0]["value"] == "me@gmail.com"

        # 8. Delete entry
        vault.delete_entry(e2)
        entries_work = vault.list_entries(work)
        assert not any(e["id"] == e2 for e in entries_work)

        # 9. Lock vault
        vault.lock()
        assert not vault.is_unlocked
        with pytest.raises(VaultLocked):
            vault.list_nodes()

        # 10. Re-unlock and verify persistence
        v2 = Vault(tmp_path)
        v2.unlock(PASSWORD)
        assert v2.is_unlocked

        # Folders still there
        nodes = v2.list_nodes()
        names = [n["name"] for n in nodes]
        assert "Work" in names
        assert "Personal" in names

        # Entry still there with updated data
        entry = v2.read_entry(e1)
        assert entry["name"] == "Production DB (primary)"
        assert len(entry["fields"]) == 4

        # Deleted entry stays deleted
        entries_work = v2.list_entries(work)
        assert not any(e["id"] == e2 for e in entries_work)

        v2.lock()

    def test_gui_dialog_journey(self, tmp_path):
        """Full journey using GUI dialogs."""
        from sezam.gui.entry_dialog import NodeDialog, EntryDialog
        from sezam.gui.main_window import MainWindow

        # 1. Create vault
        vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)

        # 2. Create folder via dialog
        dlg = NodeDialog(vault, parent_id=None)
        dlg._name_input.setText("Projects")
        dlg._save()
        nodes = vault.list_nodes()
        folder = next(n for n in nodes if n["name"] == "Projects")

        # 3. Create entry via dialog
        dlg = EntryDialog(vault, folder["id"])
        dlg._name_input.setText("API Key")
        dlg._field_rows[0]["key"].setText("key")
        dlg._field_rows[0]["value"].setText("sk-123abc")
        dlg._field_rows[0]["sensitive"].setChecked(True)
        dlg._save()
        entries = vault.list_entries(folder["id"])
        assert len(entries) == 1
        assert entries[0]["name"] == "API Key"

        # 4. Read entry
        entry = vault.read_entry(entries[0]["id"])
        assert entry["fields"][0]["key"] == "key"
        assert entry["fields"][0]["value"] == "sk-123abc"
        assert entry["fields"][0]["sensitive"] is True

        # 5. Edit entry via dialog
        dlg = EntryDialog(vault, folder["id"], entry=entry)
        assert dlg._name_input.text() == "API Key"
        dlg._name_input.setText("API Key (prod)")
        dlg._save()
        updated = vault.read_entry(entries[0]["id"])
        assert updated["name"] == "API Key (prod)"

        # 6. Main window shows everything
        w = MainWindow(tmp_path)
        w._vault = vault
        count = w._rebuild_tree()
        assert count == 1
        assert w._tree.topLevelItemCount() >= 1

        # 7. Search works
        w._on_search("API")
        assert w._tree.topLevelItemCount() >= 1

        vault.lock()
