"""Review 526419e N2: an export that left data out still reported success.

Folders and entries this device cannot decrypt (a lost DEK, a damaged blob)
were skipped without a word, and 'sezam export' said 'exported'. Someone
moving to another manager trusted an incomplete file. The export now says
it is incomplete, with the counts, and exits non-zero.
"""

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault

PARAMS = Argon2Params(time_cost=1, memory_cost=8_192, parallelism=1)


@pytest.fixture
def vault(tmp_path, monkeypatch):
    v = Vault.create(tmp_path / "v", "pw-123456789", PARAMS)
    web = v.create_node("Web")
    v.create_entry(web, "kept", [{"key": "password", "value": "a", "sensitive": True}])
    gone = v.create_entry(web, "trashed", [{"key": "password", "value": "b"}])
    v.delete_entry(gone)
    monkeypatch.setattr(cli, "_open_vault", lambda: v)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda _v: None)
    monkeypatch.setattr(Vault, "lock", lambda self: None)
    return v


def _damage(vault, table, name_filter):
    rows = vault.db.fetchall(f"SELECT id, encrypted_meta FROM {table} WHERE is_deleted = 0")
    for row in rows:
        if name_filter(row["id"]):
            blob = bytearray(row["encrypted_meta"])
            blob[-1] ^= 0xFF
            vault.db.execute(
                f"UPDATE {table} SET encrypted_meta = ? WHERE id = ?", (bytes(blob), row["id"])
            )


def _export(tmp_path, fmt):
    dest = tmp_path / f"out.{fmt}"
    result = CliRunner().invoke(
        cli.main, ["export", str(dest), "--format", fmt, "--confirm-plaintext"]
    )
    return result, dest


@pytest.mark.parametrize("fmt", ["csv", "bitwarden"])
def test_complete_export_reports_success(vault, tmp_path, fmt):
    result, dest = _export(tmp_path, fmt)
    assert result.exit_code == 0, result.output
    assert "exported to" in result.output
    assert "INCOMPLETE" not in result.output
    assert dest.exists()


@pytest.mark.parametrize("fmt", ["csv", "bitwarden"])
def test_undecryptable_entry_and_folder_are_reported(vault, tmp_path, fmt):
    ops = vault.create_node("Ops")
    vault.create_entry(ops, "inside", [{"key": "k", "value": "v"}])
    extra = vault.create_entry(vault.create_node("Mail"), "broken", [{"key": "k", "value": "v"}])
    _damage(vault, "entries", lambda i: i == extra)
    _damage(vault, "nodes", lambda i: i == ops)

    result, dest = _export(tmp_path, fmt)

    assert result.exit_code == 1, result.output
    assert "INCOMPLETE" in result.output
    assert "1 folder(s)" in result.output
    assert "1 entr(y/ies)" in result.output
    assert "exported to" not in result.output
    assert "kept" in dest.read_text(encoding="utf-8")


def test_gui_export_does_not_say_complete(vault, tmp_path, monkeypatch):
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QMessageBox

    from sezam.gui import main_window

    QApplication.instance() or QApplication([])
    extra = vault.create_entry(vault.create_node("Mail"), "broken", [{"key": "k", "value": "v"}])
    _damage(vault, "entries", lambda i: i == extra)
    dest = tmp_path / "gui.csv"
    shown = []
    w = main_window.MainWindow(tmp_path / "v")
    w._vault = vault
    monkeypatch.setattr(main_window.QInputDialog, "getItem", lambda *a: ("Plaintext CSV", True))
    monkeypatch.setattr(
        main_window.QMessageBox, "warning",
        lambda *a: shown.append(("warning", a[1], a[2])) or QMessageBox.Yes,
    )
    monkeypatch.setattr(
        main_window.QFileDialog, "getSaveFileName", lambda *a: (str(dest), "CSV Files (*.csv)")
    )
    monkeypatch.setattr(
        main_window.QMessageBox, "information", lambda *a: shown.append(("info", a[1], a[2]))
    )
    try:
        w._show_export_dialog()
    finally:
        w._tray.hide()
        w.deleteLater()

    assert not [s for s in shown if s[0] == "info"]
    assert ("Export Incomplete" in [s[1] for s in shown])
    assert any("1 entr(y/ies)" in s[2] for s in shown)
