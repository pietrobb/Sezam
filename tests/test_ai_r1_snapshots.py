"""AI broker R1 (TODO section 10): automatic encrypted vault snapshot before
every risky operation, and no risky operation without one."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault
from sezam.vault.snapshots import (
    SnapshotError,
    list_snapshots,
    snapshot_dir,
    take_snapshot,
)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PARAMS,
    PASSWORD,
    _client,
    server,
)
from tests import test_vault

_shared_folder = test_vault.TestRekeyRevocation._shared_folder

FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
MASTER = "snapshot-master-pw"


def _make_vault(path, password=MASTER, params=FAST) -> Vault:
    vault = Vault.create(path, password, params)
    vault.create_entry(vault.create_node("Servers"), "web", [{"key": "host", "value": "h"}])
    return vault


def _reasons(vault_dir) -> list[str]:
    return [s.reason for s in list_snapshots(vault_dir)]


def _opens_with(snapshot_path, tmp_path, password) -> bool:
    """A snapshot is a full vault: copy it into a fresh dir and unlock it."""
    probe = Path(tempfile.mkdtemp(dir=tmp_path, prefix="probe-"))
    (probe / "sezam.db").write_bytes(snapshot_path.read_bytes())
    vault = Vault(probe)
    try:
        vault.unlock(password)
    except ValueError:
        return False
    vault.lock()
    return True


def _break_snapshots(vault_dir) -> None:
    """A regular file where the snapshot directory belongs: every snapshot fails."""
    (vault_dir / "snapshots").write_bytes(b"not a directory")


# ── The snapshot itself ──


def test_snapshot_is_a_private_consistent_copy_in_the_vault_dir(tmp_path):
    vault = _make_vault(tmp_path / "v")
    path = take_snapshot(vault.db, "import")

    assert path.parent == snapshot_dir(tmp_path / "v")
    assert _reasons(tmp_path / "v") == ["import"]
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
    conn = sqlite3.connect(str(path))
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        user_id = conn.execute("SELECT value FROM vault_meta WHERE key='user_id'").fetchone()[0]
    finally:
        conn.close()
    assert user_id == vault.db.get_meta("user_id")
    vault.lock()
    assert _opens_with(path, tmp_path, MASTER)


def test_only_the_newest_snapshots_are_kept(tmp_path):
    vault = _make_vault(tmp_path / "v")
    for _ in range(5):
        take_snapshot(vault.db, "import", keep=3)
    snaps = list_snapshots(tmp_path / "v")
    assert len(snaps) == 3
    assert snaps == sorted(snaps, key=lambda s: s.name)
    vault.lock()


def test_snapshot_reason_cannot_name_a_path(tmp_path):
    vault = _make_vault(tmp_path / "v")
    for bad in ("../x", "a/b", "", "UPPER"):
        with pytest.raises(SnapshotError):
            take_snapshot(vault.db, bad)
    assert list_snapshots(tmp_path / "v") == []
    vault.lock()


# ── Before each risky operation ──


def test_change_password_snapshots_the_old_state_first(tmp_path):
    vault = _make_vault(tmp_path / "v")
    vault.change_password(MASTER, "new-master-pw")
    vault.lock()

    snaps = list_snapshots(tmp_path / "v")
    assert [s.reason for s in snaps] == ["change-password"]
    assert _opens_with(snaps[0].path, tmp_path, MASTER)
    assert not _opens_with(snaps[0].path, tmp_path, "new-master-pw")


def test_kdf_upgrade_snapshots_first(tmp_path):
    vault = _make_vault(tmp_path / "v")
    vault.change_password(
        MASTER, MASTER, new_params=Argon2Params(time_cost=2, memory_cost=8192, parallelism=1)
    )
    vault.lock()
    assert _reasons(tmp_path / "v") == ["kdf-upgrade"]


def test_org_recovery_snapshots_first(tmp_path):
    vault = _make_vault(tmp_path / "v")
    shares = vault.setup_org_recovery(threshold=2, shares=3)
    vault.lock()

    Vault(tmp_path / "v").org_recovery(shares[:2], "recovered-pw")
    snaps = list_snapshots(tmp_path / "v")
    assert [s.reason for s in snaps] == ["org-recovery"]
    assert _opens_with(snaps[0].path, tmp_path, MASTER)


def test_rekey_after_revocation_snapshots_first(tmp_path):
    vault = _make_vault(tmp_path / "v")
    *_, revoked_user_id, _ = _shared_folder(vault)
    assert vault.rekey_after_revocation(revoked_user_id) == 1
    assert _reasons(tmp_path / "v") == ["rekey"]
    vault.lock()


def _cli_env(vault_dir, monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "keyring",
        types.SimpleNamespace(
            set_password=lambda *a: None, get_password=lambda *a: None, delete_password=lambda *a: None
        ),
    )
    monkeypatch.setenv("SEZAM_VAULT", str(vault_dir))
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    monkeypatch.setattr(cli, "_attempt_tracker_path", lambda: vault_dir / "attempts.json")


def _csv(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(
        "folder,name,field_key,field_value,sensitive\nMail,mail,password,pw-1,true\n",
        encoding="utf-8",
    )
    return src


def _entry_count(vault_dir) -> int:
    vault = Vault(vault_dir)
    vault.unlock(MASTER)
    try:
        return vault.db.fetchone("SELECT COUNT(*) FROM entries")[0]
    finally:
        vault.lock()


def test_cli_import_snapshots_first(tmp_path, monkeypatch):
    vault_dir = tmp_path / "v"
    _make_vault(vault_dir).lock()
    _cli_env(vault_dir, monkeypatch)

    result = CliRunner().invoke(
        cli.main, ["import", str(_csv(tmp_path)), "--format", "csv"], input=MASTER + "\n"
    )
    assert result.exit_code == 0, result.output
    assert _reasons(vault_dir) == ["import"]
    assert _entry_count(vault_dir) == 2


def test_server_connect_snapshots_first(server, tmp_path):
    url, _db = server
    vault = Vault.create(tmp_path / "v", PASSWORD, PARAMS)
    vault.db.set_meta("username", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    assert _reasons(tmp_path / "v") == ["server-connect"]
    vault.lock()


def test_full_resync_snapshots_first(server, tmp_path):
    url, _db = server
    vault = Vault.create(tmp_path / "v", PASSWORD, PARAMS)
    vault.db.set_meta("username", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    assert _client(vault, url).full_resync(confirmed=True)["full_resync"]
    assert _reasons(tmp_path / "v") == ["server-connect", "full-resync"]
    vault.lock()


# ── Fail closed: no snapshot, no risky operation ──


def test_change_password_does_not_run_without_a_snapshot(tmp_path):
    vault = _make_vault(tmp_path / "v")
    _break_snapshots(tmp_path / "v")
    with pytest.raises(SnapshotError):
        vault.change_password(MASTER, "new-master-pw")
    vault.lock()
    reopened = Vault(tmp_path / "v")
    reopened.unlock(MASTER)
    reopened.lock()


def test_cli_change_password_reports_the_aborted_change(tmp_path, monkeypatch):
    vault_dir = tmp_path / "v"
    _make_vault(vault_dir).lock()
    _break_snapshots(vault_dir)
    _cli_env(vault_dir, monkeypatch)

    result = CliRunner().invoke(
        cli.main, ["change-password"], input=f"{MASTER}\nnew-pw-123\nnew-pw-123\n"
    )
    assert result.exit_code != 0
    assert "password was not changed" in result.output
    assert "new-pw-123" not in result.output
    reopened = Vault(vault_dir)
    reopened.unlock(MASTER)
    reopened.lock()


def test_org_recovery_does_not_run_without_a_snapshot(tmp_path):
    vault = _make_vault(tmp_path / "v")
    shares = vault.setup_org_recovery(threshold=2, shares=3)
    vault.lock()
    _break_snapshots(tmp_path / "v")
    with pytest.raises(SnapshotError):
        Vault(tmp_path / "v").org_recovery(shares[:2], "recovered-pw")
    reopened = Vault(tmp_path / "v")
    reopened.unlock(MASTER)
    reopened.lock()


def test_rekey_does_not_run_without_a_snapshot(tmp_path):
    vault = _make_vault(tmp_path / "v")
    node_id, _entry, old_dek_id, revoked_user_id, _ = _shared_folder(vault)
    _break_snapshots(tmp_path / "v")
    with pytest.raises(SnapshotError):
        vault.rekey_after_revocation(revoked_user_id)
    assert vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))["dek_id"] == old_dek_id
    vault.lock()


def test_cli_import_does_not_run_without_a_snapshot(tmp_path, monkeypatch):
    vault_dir = tmp_path / "v"
    _make_vault(vault_dir).lock()
    _break_snapshots(vault_dir)
    _cli_env(vault_dir, monkeypatch)

    result = CliRunner().invoke(
        cli.main, ["import", str(_csv(tmp_path)), "--format", "csv"], input=MASTER + "\n"
    )
    assert result.exit_code != 0
    assert "snapshot failed" in result.output
    assert _entry_count(vault_dir) == 1


def test_server_connect_does_not_run_without_a_snapshot(server, tmp_path):
    url, db = server
    vault = Vault.create(tmp_path / "v", PASSWORD, PARAMS)
    vault.db.set_meta("username", "admin")
    _break_snapshots(tmp_path / "v")
    with pytest.raises(SnapshotError):
        cli._server_connect_flow(url, vault, PASSWORD)
    assert not db._storage.get("users")
    assert vault.db.get_meta("server_url") is None
    vault.lock()


def test_full_resync_does_not_run_without_a_snapshot(server, tmp_path):
    url, _db = server
    vault = Vault.create(tmp_path / "v", PASSWORD, PARAMS)
    vault.db.set_meta("username", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    for snap in list_snapshots(tmp_path / "v"):
        snap.path.unlink()
    (tmp_path / "v" / "snapshots").rmdir()
    _break_snapshots(tmp_path / "v")
    seq = vault.db.get_meta("last_commit_seq")
    with pytest.raises(SnapshotError):
        _client(vault, url).full_resync(confirmed=True)
    assert vault.db.get_meta("last_commit_seq") == seq
    vault.lock()


# ── Desktop GUI paths ──


@pytest.fixture
def qapp():
    # Not pytest-qt's: that plugin is no dev dependency, and without PySide6
    # these tests skip instead of erroring.
    QApplication = pytest.importorskip("PySide6.QtWidgets").QApplication
    return QApplication.instance() or QApplication(sys.argv)


def test_gui_server_connect_snapshots_first_and_fails_closed(server, tmp_path, qapp):
    from sezam.gui.server_connect_dialog import ServerConnectWorker

    url, db = server
    broken = Vault.create(tmp_path / "broken", PASSWORD, PARAMS)
    broken.db.set_meta("username", "admin")
    _break_snapshots(tmp_path / "broken")
    worker = ServerConnectWorker(url, broken, PASSWORD)
    errors: list[str] = []
    worker.finished_error.connect(errors.append)
    worker.run()
    assert errors and "snapshot failed" in errors[0]
    assert not db._storage.get("users")
    broken.lock()

    vault = Vault.create(tmp_path / "v", PASSWORD, PARAMS)
    vault.db.set_meta("username", "admin")
    worker = ServerConnectWorker(url, vault, PASSWORD)
    ok: list[str] = []
    errors = []
    worker.finished_ok.connect(ok.append)
    worker.finished_error.connect(errors.append)
    worker.run()
    assert ok and not errors, errors
    assert _reasons(tmp_path / "v") == ["server-connect"]
    vault.lock()


def test_gui_import_snapshots_first_and_fails_closed(tmp_path, qapp):
    from sezam.gui.import_wizard import _ImportWorker

    def run(vault):
        done = []
        worker = _ImportWorker(vault, str(_csv(tmp_path)), "csv", None, "duplicate")
        worker.finished.connect(lambda count, err: done.append((count, err)))
        worker.run()
        return done[0]

    vault = _make_vault(tmp_path / "v")
    assert run(vault) == (1, "")
    assert _reasons(tmp_path / "v") == ["import"]
    vault.lock()

    broken = _make_vault(tmp_path / "b")
    _break_snapshots(tmp_path / "b")
    count, err = run(broken)
    assert count == 0 and "snapshot failed" in err
    assert broken.db.fetchone("SELECT COUNT(*) FROM entries")[0] == 1
    broken.lock()
