"""AI broker R2 (TODO section 10): `sezam snapshot list|restore`."""

from __future__ import annotations

import os
import sqlite3

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.mcp import control
from sezam.vault import snapshots
from sezam.vault.crud import Vault
from sezam.vault.snapshots import list_snapshots, take_snapshot
from tests.test_ai_r1_snapshots import MASTER, _cli_env, _make_vault


@pytest.fixture
def sent(monkeypatch) -> list[str]:
    """Commands that would reach running MCP servers."""
    calls: list[str] = []
    monkeypatch.setattr(control, "send_all", lambda cmd: calls.append(cmd) or [])
    return calls


@pytest.fixture
def vault_dir(tmp_path, monkeypatch, sent):
    path = tmp_path / "v"
    _make_vault(path).lock()
    _cli_env(path, monkeypatch)
    return path


def _with_vault(vault_dir, fn, password=MASTER):
    vault = Vault(vault_dir)
    vault.unlock(password)
    try:
        return fn(vault)
    finally:
        vault.lock()


def _names(vault_dir) -> set[str]:
    def collect(vault):
        return {
            e["name"] for n in vault.list_nodes() for e in vault.list_entries(n["id"])
        }

    return _with_vault(vault_dir, collect)


def _snapshot_then_add(vault_dir, title="later") -> str:
    def act(vault):
        snap = take_snapshot(vault.db, "import")
        vault.create_entry(vault.create_node("More"), title, [{"key": "k", "value": "v"}])
        return snap.name

    return _with_vault(vault_dir, act)


def _restore(name, *, password=MASTER, yes=True):
    args = ["snapshot", "restore", name] + (["--yes"] if yes else [])
    return CliRunner().invoke(cli.main, args, input=password + "\n")


def test_list_shows_name_time_and_reason(vault_dir):
    out = CliRunner().invoke(cli.main, ["snapshot", "list"]).output
    assert "No snapshots" in out

    name = _snapshot_then_add(vault_dir)
    out = CliRunner().invoke(cli.main, ["snapshot", "list"]).output
    row = next(line for line in out.splitlines() if line.startswith(name))
    assert "import" in row and "UTC" in row


def test_restore_returns_the_vault_to_the_snapshot_and_can_be_undone(vault_dir, sent):
    name = _snapshot_then_add(vault_dir)
    assert _names(vault_dir) == {"web", "later"}

    result = _restore(name)
    assert result.exit_code == 0, result.output
    assert _names(vault_dir) == {"web"}
    assert "pre-restore" in result.output
    assert sent == ["lock"]

    pre = [s for s in list_snapshots(vault_dir) if s.reason == "pre-restore"]
    assert len(pre) == 1
    assert _restore(pre[0].name).exit_code == 0
    assert _names(vault_dir) == {"web", "later"}

    conn = sqlite3.connect(str(vault_dir / "sezam.db"))
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()
    if os.name != "nt":
        assert (vault_dir / "sezam.db").stat().st_mode & 0o777 == 0o600
    assert not [p for p in vault_dir.iterdir() if p.name.startswith(".restore-")]
    # Reading a snapshot leaves no -wal/-shm files beside it.
    assert {p.name for p in (vault_dir / "snapshots").iterdir()} == {
        s.name for s in list_snapshots(vault_dir)
    }


def test_restore_needs_the_password_that_opens_the_snapshot(vault_dir, sent):
    def change(vault):
        vault.change_password(MASTER, "new-master-pw")

    _with_vault(vault_dir, change)
    old = next(s for s in list_snapshots(vault_dir) if s.reason == "change-password")

    wrong = _restore(old.name, password="new-master-pw")
    assert wrong.exit_code != 0
    assert "nothing restored" in wrong.output
    assert "new-master-pw" not in wrong.output
    assert [s.reason for s in list_snapshots(vault_dir)] == ["change-password"]
    assert sent == []
    # Review d615826: the change's snapshot is the way back only until the new
    # password opens the vault (then it is deleted), so restore before that.
    assert _restore(old.name, password=MASTER).exit_code == 0
    _with_vault(vault_dir, lambda v: None, password=MASTER)


@pytest.mark.parametrize("name", ["../sezam.db", "sezam.db", "snapshots/x.db", ""])
def test_restore_accepts_only_a_listed_snapshot_name(vault_dir, name):
    _snapshot_then_add(vault_dir)
    result = _restore(name)
    assert result.exit_code != 0
    assert _names(vault_dir) == {"web", "later"}


def test_restore_by_absolute_path_is_refused(vault_dir, tmp_path):
    name = _snapshot_then_add(vault_dir)
    result = _restore(str(vault_dir / "snapshots" / name))
    assert result.exit_code != 0
    assert _names(vault_dir) == {"web", "later"}


def test_a_planted_non_vault_file_is_not_restored(vault_dir, sent):
    planted = vault_dir / "snapshots"
    planted.mkdir(exist_ok=True)
    name = "20260101T000000_000000Z-import.db"
    conn = sqlite3.connect(str(planted / name))
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()

    result = _restore(name)
    assert result.exit_code != 0
    assert "not an intact Sezam vault" in result.output
    assert _names(vault_dir) == {"web"}
    assert sent == []


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlinked_snapshot_is_ignored(vault_dir, tmp_path):
    other = tmp_path / "other"
    _make_vault(other).lock()
    (vault_dir / "snapshots").mkdir(exist_ok=True)
    name = "20260101T000000_000000Z-import.db"
    os.symlink(other / "sezam.db", vault_dir / "snapshots" / name)
    assert list_snapshots(vault_dir) == []
    assert _restore(name).exit_code != 0


def test_restore_without_tty_needs_yes(vault_dir):
    name = _snapshot_then_add(vault_dir)
    result = _restore(name, yes=False)
    assert result.exit_code != 0
    assert "--yes" in result.output
    assert _names(vault_dir) == {"web", "later"}


def test_restore_does_nothing_when_the_current_vault_cannot_be_snapshotted(
    vault_dir, monkeypatch
):
    name = _snapshot_then_add(vault_dir)

    def fail(*_a, **_k):
        raise snapshots.SnapshotError("Vault snapshot failed (OSError); operation aborted")

    monkeypatch.setattr(snapshots, "take_snapshot", fail)
    result = _restore(name)
    assert result.exit_code != 0
    assert "vault unchanged" in result.output
    assert _names(vault_dir) == {"web", "later"}


def test_restore_ends_the_cli_session(vault_dir, monkeypatch):
    name = _snapshot_then_add(vault_dir)
    cleared = []
    monkeypatch.setattr(cli, "_clear_session", lambda: cleared.append(True))
    assert _restore(name).exit_code == 0
    assert cleared
