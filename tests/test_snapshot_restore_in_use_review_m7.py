"""Lockout review M7: snapshot restore must not replace a vault another process uses.

`sezam snapshot restore` only told running MCP servers to lock. A desktop app
(or another command) with the vault unlocked kept its connection to the old
file: on POSIX the file was swapped under it and its later writes went into
the unlinked file or mixed into the new one's WAL; on Windows the restore
failed half-way after the pre-restore snapshot. Every open VaultDB now holds
a shared lock on ``sezam.db.inuse`` and restore needs the exclusive one; it is
refused, with nothing changed, while anyone holds the vault open.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import time

import pytest

from sezam.vault import snapshots
from sezam.vault.crud import Vault
from sezam.vault.db import VaultDB
from sezam.vault.snapshots import list_snapshots
from tests.test_ai_r1_snapshots import MASTER
from tests.test_ai_r2_snapshot_cli import (  # noqa: F401  (fixtures)
    _names,
    _restore,
    _snapshot_then_add,
    sent,
    vault_dir,
)


@pytest.fixture(autouse=True)
def _short_wait(monkeypatch):
    monkeypatch.setattr(snapshots, "IN_USE_WAIT_SECONDS", 0.3, raising=False)


def _assert_refused(result, vault_dir, name):
    assert result.exit_code != 0
    assert "open in another Sezam program" in result.output
    assert "vault unchanged" in result.output
    assert [s.reason for s in list_snapshots(vault_dir)] == ["import"], (
        "a refused restore must not even take the pre-restore snapshot"
    )
    assert not [p for p in vault_dir.iterdir() if p.name.startswith(".restore-")]


def test_restore_is_refused_while_the_desktop_app_has_the_vault_unlocked(vault_dir):
    name = _snapshot_then_add(vault_dir)
    gui = Vault(vault_dir)
    gui.unlock(MASTER)
    try:
        _assert_refused(_restore(name), vault_dir, name)
        # The app still works on the same, intact file.
        node = next(n for n in gui.list_nodes() if n["name"] == "More")
        gui.create_entry(node["id"], "after-refused-restore", [{"key": "k", "value": "v"}])
    finally:
        gui.lock()
    assert _names(vault_dir) == {"web", "later", "after-refused-restore"}

    # Once the app has locked, the restore goes through.
    assert _restore(name).exit_code == 0
    assert _names(vault_dir) == {"web"}


def test_restore_is_refused_while_another_process_holds_the_vault_open(vault_dir):
    name = _snapshot_then_add(vault_dir)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                f"""
                import sys
                from sezam.vault.db import VaultDB
                db = VaultDB({str(vault_dir / "sezam.db")!r})
                db.open()
                print("open", flush=True)
                sys.stdin.readline()
                db.close()
                """
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "open"
        _assert_refused(_restore(name), vault_dir, name)
    finally:
        holder.communicate("\n", timeout=30)
    assert _names(vault_dir) == {"web", "later"}
    assert _restore(name).exit_code == 0
    assert _names(vault_dir) == {"web"}


def test_nobody_opens_the_vault_while_a_restore_replaces_it(tmp_path):
    from sezam.vault.inuse import InUseLock, VaultInUse

    db_path = tmp_path / "sezam.db"
    restoring = InUseLock(db_path)
    restoring.acquire(exclusive=True, timeout=0)
    try:
        db = VaultDB(db_path)
        started = time.monotonic()
        with pytest.raises(VaultInUse, match="being restored"):
            db._in_use.acquire(exclusive=False, timeout=0.2)
        assert time.monotonic() - started < 5
        assert db._conn is None
    finally:
        restoring.release()
    db = VaultDB(db_path)
    db.open()
    db.close()


def test_open_vaults_share_the_lock_and_release_it_on_close(tmp_path):
    from sezam.vault.inuse import InUseLock, VaultInUse

    db_path = tmp_path / "sezam.db"
    first, second = VaultDB(db_path), VaultDB(db_path)
    first.open()
    second.open()
    probe = InUseLock(db_path)
    with pytest.raises(VaultInUse):
        probe.acquire(exclusive=True, timeout=0)
    first.close()
    with pytest.raises(VaultInUse):
        probe.acquire(exclusive=True, timeout=0)
    second.close()
    probe.acquire(exclusive=True, timeout=0)
    probe.release()
