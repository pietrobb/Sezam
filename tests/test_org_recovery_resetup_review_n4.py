"""Lockout review N4: a repeated org-recovery setup voided every share silently.

``sezam org-recovery-setup`` (and the vault API under it) replaced the
recovery key without a word, so the shares the key holders kept stopped
working without anyone knowing. A repeated setup now warns and needs an
explicit confirmation (``--replace`` / dialog), otherwise nothing changes.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from click.testing import CliRunner

from sezam.cli import main
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault

FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "correct horse battery"


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    path = tmp_path / "vault"
    Vault.create(str(path), PASSWORD, argon2_params=FAST).lock()
    monkeypatch.setenv("SEZAM_VAULT", str(path))
    return path


def test_vault_refuses_a_second_setup_without_replace(vault_dir):
    from sezam.vault.crud import OrgRecoveryExistsError

    vault = Vault(vault_dir)
    vault.unlock(PASSWORD)
    assert not vault.org_recovery_configured()
    first = vault.setup_org_recovery(threshold=2, shares=3)
    pk = vault.db.get_meta("org_recovery_pk")
    assert vault.org_recovery_configured()

    with pytest.raises(OrgRecoveryExistsError):
        vault.setup_org_recovery(threshold=2, shares=3)
    assert vault.db.get_meta("org_recovery_pk") == pk
    vault.lock()

    # The shares already handed out still work.
    recovered = Vault(vault_dir)
    recovered.org_recovery(first[:2], "after recovery pw")
    recovered.lock()


def test_vault_replaces_only_when_asked(vault_dir):
    vault = Vault(vault_dir)
    vault.unlock(PASSWORD)
    vault.setup_org_recovery(threshold=2, shares=3)
    pk = vault.db.get_meta("org_recovery_pk")
    second = vault.setup_org_recovery(threshold=2, shares=3, replace=True)
    assert vault.db.get_meta("org_recovery_pk") != pk
    vault.lock()

    recovered = Vault(vault_dir)
    recovered.org_recovery(second[:2], "after recovery pw")
    recovered.lock()


def _pk(vault_dir) -> str | None:
    with closing(sqlite3.connect(vault_dir / "sezam.db")) as conn:
        row = conn.execute(
            "SELECT value FROM vault_meta WHERE key = 'org_recovery_pk'"
        ).fetchone()
    return row[0] if row else None


def test_cli_second_setup_warns_and_changes_nothing_without_replace(vault_dir):
    runner = CliRunner()
    first = runner.invoke(
        main, ["org-recovery-setup", "-t", "2", "-n", "3"], input=f"{PASSWORD}\n"
    )
    assert first.exit_code == 0, first.output
    pk = _pk(vault_dir)

    again = runner.invoke(
        main, ["org-recovery-setup", "-t", "2", "-n", "3"], input=f"{PASSWORD}\n"
    )
    assert again.exit_code == 1
    assert "EVERY existing share invalid" in again.output
    assert "Share 1:" not in again.output
    assert _pk(vault_dir) == pk

    replaced = runner.invoke(
        main, ["org-recovery-setup", "-t", "2", "-n", "3", "--replace"],
        input=f"{PASSWORD}\n",
    )
    assert replaced.exit_code == 0, replaced.output
    assert "Share 1:" in replaced.output
    assert _pk(vault_dir) != pk


def test_gui_warns_about_void_shares_and_passes_the_confirmation():
    src = (ROOT / "src" / "sezam" / "gui" / "team_dialog.py").read_text(encoding="utf-8")
    body = src[src.index("def _setup_org_recovery"):src.index("# Display shares")]
    assert "replace = self._vault.org_recovery_configured()" in body
    assert "zneplatní VŠETKY doterajšie kusy" in body
    assert "self._vault, password, threshold, total, replace=replace" in body
    assert "QMessageBox.No,\n        )" in body  # "No" stays the default


def test_web_setup_still_confirms_a_replacement():
    app = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    body = app[app.index("async function handleShamirGenerate"):app.index("function showShamirSharesModal")]
    assert body.index("if (!confirm(t(warning))) return;") < body.index("randombytes_buf(32)")
