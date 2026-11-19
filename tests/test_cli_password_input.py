"""Lockout review #2: piped CLI password input.

On EOF ``readline()`` returned "" for the new password and its confirmation,
they matched, and the vault (and the server) got an EMPTY master password
that the GUI, web and mobile refuse. CRLF input kept a ``\\r`` in the
password that nobody can type.
"""

from __future__ import annotations

import io

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault.crud import Vault
from tests.test_ai_r1_snapshots import FAST, MASTER, _cli_env, _make_vault


def _opens_with(vault_dir, password) -> bool:
    vault = Vault(vault_dir)
    try:
        vault.unlock(password)
    except ValueError:
        return False
    vault.lock()
    return True


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    path = tmp_path / "v"
    _make_vault(path).lock()
    _cli_env(path, monkeypatch)
    return path


def test_change_password_at_end_of_input_changes_nothing(vault_dir):
    result = CliRunner().invoke(cli.main, ["change-password"], input=f"{MASTER}\n")
    assert result.exit_code != 0
    assert "end of input" in result.output
    assert _opens_with(vault_dir, MASTER)
    assert not _opens_with(vault_dir, "")


def test_change_password_refuses_an_empty_new_password(vault_dir):
    result = CliRunner().invoke(cli.main, ["change-password"], input=f"{MASTER}\n\n\n")
    assert result.exit_code != 0
    assert "cannot be empty" in result.output
    assert _opens_with(vault_dir, MASTER)


def test_change_password_strips_crlf_line_endings(vault_dir):
    result = CliRunner().invoke(
        cli.main, ["change-password"], input=f"{MASTER}\r\nnew-pw-123\r\nnew-pw-123\r\n"
    )
    assert result.exit_code == 0, result.output
    assert _opens_with(vault_dir, "new-pw-123")


def test_piped_password_has_no_carriage_return(monkeypatch):
    # newline="" keeps the raw "\r\n" (a CRLF file piped on Windows or Linux).
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("new-pw-123\r\n", newline=""))
    assert cli._get_password() == "new-pw-123"


def test_import_key_refuses_an_empty_new_password(tmp_path, monkeypatch):
    target = tmp_path / "imported"
    _cli_env(target, monkeypatch)
    key_file = tmp_path / "backup.sezam-key"
    key_file.write_bytes(b"not used: refused before decryption")
    result = CliRunner().invoke(
        cli.main, ["import-key", str(key_file)], input=f"{MASTER}\n\n\n"
    )
    assert result.exit_code != 0
    assert "cannot be empty" in result.output
    assert not (target / "sezam.db").exists()


def test_vault_api_refuses_an_empty_master_password(tmp_path):
    with pytest.raises(ValueError, match="cannot be empty"):
        Vault.create(tmp_path / "empty", "", FAST)
    vault = _make_vault(tmp_path / "v")
    with pytest.raises(ValueError, match="cannot be empty"):
        vault.change_password(MASTER, "")
    vault.lock()
    assert _opens_with(tmp_path / "v", MASTER)
