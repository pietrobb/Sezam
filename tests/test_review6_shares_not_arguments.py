"""Review d615826 (desktop medium): the emergency kit told to pass Shamir
shares as command arguments ('sezam org-recovery -s ...'), where they stay in
the shell history and show in the process list. Shares are read only from the
prompt now (not echoed); an argument is refused before anything happens."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault

OLD = "old-password-1"
NEW = "new-password-2!"
FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)


def _vault(tmp_path, monkeypatch):
    vault = Vault.create(str(tmp_path / "v"), OLD, FAST)
    shares = vault.setup_org_recovery(threshold=2, shares=3)
    vault.lock()
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "v"))
    return shares


def test_a_share_as_argument_is_refused_and_changes_nothing(tmp_path, monkeypatch):
    shares = _vault(tmp_path, monkeypatch)
    args = ["org-recovery"]
    for idx, share in shares[:2]:
        args += ["-s", f"{idx}:{share.hex()}"]
    result = CliRunner().invoke(cli.main, args, input=f"{NEW}\n{NEW}\n")
    assert result.exit_code == 2
    assert "not taken on the command line" in result.output
    Vault(tmp_path / "v").unlock(OLD)


def test_shares_typed_at_the_prompt_recover_and_are_not_echoed(tmp_path, monkeypatch):
    shares = _vault(tmp_path, monkeypatch)
    typed = "".join(f"{idx}:{share.hex()}\n" for idx, share in shares[:2])
    result = CliRunner().invoke(cli.main, ["org-recovery"], input=f"{typed}\n{NEW}\n{NEW}\n")
    assert result.exit_code == 0, result.output
    assert "Recovery successful" in result.output
    for _idx, share in shares[:2]:
        assert share.hex() not in result.output
    recovered = Vault(tmp_path / "v")
    recovered.unlock(NEW)
    recovered.lock()


def test_the_emergency_kit_no_longer_names_share_arguments():
    kit = (Path(__file__).resolve().parent.parent / "docs" / "EMERGENCY_KIT.md").read_text("utf-8")
    assert "org-recovery -s" not in kit
    assert "sezam org-recovery`" in kit
