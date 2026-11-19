"""Review 4acfdde R11 (low): snapshots of an earlier password survive an upgrade.

Since d615826 a password change deletes the snapshots the old password opens
(their keys decrypt today's data). A change made by an older release left
them, and nothing named them until the next change. 'sezam status' and
'sezam snapshot list' now name them and 'sezam snapshot drop-old-passwords'
deletes them. Never automatically: a restored older snapshot turns the newer
snapshots into "another password" (docs: a restore loses no newer snapshot).
"""

from __future__ import annotations

import shutil

from click.testing import CliRunner

from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.snapshots import list_snapshots, take_snapshot
from tests.test_ai_r1_snapshots import MASTER, _cli_env, _make_vault

NEW = "after-upgrade-master-pw"


def _vault_changed_by_an_old_release(path, tmp_path):
    """A snapshot of MASTER that a pre-d615826 password change kept."""
    vault = _make_vault(path)
    kept = take_snapshot(vault.db, "import")
    shutil.copy2(kept, tmp_path / kept.name)
    vault.change_password(MASTER, NEW)  # this release deletes it ...
    vault.lock()
    reopened = Vault(path)
    reopened.unlock(NEW)  # ... and the change's own spare at the first unlock
    reopened.lock()
    shutil.copy2(tmp_path / kept.name, kept)  # the older release had left it
    return kept.name


def test_status_and_list_name_old_password_snapshots_and_drop_deletes_only_them(tmp_path, monkeypatch):
    path = tmp_path / "v"
    old = _vault_changed_by_an_old_release(path, tmp_path)
    vault = Vault(path)
    vault.unlock(NEW)
    current = take_snapshot(vault.db, "import").name
    vault.lock()
    _cli_env(path, monkeypatch)

    status = CliRunner().invoke(cli.main, ["status"], input=NEW + "\n")
    assert status.exit_code == 0, status.output
    assert "1 snapshot(s) open with an earlier master password" in status.output
    listed = CliRunner().invoke(cli.main, ["snapshot", "list"]).output
    assert next(line for line in listed.splitlines() if line.startswith(old)).endswith("(earlier password)")
    assert not next(line for line in listed.splitlines() if line.startswith(current)).endswith(")")

    refused = CliRunner().invoke(cli.main, ["snapshot", "drop-old-passwords"])
    assert refused.exit_code != 0 and "--yes" in refused.output
    assert {s.name for s in list_snapshots(path)} == {old, current}

    dropped = CliRunner().invoke(cli.main, ["snapshot", "drop-old-passwords", "--yes"])
    assert dropped.exit_code == 0, dropped.output
    assert old in dropped.output and "Deleted 1 snapshot(s)." in dropped.output
    assert [s.name for s in list_snapshots(path)] == [current]
    again = CliRunner().invoke(cli.main, ["status"], input=NEW + "\n")
    assert "earlier master password" not in again.output


def test_a_vault_without_old_password_snapshots_says_nothing(tmp_path, monkeypatch):
    path = tmp_path / "v"
    _make_vault(path).lock()
    _cli_env(path, monkeypatch)
    vault = Vault(path)
    vault.unlock(MASTER)
    take_snapshot(vault.db, "import")
    vault.lock()
    assert "earlier master password" not in CliRunner().invoke(cli.main, ["status"], input=MASTER + "\n").output
    out = CliRunner().invoke(cli.main, ["snapshot", "drop-old-passwords", "--yes"]).output
    assert "No snapshot opens with an earlier master password." in out
    assert len(list_snapshots(path)) == 1
