"""Capability review of R3-V1 (run 91): org recovery set up before 'connect'.

f7f43cc registered the recovery key on the server during
'sezam org-recovery-setup'. On a vault not yet connected (the natural order
init -> org-recovery-setup -> connect) the registration was skipped silently,
its body lived only in memory, and connect never made up for it: after a
forgotten password and 'sezam org-recovery' a lone admin was back at the
permanent 403. The public body now waits in vault_meta and connect sends it.
"""

from __future__ import annotations

import re
from pathlib import Path

from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)

RECOVERED = "recovered-password!"


def _setup(path: Path, monkeypatch) -> tuple[str, list[tuple[int, bytes]]]:
    _cli_env(path, monkeypatch)
    result = CliRunner().invoke(
        cli.main, ["org-recovery-setup", "-t", "2", "-n", "3"], input=f"{PASSWORD}\n"
    )
    assert result.exit_code == 0, result.output
    shares = [
        (int(i), bytes.fromhex(h))
        for i, h in re.findall(r"Share (\d+): ([0-9a-f]+)", result.output)
    ]
    return result.output, shares


def test_setup_before_connect_registers_at_connect(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.lock()

    output, shares = _setup(tmp_path / "laptop", monkeypatch)
    assert len(shares) == 3
    # Not connected yet: the user is told when the server learns the key.
    assert "sezam connect" in output
    assert not db._storage.get("org_recovery_blobs")

    vault = Vault(tmp_path / "laptop")
    vault.unlock(PASSWORD)
    try:
        cli._server_connect_flow(url, vault, PASSWORD)
        user_id = vault.db.get_meta("user_id")
    finally:
        vault.lock()
    blobs = db._storage.get("org_recovery_blobs") or []
    assert blobs and blobs[0]["created_by"] == user_id

    # The forgotten password: the shares alone get the lone admin syncing.
    recovered = Vault(tmp_path / "laptop")
    recovered.org_recovery(shares[:2], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)
    try:
        assert _client(recovered, url).push()["conflicts"] == []
        assert (pending_states.key_change_journal(recovered.db) or None) is None
    finally:
        recovered.lock()


def test_connect_warns_when_the_server_cannot_learn_the_recovery(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    try:
        laptop.setup_org_recovery(threshold=2, shares=3)
        # Path B: the vault takes the account KEK, the setup's body is void.
        laptop._drop_pending_org_recovery_registration()
        cli._server_connect_flow(url, laptop, PASSWORD)
        message = SyncClient.org_recovery_after_connect(laptop, PASSWORD)
    finally:
        laptop.lock()
    assert not db._storage.get("org_recovery_blobs")
    assert message.startswith("Warning") and "--replace" in message


def test_a_pending_registration_is_dropped_when_the_kek_changes(tmp_path):
    vault = _vault(tmp_path / "laptop", "admin")
    try:
        vault.setup_org_recovery(threshold=2, shares=3)
        assert pending_states.org_recovery_registration(vault.db)
        # The body wraps the KEK of the setup; a later KEK makes it a lie.
        vault.change_password(PASSWORD, RECOVERED)
        assert pending_states.org_recovery_registration(vault.db) is None
    finally:
        vault.lock()
