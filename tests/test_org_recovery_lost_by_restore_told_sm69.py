"""Stateful test SM69: a server restore that lost the org recovery is reported.

The admin set up org recovery and the server registered it; then the server
was restored from a backup taken before the setup. The vault kept a local
"the server has it" mark and never asked again, so neither push nor unlock
said the shares no longer work there - the admin learned it only after
forgetting the password. The check now asks the server every time.
"""

from __future__ import annotations

import copy

from sezam import cli
from sezam.vault.org_recovery_server import (
    UNREGISTERED_HINT,
    register_while_password_known,
    registration_issue,
)
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)
from tests.test_org_recovery_registration_check import _cli


def test_push_reports_a_recovery_the_restored_server_lost(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    vault = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    backup = copy.deepcopy(db._storage)  # taken before the org recovery setup

    vault.setup_org_recovery(threshold=2, shares=3)
    assert SyncClient.register_org_recovery(vault, PASSWORD)
    assert registration_issue(vault) is None

    db._storage.clear()
    db._storage.update(backup)  # the operator restores the older backup
    assert not db._storage.get("org_recovery_blobs")

    assert registration_issue(vault) == "unregistered"
    assert register_while_password_known(vault, PASSWORD) == UNREGISTERED_HINT
    vault.lock()

    result = _cli(tmp_path / "laptop", monkeypatch, ["push"])
    assert result.exit_code == 0, result.output
    assert "does not know this vault's org recovery" in result.output
