"""F1-SM (TeamLogMachine, R15): the server's org recovery of this account went
stale and the admin's device said nothing.

A password change (here, or one another device of the account made and this
one took over) leaves the server's recovery wrapping the KEK of the older
password: only the share holders could re-wrap it, so its shares open nothing.
'change-password' warned once, right after; every later unlock and push asked
the server (registration_issue) and took a stale recovery of this account for
a working one.
"""

from __future__ import annotations

from sezam.vault import org_recovery_server
from sezam.vault.org_recovery_server import STALE_NOTE, register_while_password_known
from sezam.vault.sync_client import SyncClient
from tests.test_org_recovery_registration_check import NEW, _cli, _connected
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)


def _status(vault) -> dict:
    return org_recovery_server._client(vault)._request("GET", "/api/org-recovery/status") or {}


def _change_password_and_push(vault) -> None:
    vault.change_password(PASSWORD, NEW)
    client = org_recovery_server._client(vault)
    client.push()


def test_a_stale_recovery_is_told_after_a_password_change(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    vault = _connected(url, tmp_path / "laptop", registered=True)
    try:
        assert org_recovery_server.registration_issue(vault) is None
        _change_password_and_push(vault)
        assert _status(vault).get("stale") is True
        assert org_recovery_server.registration_issue(vault) == "stale"
        assert register_while_password_known(vault, NEW) == STALE_NOTE
    finally:
        vault.lock()

    result = _cli(tmp_path / "laptop", monkeypatch, ["push"], password=NEW)
    assert result.exit_code == 0, result.output
    assert "wraps the key of an older password" in result.output
    assert "--replace" in result.output


def test_a_new_setup_after_it_is_current_again(server, tmp_path):  # noqa: F811
    url, _db = server
    vault = _connected(url, tmp_path / "laptop", registered=True)
    try:
        _change_password_and_push(vault)
        vault.setup_org_recovery(threshold=2, shares=3, replace=True)
        assert SyncClient.register_org_recovery(vault, NEW)
        assert _status(vault).get("stale") is False
        assert org_recovery_server.registration_issue(vault) is None
    finally:
        vault.lock()
