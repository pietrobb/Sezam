"""Review c78fd19 R13-10, capability run 378: the queued org.recovery record.

A desktop setup the server took queues an org.recovery record naming its key
in the team log; the next push sends it. When the admin set up org recovery
again on the web before that push, the record reached the log after the web's
blob and the server ranked the desktop's older key as the current one: the
web's shares stopped working. The setup now keeps the key it replaced until
the log names its own, and the push forgets it when the server holds a newer one.
"""

from __future__ import annotations

import pytest

from sezam.vault import org_recovery_server, pending_states
from sezam.vault.key_rotation import org_recovery_signing_key
from sezam.vault.team_log_local import queued_changes
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review11_org_recovery_current import _recovers, _store
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)


def _queued_keys(vault) -> list[str]:
    return [data["recovery_pk"] for kind, data in queued_changes(vault.db) if kind == "org.recovery"]


def _logged(client, *pks: str) -> list[str]:
    """Which of ``pks`` the log's records name, in log order."""
    records = client._request("GET", "/api/team-log", auth=True)["records"]
    return [pk for record in records for pk in pks if pk in record["body"]]


@pytest.mark.parametrize("web_anchor", [False, True])
def test_a_queued_desktop_record_does_not_replace_the_newer_web_setup(team, server, web_anchor):  # noqa: F811
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    admin_id = admin.db.get_meta("user_id")

    setup = org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    assert setup.registered
    desktop_pk = admin.db.get_meta("org_recovery_signing_pk")
    assert pending_states.org_recovery_registration(admin.db) is None
    assert _queued_keys(admin) == [desktop_pk]  # the next push sends it

    # The web's setup (its anchor, when there is one, goes through this
    # vault's client and so already reaches the desktop here).
    web = _store(admin, admin_client, anchor=web_anchor, replace=True)
    web_pk = bytes(org_recovery_signing_key(web).verify_key).hex()

    result = admin_client.push()
    status = admin_client._request("GET", "/api/org-recovery/status")
    assert status["recovery_signing_pk"] == web_pk  # before: desktop_pk
    assert _recovers(admin_client, web) == admin_id
    assert desktop_pk not in _queued_keys(admin)
    if web_anchor:
        # Sent through this vault's client, the web's anchor took the queued
        # record along ahead of it: the web's key is the one named last.
        assert _logged(admin_client, desktop_pk, web_pk)[-1] == web_pk
    else:
        assert _logged(admin_client, desktop_pk) == []
        assert result.get("org_recovery_superseded") is True
        assert not admin.org_recovery_configured()
        assert not admin_client.push().get("org_recovery_superseded")  # said once


def test_the_desktop_setup_still_reaches_the_log(team, server):  # noqa: F811
    """Nothing newer on the server: the push names the desktop's key as before."""
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    desktop_pk = admin.db.get_meta("org_recovery_signing_pk")

    result = admin_client.push()
    assert not result.get("org_recovery_superseded")
    assert _logged(admin_client, desktop_pk)
    assert _queued_keys(admin) == []
    status = admin_client._request("GET", "/api/org-recovery/status")
    assert status["recovery_signing_pk"] == desktop_pk


def test_the_server_refuses_the_record_the_desktop_check_missed(team, server, monkeypatch):  # noqa: F811
    """Operator 2026-11-20: the window between the push's check and its send.
    The server refuses an org.recovery record naming another key than the
    admin's stored blob; the desktop forgets its setup as if it had looked."""
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    admin_id = admin.db.get_meta("user_id")
    org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    desktop_pk = admin.db.get_meta("org_recovery_signing_pk")
    web = _store(admin, admin_client, anchor=False, replace=True)
    web_pk = bytes(org_recovery_signing_key(web).verify_key).hex()
    monkeypatch.setattr(admin_client, "drop_superseded_org_recovery", lambda: False)

    result = admin_client.push()
    assert _logged(admin_client, desktop_pk) == []  # before: logged, the current one
    status = admin_client._request("GET", "/api/org-recovery/status")
    assert status["recovery_signing_pk"] == web_pk
    assert _recovers(admin_client, web) == admin_id
    assert result.get("org_recovery_superseded") is True
    assert _queued_keys(admin) == [] and not admin_client.set_aside_team_changes()
    assert not admin.org_recovery_configured()
