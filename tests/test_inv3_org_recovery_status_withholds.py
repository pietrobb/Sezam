"""docs/ROOT_CAUSE_PLAN.md INV-3, review e443cbc goal #428 (F1-S4).

/api/org-recovery/status is unsigned. When it named another recovery key of
this account (configured, created_by, recovery_signing_pk), the desktop took
its own waiting setup for replaced and deleted it: its registration, its
queued org.recovery record and its local recovery key, so the shares handed
out for it stopped opening this vault. A server lying in the status destroyed
a setup it could only have withheld. The status now only keeps the setup from
being sent; the local key goes when the team log, signed, names a newer one.
"""

from __future__ import annotations

from sezam.vault import org_recovery_server
from sezam.vault.key_rotation import org_recovery_signing_key
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review11_org_recovery_current import _store
from tests.test_review13_org_recovery_queued_record import _logged, _queued_keys
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)


def test_an_unsigned_status_withholds_the_setup_and_keeps_its_key(team, server):  # noqa: F811
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    desktop_pk = admin.db.get_meta("org_recovery_signing_pk")
    # The status names another key of this account, and nothing signed does.
    web = _store(admin, admin_client, anchor=False, replace=True)
    web_pk = bytes(org_recovery_signing_key(web).verify_key).hex()

    assert admin_client.push().get("org_recovery_superseded") is True
    assert _logged(admin_client, desktop_pk) == [] and _queued_keys(admin) == []
    # Withheld, not destroyed: this vault's recovery key is still here.
    assert admin.org_recovery_configured()  # before: forgotten
    assert admin.db.get_meta("org_recovery_signing_pk") == desktop_pk
    # And not sent again by a later push.
    assert not admin_client.push().get("org_recovery_superseded")
    assert _logged(admin_client, desktop_pk) == [] and _queued_keys(admin) == []

    # Once the log names the newer key (signed by this admin), it is taken.
    admin_client.append_team_log([("org.recovery", {"recovery_pk": web_pk})])
    admin_client.push()
    assert admin.db.get_meta("org_recovery_signing_pk") == web_pk
