"""Review d615826 (web): org recovery in an organization with more than one user.

The real app.js in node against the real server: the admin sets up org
recovery on the web, a colleague joins and pushes a vault of their own, and
the admin recovers the account with the shares and a new password. The
browser's pulled records had no owner_id, so the colleague's DEK, which the
admin's KEK never opens, counted as the admin's and the recovery stopped with
recovery.unlock_all_deks_failed.
"""

from __future__ import annotations

from sezam import cli
from tests.test_cross_client_password_change import WEB_PASSWORD, _passwords, _web
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401


def test_web_org_recovery_with_a_colleague_on_the_server(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    admin_client = _client(laptop, url)
    user_id = laptop.db.get_meta("user_id")

    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    bob.create_entry(bob.create_node("Mine"), "home", [{"key": "password", "value": "b", "sensitive": True}])
    assert _client(bob, url).push()["accepted"]
    bob.lock()
    assert any(
        o["object_type"] == "dek" and o["owner_id"] == bob_id and not o["is_deleted"]
        for o in db._storage["vault_objects"]
    )

    browser: dict = {}
    setup = _web(
        url, browser,
        {"action": "login", "username": "admin", "password": PASSWORD},
        {"action": "org_recovery_setup", "threshold": 2, "total_shares": 3, "password": PASSWORD},
    )
    assert setup["error"] is None, setup
    recovered = _web(url, browser, {
        "action": "org_recovery", "shares": setup["shares"][:2], "total_shares": 3,
        "password": WEB_PASSWORD,
    })
    assert recovered["error"] is None, recovered
    assert recovered["alerts"] == ["recovery.success"]
    assert recovered["keyEpoch"] == 1
    assert _passwords(recovered) == {"db01": "s3cret"}
    epoch = next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)["key_epoch"]
    assert epoch == 1

    web = _web(url, browser, {"action": "login", "username": "admin", "password": WEB_PASSWORD})
    assert web["error"] is None, web
    assert _passwords(web) == {"db01": "s3cret"}
    laptop.lock()
