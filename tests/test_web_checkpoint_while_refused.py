"""Review e443cbc (R15-M web, goal #439): the web saved no checkpoint while the
team log was refused (app.js, pullAndBuildTreeLocked: `if (!teamLogRefusal)`).

A sign-in whose log did not come (or did not match) still pulled the server
up to its head, but the browser kept the checkpoint of the last clean pull.
A server restored to a state between the two was then taken as it was at the
next clean sign-in: no ROLLBACK DETECTED, no question. INV-2 (rollback
protection) holds whatever the log does; the log's pins stay where they were.
"""
from __future__ import annotations

import copy

import pytest

from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob, _confirm_founder  # noqa: F401
from tests.web_tab import WebTab


def _restore(db, backup) -> None:
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))


@pytest.mark.parametrize("refused_at", ["team_log", "signer_keys"])
def test_a_refused_sign_in_still_moves_the_rollback_floor(team, server, tmp_path, refused_at):  # noqa: F811
    from sezam.vault.revocation import grant_member, push_with_queued_revocations
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META

    url = server[0]
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    bob.db.set_meta(CONFIRMED_GENESIS_META, client.team_state().genesis_hash)
    ops = next(n["id"] for n in admin.list_nodes() if n["name"] == "Ops")
    grant_member(admin, client, bob.db.get_meta("user_id"), ops, "write", confirm_fingerprint=lambda _f: True)
    push_with_queued_revocations(admin, client)
    bob_client.pull()

    def bob_writes(name: str) -> None:
        bob.create_entry(ops, name, [{"key": "password", "value": name}])
        assert bob_client.push()["accepted"]

    bob_writes("first")
    fail = ({"method": "GET", "path": "/api/team-log"} if refused_at == "team_log"
            else {"method": "GET", "path": f"/api/users/{bob.db.get_meta('user_id')}/keys"})
    fail = {**fail, "mode": "status", "status": 503}

    tab = WebTab(url, tmp_path / "clean.log")
    try:
        login = tab.do("login", username="admin", password=PASSWORD)
        assert login["error"] is None and not login["view"]["teamLogRefused"], login
        pins = login["view"]["teamLogPins"]
        profile = tab.close()
    finally:
        tab.kill()

    bob_writes("second")
    backup = copy.deepcopy(db._storage)
    bob_writes("third")

    tab = WebTab(url, tmp_path / "refused.log", idb=profile)
    try:
        login = tab.do("login", username="admin", password=PASSWORD, fail=fail)
        assert login["failure"]["fired"] and login["error"] is None, login
        assert login["view"]["teamLogRefused"] and login["view"]["teamLogCause"] == "unreachable", login["view"]
        assert login["view"]["teamLogPins"] == pins
        profile = tab.close()
    finally:
        tab.kill()

    _restore(db, backup)
    tab = WebTab(url, tmp_path / "after-restore.log", idb=profile)
    try:
        login = tab.do("login", username="admin", password=PASSWORD, confirm=False)
        assert "ROLLBACK DETECTED" in (login["error"] or ""), login
        assert any("rollback_confirm" in c for c in login["confirms"]), login["confirms"]
        profile = tab.close()
    finally:
        tab.kill()

    # Accepting the restored server clears the floor as on every rollback;
    # the log's pins never moved for any of it.
    tab = WebTab(url, tmp_path / "accepted.log", idb=profile)
    try:
        login = tab.do("login", username="admin", password=PASSWORD, confirm=True)
        assert login["error"] is None and not login["view"]["teamLogRefused"], login
        assert login["view"]["teamLogPins"] == pins
    finally:
        tab.kill()
