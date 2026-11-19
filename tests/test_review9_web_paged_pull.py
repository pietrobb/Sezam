"""Review 1141a20 (R9-G), web: a paged pull and the team log head.

The browser judged a pull in pages by the team log head of its first page.
Bob's browser pulls while the admin creates the team folder HR and shares it
with him: HR's key and item come with the later pages, the log records that
make them HR's are past the first page's head. As the desktop and the phone
now do, the head of the last page judges the pull.
"""

from __future__ import annotations

from sezam.crypto.envelope_crypto import compute_fingerprint
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)
from tests.test_review_web import pytestmark  # noqa: F401  (node)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


def test_the_browser_judges_a_paged_pull_by_the_last_pages_log_head(team, server, tmp_path, monkeypatch):  # noqa: F811
    from tests.web_tab import WebTab

    url, _ = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    admin.create_entry(ops, "ops-seed", [{"key": "password", "value": "seed"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    monkeypatch.setattr("server.app.routers.sync._PULL_MAX_OBJECTS", 2)

    def between():
        hr = admin.create_node("HR")
        revocation.grant_member(admin, admin_client, bob_id, hr, "read")
        admin.create_entry(hr, "hr-item", [{"key": "password", "value": "hr-pw"}])
        assert admin_client.push()["conflicts"] == []

    def readable(seen) -> dict:
        return {e["name"]: e["password"] for e in seen["view"]["entries"] if not e["undecryptable"]}

    tab = WebTab(url, tmp_path / "paged-pull-tab.log")
    try:
        seen = tab.do("login", username="bob", password=PASSWORD)
        assert seen["error"] is None, seen
        fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
        seen = tab.do("founder", open=True, fingerprint=fingerprint)
        assert seen["error"] is None, seen
        assert readable(seen).get("ops-seed") == "seed", seen["view"]["entries"]
        for i in range(3):
            admin.create_entry(ops, f"ops-{i}", [{"key": "password", "value": f"pw-{i}"}])
        assert admin_client.push()["conflicts"] == []

        seen = tab.refresh_between_pages(between)
        assert seen["error"] is None, seen
        assert readable(seen).get("hr-item") == "hr-pw", seen["view"]["entries"]
        seen = tab.do("refresh")
        assert seen["error"] is None, seen
        assert readable(seen).get("hr-item") == "hr-pw", seen["view"]["entries"]
    finally:
        tab.kill()
