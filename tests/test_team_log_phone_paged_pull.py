"""Review 1141a20 (R9-G), phone: a paged pull and the team log head.

The server hands a pull out in pages; each page carries the team log head as
it is when that page is served. The phone judged all pages by the first
page's head. Bob's phone pulls while the admin creates the team folder HR and
shares it with him: HR's objects come with the later pages, the log records
that make them HR's come after the first page's head. HR was not shown and
the checkpoint had passed it. As the desktop does (_fetch_pull_pages), the
head of the last page judges the pull.
"""

from __future__ import annotations

from sezam.crypto.envelope_crypto import compute_fingerprint
from sezam.vault import revocation
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops

PHONE_TEST = "test/phone_paged_pull_test.dart"


def test_the_phone_judges_a_paged_pull_by_the_last_pages_log_head(team, server, tmp_path, monkeypatch):  # noqa: F811
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    admin.create_entry(ops, "ops-seed", [{"key": "password", "value": "seed"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    bob.create_personal_folder("Moje")
    assert [c for c in bob_client.push()["conflicts"] if c["error"] != "admin only"] == []
    bob.lock()
    monkeypatch.setattr("server.app.routers.sync._PULL_MAX_OBJECTS", 2)

    def filled():
        for i in range(3):
            admin.create_entry(ops, f"ops-{i}", [{"key": "password", "value": f"pw-{i}"}])
        assert admin_client.push()["conflicts"] == []

    def between():
        hr = admin.create_node("HR")
        revocation.grant_member(admin, admin_client, bob_id, hr, "read")
        admin.create_entry(hr, "hr-item", [{"key": "password", "value": "hr-pw"}])
        assert admin_client.push()["conflicts"] == []

    out = _phone(server[0], tmp_path, {
        "username": "bob", "password": PASSWORD,
        "fingerprint": compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk),
    }, {"filled": filled, "between": between}, PHONE_TEST)
    assert "All tests passed!" in out, out
