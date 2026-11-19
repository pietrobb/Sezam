"""Review 4acfdde R11 (medium): the phone dropped a pending invitation
registration after a 409/410 that its own earlier try (answer lost) caused,
leaving an orphaned account and a taken name. See
mobile/test/review11_phone_registration_lost_test.dart."""
from __future__ import annotations

from tests.test_integration_client_server import server  # noqa: F401
from tests.test_review10_phone import _link
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401


def test_phone_resumes_a_registration_whose_answer_was_lost(team, server, tmp_path):  # noqa: F811
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD

    url, db = server
    _, _admin, client, bob, _ = team
    _found_with_bob(client, bob)
    out = _phone(url, tmp_path, {"password": PASSWORD, "invitation": _link(url, client.create_invitation())},
                 {}, "test/review11_phone_registration_lost_test.dart")
    assert "All tests passed!" in out, out
    accounts = [u for u in db._storage["users"] if u["username"] == "lost-answer-phone"]
    assert len(accounts) == 1
    assert accounts[0]["id"] == (tmp_path / "phone" / "user_id.txt").read_text(encoding="utf-8")
