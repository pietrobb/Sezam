"""INV-7 / INV-5 precedence (docs/ROOT_CAUSE_PLAN.md, R15-P4), phone against a
real server (mobile/test/inv7_fault_injection_phone_test.dart): a fault at any
request of a sync after a personal write, while the admin moves a member's
access on the desktop (no answer, 500, 503), never offers or does a forget,
never moves a pin, and holds the personal change back at most until the next
clean sync; a fault anywhere but the push itself does not hold it at all.
"""
from __future__ import annotations

from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401


class _Rounds:
    """The phone's steps: one log move, then as many as it says it has rounds."""

    def __init__(self, work, move):
        self._work, self._move = work, move

    def items(self):
        yield "move0", self._move
        yield "rounds", lambda: None
        count = int((self._work / "rounds.txt").read_text(encoding="utf-8"))
        for i in range(1, count + 1):
            yield f"move{i}", self._move


def test_a_fault_at_any_request_of_a_phone_sync_never_forgets(team, server, tmp_path):  # noqa: F811
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD
    from sezam.vault.revocation import grant_member, push_with_queued_revocations

    url, _ = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = next(n["id"] for n in admin.list_nodes() if n["name"] == "Ops")
    level = {"now": "read"}

    def move():
        level["now"] = "write" if level["now"] == "read" else "read"
        grant_member(admin, client, bob.db.get_meta("user_id"), ops, level["now"], confirm_fingerprint=lambda _f: True)
        push_with_queued_revocations(admin, client)

    out = _phone(url, tmp_path, {
        "username": "admin", "user_id": admin.db.get_meta("user_id"), "password": PASSWORD,
        "genesis": client.team_state().genesis_hash,
    }, _Rounds(tmp_path / "phone", move), "test/inv7_fault_injection_phone_test.dart")
    assert "All tests passed!" in out, out
