"""INV-7 / INV-5 precedence (docs/ROOT_CAUSE_PLAN.md, R15-P4), web against a
real server: a fault at any request of a personal save or of the pull after
it, while the admin moves a member's access on the desktop (no answer, a lost
reply, 500, 503), never offers or does a forget and never moves a pin; a fault
anywhere but the push itself never holds the personal change back, and the
next clean pull and retry send whatever waited and follow the log again.
"""
from __future__ import annotations

from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401
from tests.web_tab import WebTab

FAULTS = ({"mode": "before"}, {"mode": "after"}, {"mode": "status", "status": 500}, {"mode": "status", "status": 503})
FORGET_CAUSES = {"confirmed_genesis", "log_gone", "other_genesis", "anchor_conflict"}


def test_a_fault_at_any_request_of_a_web_save_or_pull_never_forgets(team, server, tmp_path):  # noqa: F811
    from sezam.vault.revocation import grant_member, push_with_queued_revocations

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    ops = next(n["id"] for n in admin.list_nodes() if n["name"] == "Ops")
    level = {"now": "read"}

    def move():
        level["now"] = "write" if level["now"] == "read" else "read"
        grant_member(admin, client, bob.db.get_meta("user_id"), ops, level["now"], confirm_fingerprint=lambda _f: True)
        push_with_queued_revocations(admin, client)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        login = tab.do("login", username="admin", password=PASSWORD)
        assert login["error"] is None and not login["view"]["teamLogRefused"], login
        made = tab.do("save", mode="personal", name="mine")
        assert made["error"] is None and not made["view"]["dirty"], made
        mine = next(n["id"] for n in made["view"]["nodes"] if n["name"] == "mine")
        pins = made["view"]["teamLogPins"]
        assert genesis in pins, pins
        profile = tab.close()
    finally:
        tab.kill()

    tab = WebTab(url, tmp_path / "tab2.log", idb=profile)
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        # One clean round: the log moves, a personal save (and its pull); the
        # log moves again, the periodic pull.
        move()
        save = tab.do("save_object", mode="entry", name="clean", parent=mine, fields=[{"key": "password", "value": "c"}])
        move()
        pull = tab.do("refresh")
        assert save["error"] is None and pull["error"] is None, (save, pull)
        assert not pull["view"]["dirty"]
        requests = sorted({(step, c["method"], c["path"]) for step, r in (("save", save), ("refresh", pull))
                           for c in r["calls"]})
        assert ("refresh", "GET", "/api/team-log") in requests, requests

        n = 0
        for step, method, path in requests:
            for fault in FAULTS:
                label = f"{fault} at {step} {method} {path}"
                move()
                name = f"entry-{n}"
                n += 1
                fail = {"method": method, "path": path, **fault}
                save = tab.do("save_object", mode="entry", name=name, parent=mine,
                              fields=[{"key": "password", "value": name}], **({"fail": fail} if step == "save" else {}))
                move()
                pull = tab.do("refresh", **({"fail": fail} if step == "refresh" else {}))
                for result in (save, pull):
                    assert result["view"]["teamLogPins"] == pins, (label, result["view"]["teamLogPins"])
                    assert not result["confirms"], (label, result["confirms"])
                    assert result["view"]["teamLogCause"] not in FORGET_CAUSES, (label, result["view"]["teamLogCause"])
                    assert result["view"]["unlocked"], label
                assert (save if step == "save" else pull)["failure"]["fired"], label
                if (method, path) != ("POST", "/api/sync"):
                    # INV-7: only the push's own request can hold the personal change.
                    assert not save["view"]["dirty"], (label, save)
                    assert any(e["name"] == name and e["password"] == name for e in pull["view"]["entries"]), label
                # The next clean pull and retry send what waited and follow the log again.
                again = tab.do("refresh")
                if again["view"]["dirty"]:
                    again = tab.do("retry")
                assert again["error"] is None and not again["view"]["dirty"], (label, again)
                assert not again["view"]["teamLogRefused"], (label, again)
                assert again["view"]["teamLogPins"] == pins, label
    finally:
        tab.kill()
