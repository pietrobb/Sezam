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
SIGN_IN = {"/api/meta", "/api/auth/challenge", "/api/auth/verify", "/api/sync"}
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
        profile = tab.close()
    finally:
        tab.kill()

    # The unlock: a reload signs in on the same profile, with a fault at each
    # request of a clean sign-in. Only the sign-in's own requests may keep it
    # locked; once open, the personal tree is there, and nothing is forgotten.
    tab = WebTab(url, tmp_path / "login-clean.log", idb=profile)
    try:
        move()
        clean = tab.do("login", username="admin", password=PASSWORD)
        assert clean["error"] is None and not clean["view"]["teamLogRefused"], clean
        profile = tab.close()
    finally:
        tab.kill()
    signin = sorted({(c["method"], c["path"]) for c in clean["calls"]})
    assert ("GET", "/api/team-log") in signin, signin
    for method, path in signin:
        for fault in FAULTS:
            label = f"{fault} at login {method} {path}"
            move()
            tab = WebTab(url, tmp_path / f"login-{len(label)}-{fault['mode']}.log", idb=profile)
            try:
                login = tab.do("login", username="admin", password=PASSWORD,
                               fail={"method": method, "path": path, **fault})
                assert login["failure"]["fired"], label
                assert not login["confirms"], (label, login["confirms"])
                assert login["view"]["teamLogCause"] not in FORGET_CAUSES, (label, login["view"]["teamLogCause"])
                if login["view"]["unlocked"]:
                    assert login["view"]["teamLogPins"] == pins, (label, login["view"]["teamLogPins"])
                    assert any(e["password"] == "c" for e in login["view"]["entries"]), (label, login["error"])
                else:
                    # The page holds no vault of its own: without the server's
                    # parameters, the sign-in or the vault there is no unlock.
                    assert path in SIGN_IN, (label, login["error"])
                    login = tab.do("login", username="admin", password=PASSWORD)
                again = tab.do("refresh")
                assert again["error"] is None and not again["view"]["teamLogRefused"], (label, again)
                assert again["view"]["teamLogPins"] == pins, label
                profile = tab.close()
            finally:
                tab.kill()


def test_another_signers_keys_that_do_not_come_at_an_unchanged_seq_offer_no_rollback(team, server, tmp_path):  # noqa: F811
    """Capability run 465: the keys of a member who wrote what the admin sees
    do not come at a sign-in where nothing moved since the checkpoint. That
    member's objects wait, and the pull is no other state than the stored one:
    no 'accept the server's state' prompt, nothing locked, nothing forgotten."""
    from sezam.vault.revocation import grant_member, push_with_queued_revocations
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
    from tests.test_team_log_desktop import _confirm_founder

    _, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    genesis = client.team_state().genesis_hash
    bob_client.pull()
    bob.db.set_meta(CONFIRMED_GENESIS_META, genesis)
    ops = next(n["id"] for n in admin.list_nodes() if n["name"] == "Ops")
    grant_member(admin, client, bob.db.get_meta("user_id"), ops, "write", confirm_fingerprint=lambda _f: True)
    push_with_queued_revocations(admin, client)
    bob_client.pull()
    vpn = bob.create_entry(ops, "vpn", [{"key": "password", "value": "by-bob"}])
    pushed = bob_client.push()
    bob_id = bob.db.get_meta("user_id")
    assert vpn in {o["id"] for o in pushed["accepted"]}, pushed
    keys = f"/api/users/{bob_id}/keys"

    tab = WebTab(url := server[0], tmp_path / "tab.log")
    try:
        login = tab.do("login", username="admin", password=PASSWORD)
        assert login["error"] is None and not login["view"]["teamLogRefused"], login
        assert ("GET", keys) in {(c["method"], c["path"]) for c in login["calls"]}, login["calls"]
        assert any(e["password"] == "by-bob" for e in login["view"]["entries"]), login["view"]["entries"]
        pins = login["view"]["teamLogPins"]
        profile = tab.close()
    finally:
        tab.kill()

    for fault in FAULTS:
        label = f"{fault} at login GET {keys}"
        tab = WebTab(url, tmp_path / f"keys-{fault['mode']}-{fault.get('status', 0)}.log", idb=profile)
        try:
            login = tab.do("login", username="admin", password=PASSWORD, fail={"method": "GET", "path": keys, **fault})
            assert login["failure"]["fired"], label
            assert not login["confirms"], (label, login["confirms"])
            assert login["error"] is None and login["view"]["unlocked"], (label, login["error"])
            assert login["view"]["teamLogCause"] == "unreachable", (label, login["view"]["teamLogCause"])
            assert login["view"]["teamLogPins"] == pins, label
            again = tab.do("refresh")
            assert again["error"] is None and not again["confirms"], (label, again["error"], again["calls"])
            assert not again["view"]["teamLogRefused"], (label, again)
            assert any(e["password"] == "by-bob" for e in again["view"]["entries"]), label
            assert again["view"]["teamLogPins"] == pins, label
            profile = tab.close()
        finally:
            tab.kill()
