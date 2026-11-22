"""INV-7 (docs/ROOT_CAUSE_PLAN.md), web: a team log this browser refuses never
keeps the vault locked. It refuses the team only: the personal tree opens and
takes writes, no team key opens, and each cause names its way out.

On eba9493 every such sign-in failed and reset the session, so a web-only
user reached none of their own secrets:

* anchor_names_other: the account keys name another genesis than the one this
  browser confirmed (a server serving an old account bundle). Way out: both
  pins typed in Team trust's "Forget the pinned team log" (a risk, INV-8),
  then the founder confirmed again. Before, a cause-less TEAM LOG MISMATCH at
  the sign-in, with no offer to forget.
* anchor_damaged: the confirmed anchor this browser holds does not open
  (local_damaged). Way out: confirming the founder again replaces it.
  Before, "Invalid encrypted team anchor" on every sign-in, for good.
* server_went_back: the server serves a log shorter than this browser saw (a
  lying or restored server; never forgotten). Way out: once the server serves
  the log again, the next pull follows it.

Each state is a real server, a desktop admin and member, and the unmodified
web client (tests/web_tab.py) the member signed in with before.
"""

from __future__ import annotations

import pytest

from sezam.crypto import aead
from sezam.crypto.keys import compute_fingerprint
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_team_log_desktop import _forget_server_cache, _found_with_bob, team  # noqa: F401
from tests.web_tab import WebTab

STATES = ("anchor_names_other", "anchor_damaged", "server_went_back")
OTHER_GENESIS = "ab" * 32


def _readable(view: dict, password: str) -> bool:
    return any(e["password"] == password for e in view["entries"])


def _setup(team, server, tmp_path):  # noqa: F811
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "team-secret", [{"key": "password", "value": "team-only"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), ops, "read")
    assert client.push()["conflicts"] == []
    fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    tab = WebTab(url, tmp_path / "before.log")
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        confirmed = tab.do("founder", open=True, fingerprint=fingerprint)
        assert confirmed["error"] is None, confirmed
        made = tab.do("save", mode="personal", name="mine")
        assert made["error"] is None, made
        saved = tab.do("save", mode="entry", name="mine-secret", parent="mine",
                       fields=[{"key": "password", "value": "mine-only"}])
        assert saved["error"] is None and saved["view"]["dirty"] == [], saved
        assert _readable(saved["view"], "team-only") and _readable(saved["view"], "mine-only"), saved
        mine = next(n["id"] for n in saved["view"]["nodes"] if n["name"] == "mine" and n["personal"])
        profile = tab.close()
    finally:
        tab.kill()
    return url, db, bob, ops, mine, fingerprint, client.team_state().genesis_hash, profile


def _enter(state, db, bob, genesis, profile):
    """Put the browser (its profile) or the server into ``state``; returns how to undo it."""
    if state == "anchor_names_other":
        user = next(u for u in db._storage["users"] if u["id"] == bob.db.get_meta("user_id"))
        user["encrypted_keypair"] = aead.encrypt_account_keypair(
            bob.keypair.serialize_private(), OTHER_GENESIS, bob.current_kek,
            bob.db.get_meta("kek_dek_id").encode(), user["id"].encode())
        return None
    if state == "anchor_damaged":
        import json
        anchor_id = f"confirmed_team_genesis:{bob.db.get_meta('user_id')}"
        row = next(r for r in profile["keys"] if r["id"] == anchor_id)
        stored = json.loads(row["__json"])
        flipped = "0" if stored["encrypted_genesis"][-1] != "0" else "1"
        stored["encrypted_genesis"] = stored["encrypted_genesis"][:-1] + flipped
        row["__json"] = json.dumps(stored)
        return None
    honest = list(db._storage["team_log"])
    db._storage["team_log"] = honest[:-1]
    _forget_server_cache()

    def undo():
        db._storage["team_log"] = honest
        _forget_server_cache()
    return undo


@pytest.mark.parametrize("state", STATES)
def test_the_web_vault_opens_and_only_the_team_waits(team, server, tmp_path, state):  # noqa: F811
    url, db, bob, ops, mine, fingerprint, genesis, profile = _setup(team, server, tmp_path)
    undo = _enter(state, db, bob, genesis, profile)
    tab = WebTab(url, tmp_path / f"{state}.log", idb=profile)
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None and login["view"]["unlocked"], login
        assert _readable(login["view"], "mine-only"), login
        assert not _readable(login["view"], "team-only"), login
        refusal = next(a for a in login["alerts"] if a.startswith("TEAM LOG MISMATCH"))
        assert ("RISK:" in refusal) is (state == "anchor_names_other"), refusal
        if state == "anchor_damaged":
            assert "confirming the team's founder again" in refusal, refusal

        # The personal tree takes writes; the team refuses them, naming why.
        written = tab.do("save_object", mode="entry", name="written", parent=mine,
                         fields=[{"key": "password", "value": "new-mine"}])
        assert written["error"] is None and written["view"]["dirty"] == [], written
        assert _readable(written["view"], "new-mine"), written
        refused = tab.do("save_object", mode="entry", name="team-write", parent=ops,
                         fields=[{"key": "password", "value": "x"}])
        assert refused["error"] and refused["error"].startswith("TEAM LOG MISMATCH"), refused

        # The way out, from the vault the sign-in opened.
        if state == "anchor_names_other":
            both = f"{genesis[:16]} {OTHER_GENESIS[:16]}"
            typo = tab.do("forget_pin", typed=genesis[:16], password=PASSWORD, confirm=True)
            assert "team.forget_typed" in (typo["error"] or "") or "every one" in (typo["error"] or ""), typo
            # INV-8 (review e443cbc): the forget only with the account password.
            for wrong in ("", PASSWORD + "x"):
                denied = tab.do("forget_pin", typed=both, password=wrong, confirm=True)
                assert "forget_wrong_password" in (denied["error"] or ""), denied
                assert denied["view"]["teamLogPins"] == typo["view"]["teamLogPins"], denied
            left = tab.do("forget_pin", typed=both, password=PASSWORD, confirm=True)
            assert not _readable(left["view"], "team-only"), left
            out = tab.do("founder", open=True, fingerprint=fingerprint)
        elif state == "anchor_damaged":
            out = tab.do("founder", open=True, fingerprint=fingerprint)
        else:
            undo()
            out = tab.do("refresh")
        assert out["error"] is None, out
        assert _readable(out["view"], "team-only") and _readable(out["view"], "mine-only"), out
        assert _readable(out["view"], "new-mine"), out
    finally:
        tab.kill()
        if undo:
            undo()
