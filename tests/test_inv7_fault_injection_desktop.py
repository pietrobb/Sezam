"""INV-5/INV-7 precedence (docs/ROOT_CAUSE_PLAN.md, review e443cbc #436): a
fault in any step of the team log check never stops the personal tree.

A connection error or a 5xx is injected at every request of a pull and a push
of the member bob while the admin changes the team (each round moves bob's
access to Ops, so the pull fetches the log, the envelope and the keys). After
each round: forgetting the log was neither offered nor done (the pins stand),
the personal entry written before it is on the server once a clean round ran,
and a fault in the pull never kept it from the push of the same round.

Then the push's own check of the log fails in three ways (the founder not
confirmed here yet, a pinned log whose download answers 503, the check
raising): the personal change goes out in that push, the team's change waits,
and the push still reports the failure.
"""

from __future__ import annotations

import urllib.error

import pytest

from sezam.vault import sync_push
from sezam.vault.revocation import grant_member, push_with_queued_revocations
from sezam.vault.sync_client import ServerError
from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META, GENESIS_META
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401

PINS = (GENESIS_META, CONFIRMED_GENESIS_META, FORGOTTEN_GENESIS_META)


def _on_server(db, obj_id: str):
    return next((o for o in db._storage["vault_objects"] if o["id"] == obj_id), None)


def _yes(_fingerprint):
    return True


def _member_in_team(team):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    mine = bob.create_personal_folder("mine")
    bob_client.pull()
    bob.db.set_meta(CONFIRMED_GENESIS_META, admin_client.team_state().genesis_hash)
    bob_client.push()
    ops = next(n["id"] for n in admin.list_nodes() if n["name"] == "Ops")
    level = {"now": "read"}

    def team_moves():
        level["now"] = "write" if level["now"] == "read" else "read"
        grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, level["now"], confirm_fingerprint=_yes)
        push_with_queued_revocations(admin, admin_client)

    return db, admin, bob, bob_client, mine, ops, team_moves


def _cycle(client) -> dict:
    """A pull and a push, each reported and not stopping the other (as 'sezam pull' and 'sezam push')."""
    errors = {}
    for step in (client.pull, client.push):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - the step's failure is reported, not the test's
            errors[step.__name__] = exc
    return errors


def _requests_of_a_round(bob_client, bob, mine, team_moves) -> list[str]:
    seen, real = [], bob_client._request

    def tracing(method, path, *args, **kwargs):
        seen.append(f"{method} {path.split('?')[0]}")
        return real(method, path, *args, **kwargs)

    team_moves()
    bob.create_entry(mine, "traced", [{"key": "password", "value": "v"}])
    bob_client._request = tracing
    try:
        assert _cycle(bob_client) == {}
    finally:
        bob_client._request = real
    return seen


@pytest.mark.parametrize("fault", ["connection", "500", "503"])
def test_a_fault_at_any_request_never_forgets_and_never_holds_the_personal_tree(team, fault):  # noqa: F811
    db, _, bob, bob_client, mine, _, team_moves = _member_in_team(team)
    requests = _requests_of_a_round(bob_client, bob, mine, team_moves)
    assert "GET /api/team-log" in requests, requests  # the round reaches the log
    pins = [bob.db.get_meta(k) for k in PINS]
    real = bob_client._request
    for at in range(len(requests)):
        team_moves()
        entry = bob.create_entry(mine, f"r{at}", [{"key": "password", "value": "v"}])
        count, failed_in = {"n": 0}, []

        def faulty(method, path, *args, **kwargs):
            count["n"] += 1
            if count["n"] == at + 1:
                failed_in.append(path)
                if fault == "connection":
                    raise urllib.error.URLError("injected")
                raise ServerError(int(fault), '{"detail": "injected"}')
            return real(method, path, *args, **kwargs)

        bob_client._request = faulty
        try:
            errors = _cycle(bob_client)
        finally:
            bob_client._request = real
        if "pull" in errors and "push" not in errors:
            assert _on_server(db, entry), (at, requests[at], errors)  # the pull's fault did not hold it
        for error in errors.values():
            assert not getattr(error, "offers_forget", False), (at, error)
        refusal = bob_client.team_log_refusal()
        assert refusal is None or not refusal.offers_forget, (at, refusal)
        assert [bob.db.get_meta(k) for k in PINS] == pins, at
        assert _cycle(bob_client) == {}, at  # a clean round: the team's log is followed again
        assert _on_server(db, entry), (at, requests[at])


def _refused_check(case, team, monkeypatch):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    mine = bob.create_personal_folder("mine")
    if case == "founder_unconfirmed":
        with pytest.raises(RuntimeError, match="founder is not confirmed"):
            bob_client.pull()  # the log is here, its founder not confirmed yet
        assert bob_client.team_state() is not None
        return db, bob, bob_client, mine, None
    _confirm_founder(admin, bob)
    if case == "pinned_log_unreachable":
        bob.db.set_meta(CONFIRMED_GENESIS_META, admin_client.team_state().genesis_hash)
        real = bob_client._request

        def unreachable(method, path, *args, **kwargs):
            if path.startswith("/api/team-log"):
                raise ServerError(503, '{"detail": "injected"}')
            return real(method, path, *args, **kwargs)

        monkeypatch.setattr(bob_client, "_request", unreachable)
        return db, bob, bob_client, mine, None
    ops = next(n["id"] for n in admin.list_nodes() if n["name"] == "Ops")
    org_entry = admin.create_entry(ops, "vpn", [{"key": "password", "value": "v1"}])
    grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, "write", confirm_fingerprint=_yes)
    push_with_queued_revocations(admin, admin_client)
    bob_client.pull()
    bob.update_entry(org_entry, fields=[{"key": "password", "value": "v2"}])

    def raising(_db):
        raise RuntimeError("injected in the check")

    monkeypatch.setattr(sync_push, "local_team_state", raising)
    return db, bob, bob_client, mine, org_entry


@pytest.mark.parametrize("case", ["founder_unconfirmed", "pinned_log_unreachable", "check_raises"])
def test_a_failed_check_in_the_push_sends_the_personal_tree_and_holds_the_team(team, monkeypatch, case):  # noqa: F811
    db, bob, client, mine, team_entry = _refused_check(case, team, monkeypatch)
    team_version = team_entry and _on_server(db, team_entry)["version"]
    entry = bob.create_entry(mine, "written", [{"key": "password", "value": "new"}])
    with pytest.raises(Exception) as failed:
        client.push()
    assert _on_server(db, entry), failed.value
    assert "personal change(s) went out" in str(failed.value), failed.value
    assert not getattr(failed.value, "offers_forget", False)
    if team_entry is not None:
        assert _on_server(db, team_entry)["version"] == team_version  # the team's change waits
