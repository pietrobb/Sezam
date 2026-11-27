"""Review c02cc47 R17-N8, capability finding 689: a removal takes the access
still waiting for the member, also once the member is added back.

0c5bf83 voided a waiting access.set only while the log held the member as
removed. The admin raised Bob to write on this device (the push failed: the
access.set and Bob's new envelope wait in the re-key batch); another device of
the admin removed Bob and later added him back. This device pulled both, Bob
was active again, and its push gave Bob the write the removal had taken.
"""

from __future__ import annotations

from sezam import teamlog
from sezam.vault import pending_states, revocation
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_sync_state_machine import _fail_once
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401
from tests.test_team_log_desktop_changes import _member, _ops


def _server_state(client) -> teamlog.TeamState:
    return teamlog.replay(client._request("GET", "/api/team-log?since=-1", auth=True)["records"])


def _elsewhere(client, admin, change: tuple) -> None:
    """Another device of the admin appends ``change``; this copy lags until it pulls."""
    state = _server_state(client)
    body = teamlog.next_body(state, change[0], admin.db.get_meta("user_id"), change[1])
    record = teamlog.sign_record(body, admin.keypair.to_nacl_signing_key())
    client._request("POST", "/api/team-log", {"records": [record]}, auth=True)


def test_a_removal_takes_the_raise_still_waiting_also_after_a_re_add(team):  # noqa: F811
    _, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "read")
    assert _server_state(client).access[ops][bob_id] == "read"

    undo = _fail_once(client, "POST", "/api/sync", "before")
    try:
        revocation.grant_member(admin, client, bob_id, ops, "write")
    except (ValueError, RuntimeError):
        pass  # it goes with the next push
    finally:
        undo()
    assert pending_states.rekey_batch(admin.db).get("team_changes")

    _elsewhere(client, admin, ("member.remove", {"user_id": bob_id}))
    _elsewhere(client, admin, ("member.add", _member(bob) | {"role": "member"}))
    assert _server_state(client).members[bob_id].active

    client.push()
    client.push()
    logged = _server_state(client)
    assert logged.members[bob_id].active
    assert bob_id not in logged.access.get(ops, {})  # the removal took the read and the waiting write
    assert not pending_states.rekey_batch(admin.db)
    assert not [c for c in client.pending_team_changes() if c[0] == "access.set"]
    sealed = admin.db.fetchall(
        "SELECT id FROM access_envelopes WHERE user_id = ? AND dek_id IN "
        "(SELECT dek_id FROM nodes WHERE id = ?)", (bob_id, ops))
    assert not sealed  # the waiting envelope left with its access.set


def test_access_queued_after_a_queued_removal_stays(team):  # noqa: F811
    """A readmit made here (removal, re-add, then access) was made knowing the
    removal; one queued before it goes with the pulled removal."""
    from sezam.vault.team_log_state import _set_queued_changes, queued_changes

    _, admin, client, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    before = ["access.set", {"folder": "F", "user_id": bob_id, "level": "write"}]
    readmit = [["member.remove", {"user_id": bob_id}], ["member.add", _member(bob) | {"role": "member"}],
               ["access.set", {"folder": "F", "user_id": bob_id, "level": "read"}]]
    _set_queued_changes(admin.db, [before, *readmit])
    pulled = {"body": teamlog.canonical({"type": "member.remove", "data": {"user_id": bob_id}}), "sig": ""}
    with admin.db.transaction(immediate=True):
        client._drop_access_removed_since([pulled])
    assert queued_changes(admin.db) == readmit
