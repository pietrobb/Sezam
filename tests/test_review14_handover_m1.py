"""Review 8bc70f7 M1 (goal #417): the admin's authority comes from the log's
rules, not from access a handover granted.

* The handover gave the new admin ``access.set`` write to every folder whose
  key it lacked. That access outlived the role: in A -> B -> C, B kept write
  to folders nobody had shared with B. Now the log lets the admin hold every
  current key by the role (``teamlog.may_hold_key``); the envelopes go with
  the member.role records and the next admin's re-key leaves B out.
* The grants went before the role change: a failed append left them. Now
  envelopes and records are one atomic request.
* The former admin's unsent writes went after the role change, and the
  server refused them there. Now they go out first.
"""

from __future__ import annotations

import json

import pytest

from sezam import teamlog
from sezam.vault import revocation
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops


def _password(vault, entry_id: str) -> str:
    return vault.read_entry(entry_id)["fields"][0]["value"]


def test_the_next_admin_keeps_no_folder_nobody_shared(team, server, tmp_path, monkeypatch):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    carol = _carol(server[0], admin_client, tmp_path, monkeypatch)
    carol_client = _client(carol, server[0])
    admin_client.append_team_log([("member.add", _member(carol))])
    bob_id, carol_id = bob.db.get_meta("user_id"), carol.db.get_meta("user_id")
    ops, side = _ops(admin), admin.create_node("Side")
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    revocation.grant_member(admin, admin_client, carol_id, side, "read")
    in_side = admin.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
    assert admin_client.push()["conflicts"] == []

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    state = admin_client.team_state()
    assert teamlog.is_admin(state, bob_id)
    # Side is not shared with Bob: he holds its key as admin, by no access.set.
    assert bob_id not in state.access[side]
    assert teamlog.may_hold_key(state, bob_id, teamlog.current_key(state, side))
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert _password(bob, in_side) == "side-pw"
    assert revocation.push_with_queued_revocations(bob, bob_client)["handover_rekeyed"]

    hand_over_admin(bob, bob_client, carol_id, lambda fingerprint: True)
    _confirm_founder(admin, carol)
    carol_client.pull()
    result = revocation.push_with_queued_revocations(carol, carol_client)
    assert bob_id in result["handover_rekeyed"]
    state = carol_client.team_state()
    key = teamlog.current_key(state, side)
    assert state.folders[side][-1][1] == carol_id
    assert not teamlog.may_write(state, side, bob_id)
    assert not teamlog.may_hold_key(state, bob_id, key)
    assert bob_id not in state.access[side]
    assert _password(carol, in_side) == "side-pw"
    # Ops was shared with Bob: he keeps reading it.
    assert state.access[ops][bob_id] == "read"
    assert teamlog.may_hold_key(state, bob_id, teamlog.current_key(state, ops))
    carol.lock()


def test_a_handover_that_does_not_land_leaves_nothing(team, server, tmp_path, monkeypatch):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    carol = _carol(server[0], admin_client, tmp_path, monkeypatch)
    admin_client.append_team_log([("member.add", _member(carol))])
    bob_id = bob.db.get_meta("user_id")
    side = admin.create_node("Side")
    revocation.grant_member(admin, admin_client, carol.db.get_meta("user_id"), side, "read")
    admin.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
    assert admin_client.push()["conflicts"] == []
    carol.lock()
    before = admin_client.team_state()

    sent = admin_client._request

    def lost(method, path, body=None, **kwargs):
        if body is not None and "member.role" in json.dumps(body, default=str):
            raise RuntimeError("Server unreachable")
        return sent(method, path, body, **kwargs)

    monkeypatch.setattr(admin_client, "_request", lost)
    with pytest.raises(RuntimeError, match="unreachable"):
        hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    monkeypatch.setattr(admin_client, "_request", sent)

    admin_client.pull()
    state = admin_client.team_state()
    assert not teamlog.is_admin(state, bob_id)
    assert state.head_seq == before.head_seq  # no grant landed before the role change
    assert bob_id not in state.access.get(side, {})
    assert not admin.db.fetchone("SELECT 1 FROM access_envelopes WHERE user_id = ?", (bob_id,))
    assert [tuple(r) for r in admin.db.fetchall("SELECT kind, object_id, body FROM outbox WHERE state = 'queued'")] == []
    # Tried again, it lands.
    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    assert teamlog.is_admin(admin_client.team_state(), bob_id)


def test_the_former_admins_unsent_writes_go_out_first(team, server):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    bob_id = bob.db.get_meta("user_id")
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    unsent = admin.create_entry(ops, "vpn", [{"key": "password", "value": "written-as-admin"}])

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    assert not admin.db.fetchone("SELECT 1 FROM outbox WHERE state = 'queued'")
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert _password(bob, unsent) == "written-as-admin"
