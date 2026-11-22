"""Review c78fd19 (R13-8, goal #406): an admin who hands the role over keeps
no folder key and no write exception.

After ``member.role`` admin -> member the former admin still held the current
key of every team folder (as the key's author) and the log took their pulled
copies under it (``former_admins``) until some later re-key, which nothing made.
Now the handover gives the new admin every folder key it lacked (an envelope
the admin role lets it hold; review 8bc70f7 M1), and the new admin's next push re-keys
each folder the former admin held only as admin: the new keys go to the
members the log names, not to the former admin, and ``former_admins`` ends.
"""

from __future__ import annotations

import pytest
from nacl.exceptions import CryptoError

from sezam import teamlog
from sezam.vault import revocation
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops


def _password(vault, entry_id: str) -> str:
    return vault.read_entry(entry_id)["fields"][0]["value"]


def test_the_new_admin_rekeys_what_the_former_admin_held(team, server, tmp_path, monkeypatch):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    carol = _carol(server[0], admin_client, tmp_path, monkeypatch)
    admin_client.append_team_log([("member.add", _member(carol))])
    admin_id, bob_id, carol_id = (v.db.get_meta("user_id") for v in (admin, bob, carol))
    ops, side = _ops(admin), admin.create_node("Side")
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    revocation.grant_member(admin, admin_client, carol_id, side, "read")
    in_ops = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    in_side = admin.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
    assert admin_client.push()["conflicts"] == []
    before = admin_client.team_state()
    old_keys = {f: teamlog.current_key(before, f) for f in (ops, side)}

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    state = admin_client.team_state()
    assert teamlog.is_admin(state, bob_id) and not teamlog.is_admin(state, admin_id)
    # Bob had no key of Side: the handover gave it to him by the role
    # (review 8bc70f7 M1: no access.set), Ops stays read.
    assert bob_id not in state.access[side] and state.access[ops][bob_id] == "read"
    assert teamlog.may_hold_key(state, bob_id, old_keys[side])
    assert all(admin_id in state.former_admins.get(f, ()) for f in (ops, side))

    _confirm_founder(admin, bob)
    bob_client.pull()
    result = revocation.push_with_queued_revocations(bob, bob_client)
    assert result["conflicts"] == [] and not result["blocked"]
    assert result["handover_rekeyed"] == {admin_id: 2}
    state = bob_client.team_state()
    for folder in (ops, side):
        key = teamlog.current_key(state, folder)
        assert key != old_keys[folder]
        assert state.folders[folder][-1][1] == bob_id  # the new admin made the key
        assert not state.former_admins.get(folder)  # no write exception left
        assert not teamlog.may_hold_key(state, admin_id, key)
    assert teamlog.may_hold_key(state, carol_id, teamlog.current_key(state, side))
    assert _password(bob, in_ops) == "ops-pw" and _password(bob, in_side) == "side-pw"

    # A copy the former admin seals under the key they kept is not taken.
    refusal = teamlog.item_refusal(state, admin_id, in_ops, ops, old_keys[ops], False, sealing=False)
    assert refusal == "sealed with an old key generation"
    later = bob.create_entry(ops, "new", [{"key": "password", "value": "after-handover"}])
    assert bob_client.push()["conflicts"] == []
    admin_client.pull()
    assert admin.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (later,))  # pulled, not opened
    with pytest.raises((CryptoError, KeyError)):
        _password(admin, later)

    # Nothing more to re-key: the next push makes no batch.
    again = revocation.push_with_queued_revocations(bob, bob_client)
    assert again["handover_rekeyed"] == {} and teamlog.current_key(bob_client.team_state(), ops) == (
        teamlog.current_key(state, ops)
    )


def test_a_former_admin_with_write_access_keeps_the_key(team, server):  # noqa: F811
    """A folder the former admin may write anyway is not re-keyed for them."""
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    _confirm_founder(admin, bob)
    bob_client.pull()
    # Bob gives the former admin write access in Ops before his push.
    bob_client.append_team_log([("access.set", {"folder": ops, "user_id": admin_id, "level": "write"})])
    key = teamlog.current_key(bob_client.team_state(), ops)
    result = revocation.push_with_queued_revocations(bob, bob_client)
    assert result["handover_rekeyed"] == {}
    assert teamlog.current_key(bob_client.team_state(), ops) == key
