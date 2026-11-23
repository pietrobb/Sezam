"""The admin rotates its identity while it holds a folder key by another member's envelope (R15, goal #441).

Found by the stateful run of the R14-M1 handover rule on 4ee7d65: the admin
handed the role to Bob, whose push re-keyed the folder the admin held only as
admin; Bob handed the role back and sent the admin his envelope of the new
key. The admin then rotated its identity. That envelope is sealed to the old
key and only the admin may reissue a team key, so no device of the account
opened the folder again: before the push the log still names the old key
(the envelope opens with the old private key), after it the admin seals the
key to itself.
"""

from __future__ import annotations

from sezam.vault import revocation
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)


def _read_fresh(vault, entry_id) -> str:
    vault.dek_mgr._dek_cache.clear()
    return vault.read_entry(entry_id)["fields"][0]["value"]


def test_the_admin_rotates_while_holding_a_key_by_a_members_envelope(team, server):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    url = server[0]
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    side = admin.create_node("Side")
    in_side = admin.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, side, "read")

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    bob_client.pull()
    assert revocation.push_with_queued_revocations(bob, bob_client)["conflicts"] == []
    hand_over_admin(bob, bob_client, admin_id, lambda fingerprint: True)
    admin_client.pull()
    assert _read_fresh(admin, in_side) == "side-pw"  # by Bob's envelope: no push of the admin since

    admin_client.prepare_key_change()
    proof = admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    assert _read_fresh(admin, in_side) == "side-pw"  # the rotation is not on the server yet
    admin_client = _client(admin, url)
    assert admin_client.push()["conflicts"] == []
    assert _read_fresh(admin, in_side) == "side-pw"
    admin_client.pull()
    assert _read_fresh(admin, in_side) == "side-pw"
