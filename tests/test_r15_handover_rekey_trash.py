"""The new admin's re-key after a handover meets a deleted folder (R15, goal #441).

Found by the stateful run of the R14-M1 handover rule on 4ee7d65: the admin
deleted a folder nobody shared with it, then handed the role over. The new
admin's push re-keys that folder (the former admin holds it only as admin)
and re-sealed the items still in it, queued as writes. The server takes
nothing live below a deleted folder, so the push revived the folder for them,
which needs the parent's key the folder's name is sealed with: the new
admin, a member, holds no such key, and every push raised CryptoError.
Items of a deleted folder keep the old key now, as the rest of the trash does.
"""

from __future__ import annotations

from sezam import teamlog
from sezam.vault import revocation, trash
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member


def test_the_new_admin_rekeys_past_a_deleted_folder(team, server, tmp_path, monkeypatch):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    carol = _carol(server[0], admin_client, tmp_path, monkeypatch)
    admin_client.append_team_log([("member.add", _member(carol))])
    bob_id, carol_id = bob.db.get_meta("user_id"), carol.db.get_meta("user_id")
    side = admin.create_node("Side")
    revocation.grant_member(admin, admin_client, carol_id, side, "read")
    in_side = admin.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
    assert admin_client.push()["conflicts"] == []
    carol.lock()
    bob_client.pull()
    live = dict(bob.db.fetchone("SELECT * FROM entries WHERE id = ?", (in_side,)))
    admin.delete_node(side)
    assert admin_client.push()["conflicts"] == []

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    bob_client.pull()
    # In the stateful run a server restored from a backup served the item
    # live below the deleted folder: Bob holds the copy from before the delete.
    bob.db.execute(
        "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, version = ?, is_deleted = 0 WHERE id = ?",
        (live["encrypted_meta"], live["encrypted_data"], live["version"], in_side),
    )
    old_key = teamlog.current_key(bob_client.team_state(), side)
    result = revocation.push_with_queued_revocations(bob, bob_client)
    assert result["conflicts"] == []
    assert bob_client.push()["conflicts"] == []  # settles: nothing below the deleted folder waits
    assert teamlog.current_key(bob_client.team_state(), side) != old_key  # re-keyed all the same
    assert bob.db.fetchone("SELECT is_deleted FROM nodes WHERE id = ?", (side,))["is_deleted"] == 1

    # The admin's account, back as admin, restores it and reads what was in it.
    hand_over_admin(bob, bob_client, admin.db.get_meta("user_id"), lambda fingerprint: True)
    admin_client.pull()
    revocation.push_with_queued_revocations(admin, admin_client)
    trash.restore_node(admin, side)
    assert admin_client.push()["conflicts"] == []
    assert admin.read_entry(in_side)["fields"][0]["value"] == "side-pw"
