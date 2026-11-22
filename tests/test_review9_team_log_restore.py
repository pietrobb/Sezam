"""Review 1141a20 (medium): a server restored from a backup lost team-log records (R9-E, goal #361).

Every device then reported TEAM LOG MISMATCH for good. A device holding the
lost records (signed by their authors, accepted here) uploads them again; a
server whose log is not a prefix of this device's (fork, other genesis) is
still refused.
"""

from __future__ import annotations

import pytest

from sezam.models import new_ulid
from sezam.vault import revocation
from sezam.vault.team_log_local import GENESIS_META, TeamLogMismatch
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import (  # noqa: F401
    _confirm_founder,
    _forget_server_cache,
    _found_with_bob,
    team,
)
from tests.test_team_log_desktop_changes import _ops, _server_head


def _restore_backup(db, keep: int) -> None:
    db._storage["team_log"] = [r for r in db._storage["team_log"] if r["seq"] < keep]
    _forget_server_cache()


@pytest.mark.parametrize("keep", [0, 2])
def test_a_restored_server_gets_the_lost_records_back(team, keep):  # noqa: F811
    db, admin, client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    revocation.grant_member(admin, client, bob_id, _ops(admin), "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    head = client.team_state().head_seq
    _restore_backup(db, keep)

    bob_client.pull()  # the member's device holds the records too

    assert _server_head(db) == head
    assert bob_client.team_state().head_seq == head
    client.pull()
    assert client.team_state().head_seq == head


def _forged_folder_key(db, client) -> dict:
    """A valid admin record the devices never saw, on the server's head."""
    from sezam import teamlog

    state = teamlog.replay([{"body": r["body"], "sig": r["sig"]} for r in db._storage["team_log"]])
    return teamlog.sign_record(
        teamlog.next_body(state, "folder.key", client._user_id,
                          {"folder": new_ulid(), "gen": 0, "dek_id": new_ulid(), "prev_dek_id": None}),
        client._keypair.to_nacl_signing_key(),
    )


def test_a_forked_server_log_is_still_refused(team):  # noqa: F811
    db, admin, client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    revocation.grant_member(admin, client, bob_id, _ops(admin), "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    held = bob_client.team_state().head_seq
    _restore_backup(db, 1)
    # The server puts another record where the device holds member.add bob.
    client._request("POST", "/api/team-log", {"records": [_forged_folder_key(db, client)]}, auth=True)
    stored = list(db._storage["team_log"])

    with pytest.raises(TeamLogMismatch, match="went back"):
        bob_client.pull()
    assert db._storage["team_log"] == stored  # nothing was put on top of the fork
    assert bob_client.team_state().head_seq == held


def test_a_server_log_with_another_genesis_is_still_refused(team):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    db._storage["team_log"] = []
    _forget_server_cache()
    client._db.execute("DELETE FROM team_log")
    client._db.execute("DELETE FROM vault_meta WHERE key = ?", (GENESIS_META,))
    client.found_team_log(new_ulid())  # another genesis, server head 0

    with pytest.raises(TeamLogMismatch, match="another genesis"):
        bob_client.pull()
    assert _server_head(db) == 0


def test_a_restore_the_server_refuses_stays_a_mismatch(team, monkeypatch):  # noqa: F811
    from server.app import team_log as server_log

    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    _restore_backup(db, 1)

    async def refuse(cur, records, user_id, **_):
        raise server_log.ApiError(400, server_log.TEAM_LOG_REFUSED, {"message": "no"})

    monkeypatch.setattr(server_log, "restore", refuse)
    with pytest.raises(TeamLogMismatch, match="went back"):
        bob_client.pull()
    assert _server_head(db) == 0


def test_a_member_cannot_found_an_organisation_through_restore(team):  # noqa: F811
    """A restore is no way around the genesis rule: founder must be an admin."""
    from sezam import teamlog

    db, admin, client, bob, bob_client = team
    genesis = teamlog.sign_record(
        teamlog.next_body(teamlog.TeamState(), "genesis", bob_client._user_id, {
            "org": new_ulid(), "user_id": bob_client._user_id,
            "signing_pk": bytes(bob.keypair.signing_pk).hex(),
            "encryption_pk": bytes(bob.keypair.encryption_pk).hex(),
        }),
        bob.keypair.to_nacl_signing_key(),
    )
    with pytest.raises(RuntimeError, match="founder .*admin here"):
        bob_client._request("POST", "/api/team-log/restore", {"records": [genesis]}, auth=True)
    assert db._storage["team_log"] == []


@pytest.mark.parametrize("who", ["member", "admin"])
def test_a_restore_from_before_an_identity_rotation_brings_the_rotation_back(team, server, who):  # noqa: F811
    """Capability run 277: a real backup rolls back the users table with the log."""
    import copy

    from sezam.vault import pending_states
    from sezam.vault.sync_client import KeyEpochStale, SyncClient
    from tests.test_integration_client_server import PASSWORD, _client
    from tests.test_review9_team_identity import _rotate

    url, _ = server
    db, admin, client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.get_field_value(item, "password") == "ops-pw"
    backup = copy.deepcopy(db._storage)
    vault, other = (bob, admin) if who == "member" else (admin, bob)
    uid = vault.db.get_meta("user_id")
    rotated = _rotate(vault, bob_client if who == "member" else client, url)
    rotated.push()
    new_pk = bytes(vault.keypair.signing_pk).hex()
    other_client = _client(other, url)
    other_client._refresh_team_log()  # the other device holds member.keys too
    head = other_client.team_state().head_seq
    assert other_client.team_state().members[uid].signing_pk == new_pk

    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    _forget_server_cache()

    if who == "member":
        _pull_confirming(other_client)  # puts member.keys back although the account lost the rotation
        assert _server_head(db) == head
    else:
        # Review c78fd19 #2: only the admin puts back a lost key rotation;
        # here the admin is the one that rotated: its own device does it below.
        with pytest.raises(TeamLogMismatch, match="went back"):
            _pull_confirming(other_client)
        assert _server_head(db) < head
    rotated = SyncClient(vault.db, url, vault.keypair, uid)
    rotated.set_dek_manager(vault.dek_mgr)
    with pytest.raises(KeyEpochStale):
        rotated.authenticate()  # the server knows only the retired keypair
    rotated.adopt_rotated_key_material(vault, PASSWORD)  # the user types the password
    rotated = SyncClient(vault.db, url, vault.keypair, uid)
    rotated.set_dek_manager(vault.dek_mgr)
    rotated.full_resync(confirmed=True)
    rotated.push()
    assert not pending_states.key_change_journal(vault.db)
    assert _server_head(db) == head
    assert bytes(vault.keypair.signing_pk).hex() == new_pk  # never back to the retired keypair
    assert rotated.team_state().members[uid].signing_pk == new_pk
    user = next(u for u in db._storage["users"] if u["id"] == uid)
    assert bytes(user["signing_pk"]).hex() == new_pk
    # It writes under the rotated key again, and every device follows.
    folder = ops if who == "admin" else vault.db.get_meta("root_node_id")
    written = vault.create_entry(folder, "after-restore", [{"key": "password", "value": "rotated"}])
    rotated.push()
    stored = [o for o in db._storage["vault_objects"] if o["id"] == written]
    assert stored and not stored[0].get("is_deleted")
    other_client = _client(other, url)
    _pull_confirming(other_client)
    other_client.push()  # a member's rotation: the admin seals its keys to it (goal #369)
    _pull_confirming(_client(vault, url))
    vault.lock()
    vault.unlock(PASSWORD)
    _pull_confirming(_client(vault, url))
    _pull_confirming(_client(bob, url))
    assert bob.get_field_value(written, "password") == "rotated"
    assert bob.get_field_value(item, "password") == "ops-pw"


def _pull_confirming(client) -> dict:
    """A pull whose user confirms a rotated member key (TOFU), as the CLI asks."""
    from sezam.vault.sync_common import TofuKeyChangeError

    for _ in range(4):
        try:
            return client.pull()
        except TofuKeyChangeError as change:
            client.confirm_tofu_key_change(change, change.new_fingerprint)
    raise AssertionError("pull kept asking to confirm keys")


def test_restore_never_gives_a_member_keys_the_account_does_not_hold(team):  # noqa: F811
    from sezam import teamlog

    db, admin, client, bob, bob_client = team
    client.found_team_log(new_ulid())
    state = client.team_state()
    ghost = teamlog.sign_record(
        teamlog.next_body(state, "member.add", client._user_id, {
            "user_id": bob_client._user_id, "signing_pk": "11" * 32, "encryption_pk": "22" * 32,
            "role": "member",
        }),
        client._keypair.to_nacl_signing_key(),
    )
    with pytest.raises(RuntimeError, match="keys the account does not sign in with"):
        client._request("POST", "/api/team-log/restore", {"records": [ghost]}, auth=True)
    assert _server_head(db) == 0
