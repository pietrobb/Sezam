"""Capability run 294: a restore from before an identity rotation revived the retired key.

The devices put member.keys back (R9-E), but the account still signed in
with the key that record retired, and the server took its pushes as the
member's. A lost or stolen device the rotation was for (it holds the old
key, here a copy of the vault from before) wrote into the member's tree and
into a shared folder, and the admin's desktop showed it without a question.

Now the server gives such a session nothing but reads and the rotation to the
log's keys, and every client takes a key its own log retired for a member
only below that key's archive bound, whatever the server calls current.
"""

from __future__ import annotations

import copy
import shutil

import pytest

from sezam.vault import revocation
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_common import IDENTITY_KEY_RETIRED, server_error
from tests.node_support import requires_node
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import (  # noqa: F401
    _confirm_founder,
    _forget_server_cache,
    _found_with_bob,
    team,
)
from tests.test_team_log_desktop_changes import _ops


def _steal_then_restore(team, server, tmp_path, who: str):  # noqa: F811
    """Rotate ``who`` away from K0, restore the server from before, keep a K0 device."""
    from tests.test_review9_team_identity import _rotate

    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    _confirm_founder(admin, bob)
    bob_client.pull()
    backup = copy.deepcopy(db._storage)
    vault, other = (bob, admin) if who == "member" else (admin, bob)
    name = "bob" if who == "member" else "admin"
    vault.lock()
    shutil.copytree(tmp_path / name, tmp_path / "stolen")  # the device the rotation shuts out
    vault.unlock(PASSWORD)
    _rotate(vault, _client(vault, url), url).push()
    other_client = _client(other, url)
    other_client._refresh_team_log()
    uid = vault.db.get_meta("user_id")
    assert other_client.team_state().members[uid].signing_pk == vault.keypair.signing_pk.hex()

    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    _forget_server_cache()
    if who == "member":
        other_client.pull()  # puts member.keys back; no key change to confirm
    else:
        # Review c78fd19 #2: only the admin puts back a lost key rotation,
        # here the rotated admin's own device; it stops before the rotation goes out.
        from sezam.vault.sync_client import KeyEpochStale

        rotated = SyncClient(vault.db, url, vault.keypair, uid)
        rotated.set_dek_manager(vault.dek_mgr)
        with pytest.raises(KeyEpochStale):
            rotated.authenticate()
        rotated.adopt_rotated_key_material(vault, PASSWORD)
        rotated = SyncClient(vault.db, url, vault.keypair, uid)
        rotated.set_dek_manager(vault.dek_mgr)
        rotated._put_back_lost_team_log(rotated._request("GET", "/api/team-log?since=999999", auth=True)["head"])
        other_client.pull()
    assert db._storage["team_log"][-1]["seq"] == other_client.team_state().head_seq
    thief = Vault(tmp_path / "stolen")
    thief.unlock(PASSWORD)
    thief_client = SyncClient(thief.db, url, thief.keypair, uid)
    thief_client.set_dek_manager(thief.dek_mgr)
    return db, ops, thief, thief_client, other, other_client



def _objects(db, entry_id):
    return [o for o in db._storage["vault_objects"] if o["id"] == entry_id]


@pytest.mark.parametrize("who", ["member", "admin"])
def test_the_server_takes_nothing_but_reads_from_a_retired_key(team, server, tmp_path, who):  # noqa: F811
    db, ops, thief, thief_client, _, _ = _steal_then_restore(team, server, tmp_path, who)
    thief_client.authenticate()
    thief_client._request("GET", "/api/team-log", auth=True)  # the log and keys stay readable
    with pytest.raises(RuntimeError) as refused:  # capability run 300: no objects
        thief_client._request("GET", "/api/sync?since_commit_seq=0", auth=True)
    assert server_error(refused.value, 403, IDENTITY_KEY_RETIRED), refused.value
    head = db._storage["team_log"][-1]["seq"]
    for folder in (thief.db.get_meta("root_node_id"), ops):
        written = thief.create_entry(folder, "by-retired-key", [{"key": "password", "value": "stolen"}])
        with pytest.raises(Exception) as refused:
            thief_client.push()
        assert server_error(refused.value, 403, IDENTITY_KEY_RETIRED), refused.value
        assert not _objects(db, written)
    for call in (
        lambda: thief_client._request("POST", "/api/team-log", {"records": []}, auth=True),
        lambda: thief_client._request("POST", "/api/team-log/restore", {"records": []}, auth=True),
        lambda: thief_client.create_invitation(),
    ):
        with pytest.raises(RuntimeError, match="403"):
            call()
    assert db._storage["team_log"][-1]["seq"] == head


@pytest.mark.parametrize("who", ["member", "admin"])
def test_a_retired_key_reads_nothing_written_after_the_restore(team, server, tmp_path, who, monkeypatch):  # noqa: F811
    """Capability run 300: the folder DEKs outlive a rotation, so whatever the
    K0 session pulls, a K0 device opens (its own checks off, as a thief runs it)."""
    from sezam import teamlog

    db, ops, thief, thief_client, other, other_client = _steal_then_restore(team, server, tmp_path, who)
    other.create_entry(ops, "after-restore", [{"key": "password", "value": "secret2"}])
    other_client.push()
    monkeypatch.setattr(teamlog, "envelope_valid", lambda *a, **k: True)
    monkeypatch.setattr(thief_client, "_verify_object_signature", lambda obj: True)
    thief_client.authenticate()
    with pytest.raises(RuntimeError) as refused:
        thief_client.pull()
    assert server_error(refused.value, 403, IDENTITY_KEY_RETIRED), refused.value
    # Nor does it prove the log's key with the one it holds.
    from sezam.vault.sync_common import auth_verify_body

    challenge = thief_client._request("POST", "/api/auth/challenge", {"username": thief_client._get_username()})
    signing = thief.keypair.to_nacl_signing_key()
    body = auth_verify_body(thief_client._get_username(), challenge["challenge"], signing, signing)
    thief_client._token = thief_client._request("POST", "/api/auth/verify", body)["token"]
    with pytest.raises(RuntimeError, match="403"):
        thief_client._request("GET", "/api/sync?since_commit_seq=0", auth=True)
    assert "after-restore" not in {e["name"] for e in thief.list_entries(ops)}


def test_the_desktop_refuses_a_retired_key_the_server_calls_current(team, server, tmp_path, monkeypatch):  # noqa: F811
    from server.app import team_log as server_log

    db, ops, thief, thief_client, admin, admin_client = _steal_then_restore(team, server, tmp_path, "member")
    monkeypatch.setattr(server_log, "key_retired", lambda *a: False)  # a server that takes it anyway
    thief_client.authenticate()
    written = thief.create_entry(ops, "by-retired-key", [{"key": "password", "value": "stolen"}])
    thief_client.push()
    assert _objects(db, written)

    with pytest.raises(RuntimeError, match="unverifiable signature"):
        _client(admin, admin_client._server_url).pull()  # no key change asked, none confirmed
    assert written not in {e["id"] for e in admin.list_entries(ops)}


def test_the_phone_refuses_a_retired_key_the_server_calls_current(team, server, tmp_path, monkeypatch):  # noqa: F811
    """Capability run 300: TeamLog.signingKeyRetired in the phone's pull."""
    from server.app import team_log as server_log
    from tests.test_cross_client_password_change import _phone

    url, _ = server
    db, ops, thief, thief_client, admin, admin_client = _steal_then_restore(team, server, tmp_path, "member")
    monkeypatch.setattr(server_log, "key_retired", lambda *a: False)
    thief_client.authenticate()
    seq = max(o["commit_seq"] for o in db._storage["vault_objects"])
    written = thief.create_entry(ops, "by-retired-key", [{"key": "password", "value": "stolen"}])
    thief_client.push()
    forged = [o["id"] for o in db._storage["vault_objects"] if o["commit_seq"] > seq]
    assert written in forged
    out = _phone(url, tmp_path, {
        "username": "admin", "password": PASSWORD, "user_id": admin.db.get_meta("user_id"),
        "genesis": admin_client.team_state().genesis_hash, "forged": forged,
    }, {}, "test/phone_retired_key_test.dart")
    assert "All tests passed!" in out, out


@requires_node
def test_the_browser_refuses_a_retired_key_the_server_calls_current(team, server, tmp_path, monkeypatch):  # noqa: F811
    from server.app import team_log as server_log
    from tests.web_tab import WebTab

    url, _ = server
    db, ops, thief, thief_client, _, _ = _steal_then_restore(team, server, tmp_path, "member")
    monkeypatch.setattr(server_log, "key_retired", lambda *a: False)
    thief_client.authenticate()
    thief.create_entry(ops, "by-retired-key", [{"key": "password", "value": "stolen"}])
    thief_client.push()

    tab = WebTab(url, tmp_path / "retired-key-tab.log")  # a fresh session: K0 is its first sight of bob
    try:
        seen = tab.do("login", username="admin", password=PASSWORD)
        assert seen["error"] and "invalid Ed25519 signature" in seen["error"], seen
        names = {e["name"] for e in (seen.get("view") or {}).get("entries", [])}
        assert "by-retired-key" not in names
    finally:
        tab.kill()
