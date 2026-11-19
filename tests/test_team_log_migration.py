"""Founding the team log of an organisation that already shares folders (TL6; docs/DESIGN_TEAM_LOG.md §9).

Real desktop clients against the real server. Before the log the admin shared
Ops with Bob (write) and Carol (read) the old way; Dan is approved but his key
was never confirmed. The admin founds the log from that state in one append:
Bob and Carol are members with the levels of the admin's envelopes, Dan gets
nothing, and from then on the log decides (server write_acl, re-key to the
log's members only).
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli, teamlog
from sezam.vault import revocation
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from sezam.vault.team_migration import add_member, found_team_log
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_team_log_desktop import team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops, _server_head


def _yes(_fp: str) -> bool:
    return True


def _approved(url, admin_client, path, name, monkeypatch):
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    invitation = admin_client.create_invitation()
    vault = _vault(path, name)
    cli._server_register_and_upload(
        url, vault, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    admin_client.approve_user(vault.db.get_meta("user_id"))
    return vault


@pytest.fixture
def org(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    carol = _approved(url, admin_client, tmp_path / "carol", "carol", monkeypatch)
    dan = _approved(url, admin_client, tmp_path / "dan", "dan", monkeypatch)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []
    ids = {name: v.db.get_meta("user_id") for name, v in (("bob", bob), ("carol", carol), ("dan", dan))}
    revocation.grant_member(admin, admin_client, ids["bob"], ops, "write", confirm_fingerprint=_yes)
    revocation.grant_member(admin, admin_client, ids["carol"], ops, "read", confirm_fingerprint=_yes)
    assert admin_client.team_state() is None
    yield db, admin, admin_client, bob, bob_client, carol, ids, ops, dan
    carol.lock()
    dan.lock()


def test_the_log_is_founded_from_the_current_state(org):
    db, admin, admin_client, bob, bob_client, _carol, ids, ops, _dan = org
    asked = []
    result = found_team_log(admin, admin_client, lambda uid, fp: asked.append(uid) or False)

    assert asked == [ids["dan"]]  # Bob and Carol were confirmed by their grants
    assert result.unconfirmed == [ids["dan"]]
    assert sorted(result.members) == sorted([ids["bob"], ids["carol"]])
    assert result.folders == [ops]
    state = admin_client.team_state()
    assert state.head_seq == _server_head(db) == 5  # seq 0-5: genesis, 2 members, key, 2 access
    assert state.access[ops] == {ids["bob"]: "write", ids["carol"]: "read"}
    assert teamlog.current_key(state, ops) == admin.dek_mgr.get_dek_for_node(ops)[0]
    assert ids["dan"] not in state.members
    assert teamlog.is_admin(state, admin.db.get_meta("user_id"))
    assert not teamlog.is_admin(state, ids["bob"])
    # The server's write_acl is the log's now.
    acl = {(r["user_id"], r["node_id"]) for r in db._storage["write_acl"]}
    assert (ids["bob"], ops) in acl and (ids["carol"], ops) not in acl

    bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin.db.get_meta("user_id"): admin.keypair.fingerprint,
    })
    bob_client.pull()
    assert bob_client.team_state().to_json() == state.to_json()

    with pytest.raises(RuntimeError, match="already has a team log"):
        found_team_log(admin, admin_client)


def test_migration_does_not_sign_server_invented_write_access(org, server, tmp_path):  # noqa: F811
    url, _ = server
    db, admin, admin_client, _bob, _bob_client, _carol, ids, ops, _dan = org
    for envelope in _bob_envelopes_live(db, ids["carol"]):
        envelope["access_level"] = "write"  # Not covered by the envelope signature.
    other = _vault(tmp_path / "migrator", "admin")
    try:
        cli._server_connect_flow(url, other, PASSWORD)
        other_client = _client(other, url)
        found_team_log(other, other_client, lambda uid, fp: True)
        assert other_client.team_state().access[ops][ids["carol"]] == "read"
        assert (ids["carol"], ops) not in {
            (row["user_id"], row["node_id"]) for row in db._storage["write_acl"]
        }
    finally:
        other.lock()


@pytest.mark.parametrize("cut", [False, True])
def test_founding_more_records_than_one_append_holds(org, monkeypatch, cut):
    """Review 1141a20: one POST of >1000 records was refused (422) on every push, forever."""
    db, admin, admin_client, bob, _bob_client, _carol, ids, ops, _dan = org
    bob_pk = admin_client.verified_encryption_pk(ids["bob"])
    folders = [admin.create_node(f"shared-{i:03}") for i in range(520)]
    for folder in folders:
        admin.grant_folder_access(folder, ids["bob"], bob_pk, "read")
    assert admin_client.push()["conflicts"] == []

    if cut:  # The connection drops after the first part landed.
        real, appends = admin_client._request, []

        def second_append_fails(method, path, *args, **kwargs):
            if method == "POST" and path == "/api/team-log":
                appends.append(path)
                if len(appends) == 2:
                    raise OSError("connection reset")
            return real(method, path, *args, **kwargs)

        monkeypatch.setattr(admin_client, "_request", second_append_fails)
        with pytest.raises(OSError):
            found_team_log(admin, admin_client, lambda uid, fp: False)
        assert _server_head(db) == admin_client.team_state().head_seq == 999
        assert admin_client.pending_team_changes()  # the rest waits, nothing is lost
        monkeypatch.setattr(admin_client, "_request", real)
        assert admin_client.push()["conflicts"] == []
        result = None
    else:
        result = found_team_log(admin, admin_client, lambda uid, fp: False)

    state = admin_client.team_state()
    # genesis, Bob, Carol, then key + access for Ops and every new folder.
    assert state.head_seq == _server_head(db) == 2 + 2 * (len(folders) + 1) + 1
    assert admin_client.pending_team_changes() == []
    assert result is None or len(result.folders) == len(folders) + 1
    assert all(state.access[f] == {ids["bob"]: "read"} for f in folders)
    assert state.access[ops] == {ids["bob"]: "write", ids["carol"]: "read"}
    assert admin_client.push()["conflicts"] == []  # nothing stuck behind the log


def test_after_founding_a_removal_rekeys_to_the_logs_members_only(org):
    db, admin, admin_client, _bob, _bob_client, _carol, ids, ops, _dan = org
    found_team_log(admin, admin_client, lambda uid, fp: False)
    old_key = teamlog.current_key(admin_client.team_state(), ops)

    assert revocation.revoke_member(admin, admin_client, ids["carol"]) == 1

    state = admin_client.team_state()
    new_key = teamlog.current_key(state, ops)
    assert new_key != old_key
    holders = {o["target_user_id"] for o in db._storage["vault_objects"]
               if o["object_type"] == "envelope" and not o["is_deleted"] and o.get("parent_ref") == new_key}
    assert holders == {ids["bob"]}
    assert _bob_envelopes_live(db, ids["dan"]) == []


def test_the_founder_is_the_only_admin(org):
    """TL7: one admin per organisation for now, whatever the server's flag says."""
    db, admin, admin_client, *_rest, ids, _ops_id, _dan = org
    next(u for u in db._storage["users"] if u["id"] == ids["bob"])["is_admin"] = 1
    found_team_log(admin, admin_client, lambda uid, fp: False)
    state = admin_client.team_state()
    assert [uid for uid in state.members if teamlog.is_admin(state, uid)] == [admin.db.get_meta("user_id")]
    with pytest.raises(Exception, match="one admin"):
        admin_client.append_team_log([("member.role", {"user_id": ids["bob"], "role": "admin"})])
    assert not teamlog.is_admin(admin_client.team_state(), ids["bob"])


def test_an_admin_left_out_of_the_log_loses_the_admin_flag(org, server):  # noqa: F811
    """Review 1141a20: an account left out at founding kept is_admin."""
    url, _ = server
    db, admin, admin_client, *_rest, ids, _ops_id, dan = org
    next(u for u in db._storage["users"] if u["id"] == ids["dan"])["is_admin"] = 1
    dan_client = _client(dan, url)
    dan_client.create_invitation()  # an admin before the log

    found_team_log(admin, admin_client, lambda uid, fp: False)

    assert ids["dan"] not in admin_client.team_state().members
    assert next(u for u in db._storage["users"] if u["id"] == ids["dan"])["is_admin"] == 0
    with pytest.raises(Exception, match="401|403"):
        dan_client.create_invitation()  # the old token, then a fresh login: no admin
    dan_client._token = None
    with pytest.raises(Exception, match="403"):
        dan_client.create_invitation()
    admin_client.create_invitation()  # the founder stays the admin


def test_a_device_without_the_log_cannot_found_a_second_one(org, server, tmp_path):  # noqa: F811
    url, _ = server
    _db, admin, admin_client, *_rest = org
    found_team_log(admin, admin_client, lambda uid, fp: False)
    other = _vault(tmp_path / "admin2", "admin")
    cli._server_connect_flow(url, other, PASSWORD)
    with pytest.raises(RuntimeError, match="already has a team log"):
        found_team_log(other, _client(other, url))
    other.lock()


def test_an_account_left_out_is_added_later_with_a_confirmed_key(org):
    _db, admin, admin_client, *_rest, ids, ops, dan = org
    found_team_log(admin, admin_client, lambda uid, fp: False)
    with pytest.raises(ValueError, match="not confirmed"):
        add_member(admin, admin_client, ids["dan"], confirm_fingerprint=lambda fp: False)
    add_member(admin, admin_client, ids["dan"],
               confirm_fingerprint=lambda fp: fp == dan.keypair.fingerprint)
    state = admin_client.team_state()
    assert state.members[ids["dan"]].active and state.members[ids["dan"]].role == "member"
    # A member gets folders by a grant, which the log records.
    revocation.grant_member(admin, admin_client, ids["dan"], ops, "read")
    assert admin_client.team_state().access[ops][ids["dan"]] == "read"


def _as(vault, monkeypatch):
    monkeypatch.setattr(cli, "_open_vault", lambda: vault)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda v, *a, **k: PASSWORD)
    monkeypatch.setattr(vault, "lock", lambda: None)


@pytest.mark.parametrize("anchor", ["original", "intermediate", "current"])
def test_cli_confirms_founder_through_rotations(team, server, monkeypatch, anchor):  # noqa: F811
    from tests.test_review9_team_identity import _rotate
    from tests.test_team_log_desktop import _found_with_bob

    url, _ = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    fingerprints = [admin.keypair.fingerprint]
    for _ in range(2):
        admin_client = _rotate(admin, admin_client, url)
        admin_client.push()
        fingerprints.append(admin.keypair.fingerprint)
    fingerprint = fingerprints[["original", "intermediate", "current"].index(anchor)]
    lock = bob.lock
    _as(bob, monkeypatch)
    out = CliRunner().invoke(cli.main, ["team-log", "confirm-founder", fingerprint])
    assert out.exit_code == 0, out.output
    assert bob_client.team_log_trusted()
    assert bob.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META)[admin.db.get_meta("user_id")] == fingerprint
    assert admin.keypair.fingerprint in CliRunner().invoke(cli.main, ["team-log", "status"]).output
    lock()
    bob.unlock(PASSWORD)
    assert _client(bob, url).team_log_trusted()


def test_cli_init_and_the_member_confirms_the_founder(org, monkeypatch):
    _db, admin, admin_client, bob, bob_client, _carol, ids, _ops_id, dan = org
    _as(admin, monkeypatch)
    init = ["team-log", "init", "--fingerprint", f"{ids['dan']}={dan.keypair.fingerprint}"]
    out = CliRunner().invoke(cli.main, init, input="n\n")
    assert out.exit_code != 0 and "nothing was signed" in out.output
    assert admin_client.team_state() is None and not _db._storage["team_log"]
    out = CliRunner().invoke(cli.main, init, input="y\n")
    assert out.exit_code == 0, out.output
    # Review 1141a20 H3: the admin saw what is signed, with the folder's name.
    assert f"{ids['bob']}=write, {ids['carol']}=read" in out.output
    assert f"folder {admin.read_node(_ops_id)['name']} ({_ops_id})" in out.output
    assert "3 member(s), 1 shared folder(s)" in out.output
    assert ids["dan"] in admin_client.team_state().members

    _as(bob, monkeypatch)
    out = CliRunner().invoke(cli.main, ["team-log", "status"])
    assert out.exit_code == 0, out.output
    assert admin.keypair.fingerprint in out.output and "NOT trusted" in out.output
    assert not bob_client.team_log_trusted()
    out = CliRunner().invoke(cli.main, ["team-log", "confirm-founder", "00" * 32])
    assert out.exit_code != 0 and "Nothing was confirmed" in out.output
    assert not bob_client.team_log_trusted()
    out = CliRunner().invoke(cli.main, ["team-log", "confirm-founder", admin.keypair.fingerprint])
    assert out.exit_code == 0, out.output
    assert bob_client.team_log_trusted()
    assert "Trusted on this device" in CliRunner().invoke(cli.main, ["team-log", "status"]).output
