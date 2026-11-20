"""Review 1141a20 H6 (desktop): outside team folders the old heuristics.

Below the first level of the organisation's own tree (a folder the admin did
not share, so not in the log, not a member's personal tree) the desktop
applied any member's write and any member's deletion: a lying server let
Bob plant an item in the admin's unshared folder and delete the admin's own.
With a team log only an admin the log made writes there.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest
from nacl.exceptions import CryptoError

import server.app.team_log as server_team_log
from sezam import teamlog
from sezam.models import new_ulid
from sezam.vault import revocation
from sezam.vault.sync_writers import IGNORED_WRITES_META
from sezam.vault.team_log_local import TeamLogMismatch
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review6_web_member_personal_folder import sealed
from tests.test_review7_forged_root_folder_desktop_h4 import _login, _post, _server_base
from tests.test_server_spec import _sign_sync_object
from tests.test_team_log_desktop import (
    _confirm_founder,
    _found_with_bob,
    team,  # noqa: F401  (fixture)
)
from tests.test_team_log_desktop_changes import _carol, _ops
from tests.test_team_log_desktop_pull import (
    _applied,
    _entry_payload,
    _lying_server,
    shared,  # noqa: F401  (fixture)
)


def test_a_head_with_two_admins_is_refused(team, monkeypatch):  # noqa: F811
    """TL7: one admin per organisation in every client, not only the server."""
    _db, _admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    lax = SimpleNamespace(**{**vars(teamlog), "admin_policy_refusal": lambda _state: None})
    monkeypatch.setattr(server_team_log, "core", lax)
    admin_client.append_team_log([("member.role", {"user_id": bob.db.get_meta("user_id"), "role": "admin"})])
    with pytest.raises(TeamLogMismatch, match="more than one admin"):
        bob_client.pull()


def test_after_a_handover_a_new_device_keeps_the_former_admins_items(team):  # noqa: F811
    """Review 1141a20: after the handover everything the old admin wrote vanished."""
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, "read")
    assert ops in admin_client.team_state().folders
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    root = admin.db.get_meta("root_node_id")
    unshared = admin.create_node("Secret", parent_id=root, create_dek=False)
    deep = admin.create_entry(unshared, "db", [{"key": "password", "value": "x"}])
    assert admin_client.push()["conflicts"] == []
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    admin_client.append_team_log([
        ("member.role", {"user_id": bob_id, "role": "admin"}),
        ("member.role", {"user_id": admin_id, "role": "member"}),
    ])
    assert not teamlog.is_admin(admin_client.team_state(), admin_id)

    _confirm_founder(admin, bob)
    assert bob_client.pull()["skipped"] == 0
    assert _applied(bob, item) and _applied(bob, deep)


def test_a_member_takes_no_key_the_log_does_not_know(team, monkeypatch):  # noqa: F811
    """Review 1141a20 H6: with a log, a key reaches a member only through the log.

    An envelope on a key without folder.key was judged by the old rules (who
    signed the top of the tree): the member took it and could seal with it.
    """
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    side = admin.create_node("Side")
    assert admin_client.push()["conflicts"] == []
    key = admin.dek_mgr.get_dek_for_node(side)[0]
    envelope = admin.grant_folder_access(side, bob.db.get_meta("user_id"), bytes(bob.keypair.encryption_pk), "read")
    # Review c78fd19 R13-10: the server refuses it too ...
    assert [c["error"] for c in admin_client.push()["conflicts"]] == [
        "team log: another account gets a key only with an access.set"]
    # ... and a server that takes it anyway gives the member nothing.
    _lying_server(monkeypatch)
    monkeypatch.setattr(server_team_log, "envelope_refusal", lambda *_a, **_k: None)
    assert admin_client.push()["conflicts"] == []
    assert key not in admin_client.team_state().dek_index

    bob_client.pull()
    assert bob.db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (envelope,)) is None
    with pytest.raises(CryptoError):
        bob.dek_mgr.unlock_dek(key)


def test_a_rekey_seals_a_key_the_log_does_not_know_to_nobody_else(team, server, tmp_path, monkeypatch):  # noqa: F811
    """§9: who holds a key without a record in the log does not get the next one."""
    _db, admin, admin_client, bob, _bob_client = team
    carol = _carol(server[0], admin_client, tmp_path, monkeypatch)
    side = admin.create_node("Side")
    for member in (bob, carol):
        admin_client.verified_encryption_pk(member.db.get_meta("user_id"))
        admin.grant_folder_access(side, member.db.get_meta("user_id"), bytes(member.keypair.encryption_pk), "read")
    assert admin_client.push()["conflicts"] == []
    _found_with_bob(admin_client, bob)
    assert side not in admin_client.team_state().folders
    old = admin.dek_mgr.get_dek_for_node(side)[0]
    admin.rekey_after_revocation(carol.db.get_meta("user_id"))
    new = admin.dek_mgr.get_dek_for_node(side)[0]
    assert new != old
    assert admin.db.fetchall("SELECT user_id FROM access_envelopes WHERE dek_id = ? AND user_id != ?",
                             (new, admin.db.get_meta("user_id"))) == []


def _push(url, token, sk, obj_id, kind, parent, payload, version=1, deleted=0):
    digest = hashlib.sha256(payload).hexdigest()
    result = _post(url, "/api/sync", {"atomic_batch": False, "objects": [{
        "id": obj_id, "object_type": kind, "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "version": version, "is_deleted": deleted, "payload_hash": digest,
        "signature": _sign_sync_object(sk, obj_id, kind, parent, None, deleted, version, digest),
        "write_policy": "owner_only",
        **(_server_base(url, token, obj_id) if version > 1 else {}),
    }]}, token)
    assert len(result["accepted"]) == 1, result
    return result


def _unshared_folder(admin, admin_client):
    """The admin's folder below the root, under the root's key: not in the log."""
    root = admin.db.get_meta("root_node_id")
    secret = admin.create_node("Secret", parent_id=root, create_dek=False)
    item = admin.create_entry(secret, "db", [{"key": "password", "value": "admin-pw"}])
    assert admin_client.push()["conflicts"] == []
    assert secret not in admin_client.team_state().folders
    root_dek = admin.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (root,))["dek_id"]
    return secret, item, root_dek


def test_a_member_cannot_write_into_the_admins_unshared_folder(shared, monkeypatch):  # noqa: F811
    url, admin, admin_client, _bob_id, _ops, sk, token = shared
    secret, _item, root_dek = _unshared_folder(admin, admin_client)
    _lying_server(monkeypatch)
    planted, sub = new_ulid(), new_ulid()
    _push(url, token, sk, planted, "entry", secret, _entry_payload(root_dek))
    _push(url, token, sk, sub, "node", secret, sealed(root_dek))

    assert admin_client.pull()["skipped"] == 2
    assert not _applied(admin, planted)
    assert admin.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (sub,)) is None
    assert {planted, sub} <= set(admin.db.get_meta_json(IGNORED_WRITES_META))


def test_a_member_cannot_delete_from_the_admins_unshared_folder(shared, team, monkeypatch):  # noqa: F811
    url, admin, admin_client, bob_id, _ops, sk, _token = shared
    secret, item, _root_dek = _unshared_folder(admin, admin_client)
    # The server calls Bob an admin; the log does not.
    next(u for u in team[0]._storage["users"] if u["id"] == bob_id)["is_admin"] = 1
    token = _login(url, sk, "bob")
    _lying_server(monkeypatch)
    version = admin.db.fetchone("SELECT version FROM entries WHERE id = ?", (item,))["version"]
    _push(url, token, sk, item, "entry", secret, b"", version=version + 1, deleted=1)

    assert admin_client.pull()["skipped"] == 1
    assert {e["name"] for e in admin.list_entries(secret)} == {"db"}


def test_the_admins_own_writes_there_still_apply(shared):  # noqa: F811
    url, admin, admin_client, _bob_id, _ops, _sk, _token = shared
    secret, item, _root_dek = _unshared_folder(admin, admin_client)
    laptop_entry = admin.create_entry(secret, "second", [{"key": "password", "value": "x"}])
    admin.delete_entry(item)
    assert admin_client.push()["conflicts"] == []
    assert admin_client.pull()["skipped"] == 0
    assert {e["name"] for e in admin.list_entries(secret)} == {"second"}
    assert _applied(admin, laptop_entry)
