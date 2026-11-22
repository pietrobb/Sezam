"""Pushes once the organisation has a team log (TL3; docs/DESIGN_TEAM_LOG.md §4.3.4-6, §5).

Rights, the current key and who may hold it come from the log: write_acl of a
team folder is its access.set records, an item must be sealed with the
folder's current generation by someone the log lets write, an envelope only
gives the current key to a member the log grants it, admins included.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    _sign_sync_object,
    _with_server_base,
    app_client,
    mock_db,
)
from tests.test_team_log_server import ADMIN, BOB, CAROL, FOLDER, K1, K2, K3, Team, _auth, _founded

DAN = "01JM0000000000000000000004"
ENTRY = "01JE0000000000000000000001"


def _sealed(dek_id: str, salt: bytes = b"") -> bytes:
    # alg, schema, kind, 26-byte DEK id, 24-byte nonce, ciphertext (the header the server reads)
    return b"\x01\x01\x01" + dek_id.encode() + (b"\x00" * 24) + b"c" * 20 + salt


def _obj(sk, obj_id: str, object_type: str, payload: bytes, *, parent=None, target=None,
         level=None, version: int = 1, deleted: int = 0) -> dict:
    payload_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": obj_id, "object_type": object_type, "payload": base64.b64encode(payload).decode(),
        "parent_ref": parent, "target_user_id": target, "access_level": level,
        "version": version, "is_deleted": deleted, "payload_hash": payload_hash,
        "signature": _sign_sync_object(sk, obj_id, object_type, parent, target, deleted, version,
                                       payload_hash),
    }


async def _push(client, team: Team, author: str, objects: list, records: list | None = None):
    body = {"objects": _with_server_base(objects), "atomic_batch": True}
    if records:
        body["team_log"] = records
    return await client.post("/api/sync", json=body, headers=_auth(team.token[author]))


def _errors(resp) -> list[str]:
    assert resp.status_code == 409, resp.text
    return [c["error"] for c in resp.json()["detail"]["conflicts"]]


def _acl(mock_db) -> list[tuple[str, str]]:
    return sorted((a["user_id"], a["node_id"]) for a in mock_db._storage.get("write_acl", []))


async def _team_folder(client, team: Team) -> None:
    """FOLDER with key K1; Bob may write, Carol may read."""
    await _founded(client, team)
    records = []
    for kind, data in (
        ("folder.key", {"folder": FOLDER, "gen": 0, "dek_id": K1, "prev_dek_id": None}),
        ("access.set", {"folder": FOLDER, "user_id": BOB, "level": "write"}),
        ("access.set", {"folder": FOLDER, "user_id": CAROL, "level": "read"}),
    ):
        records.append(team.record(kind, ADMIN, data))
        team.accept(records[-1])
    sk = team.sk[ADMIN]
    resp = await _push(client, team, ADMIN, [
        _obj(sk, FOLDER, "node", _sealed(K1)),
        _obj(sk, K1, "dek", b"wrapped K1" * 8, parent=FOLDER),
    ], records)
    assert resp.status_code == 200, resp.text


def _entry(team: Team, author: str, dek: str, obj_id: str = ENTRY, version: int = 1,
           parent: str | None = FOLDER) -> dict:
    # An entry's payload: u32be(len(meta)) + meta + data, the meta's header names the key.
    meta = _sealed(dek, author.encode())
    return _obj(team.sk[author], obj_id, "entry", len(meta).to_bytes(4, "big") + meta + _sealed(dek),
                parent=parent, version=version)


@pytest.mark.asyncio
async def test_write_acl_is_the_logs_access(app_client, mock_db):
    team = Team(mock_db)
    await _team_folder(app_client, team)
    assert _acl(mock_db) == [(BOB, FOLDER)]
    sk = team.sk[ADMIN]
    # An envelope claiming more than the log grants is refused ...
    wider = _obj(sk, "01JV0000000000000000000001", "envelope", b"e" * 80, parent=K1, target=CAROL,
                 level="write")
    assert _errors(await _push(app_client, team, ADMIN, [wider])) == [
        "envelope access differs from the team log"]
    # ... the matching one lands and does not touch write_acl.
    read = _obj(sk, "01JV0000000000000000000001", "envelope", b"e" * 80, parent=K1, target=CAROL,
                level="read")
    assert (await _push(app_client, team, ADMIN, [read])).status_code == 200
    assert _acl(mock_db) == [(BOB, FOLDER)]
    # Taking the write away in the log takes the write_acl row away.
    down = team.record("access.set", ADMIN, {"folder": FOLDER, "user_id": BOB, "level": "read"})
    team.accept(down)
    resp = await app_client.post("/api/team-log", json={"records": [down]}, headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200, resp.text
    assert _acl(mock_db) == []


@pytest.mark.asyncio
async def test_a_member_writes_with_log_access_and_the_current_key(app_client, mock_db):
    team = Team(mock_db)
    await _team_folder(app_client, team)
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K1)])).status_code == 200
    assert _errors(await _push(app_client, team, CAROL, [
        _entry(team, CAROL, K1, "01JE0000000000000000000002")])) == [
        "team log gives no write access here"]
    assert _errors(await _push(app_client, team, BOB, [
        _entry(team, BOB, K3, "01JE0000000000000000000003")])) == [
        "sealed with a key the team log does not know"]


@pytest.mark.asyncio
async def test_a_lowered_access_stops_sealing_until_the_rekey(app_client, mock_db):
    team = Team(mock_db)
    await _team_folder(app_client, team)
    gone = team.record("access.set", ADMIN, {"folder": FOLDER, "user_id": CAROL, "level": None})
    team.accept(gone)
    resp = await app_client.post("/api/team-log", json={"records": [gone]}, headers=_auth(team.token[ADMIN]))
    assert resp.status_code == 200, resp.text
    # Carol still knows K1: nothing new is sealed with it, not even by the admin.
    assert _errors(await _push(app_client, team, ADMIN, [_entry(team, ADMIN, K1)])) == [
        "folder waits for a re-key"]
    rekey = team.record("folder.key", ADMIN, {"folder": FOLDER, "gen": 1, "dek_id": K2, "prev_dek_id": K1})
    team.accept(rekey)
    resp = await _push(app_client, team, ADMIN, [
        _obj(team.sk[ADMIN], K2, "dek", b"wrapped K2" * 8, parent=FOLDER)], [rekey])
    assert resp.status_code == 200, resp.text
    assert _errors(await _push(app_client, team, BOB, [_entry(team, BOB, K1)])) == [
        "sealed with an old key generation"]
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K2)])).status_code == 200


@pytest.mark.asyncio
async def test_an_admin_the_log_does_not_name_has_no_team_rights(app_client, mock_db):
    team = Team(mock_db)
    await _team_folder(app_client, team)
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K1)])).status_code == 200
    sk, _ = _create_admin_user(mock_db._storage, DAN, "dan")
    team.sk[DAN], team.token[DAN] = sk, _create_jwt(DAN, "dan", True)
    assert _errors(await _push(app_client, team, DAN, [
        _entry(team, DAN, K1, "01JE0000000000000000000004")])) == ["team log gives no write access here"]
    tombstone = _obj(sk, ENTRY, "entry", b"", parent=FOLDER, version=2, deleted=1)
    assert _errors(await _push(app_client, team, DAN, [tombstone])) == [
        "team log gives no write access here"]
    envelope = _obj(sk, "01JV0000000000000000000002", "envelope", b"e" * 80, parent=K1, target=CAROL,
                    level="read")
    # R15-F1-S2: the log names another admin, so this request has none at all
    # (authority.team_admin): the first admin-only check refuses the envelope.
    assert _errors(await _push(app_client, team, DAN, [envelope])) == [
        "target_user_id is admin only"]


@pytest.mark.asyncio
@pytest.mark.parametrize("author", ["unnamed_admin", "reader"])
async def test_a_personal_key_does_not_bypass_the_logs_write_access(app_client, mock_db, author):
    """Capability finding 204: an own DEK (no parent_ref) under a team folder still needs may_write."""
    team = Team(mock_db)
    await _team_folder(app_client, team)
    if author == "unnamed_admin":
        sk, _ = _create_admin_user(mock_db._storage, DAN, "dan")
        team.sk[DAN], team.token[DAN] = sk, _create_jwt(DAN, "dan", True)
        user = DAN
    else:
        user = CAROL
    own = "01JD0000000000000000000009"
    resp = await _push(app_client, team, user, [
        _obj(team.sk[user], own, "dek", b"own key" * 10),
        _entry(team, user, own, "01JE0000000000000000000009"),
    ])
    assert "team log gives no write access here" in _errors(resp)
    assert not any(o["id"] == "01JE0000000000000000000009" for o in mock_db._storage["vault_objects"])
    # A writer may still keep a personal (tier-2) item there until TL7 moves it.
    resp = await _push(app_client, team, BOB, [
        _obj(team.sk[BOB], "01JD000000000000000000000A", "dek", b"own key" * 10),
        _entry(team, BOB, "01JD000000000000000000000A", "01JE000000000000000000000A"),
    ])
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("author", ["unnamed_admin", "reader"])
@pytest.mark.parametrize("target", [None, "elsewhere"])
async def test_moving_an_item_out_of_a_team_folder_needs_write_there(app_client, mock_db, author, target):
    """Capability finding 205: leaving a team folder is a removal from it, decided by the log."""
    team = Team(mock_db)
    await _team_folder(app_client, team)
    assert (await _push(app_client, team, BOB, [_entry(team, BOB, K1)])).status_code == 200
    if author == "unnamed_admin":
        sk, _ = _create_admin_user(mock_db._storage, DAN, "dan")
        team.sk[DAN], team.token[DAN] = sk, _create_jwt(DAN, "dan", True)
        user = DAN
    else:
        user = CAROL
    parent = None
    if target == "elsewhere":
        # A folder outside every team folder.
        parent, admin_own = "01JN000000000000000000000B", "01JD000000000000000000000C"
        resp = await _push(app_client, team, ADMIN, [
            _obj(team.sk[ADMIN], admin_own, "dek", b"own key" * 10),
            _obj(team.sk[ADMIN], parent, "node", _sealed(admin_own)),
        ])
        assert resp.status_code == 200, resp.text
    own = "01JD000000000000000000000B"
    resp = await _push(app_client, team, user, [
        _obj(team.sk[user], own, "dek", b"own key" * 10),
        _entry(team, user, own, version=2, parent=parent),
    ])
    assert _errors(resp) == ["team log gives no write access here"]
    stored = next(o for o in mock_db._storage["vault_objects"] if o["id"] == ENTRY)
    assert stored["parent_ref"] == FOLDER and stored["owner_id"] == BOB
    # The log's admin, who writes in F1, may move it out.
    admin_key = "01JD000000000000000000000D"
    resp = await _push(app_client, team, ADMIN, [
        _obj(team.sk[ADMIN], admin_key, "dek", b"own key" * 10),
        _entry(team, ADMIN, admin_key, version=2, parent=parent),
    ])
    assert resp.status_code == 200, resp.text
    stored = next(o for o in mock_db._storage["vault_objects"] if o["id"] == ENTRY)
    assert stored["parent_ref"] == parent


@pytest.mark.asyncio
async def test_keys_and_envelopes_the_log_does_not_name_are_refused(app_client, mock_db):
    team = Team(mock_db)
    await _team_folder(app_client, team)
    sk = team.sk[ADMIN]
    assert _errors(await _push(app_client, team, ADMIN, [
        _obj(sk, K3, "dek", b"wrapped K3" * 8, parent=FOLDER)])) == ["folder key missing from the team log"]
    _create_regular_user(mock_db._storage, DAN, "dan")
    outsider = _obj(sk, "01JV0000000000000000000003", "envelope", b"e" * 80, parent=K1, target=DAN,
                    level="read")
    assert _errors(await _push(app_client, team, ADMIN, [outsider])) == [
        "team log gives this account no access to the key"]


@pytest.mark.asyncio
@pytest.mark.parametrize("level", ["read", "write"])
async def test_a_key_outside_the_log_goes_to_another_account_only_as_a_reseal(app_client, mock_db, level):
    """Review c78fd19 R13-10: with a log, another account gets a key only by access.set.

    The server took an envelope on a folder outside every team folder, and for
    level=write its write_acl, though every client ignores it.
    """
    team = Team(mock_db)
    await _team_folder(app_client, team)
    sk = team.sk[ADMIN]
    folder, key = "01JN000000000000000000000E", "01JD000000000000000000000E"
    resp = await _push(app_client, team, ADMIN, [
        _obj(sk, folder, "node", _sealed(key)),
        _obj(sk, key, "dek", b"wrapped own" * 8, parent=folder),
    ])
    assert resp.status_code == 200, resp.text
    grant = _obj(sk, "01JV000000000000000000000E", "envelope", b"e" * 80, parent=key, target=BOB,
                 level=level)
    assert _errors(await _push(app_client, team, ADMIN, [grant])) == [
        "team log: another account gets a key only with an access.set"]
    assert not any(o["id"] == grant["id"] for o in mock_db._storage["vault_objects"])
    assert (BOB, folder) not in _acl(mock_db)
    # A grant from before the log, re-sealed (identity rotation: new id).
    mock_db._storage["vault_objects"].append({
        "id": "01JV000000000000000000000F", "object_type": "envelope", "parent_ref": key,
        "target_user_id": BOB, "access_level": level, "owner_id": ADMIN, "version": 1,
        "is_deleted": 0,
    })
    assert (await _push(app_client, team, ADMIN, [grant])).status_code == 200
    # The same re-seal at another level is a new grant.
    other = "write" if level == "read" else "read"
    wider = _obj(sk, "01JV000000000000000000000G", "envelope", b"e" * 80, parent=key, target=BOB,
                 level=other)
    assert _errors(await _push(app_client, team, ADMIN, [wider])) == [
        "team log: another account gets a key only with an access.set"]


async def _outside_key(app_client, team, mock_db, old_deleted: int):
    """A folder outside the log with a pre-log grant to Bob (live or withdrawn)."""
    await _team_folder(app_client, team)
    sk = team.sk[ADMIN]
    folder, key = "01JN000000000000000000000E", "01JD000000000000000000000E"
    resp = await _push(app_client, team, ADMIN, [
        _obj(sk, folder, "node", _sealed(key)),
        _obj(sk, key, "dek", b"wrapped own" * 8, parent=folder),
    ])
    assert resp.status_code == 200, resp.text
    old = "01JV000000000000000000000F"
    mock_db._storage["vault_objects"].append({
        "id": old, "object_type": "envelope", "parent_ref": key,
        "target_user_id": BOB, "access_level": "write", "owner_id": ADMIN,
        "version": 1 + old_deleted, "is_deleted": old_deleted,
        "payload_hash": hashlib.sha256(b"e" * 80).hexdigest(),
    })
    grant = _obj(sk, "01JV000000000000000000000E", "envelope", b"e" * 80, parent=key, target=BOB,
                 level="write")
    tombstone = _obj(sk, old, "envelope", b"", parent=key, target=BOB, level="write", version=3,
                     deleted=1)
    return folder, grant, tombstone


@pytest.mark.asyncio
async def test_a_withdrawn_grant_outside_the_log_is_not_given_again(app_client, mock_db):
    """Review e443cbc R15 (goal #438 item 5): the re-seal exception took any
    earlier envelope of the sender, a withdrawn one too. Bob's access, taken
    away before, came back with write_acl and no access.set."""
    team = Team(mock_db)
    folder, grant, _tombstone = await _outside_key(app_client, team, mock_db, old_deleted=1)
    assert _errors(await _push(app_client, team, ADMIN, [grant])) == [
        "team log: another account gets a key only with an access.set"]
    assert (BOB, folder) not in _acl(mock_db)


@pytest.mark.asyncio
async def test_a_resent_tombstone_does_not_vouch_for_a_new_grant(app_client, mock_db):
    team = Team(mock_db)
    folder, grant, tombstone = await _outside_key(app_client, team, mock_db, old_deleted=1)
    assert _errors(await _push(app_client, team, ADMIN, [tombstone, grant])) == [
        "team log: another account gets a key only with an access.set"]
    assert (BOB, folder) not in _acl(mock_db)


@pytest.mark.asyncio
async def test_a_reseal_withdrawing_the_live_grant_in_the_same_batch_lands(app_client, mock_db):
    team = Team(mock_db)
    _folder, grant, tombstone = await _outside_key(app_client, team, mock_db, old_deleted=0)
    assert (await _push(app_client, team, ADMIN, [tombstone, grant])).status_code == 200
