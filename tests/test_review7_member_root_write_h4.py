"""Review 7c10379 H4: a read-only member wrote folders directly below the root.

The fix for members' personal folders (d615826) let any member create any
folder directly below a top-level node. A read-only member made folders
sealed with the shared root key - and items in them, such as 'IT - new VPN
login' - that colleagues saw as the company's own; one push took 500 of them.
The start of a personal tree is now taken only when its meta is sealed with
a DEK of the author's own (on the server, or in the same push); a move below
the root follows the same rule, and a member may still delete their own.
"""

from __future__ import annotations

import pytest

from tests.test_review6_web_member_personal_folder import ALICE_DEK, ROOT, sealed
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_jwt,
    _create_regular_user,
    _push_object,
    _with_server_base,
    app_client,
    mock_db,
)

ADMIN = "ADMIN000000000000000000001"
ROOT_DEK = "ROOTDEK0000000000000000001"


def _object(obj_id, object_type, owner, parent=None, payload=b"x" * 72):
    import hashlib

    return {
        "id": obj_id, "object_type": object_type, "payload": payload,
        "owner_id": owner, "signature_user_id": owner,
        "write_policy": "owner_only", "target_user_id": None, "parent_ref": parent,
        "access_level": None, "version": 1, "commit_seq": 1, "is_deleted": 0,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "client_signature": b"x" * 64, "modified_at": 1, "dek_scope": None,
    }


@pytest.fixture
def member(mock_db):  # noqa: F811
    alice_id = "USER0000000000000000000001"
    alice_sk, _ = _create_regular_user(mock_db._storage, alice_id, "alice")
    storage = mock_db._storage["vault_objects"]
    storage.append(_object(ROOT, "node", ADMIN, payload=sealed(ROOT_DEK)))
    storage.append(_object(ROOT_DEK, "dek", ADMIN, parent=ROOT))
    storage.append(_object("ADMINFOLDER000000000000001", "node", ADMIN, ROOT, sealed(ROOT_DEK)))
    return alice_id, alice_sk, _create_jwt(alice_id, "alice", False)


@pytest.mark.asyncio
async def test_member_cannot_start_a_folder_below_the_root_under_the_shared_key(app_client, member):  # noqa: F811
    _alice, sk, token = member
    fake = await _push_object(app_client, token, sk, "FAKEITFOLDER00000000000001", "node", ROOT, 1, sealed(ROOT_DEK))
    assert fake.json()["accepted"] == [], fake.json()
    assert fake.json()["conflicts"][0]["error"] == "write_acl denied"
    unsealed = await _push_object(app_client, token, sk, "FAKEITFOLDER00000000000002", "node", ROOT, 1, b"f")
    assert unsealed.json()["accepted"] == [], unsealed.json()


@pytest.mark.asyncio
async def test_member_starts_a_personal_folder_under_their_own_key_and_deletes_it(app_client, member):  # noqa: F811
    _alice, sk, token = member
    dek = await _push_object(app_client, token, sk, ALICE_DEK, "dek", None, 1, b"k" * 72)
    assert len(dek.json()["accepted"]) == 1, dek.json()
    mine = await _push_object(app_client, token, sk, "ALICEPERSONAL0000000000001", "node", ROOT, 1, sealed(ALICE_DEK))
    assert len(mine.json()["accepted"]) == 1, mine.json()
    gone = await _push_object(
        app_client, token, sk, "ALICEPERSONAL0000000000001", "node", ROOT, 2, sealed(ALICE_DEK), is_deleted=1,
    )
    assert len(gone.json()["accepted"]) == 1, gone.json()


@pytest.mark.asyncio
async def test_member_cannot_seal_a_root_folder_with_another_users_dek(app_client, member, mock_db):  # noqa: F811
    _alice, sk, token = member
    bob_dek = "BOBDEK00000000000000000001"
    mock_db._storage["vault_objects"].append(_object(bob_dek, "dek", "USER0000000000000000000002"))
    fake = await _push_object(app_client, token, sk, "FAKEITFOLDER00000000000003", "node", ROOT, 1, sealed(bob_dek))
    assert fake.json()["accepted"] == [], fake.json()


def _wire(sk, obj_id, object_type, parent_ref, version, payload):
    import base64
    import hashlib

    from tests.test_server_spec import _sign_sync_object

    p_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": obj_id, "object_type": object_type, "payload": base64.b64encode(payload).decode("ascii"),
        "parent_ref": parent_ref, "version": version, "is_deleted": 0, "payload_hash": p_hash,
        "write_policy": "owner_only",
        "signature": _sign_sync_object(sk, obj_id, object_type, parent_ref, None, 0, version, p_hash),
    }


async def _push(client, token, objects):
    resp = await client.post(
        "/api/sync", json={"objects": _with_server_base(objects), "atomic_batch": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    return resp.json()


@pytest.mark.asyncio
@pytest.mark.parametrize("dek_parent", [None, ROOT])
async def test_a_rejected_dek_in_the_same_push_does_not_prove_an_own_seal(
    app_client, member, mock_db, dek_parent,  # noqa: F811
):
    """Capability run 172: the same-push proof came from every DEK object in the
    request, accepted or not. A DEK object named after the shared root DEK is
    refused ('not owner' / 'invalid personal DEK metadata'), and the folder
    sealed with the shared key it vouched for went in, with an item inside."""
    _alice, sk, token = member
    folder, entry = "FAKEITFOLDER00000000000009", "FAKEITENTRY000000000000009"
    body = await _push(app_client, token, [
        _wire(sk, ROOT_DEK, "dek", dek_parent, 2, b"k" * 72),
        _wire(sk, folder, "node", ROOT, 1, sealed(ROOT_DEK)),
        _wire(sk, entry, "entry", folder, 1, sealed(ROOT_DEK)),
    ])
    assert body["accepted"] == [], body
    stored = {o["id"] for o in mock_db._storage["vault_objects"]}
    assert folder not in stored and entry not in stored


@pytest.mark.asyncio
async def test_a_new_own_dek_in_the_same_push_still_starts_a_personal_folder(app_client, member):  # noqa: F811
    _alice, sk, token = member
    body = await _push(app_client, token, [
        _wire(sk, "ALICEPERSONAL0000000000009", "node", ROOT, 1, sealed(ALICE_DEK)),
        _wire(sk, ALICE_DEK, "dek", None, 1, b"k" * 72),
    ])
    assert len(body["accepted"]) == 2, body


@pytest.mark.asyncio
async def test_a_rejected_dek_in_the_same_push_does_not_carry_a_move_below_the_root(
    app_client, member, mock_db,  # noqa: F811
):
    alice, sk, token = member
    shared = "ADMINFOLDER000000000000001"
    moved = "ALICEFOLDER000000000000009"
    mock_db._storage["vault_objects"].append(_object(moved, "node", alice, shared, sealed(ROOT_DEK)))
    mock_db._storage["write_acl"].append({"user_id": alice, "node_id": shared, "granted_at": 1})
    body = await _push(app_client, token, [
        _wire(sk, ROOT_DEK, "dek", None, 2, b"k" * 72),
        _wire(sk, moved, "node", ROOT, 2, sealed(ROOT_DEK)),
    ])
    assert body["accepted"] == [], body
    row = next(o for o in mock_db._storage["vault_objects"] if o["id"] == moved)
    assert row["parent_ref"] == shared
