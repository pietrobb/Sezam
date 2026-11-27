"""Key voucher lists on the server (review e443cbc R15, goal #443, INV-3).

The server keeps the lists only: it stores one only under the account's
current key that signed it (an identity rotation's lists under the NEW key, in
the push's transaction) and serves the lists of the current key. What a list
vouches for is decided by the clients (src/sezam/key_vouchers.py).
"""

from __future__ import annotations

import hashlib
import os

import pytest
from nacl.signing import SigningKey

from sezam import key_vouchers as kv
from server.app.auth import key_rotation_message
from tests.test_review2_rotation_server import (
    DEK_ID,
    USER_ID,
    _auth,
    _dek,
    _keypair,
    _seeded,
    _user,
)
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    _sign_challenge,
    _sign_sync_object,
    app_client,
    mock_db,
)


def _entry(mock_db) -> list:
    dek = next(o for o in mock_db._storage["vault_objects"] if o["id"] == DEK_ID)
    return [DEK_ID, dek["version"], dek["payload_hash"]]


def _old_object(mock_db, sk) -> list:
    """A live object the account's key signed that the rotation does not replace."""
    obj_id, payload_hash = "ROTOLD00000000000000000001", hashlib.sha256(b"old").hexdigest()
    signature = _sign_sync_object(sk, obj_id, "node", None, None, 0, 1, payload_hash)
    row = {
        "id": obj_id, "object_type": "node", "parent_ref": None, "target_user_id": None, "is_deleted": 0,
        "version": 1, "payload_hash": payload_hash, "client_signature": bytes.fromhex(signature),
        "signature_user_id": USER_ID, "owner_id": USER_ID, "commit_seq": 1, "payload": b"old",
    }
    mock_db._storage["vault_objects"].append(row)
    return list(kv.object_entry(row, USER_ID, bytes(sk.verify_key)))


@pytest.mark.asyncio
async def test_a_rotation_list_naming_other_signed_fields_is_incomplete(app_client, mock_db):
    """R17-N1: the entry of the old key's version with another parent, or
    deleted, does not stand for the version it signed."""
    sk, token = await _seeded(app_client, mock_db)
    new_sk = SigningKey.generate()
    old_entry = _old_object(mock_db, sk)
    row = mock_db._storage["vault_objects"][-1]
    for changed in ({"is_deleted": 1}, {"parent_ref": DEK_ID}):
        other = list(kv.object_entry({**row, **changed}, USER_ID, bytes(sk.verify_key)))
        assert other[:2] == old_entry[:2] and other != old_entry
        rotation = await _identity_rotation(
            app_client, mock_db, sk, new_sk, [kv.sign_vouchers(USER_ID, new_sk, [other])]
        )
        resp = await app_client.post("/api/sync", json={
            "objects": [_dek(new_sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
            "key_rotation": rotation,
        }, headers=_auth(token))
        assert resp.status_code == 409, resp.text
        assert resp.json()["code"] == "key_vouchers_incomplete"


async def _identity_rotation(app_client, mock_db, sk, new_sk, vouchers) -> dict:
    user = _user(mock_db)
    new_enc = bytes(SigningKey.generate().verify_key)
    message = key_rotation_message(
        USER_ID, user["signing_pk"], user["encryption_pk"], bytes(new_sk.verify_key), new_enc
    )
    challenge = (await app_client.post("/api/auth/challenge", json={"username": "admin"})).json()["challenge"]
    return {
        "encrypted_keypair": _keypair().hex(), "argon2_salt": "ab" * 16, "auth_salt": "ab" * 16,
        "auth_proof": os.urandom(32).hex(),
        "argon2_params": {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 64},
        "challenge": challenge, "signature": _sign_challenge(new_sk, bytes.fromhex(challenge)).hex(),
        "identity": {
            "new_signing_pk": bytes(new_sk.verify_key).hex(), "new_encryption_pk": new_enc.hex(),
            "rotation_signature": new_sk.sign(message).signature.hex(),
            "authorization_signature": sk.sign(message).signature.hex(),
            "key_vouchers": vouchers,
        },
    }


async def _vouchers(app_client, token) -> dict:
    resp = await app_client.get(f"/api/users/{USER_ID}/key-vouchers", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_signed_objects_name_what_the_account_signed(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)

    resp = await app_client.get("/api/users/me/signed-objects", headers=_auth(token))

    assert resp.status_code == 200, resp.text
    (obj,) = resp.json()["objects"]
    assert [obj["id"], obj["version"], obj["payload_hash"]] == _entry(mock_db)
    assert obj["object_type"] == "dek" and obj["signature"] == _dek(sk, 1, b"dek under old KEK")["signature"]
    assert resp.json()["more"] is False
    after = await app_client.get(f"/api/users/me/signed-objects?after={DEK_ID}", headers=_auth(token))
    assert after.json()["objects"] == []


@pytest.mark.asyncio
async def test_only_a_list_signed_by_the_current_key_is_kept(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    good = kv.sign_vouchers(USER_ID, sk, [_entry(mock_db)])

    for bad in (
        kv.sign_vouchers(USER_ID, SigningKey.generate(), [_entry(mock_db)]),  # another key
        kv.sign_vouchers("ADMIN000000000000000000002", sk, [_entry(mock_db)]),  # another account
        {**good, "entries": [_entry(mock_db), [DEK_ID, 9, "00" * 32]]},  # changed after signing
    ):
        resp = await app_client.post("/api/users/me/key-vouchers", json=bad, headers=_auth(token))
        assert resp.status_code == 400, resp.text
        assert resp.json()["code"] == "invalid_key_vouchers"
    assert mock_db._storage["key_vouchers"] == []

    resp = await app_client.post("/api/users/me/key-vouchers", json=good, headers=_auth(token))
    assert resp.status_code == 200, resp.text
    served = await _vouchers(app_client, token)
    assert served == {"signing_pk": bytes(sk.verify_key).hex(), "lists": [good]}
    assert kv.vouched(USER_ID, bytes(sk.verify_key), served["lists"]) == {tuple(_entry(mock_db))}


@pytest.mark.asyncio
async def test_identity_rotation_stores_lists_of_the_new_key_and_serves_only_those(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    before = kv.sign_vouchers(USER_ID, sk, [_entry(mock_db)])
    assert (await app_client.post("/api/users/me/key-vouchers", json=before, headers=_auth(token))).status_code == 200
    new_sk = SigningKey.generate()
    old_entry = _old_object(mock_db, sk)

    # Lists signed by the old key do not ride a rotation: nothing changes.
    rotation = await _identity_rotation(app_client, mock_db, sk, new_sk, [before])
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(new_sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": rotation,
    }, headers=_auth(token))
    assert resp.status_code == 400, resp.text
    assert _user(mock_db)["signing_pk"] == bytes(sk.verify_key)
    assert len(mock_db._storage["key_vouchers"]) == 1

    # Nor does a rotation whose lists leave out a live object of the old key
    # (one another device pushed after this one fetched its signed objects).
    rotation = await _identity_rotation(app_client, mock_db, sk, new_sk, [kv.sign_vouchers(USER_ID, new_sk, [])])
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(new_sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": rotation,
    }, headers=_auth(token))
    assert resp.status_code == 409, resp.text
    assert resp.json()["code"] == "key_vouchers_incomplete"
    assert _user(mock_db)["signing_pk"] == bytes(sk.verify_key)

    after = kv.sign_vouchers(USER_ID, new_sk, [old_entry])
    rotation = await _identity_rotation(app_client, mock_db, sk, new_sk, [after])
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(new_sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": rotation,
    }, headers=_auth(token))
    assert resp.status_code == 200, resp.text
    assert _user(mock_db)["signing_pk"] == bytes(new_sk.verify_key)
    new_token = resp.json()["token"]
    served = await _vouchers(app_client, new_token)
    assert served == {"signing_pk": bytes(new_sk.verify_key).hex(), "lists": [after]}
    # The old key may no longer add lists.
    resp = await app_client.post("/api/users/me/key-vouchers", json=before, headers=_auth(new_token))
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_signed_objects_are_the_callers_own(app_client, mock_db):
    await _seeded(app_client, mock_db)
    _create_regular_user(mock_db._storage)
    other = _create_jwt("USER0000000000000000000001", "user", False)

    resp = await app_client.get("/api/users/me/signed-objects", headers=_auth(other))

    assert resp.status_code == 200, resp.text
    assert resp.json()["objects"] == []
