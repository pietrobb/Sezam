"""Follow-up review 2052248, finding 1 (server half, R-C1).

A password/KEK rotation is one unit on the server: the new key material
(encrypted keypair, salts, KDF params, auth proof) is applied in the SAME
transaction as the DEK rewrap batch and the key_epoch advance. Before, the
keypair upload and the epoch push were separate requests; when the second one
failed, web/recovery used the new password while every DEK was still wrapped
under the old KEK.
"""

from __future__ import annotations

import base64
import hashlib
import os

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _sign_challenge,
    _sign_sync_object,
    app_client,
    mock_db,
)

USER_ID = "ADMIN000000000000000000001"
DEK_ID = "ROTDEK00000000000000000001"
NODE_ID = "ROTNODE0000000000000000001"


def _dek(sk, version: int, payload: bytes) -> dict:
    payload_hash = hashlib.sha256(payload).hexdigest()
    return {
        "id": DEK_ID, "object_type": "dek",
        "payload": base64.b64encode(payload).decode(),
        "parent_ref": NODE_ID, "version": version, "is_deleted": 0,
        "payload_hash": payload_hash,
        "signature": _sign_sync_object(sk, DEK_ID, "dek", NODE_ID, None, 0, version, payload_hash),
    }


def _keypair() -> bytes:
    """Random bytes behind a canonical KEYPAIR_WRAP header (alg 1, schema 1, kind 7)."""
    return bytes((1, 1, 7)) + os.urandom(194)


async def _rotation(client, sk, keypair: bytes, proof: bytes) -> dict:
    challenge = (await client.post("/api/auth/challenge", json={"username": "admin"})).json()["challenge"]
    return {
        "encrypted_keypair": keypair.hex(),
        "argon2_salt": "ab" * 16,
        "auth_salt": "ab" * 16,
        "auth_proof": proof.hex(),
        "argon2_params": {"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 64},
        "challenge": challenge,
        "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
    }


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _user(mock_db) -> dict:
    return next(u for u in mock_db._storage["users"] if u["id"] == USER_ID)


def _server_dek(mock_db) -> dict:
    return next(o for o in mock_db._storage["vault_objects"] if o["id"] == DEK_ID)


async def _seeded(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    token = _create_jwt(USER_ID, "admin", True)
    first = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 1, b"dek under old KEK")], "atomic_batch": False,
    }, headers=_auth(token))
    assert first.status_code == 200, first.text
    return sk, token


@pytest.mark.asyncio
async def test_epoch_advance_without_key_material_is_refused(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
    }, headers=_auth(token))
    assert resp.status_code == 409
    assert "key material" in resp.json()["detail"]
    assert _server_dek(mock_db)["version"] == 1
    assert mock_db._storage["sync_state"][0]["key_epoch"] == 0


@pytest.mark.asyncio
async def test_rotation_applies_key_material_deks_and_epoch_together(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    new_keypair, proof = _keypair(), os.urandom(32)

    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": await _rotation(app_client, sk, new_keypair, proof),
    }, headers=_auth(token))

    assert resp.status_code == 200, resp.text
    user = _user(mock_db)
    assert user["encrypted_keypair"] == new_keypair
    assert user["argon2_salt"] == bytes.fromhex("ab" * 16)
    assert user["token_epoch"] == 1
    assert _server_dek(mock_db)["version"] == 2
    assert mock_db._storage["sync_state"][0]["key_epoch"] == 1
    # Older tokens are revoked; the response carries a fresh one.
    new_token = resp.json()["token"]
    assert (await app_client.get("/api/sync", headers=_auth(token))).status_code == 401
    assert (await app_client.get("/api/sync", headers=_auth(new_token))).status_code == 200
    # Password recovery now hands out exactly the rotated key material.
    recovered = await app_client.post("/api/auth/recover", json={
        "username": "admin", "auth_proof": proof.hex(),
    })
    assert recovered.status_code == 200
    assert recovered.json()["encrypted_keypair"] == new_keypair.hex()


@pytest.mark.asyncio
async def test_rejected_rewrap_batch_leaves_old_key_material(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    old_keypair = _user(mock_db)["encrypted_keypair"]
    # Version 1 again with a different payload: a conflict inside the atomic batch.
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 1, b"conflicting wrap")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": await _rotation(app_client, sk, _keypair(), os.urandom(32)),
    }, headers=_auth(token))
    assert resp.status_code == 409
    assert _user(mock_db)["encrypted_keypair"] == old_keypair
    assert _user(mock_db).get("token_epoch", 0) == 0
    assert mock_db._storage["sync_state"][0]["key_epoch"] == 0


@pytest.mark.asyncio
async def test_rotation_needs_a_challenge_signed_by_the_account_key(app_client, mock_db):
    from nacl.signing import SigningKey

    sk, token = await _seeded(app_client, mock_db)
    rotation = await _rotation(app_client, SigningKey.generate(), _keypair(), os.urandom(32))
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": rotation,
    }, headers=_auth(token))
    assert resp.status_code == 401
    assert _server_dek(mock_db)["version"] == 1
    assert mock_db._storage["sync_state"][0]["key_epoch"] == 0


@pytest.mark.asyncio
async def test_retry_of_an_applied_rotation_is_idempotent(app_client, mock_db):
    """The response of a rotation can be lost; the device retries the same unit."""
    sk, token = await _seeded(app_client, mock_db)
    new_keypair, proof = _keypair(), os.urandom(32)
    body = {"objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1}
    first = await app_client.post("/api/sync", json={
        **body, "key_rotation": await _rotation(app_client, sk, new_keypair, proof),
    }, headers=_auth(token))
    assert first.status_code == 200
    token = first.json()["token"]

    retry = await app_client.post("/api/sync", json={
        **body, "key_rotation": await _rotation(app_client, sk, new_keypair, proof),
    }, headers=_auth(token))
    assert retry.status_code == 200, retry.text
    assert [a["id"] for a in retry.json()["accepted"]] == [DEK_ID]
    assert retry.json()["token"] is None
    assert _user(mock_db)["token_epoch"] == 1  # not bumped again


@pytest.mark.asyncio
async def test_key_material_cannot_change_without_an_epoch_advance(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    first = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": await _rotation(app_client, sk, _keypair(), os.urandom(32)),
    }, headers=_auth(token))
    token = first.json()["token"]
    applied = _user(mock_db)["encrypted_keypair"]

    other = await app_client.post("/api/sync", json={
        "objects": [], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": await _rotation(app_client, sk, _keypair(), os.urandom(32)),
    }, headers=_auth(token))
    assert other.status_code == 409
    # A rival rotation from the same epoch is a stale epoch: the clients map
    # exactly this to "take the server's key material over".
    assert other.json()["detail"].startswith("Stale key epoch")
    assert _user(mock_db)["encrypted_keypair"] == applied

    pulled = await app_client.get("/api/sync?since_commit_seq=0", headers=_auth(token))
    assert pulled.json()["key_epoch"] == 1
    assert pulled.json()["key_material_hash"] == hashlib.sha256(bytes(applied)).hexdigest()
