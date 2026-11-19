"""Lockout review 2026-11-08 #11: the server overwrote key material in place.

A key_rotation push replaced encrypted_keypair/salt/proof without looking at
it and without keeping the previous generation, so one bad push left the
account with key material no client could open and nothing to fall back to.
"""

from __future__ import annotations

import os

import pytest

from tests.test_review2_rotation_server import (
    USER_ID,
    _auth,
    _dek,
    _keypair,
    _rotation,
    _seeded,
    _server_dek,
    _user,
)
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [
    os.urandom(120),                         # no envelope at all
    bytes((1, 1, 6)) + os.urandom(194),      # a DEK wrap, not a keypair wrap
    bytes((1, 1, 7)) + os.urandom(40),       # too short to hold the keypair
], ids=["no-envelope", "dek-wrap", "too-short"])
async def test_rotation_with_unopenable_keypair_is_refused(app_client, mock_db, bad):
    sk, token = await _seeded(app_client, mock_db)
    old_keypair = _user(mock_db)["encrypted_keypair"]
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": await _rotation(app_client, sk, bad, os.urandom(32)),
    }, headers=_auth(token))
    assert resp.status_code == 400
    assert _user(mock_db)["encrypted_keypair"] == old_keypair
    assert _server_dek(mock_db)["version"] == 1
    assert mock_db._storage["sync_state"][0]["key_epoch"] == 0


@pytest.mark.asyncio
async def test_rotation_keeps_the_replaced_generations(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    generations = [_user(mock_db)["encrypted_keypair"]]
    current_proof = None
    for epoch in range(1, 13):
        keypair, proof = _keypair(), os.urandom(32)
        rotation = await _rotation(app_client, sk, keypair, proof)
        if current_proof is not None:
            # Review 688edcb K1: each change proves the password it replaces.
            rotation["current_auth_proof"] = current_proof.hex()
        resp = await app_client.post("/api/sync", json={
            "objects": [_dek(sk, epoch + 1, b"dek %d" % epoch)],
            "atomic_batch": True, "key_epoch": epoch, "key_rotation": rotation,
        }, headers=_auth(token))
        assert resp.status_code == 200, resp.text
        token = resp.json()["token"]
        generations.append(keypair)
        current_proof = proof

    archive = sorted(
        (r for r in mock_db._storage["user_key_material_archive"] if r["user_id"] == USER_ID),
        key=lambda r: r["key_epoch"],
    )
    # The newest ten replaced generations, each under the epoch it served.
    assert [r["key_epoch"] for r in archive] == list(range(2, 12))
    assert [bytes(r["encrypted_keypair"]) for r in archive] == [
        bytes(k) for k in generations[2:12]
    ]
    assert _user(mock_db)["encrypted_keypair"] == generations[-1]


@pytest.mark.asyncio
async def test_first_rotation_archives_the_original_material(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    original = _user(mock_db)["encrypted_keypair"]
    resp = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 2, b"dek under new KEK")], "atomic_batch": True, "key_epoch": 1,
        "key_rotation": await _rotation(app_client, sk, _keypair(), os.urandom(32)),
    }, headers=_auth(token))
    assert resp.status_code == 200, resp.text
    [row] = mock_db._storage["user_key_material_archive"]
    assert row["user_id"] == USER_ID and row["key_epoch"] == 0
    assert bytes(row["encrypted_keypair"]) == bytes(original)
