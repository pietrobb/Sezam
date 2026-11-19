"""Review 688edcb (low): the key material archive (lockout review #11).

Every rotation and password change archived the account keypair wrapped under
the OLD password, ten generations, forever - a leaked database stayed an
offline-guessing target for each of them (after changing a leaked password,
the archive still opened with it), and nothing could read them back for the
fallback they were kept for. The archive now expires after
SEZAM_KEY_MATERIAL_ARCHIVE_DAYS, and the owner reads or purges it with the
current password.
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
    _user,
)
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)


async def _two_rotations(app_client, mock_db):
    sk, token = await _seeded(app_client, mock_db)
    original = bytes(_user(mock_db)["encrypted_keypair"])
    keypairs, current = [], None
    for epoch in (1, 2):
        keypair, proof = _keypair(), os.urandom(32)
        rotation = await _rotation(app_client, sk, keypair, proof)
        if current is not None:
            rotation["current_auth_proof"] = current.hex()
        resp = await app_client.post("/api/sync", json={
            "objects": [_dek(sk, epoch + 1, b"dek %d" % epoch)],
            "atomic_batch": True, "key_epoch": epoch, "key_rotation": rotation,
        }, headers=_auth(token))
        assert resp.status_code == 200, resp.text
        token, current = resp.json()["token"], proof
        keypairs.append(keypair)
    return token, current, [original, keypairs[0]]


@pytest.mark.asyncio
async def test_owner_reads_the_archive_with_the_current_password(app_client, mock_db):
    token, proof, archived = await _two_rotations(app_client, mock_db)

    resp = await app_client.post(
        "/api/me/key-material-archive", json={"auth_proof": proof.hex()}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    generations = resp.json()["generations"]
    assert [g["key_epoch"] for g in generations] == [1, 0]  # newest first
    assert [bytes.fromhex(g["encrypted_keypair"]) for g in generations] == archived[::-1]
    assert generations[0]["argon2_salt"] == "ab" * 16


@pytest.mark.asyncio
async def test_token_alone_reads_nothing_and_wrong_proofs_count(app_client, mock_db):
    token, _, _ = await _two_rotations(app_client, mock_db)

    for n in range(10):
        resp = await app_client.post(
            "/api/me/key-material-archive", json={"auth_proof": os.urandom(32).hex()},
            headers=_auth(token),
        )
        assert resp.status_code == 403, resp.text
        assert "generations" not in resp.json()
    assert _user(mock_db)["recovery_locked"] == 1  # like ten wrong /recover proofs
    resp = await app_client.post(
        "/api/me/key-material-archive/purge", json={"auth_proof": os.urandom(32).hex()},
        headers=_auth(token),
    )
    assert resp.status_code == 423
    assert len(mock_db._storage["user_key_material_archive"]) == 2


@pytest.mark.asyncio
async def test_owner_purges_the_archive(app_client, mock_db):
    token, proof, _ = await _two_rotations(app_client, mock_db)

    resp = await app_client.post(
        "/api/me/key-material-archive/purge", json={"auth_proof": proof.hex()},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["purged"] == 2
    assert [
        r for r in mock_db._storage["user_key_material_archive"] if r["user_id"] == USER_ID
    ] == []


@pytest.mark.asyncio
async def test_archive_expires(app_client, mock_db):
    from server.app.config import ServerConfig
    from server.app.main import _cleanup_key_material_archive

    token, proof, _ = await _two_rotations(app_client, mock_db)
    keep_days = ServerConfig.key_material_archive_days
    oldest = min(mock_db._storage["user_key_material_archive"], key=lambda r: r["key_epoch"])
    oldest["archived_at"] -= keep_days * 86_400_000 + 1

    resp = await app_client.post(
        "/api/me/key-material-archive", json={"auth_proof": proof.hex()}, headers=_auth(token)
    )
    assert [g["key_epoch"] for g in resp.json()["generations"]] == [1]  # not served

    await _cleanup_key_material_archive(mock_db, keep_days)
    assert [r["key_epoch"] for r in mock_db._storage["user_key_material_archive"]] == [1]
