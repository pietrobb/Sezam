"""Review e4cd15a S2: an admin unlock did not get the owner back in.

POST /api/users/:id/unlock-recovery only cleared the counters: an attacker's
next ten guesses (or three networks filling the locked-name ration) locked the
name again before the owner, on a network the account never used, got a turn.
The 429 then sent a lone admin to "ask an admin". The unlock now hands out a
one-time code that skips the name's shared ration (the code holder's own
network keeps its slot), and the hint names it. The key material archive also
refused the owner's correct current password with 423 whenever strangers had
locked the name.
"""

from __future__ import annotations

import os

import pytest

from tests.test_recover_lockout_dos import (
    _client_from,
    _locked_by_attacker,
    _recover,
    _three_networks_fill_the_ration,
)
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _do_challenge_verify,
    app_client,
    mock_db,
)

ADMIN_IP = "198.51.100.5"
NEW_NETWORK = "198.51.100.99"  # never used by the account


async def _unlock_code(mock_db, sk) -> str:
    user_id = mock_db._storage["users"][0]["id"]
    async with _client_from(ADMIN_IP) as admin:
        token = await _do_challenge_verify(admin, mock_db._storage, sk, "admin")
        resp = await admin.post(
            f"/api/users/{user_id}/unlock-recovery",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200, resp.text
    return resp.json()["unlock_code"]


async def _recover_with(code: str, proof: bytes, ip: str = NEW_NETWORK):
    async with _client_from(ip) as owner:
        return await owner.post("/api/auth/recover", json={
            "username": "admin", "auth_proof": proof.hex(), "unlock_code": code,
        })


@pytest.mark.asyncio
async def test_unlock_code_gets_the_owner_past_a_relock(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    row, proof = await _locked_by_attacker(mock_db)

    code = await _unlock_code(mock_db, sk)
    assert row["recovery_locked"] == 0
    async with _client_from("203.0.113.8") as attacker:  # re-locks at once
        for _ in range(10):
            await _recover(attacker, os.urandom(32))
    await _three_networks_fill_the_ration(mock_db)
    assert row["recovery_locked"] == 1

    async with _client_from(NEW_NETWORK) as owner:  # without the code: refused
        assert await _recover(owner, proof) == 429

    resp = await _recover_with(code, proof)
    assert resp.status_code == 200, resp.text
    assert row["recovery_locked"] == 0
    assert row.get("recovery_unlock_hash") is None  # one-time


@pytest.mark.asyncio
async def test_unlock_code_is_one_time_and_must_match(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    row, proof = await _locked_by_attacker(mock_db)
    code = await _unlock_code(mock_db, sk)
    row["recovery_locked"] = 1
    await _three_networks_fill_the_ration(mock_db)

    wrong = "0" * 20 if code != "0" * 20 else "1" * 20
    assert (await _recover_with(wrong, proof)).status_code == 429
    assert (await _recover_with(code, proof)).status_code == 200

    row["recovery_locked"] = 1
    await _three_networks_fill_the_ration(mock_db)
    assert (await _recover_with(code, proof, "198.51.100.120")).status_code == 429


@pytest.mark.asyncio
async def test_unlock_code_keeps_one_guess_per_window_per_network(app_client, mock_db):
    """A leaked code must not turn into unlimited guessing."""
    sk, _ = _create_admin_user(mock_db._storage)
    row, proof = await _locked_by_attacker(mock_db)
    code = await _unlock_code(mock_db, sk)
    row["recovery_locked"] = 1

    assert (await _recover_with(code, os.urandom(32))).status_code == 423
    assert (await _recover_with(code, os.urandom(32))).status_code == 429
    assert (await _recover_with(code, proof)).status_code == 429


@pytest.mark.asyncio
async def test_unlock_code_expires(app_client, mock_db):
    sk, _ = _create_admin_user(mock_db._storage)
    row, proof = await _locked_by_attacker(mock_db)
    code = await _unlock_code(mock_db, sk)
    row["recovery_locked"] = 1
    row["recovery_unlock_until"] -= 24 * 3600 * 1000 + 1
    await _three_networks_fill_the_ration(mock_db)
    assert (await _recover_with(code, proof)).status_code == 429


@pytest.mark.asyncio
async def test_429_points_to_the_unlock_code(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    await _locked_by_attacker(mock_db)
    await _three_networks_fill_the_ration(mock_db)
    async with _client_from(NEW_NETWORK) as owner:
        resp = await owner.post(
            "/api/auth/recover", json={"username": "admin", "auth_proof": os.urandom(32).hex()}
        )
    assert resp.status_code == 429
    assert "sezam unlock-recovery" in resp.json()["detail"]


def test_desktop_sends_the_unlock_code_and_names_it_on_refusal():
    from click.testing import CliRunner

    from sezam.cli import connect
    from sezam.crypto.kdf import Argon2Params
    from sezam.vault.crud import recover_refusal, recover_with_password
    from sezam.vault.sync_common import ServerError

    sent = []
    recover_with_password(
        lambda body: sent.append(body) or {}, "admin", "pw", b"\x00" * 16,
        Argon2Params(time_cost=1, memory_cost=8, parallelism=1), unlock_code=" ab12 ",
    )
    assert sent[0]["unlock_code"] == "ab12"
    assert "--unlock-code" in CliRunner().invoke(connect, ["--help"]).output
    for code in (429, 423):
        assert "sezam unlock-recovery" in recover_refusal(ServerError(code, "x"))


@pytest.mark.asyncio
async def test_archive_takes_the_owners_proof_while_strangers_lock_the_name(
    app_client, mock_db
):
    from tests.test_key_material_archive_access import _two_rotations
    from tests.test_review2_rotation_server import _auth, _user

    token, proof, _ = await _two_rotations(app_client, mock_db)
    user = _user(mock_db)
    user["recovery_locked"] = 1  # a stranger's /recover guesses
    user["recovery_attempts"] = 10
    import time

    user["last_recovery_attempt"] = int(time.time() * 1000)

    resp = await app_client.post(
        "/api/me/key-material-archive/purge", json={"auth_proof": proof.hex()},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    user["recovery_locked"] = 1
    resp = await app_client.post(  # still one proof per window while locked
        "/api/me/key-material-archive", json={"auth_proof": os.urandom(32).hex()},
        headers=_auth(token),
    )
    assert resp.status_code == 429
