"""Review e4cd15a (low): after the bare-signature grace period ends (2027-05-01)
a client released before the signature context got 401 "Authentication
failed", as if its key were wrong, instead of 426 "update the app" - the
answer every other outdated-client refusal gives.
"""

from __future__ import annotations

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    app_client,
    mock_db,
)


async def _login_with(app_client, sk, *, bare: bool):
    challenge = (await app_client.post(
        "/api/auth/challenge", json={"username": "admin"}
    )).json()["challenge"]
    message = bytes.fromhex(challenge)
    if not bare:
        message = b"sezam-auth-challenge-signature-v1" + message
    return await app_client.post("/api/auth/verify", json={
        "username": "admin",
        "challenge": challenge,
        "signature": sk.sign(message).signature.hex(),
    })


@pytest.mark.asyncio
async def test_bare_signature_after_the_end_date_asks_for_an_update(
    app_client, mock_db, monkeypatch
):
    sk, _ = _create_admin_user(mock_db._storage)
    monkeypatch.setenv("SEZAM_LEGACY_BARE_SIGNATURE_UNTIL", "2020-01-01")
    resp = await _login_with(app_client, sk, bare=True)
    assert resp.status_code == 426, resp.text
    assert "Update the Sezam app" in resp.json()["detail"]

    assert (await _login_with(app_client, sk, bare=False)).status_code == 200


@pytest.mark.asyncio
async def test_a_wrong_key_still_gets_401(app_client, mock_db, monkeypatch):
    from nacl.signing import SigningKey

    _create_admin_user(mock_db._storage)
    monkeypatch.setenv("SEZAM_LEGACY_BARE_SIGNATURE_UNTIL", "2020-01-01")
    for bare in (True, False):
        assert (await _login_with(app_client, SigningKey.generate(), bare=bare)).status_code == 401
