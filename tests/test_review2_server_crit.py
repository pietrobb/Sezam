"""Follow-up review 2052248, finding 6: the login challenge must be unforgeable.

The fake salt from /api/meta and the challenge MAC were the same HMAC key and
construction, so anyone could ask /meta for a valid challenge MAC; and a
challenge stamped in the future passed the freshness check forever.
"""

from __future__ import annotations

import os
import time

import pytest

from server.app import auth as server_auth
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    _sign_challenge,
    app_client,
    mock_db,
)

SECRET = "test-server-secret-key-12345"  # app_client's hmac_server_secret
CONTEXT = b"sezam-auth-challenge-v1"


def _future_ascii_ts() -> bytes:
    # 0x0000020000000000 ms ≈ year 2039: every byte is ASCII, so the bytes can
    # travel inside a UTF-8 username, and the time is in the future.
    ts = (0x0000020000000000).to_bytes(8, "big")
    assert int.from_bytes(ts, "big") > time.time() * 1000
    return ts


@pytest.mark.asyncio
async def test_meta_fake_salt_cannot_be_used_as_a_login_challenge_mac(app_client, mock_db):
    sk, _ = _create_regular_user(mock_db._storage, username="alice")
    nonce = b"A" * 16
    ts = _future_ascii_ts()
    crafted = (CONTEXT + nonce + ts + b"alice").decode("utf-8")

    meta = await app_client.get("/api/meta", params={"username": crafted})
    assert meta.status_code == 200
    mac = bytes.fromhex(meta.json()["argon2_salt"])
    forged = nonce + mac + ts

    assert not server_auth.bound_challenge_is_authentic(forged, SECRET, "alice")
    resp = await app_client.post("/api/auth/verify", json={
        "username": "alice",
        "challenge": forged.hex(),
        "signature": _sign_challenge(sk, forged).hex(),
    })
    assert resp.status_code == 401


def test_fake_salt_challenge_mac_and_ip_hmac_use_separate_keys():
    value = "203.0.113.7"
    fake = server_auth.generate_fake_salt(SECRET, value)
    ip = bytes.fromhex(server_auth.compute_ip_hmac(SECRET, value))
    assert fake != ip[:16]
    # The argon2 and auth fake salts of two names never coincide either.
    assert server_auth.generate_fake_salt(SECRET, "bob_auth") != server_auth.generate_fake_salt(
        SECRET, "bob", kind="auth"
    )


def test_challenge_stamped_in_the_future_is_rejected():
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    future_ms = int(time.time() * 1000) + 3600 * 1000
    challenge = os.urandom(32) + future_ms.to_bytes(8, "big")
    sig = sk.sign(challenge).signature
    assert not server_auth.verify_challenge_signature(challenge, sig, bytes(sk.verify_key))

    now_ms = int(time.time() * 1000)
    fresh = os.urandom(32) + now_ms.to_bytes(8, "big")
    assert server_auth.verify_challenge_signature(
        fresh, sk.sign(server_auth.auth_challenge_message(fresh)).signature, bytes(sk.verify_key)
    )


@pytest.mark.asyncio
async def test_server_issued_future_challenge_cannot_log_in(app_client, mock_db, monkeypatch):
    """Even a genuinely server-MAC'd challenge with a future time is refused:
    one signature on it would otherwise be a login that never expires (the
    spent-challenge row is garbage-collected long before the time arrives)."""
    sk, _ = _create_regular_user(mock_db._storage, username="alice")
    real_time = time.time
    monkeypatch.setattr(server_auth.time, "time", lambda: real_time() + 7 * 86400)
    challenge, _ = server_auth.generate_bound_challenge(SECRET, "alice")
    monkeypatch.setattr(server_auth.time, "time", real_time)

    resp = await app_client.post("/api/auth/verify", json={
        "username": "alice",
        "challenge": challenge.hex(),
        "signature": _sign_challenge(sk, challenge).hex(),
    })
    assert resp.status_code == 401
