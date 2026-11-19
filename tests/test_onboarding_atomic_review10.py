"""Lockout review 2026-11-08 #10: bootstrap and onboarding were not atomic.

The first admin (and every invited user) exists on the server before its
keypair upload. When the upload never happened — web keeps the private key
only in memory until then — the server refused every later bootstrap for
good, and a failed registration kept its username forever.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _make_ed25519_keypair,
    app_client,
    mock_db,
)

APP_JS = Path(__file__).resolve().parents[1] / "web" / "static" / "js" / "app.js"
HOUR_MS = 3600 * 1000


def _keys() -> dict:
    _, signing_pk = _make_ed25519_keypair()
    _, encryption_pk = _make_ed25519_keypair()
    return {"signing_pk": signing_pk.hex(), "encryption_pk": encryption_pk.hex()}


async def _bootstrap(client, username: str):
    return await client.post("/api/bootstrap", json={"username": username, **_keys()})


def _age(mock_db, user_id: str, ms: int) -> None:
    user = next(u for u in mock_db._storage["users"] if u["id"] == user_id)
    user["created_at"] -= ms


async def _needs_setup(client) -> bool:
    return (await client.get("/api/bootstrap-status")).json()["needs_setup"]


@pytest.mark.asyncio
async def test_abandoned_keyless_bootstrap_can_be_redone(app_client, mock_db):
    first = await _bootstrap(app_client, "lost-admin")
    assert first.status_code == 200
    lost_id = first.json()["user_id"]

    # Within the window the device that holds the key may still finish.
    assert not await _needs_setup(app_client)
    assert (await _bootstrap(app_client, "admin")).status_code == 403

    _age(mock_db, lost_id, HOUR_MS + 1000)
    assert await _needs_setup(app_client)
    second = await _bootstrap(app_client, "admin")
    assert second.status_code == 200, second.text
    assert [u["username"] for u in mock_db._storage["users"]] == ["admin"]
    assert not await _needs_setup(app_client)


@pytest.mark.asyncio
async def test_bootstrap_admin_with_keys_or_traces_is_kept(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    _age(mock_db, "ADMIN000000000000000000001", 30 * 24 * HOUR_MS)
    assert (await _bootstrap(app_client, "intruder")).status_code == 403

    mock_db._storage["users"][0]["encrypted_keypair"] = None
    mock_db._storage["vault_objects"].append({
        "id": "OBJ00000000000000000000001", "owner_id": "ADMIN000000000000000000001",
    })
    assert not await _needs_setup(app_client)
    assert (await _bootstrap(app_client, "intruder")).status_code == 403
    assert [u["username"] for u in mock_db._storage["users"]] == ["admin"]


async def _register(client, admin_token: str, username: str):
    invite = await client.post(
        "/api/users/invite", headers={"Authorization": f"Bearer {admin_token}"}
    )
    return await client.post("/api/users/register", json={
        "invitation_token": invite.json()["invitation_token"],
        "username": username, **_keys(),
    })


@pytest.mark.asyncio
async def test_failed_registration_frees_the_username_after_the_token_expired(
    app_client, mock_db
):
    _create_admin_user(mock_db._storage)
    admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)
    first = await _register(app_client, admin_token, "bob")
    assert first.status_code == 200
    stale_id = first.json()["user_id"]

    # The onboarding token may still upload: the name stays taken.
    assert (await _register(app_client, admin_token, "bob")).status_code == 409

    _age(mock_db, stale_id, 900 * 1000 + 1000)
    again = await _register(app_client, admin_token, "bob")
    assert again.status_code == 200, again.text
    bobs = [u for u in mock_db._storage["users"] if u["username"] == "bob"]
    assert [u["id"] for u in bobs] == [again.json()["user_id"]]


@pytest.mark.asyncio
async def test_registration_with_uploaded_keys_keeps_the_username(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)
    first = await _register(app_client, admin_token, "bob")
    user = next(u for u in mock_db._storage["users"] if u["id"] == first.json()["user_id"])
    user["encrypted_keypair"] = b"\x01" * 197
    user["created_at"] = int(time.time() * 1000) - 30 * 24 * HOUR_MS
    assert (await _register(app_client, admin_token, "bob")).status_code == 409


def _js_function(name: str) -> str:
    src = APP_JS.read_text(encoding="utf-8")
    start = src.index(f"async function {name}(")
    nxt = re.compile(r"^(?:async )?function ", re.M).search(src, start + 1)
    return src[start:nxt.start() if nxt else len(src)]


@pytest.mark.parametrize("name,server_call", [
    ("handleBootstrap", "'/api/bootstrap'"),
    ("handleOnboarding", "'/api/users/register'"),
])
def test_web_derives_the_kek_before_the_account_exists(name, server_call):
    body = _js_function(name)
    derive = body.index("await deriveKEK(")
    create = body.index(server_call)
    wrap = body.index("encryptKeypairWrap(")
    upload = body.index("'/api/me/keypair'")
    assert derive < create < wrap < upload
    # Nothing slow or remote between creating the account and the upload.
    between = body[create:upload]
    assert between.count("await ") == 1 and "apiFetch('/api/meta')" not in between
