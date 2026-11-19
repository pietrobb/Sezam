"""Review e4cd15a (low): a migration-renamed account kept its old name on devices.

trim_stored_usernames renamed an untrimmed account whose normalized name
belonged to another account to "<name>-2", but only the server log said so.
Its devices kept signing in with the old name, which reached the other
account, so every login failed. The migration records the old name in
renamed_from; /auth/verify signs a login under it in when the renamed
account's key signed it and answers the current name, which desktop, web
and mobile store.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest import mock

import pytest

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_regular_user,
    _make_ed25519_keypair,
    _sign_challenge,
    app_client,
    mock_db,
)
from tests.test_username_trim_review_n3 import _Cursor

ROOT = Path(__file__).resolve().parents[1]
OTHER_ID = "USER0000000000000000000001"
RENAMED_ID = "USER0000000000000000000002"


def test_migration_records_the_old_name_of_a_renamed_account():
    from server.app.database import trim_stored_usernames

    cur = _Cursor({"C": "carol", "D": " carol "})
    asyncio.run(trim_stored_usernames(cur))
    assert cur.users == {"C": "carol", "D": "carol-2"}
    assert cur.renamed_from == {"D": "carol"}


async def _login(client, username: str, sk):
    challenge = (await client.post(
        "/api/auth/challenge", json={"username": username}
    )).json()["challenge"]
    return await client.post("/api/auth/verify", json={
        "username": username,
        "challenge": challenge,
        "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
    })


def _renamed_pair(storage):
    other_sk, _ = _create_regular_user(storage, OTHER_ID, "carol")
    renamed_sk, _ = _create_regular_user(storage, RENAMED_ID, "carol-2")
    storage["users"][1]["renamed_from"] = "carol"
    return other_sk, renamed_sk


@pytest.mark.asyncio
async def test_device_under_the_old_name_reaches_the_renamed_account(app_client, mock_db):
    _, renamed_sk = _renamed_pair(mock_db._storage)

    resp = await _login(app_client, "carol", renamed_sk)
    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == RENAMED_ID
    assert resp.json()["username"] == "carol-2"


@pytest.mark.asyncio
async def test_old_name_still_opens_the_other_account_and_nothing_else(app_client, mock_db):
    other_sk, _ = _renamed_pair(mock_db._storage)

    resp = await _login(app_client, "carol", other_sk)
    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == OTHER_ID
    assert resp.json()["username"] == "carol"

    stranger_sk, _ = _make_ed25519_keypair()
    assert (await _login(app_client, "carol", stranger_sk)).status_code == 401


def test_desktop_stores_the_current_name():
    from server.app.auth import generate_challenge
    from sezam.crypto.keys import generate_keypair
    from sezam.vault.sync_client import SyncClient

    meta = {"username": "carol"}
    db = mock.Mock()
    db.get_meta.side_effect = meta.get
    db.set_meta.side_effect = meta.__setitem__
    client = SyncClient.__new__(SyncClient)
    client._db = db
    client._keypair = generate_keypair()
    client._token = None
    client._report_legacy_kdf_params = lambda: None
    client._pending_old_keypair = lambda: None
    challenge, _ = generate_challenge()
    replies = [{"challenge": challenge.hex()}, {"token": "jwt", "username": "carol-2"}]
    client._request = lambda method, path, body=None, auth=False: replies.pop(0)

    assert client.authenticate() == "jwt"
    assert meta["username"] == "carol-2"


def test_web_and_mobile_keep_the_current_name():
    web = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert "state.username = authResp.username || username;" in web
    sync = (ROOT / "mobile" / "lib" / "services" / "sync_service.dart").read_text(
        encoding="utf-8"
    )
    assert "await prefs.setString(usernamePrefKey, _accountName!);" in sync
    auth = (ROOT / "mobile" / "lib" / "services" / "auth_service.dart").read_text(
        encoding="utf-8"
    )
    assert "prefs.setString(_usernameKey, username)" not in auth
