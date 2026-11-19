"""Review 526419e N8: a renamed account got 401, not 409, after a key rotation.

A device of a migration-renamed account still signs in under the old name.
When another device of the account rotated the identity key, /auth/verify
answered that old key with 401 instead of the 409 'Identity key rotated' that
makes a device take the new keypair over - and the takeover would have run
under the old name, i.e. against the account holding that name now. The 409
carries the current name, which desktop and mobile store before the takeover.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from tests.test_renamed_account_login import RENAMED_ID, _login, _renamed_pair
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _make_ed25519_keypair,
    app_client,
    mock_db,
)

ROOT = Path(__file__).resolve().parents[1]


def _archive(storage, user_id: str, retired_pk: bytes) -> None:
    storage.setdefault("user_key_archives", []).append({
        "id": "ARCHIVE0000000000000000009", "user_id": user_id,
        "signing_pk": retired_pk, "encryption_pk": retired_pk,
        "key_fingerprint": "f" * 64, "archived_at": 5,
        "successor_signing_pk": b"s" * 32, "rotation_signature": b"c" * 64,
        "authorization_signature": None, "retired_seq": 1,
    })


@pytest.mark.asyncio
async def test_retired_key_of_a_renamed_account_gets_409_with_its_name(app_client, mock_db):
    _renamed_pair(mock_db._storage)
    retired_sk, retired_pk = _make_ed25519_keypair()
    _archive(mock_db._storage, RENAMED_ID, retired_pk)

    resp = await _login(app_client, "carol", retired_sk)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"] == {"error": "Identity key rotated", "username": "carol-2"}


@pytest.mark.asyncio
async def test_a_stranger_under_the_old_name_still_gets_401(app_client, mock_db):
    _renamed_pair(mock_db._storage)
    stranger_sk, _ = _make_ed25519_keypair()
    resp = await _login(app_client, "carol", stranger_sk)
    assert resp.status_code == 401
    assert "carol-2" not in resp.text


def test_desktop_takes_over_under_the_current_name():
    import json

    from server.app.auth import generate_challenge
    from sezam.crypto.keys import generate_keypair
    from sezam.vault.sync_client import KeyEpochStale, ServerError, SyncClient

    meta = {"username": "carol"}
    db = mock.Mock()
    db.get_meta.side_effect = meta.get
    db.set_meta.side_effect = meta.__setitem__
    client = SyncClient.__new__(SyncClient)
    client._db = db
    client._keypair = generate_keypair()
    client._token = None
    client._pending_old_keypair = lambda: None
    challenge, _ = generate_challenge()
    body = json.dumps({
        "detail": {"error": "Identity key rotated", "username": "carol-2"},
        "code": "identity_key_rotated",
    })
    replies = [{"challenge": challenge.hex()}, ServerError(409, body)]

    def request(method, path, body=None, auth=False):
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    client._request = request
    with pytest.raises(KeyEpochStale):
        client.authenticate()
    assert meta["username"] == "carol-2"


def test_mobile_stores_the_name_of_the_409():
    sync = (ROOT / "mobile" / "lib" / "services" / "sync_service.dart").read_text(
        encoding="utf-8"
    )
    block = sync.split("verifyResp.body.contains('Identity key rotated')", 1)[1]
    block = block.split("throw const KeyEpochStaleException();", 1)[0]
    assert "_rotatedAccountName(verifyResp.body)" in block
    assert "prefs.setString(usernamePrefKey, currentName)" in block
