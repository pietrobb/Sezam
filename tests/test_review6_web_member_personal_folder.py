"""Review d615826 (web): a team member can create a personal folder on the web.

The real app.js in node against the real server: an approved member signs in
on the web, creates a personal folder and an entry in it, and finds both
again at the next sign-in (and the admin cannot read them).
"""

from __future__ import annotations

import hashlib

import pytest

from sezam import cli
from tests.test_cross_client_password_change import _passwords, _web
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_jwt,
    _create_regular_user,
    _push_object,
    app_client,
    mock_db,
)

ROOT = "SHAREDROOT0000000000000001"
ALICE_DEK = "ALICEDEK000000000000000001"


def sealed(dek_id: str) -> bytes:
    """A blob shaped like an AEAD envelope (alg, schema, kind, DEK id, nonce, ciphertext)."""
    return bytes([1, 1, 2]) + dek_id.encode("ascii") + b"\x00" * 24 + b"c" * 32


@pytest.mark.asyncio
async def test_server_takes_a_members_folder_but_no_entry_directly_below_the_root(app_client, mock_db):  # noqa: F811
    alice_id = "USER0000000000000000000001"
    alice_sk, _ = _create_regular_user(mock_db._storage, alice_id, "alice")
    token = _create_jwt(alice_id, "alice", False)
    mock_db._storage["vault_objects"].append({
        "id": ROOT, "object_type": "node", "payload": b"vault root",
        "owner_id": "ADMIN000000000000000000001", "signature_user_id": "ADMIN000000000000000000001",
        "write_policy": "owner_only", "target_user_id": None, "parent_ref": None,
        "access_level": None, "version": 1, "commit_seq": 1, "is_deleted": 0,
        "payload_hash": hashlib.sha256(b"vault root").hexdigest(),
        "client_signature": b"x" * 64, "modified_at": 1,
    })
    dek = await _push_object(app_client, token, alice_sk, ALICE_DEK, "dek", None, 1, b"k" * 72)
    assert len(dek.json()["accepted"]) == 1, dek.json()
    folder = await _push_object(
        app_client, token, alice_sk, "ALICEPERSONAL0000000000001", "node", ROOT, 1, sealed(ALICE_DEK),
    )
    assert len(folder.json()["accepted"]) == 1, folder.json()
    entry = await _push_object(app_client, token, alice_sk, "ALICEENTRY0000000000000001", "entry", ROOT, 1, b"e")
    assert entry.json()["conflicts"][0]["error"] == "write_acl denied"
    inside = await _push_object(
        app_client, token, alice_sk, "ALICEENTRY0000000000000002", "entry", "ALICEPERSONAL0000000000001", 1, b"e",
    )
    assert len(inside.json()["accepted"]) == 1, inside.json()


def test_member_creates_a_personal_folder_on_the_web(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_entry(laptop.create_node("Servers"), "db01", [{"key": "password", "value": "s", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    admin_client = _client(laptop, url)

    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    admin_client.approve_user(bob.db.get_meta("user_id"))
    bob.lock()

    browser: dict = {}
    made = _web(
        url, browser,
        {"action": "login", "username": "bob", "password": PASSWORD},
        {"action": "save", "mode": "personal", "name": "Mine"},
        {"action": "save", "mode": "entry", "name": "home", "parent": "Mine",
         "fields": [{"key": "password", "value": "bob-pw"}]},
    )
    assert made["error"] is None, made
    again = _web(url, browser, {"action": "login", "username": "bob", "password": PASSWORD})
    assert again["error"] is None, again
    assert any(n["name"] == "Mine" and n["personal"] for n in again["nodes"]), again["nodes"]
    assert _passwords(again).get("home") == "bob-pw"

    admin = _web(url, {}, {"action": "login", "username": "admin", "password": PASSWORD})
    assert admin["error"] is None, admin
    assert "home" not in _passwords(admin)
    laptop.lock()
