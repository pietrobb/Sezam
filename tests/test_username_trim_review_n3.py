"""Lockout review N3: whitespace around the username.

Web onboarding and mobile trimmed the name, the server (except bootstrap),
desktop CLI and web login did not. "alice " registered a second account
next to "alice", and logging in as "alice " got a fake /meta salt (wrong
password) or no account at all. Every endpoint now strips the name, clients
send the stripped name, and accounts stored untrimmed are renamed once.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from unittest import mock

import click
import pytest

from server.app.auth import compute_auth_proof_hash
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    _make_ed25519_keypair,
    _sign_challenge,
    app_client,
    mock_db,
)

ROOT = Path(__file__).resolve().parents[1]
ADMIN_ID = "ADMIN000000000000000000001"


def _keys() -> dict:
    _, signing_pk = _make_ed25519_keypair()
    _, encryption_pk = _make_ed25519_keypair()
    return {"signing_pk": signing_pk.hex(), "encryption_pk": encryption_pk.hex()}


async def _register(client, username: str):
    admin_token = _create_jwt(ADMIN_ID, "admin", True)
    invite = await client.post(
        "/api/users/invite", headers={"Authorization": f"Bearer {admin_token}"}
    )
    return await client.post("/api/users/register", json={
        "invitation_token": invite.json()["invitation_token"],
        "username": username,
        **_keys(),
    })


# ── server ──


@pytest.mark.asyncio
async def test_padded_name_registers_the_trimmed_account_once(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    first = await _register(app_client, "  bob ")
    assert first.status_code == 200, first.text
    assert [u["username"] for u in mock_db._storage["users"]] == ["admin", "bob"]

    second = await _register(app_client, "bob\t")
    assert second.status_code == 409
    assert (await _register(app_client, "   ")).status_code == 422
    assert [u["username"] for u in mock_db._storage["users"]] == ["admin", "bob"]


@pytest.mark.asyncio
async def test_bootstrap_rejects_a_blank_name(app_client, mock_db):
    resp = await app_client.post("/api/bootstrap", json={"username": " \t ", **_keys()})
    assert resp.status_code == 422
    assert mock_db._storage.get("users", []) == []


@pytest.mark.asyncio
async def test_padded_name_logs_in_to_the_existing_account(app_client, mock_db):
    sk, _ = _create_regular_user(mock_db._storage, username="alice")
    mock_db._storage["users"][0]["argon2_salt"] = b"\x11" * 16

    meta = (await app_client.get("/api/meta", params={"username": " alice "})).json()
    assert meta["argon2_salt"] == "11" * 16  # the real salt, not a fake one

    challenge = (await app_client.post(
        "/api/auth/challenge", json={"username": "alice "}
    )).json()["challenge"]
    signature = _sign_challenge(sk, bytes.fromhex(challenge)).hex()
    resp = await app_client.post("/api/auth/verify", json={
        "username": " alice", "challenge": challenge, "signature": signature,
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == "USER0000000000000000000001"


@pytest.mark.asyncio
async def test_recover_with_a_padded_name_reaches_the_account(app_client, mock_db):
    _create_regular_user(mock_db._storage, username="alice")
    proof = bytes.fromhex("ab" * 32)
    verify_salt = b"\x22" * 32
    user = mock_db._storage["users"][0]
    user["verify_salt"] = verify_salt
    user["auth_proof_hash"] = compute_auth_proof_hash(verify_salt, proof)

    resp = await app_client.post("/api/auth/recover", json={
        "username": "alice ", "auth_proof": proof.hex(),
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["encrypted_keypair"] == "00" * 64


class _Cursor:
    """Just enough of a cursor for trim_stored_usernames."""

    def __init__(self, users: dict[str, str]):
        self.users = users
        self.renamed_from: dict[str, str] = {}
        self._rows: list = []

    async def execute(self, query: str, args: tuple = ()) -> None:
        if query.startswith("SELECT id, username"):
            self._rows = [
                (uid, name) for uid, name in self.users.items()
                if re.search(r"^\s|\s$", name)
            ]
        elif query.startswith("SELECT COUNT(*)"):
            name, uid = args
            self._rows = [(sum(
                1 for other, n in self.users.items() if n == name and other != uid
            ),)]
        elif query.startswith("UPDATE users SET username = %s, renamed_from = %s"):
            name, old, uid = args
            self.users[uid] = name
            self.renamed_from[uid] = old
        elif query.startswith("UPDATE users"):
            name, uid = args
            self.users[uid] = name
        else:
            raise AssertionError(query)

    async def fetchall(self):
        return self._rows

    async def fetchone(self):
        return self._rows[0] if self._rows else None


def test_existing_untrimmed_accounts_are_renamed_unless_taken():
    from server.app.database import trim_stored_usernames

    cur = _Cursor({
        "A": " alice", "B": "bob\t", "C": "carol", "D": " carol ", "E": "dave",
    })
    asyncio.run(trim_stored_usernames(cur))
    assert cur.users == {
        "A": "alice", "B": "bob", "C": "carol", "D": "carol-2", "E": "dave",
    }  # review 688edcb N3: a taken name gets a reachable suffix


def test_schema_migration_runs_the_rename():
    src = (ROOT / "server" / "app" / "database.py").read_text(encoding="utf-8")
    body = src[src.index("async def create_schema"):src.index("async def hold_maintenance_lock")]
    assert "await trim_stored_usernames(cur)" in body


# ── desktop ──


def test_cli_username_prompt_strips_and_refuses_blank():
    from sezam.cli import _username_value

    assert _username_value("  alice \t") == "alice"
    with pytest.raises(click.BadParameter):
        _username_value("   ")


def test_desktop_sends_the_trimmed_name_of_an_older_vault(tmp_path):
    from sezam.vault.sync_client import SyncClient

    db = mock.Mock()
    db.get_meta.side_effect = lambda key: " alice " if key == "username" else None
    client = SyncClient.__new__(SyncClient)
    client._db = db
    assert client._get_username() == "alice"


def test_reseed_signs_the_trimmed_name():
    src = (ROOT / "src" / "sezam" / "vault" / "reseed.py").read_text(encoding="utf-8")
    assert 'username = normalize_username(db.get_meta("username") or "")' in src


# ── web ──


def _function(src: str, name: str) -> str:
    start = re.search(rf"^(async )?function {name}\(", src, re.M).start()
    end = re.search(r"^}", src[start:], re.M).end()
    return src[start:start + end]


def test_web_login_uses_the_trimmed_name():
    login = _function(
        (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8"),
        "handleLogin",
    )
    assert "normalizeUsername(document.getElementById('username').value);" in login
    assert "if (!username) {" in login
    assert login.index("if (!username) {") < login.index("resetSession();")
