"""Regressions for code review HEAD 2c7e809, section 3 (server, medium/low)."""

from __future__ import annotations

import asyncio
import hashlib
import pathlib
import time

import pytest
from nacl.signing import SigningKey

from tests.test_server_spec import (  # noqa: F401  (fixtures)
    MockCursor,
    _create_admin_user,
    _create_jwt,
    app_client,
    mock_db,
)

ADMIN_ID = "ADMIN000000000000000000001"


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# -- S1: all workers end up with one JWT key --------------------------------

def test_jwt_key_race_loser_adopts_winner_key(tmp_path, monkeypatch):
    from server.app.config import JWTKeyManager

    key_path = tmp_path / "keys" / "jwt.key"
    winner = JWTKeyManager(str(key_path))
    winner_pk = winner.verify_key_bytes

    # The loser checked exists() before the winner published its key.
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: False)
    loser = JWTKeyManager(str(key_path))
    assert loser.verify_key_bytes == winner_pk
    monkeypatch.undo()
    assert sorted(p.name for p in key_path.parent.iterdir()) == ["jwt.key"]


# -- S2: a pull page never loads payloads beyond its byte budget ------------

@pytest.mark.asyncio
async def test_pull_loads_only_payloads_that_fit(app_client, mock_db, monkeypatch):
    _create_admin_user(mock_db._storage)
    token = _create_jwt(ADMIN_ID, "admin", True)
    payload = b"x" * (1024 * 1024)
    for seq in range(1, 7):
        mock_db._storage["vault_objects"].append({
            "id": f"BYTES{seq:021d}", "object_type": "dek", "payload": payload,
            "owner_id": ADMIN_ID, "parent_ref": None, "target_user_id": None,
            "version": 1, "commit_seq": seq, "is_deleted": 0,
            "payload_hash": hashlib.sha256(payload).hexdigest(),
            "client_signature": b"\x00" * 64, "modified_at": int(time.time() * 1000),
        })
    loaded_payload_bytes = []
    original = MockCursor.execute

    async def spy(self, query, args=()):
        await original(self, query, args)
        if "FROM vault_objects" in query and "payload," in query:
            loaded_payload_bytes.append(sum(len(r[2]) for r in self._results))

    monkeypatch.setattr(MockCursor, "execute", spy)
    response = await app_client.get(
        "/api/sync?since_commit_seq=0&full_resync=true", headers=_auth(token)
    )

    assert response.status_code == 200
    assert len(response.json()["objects"]) == 2
    assert loaded_payload_bytes == [2 * len(payload)]


# -- S3: org-recovery challenge is rate limited -----------------------------

@pytest.mark.asyncio
async def test_org_recovery_challenge_is_rate_limited(app_client, mock_db):
    mock_db._storage.setdefault("org_recovery_blobs", []).append({
        "id": 1, "wrapped_kek": b"\x01" * 80, "recovery_signing_pk": b"\x02" * 32,
        "threshold": 3, "total_shares": 5, "created_by": ADMIN_ID, "created_at": 1,
    })
    statuses = [
        (await app_client.post("/api/org-recovery/challenge")).status_code
        for _ in range(21)
    ]
    assert statuses[:20] == [200] * 20
    assert statuses[20] == 429
    assert len(mock_db._storage["spent_challenges"]) == 20


# -- S4: provisioning tokens can actually be issued -------------------------

@pytest.mark.asyncio
async def test_provisioning_token_round_trip(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    token = _create_jwt(ADMIN_ID, "admin", True)

    issued = await app_client.post("/api/auth/provisioning-token", headers=_auth(token))
    assert issued.status_code == 200
    body = issued.json()
    assert body["username"] == "admin"
    assert body["expires_at"] - int(time.time() * 1000) <= 10 * 60 * 1000
    stored = mock_db._storage["provisioning_tokens"][0]
    assert stored["token_hash"] == hashlib.sha256(body["token"].encode()).hexdigest()

    redeemed = await app_client.post(
        "/api/auth/provision", json={"token": body["token"], "username": "admin"}
    )
    assert redeemed.status_code == 200
    assert redeemed.json()["user_id"] == ADMIN_ID
    again = await app_client.post(
        "/api/auth/provision", json={"token": body["token"], "username": "admin"}
    )
    assert again.status_code == 410


@pytest.mark.asyncio
async def test_scoped_jwt_cannot_mint_provisioning_token(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    scoped = _create_jwt(ADMIN_ID, "admin", True, scope="keypair_upload")
    response = await app_client.post("/api/auth/provisioning-token", headers=_auth(scoped))
    assert response.status_code in (401, 403)
    assert not mock_db._storage.get("provisioning_tokens")


# -- S5: malformed hex is a 422, never a 500 --------------------------------

@pytest.mark.asyncio
async def test_malformed_hex_is_rejected_as_validation_error(app_client, mock_db):
    bad_key = "zz" * 32
    bootstrap = await app_client.post("/api/bootstrap", json={
        "username": "root", "signing_pk": bad_key, "encryption_pk": bad_key,
    })
    assert bootstrap.status_code == 422
    assert not mock_db._storage.get("users")

    register = await app_client.post("/api/users/register", json={
        "invitation_token": "x", "username": "bob",
        "signing_pk": "0" * 63, "encryption_pk": "0" * 64,
    })
    assert register.status_code == 422

    _create_admin_user(mock_db._storage)
    token = _create_jwt(ADMIN_ID, "admin", True)
    push = await app_client.post("/api/sync", headers=_auth(token), json={"objects": [{
        "id": "OBJ00000000000000000000001", "object_type": "node", "payload": "AA==",
        "version": 1, "payload_hash": "g" * 64, "signature": "0" * 128,
    }]})
    assert push.status_code == 422


# -- S6: audit CSV neutralizes spreadsheet formulas -------------------------

def test_csv_safe_neutralizes_formulas():
    from server.app.routers.audit import csv_safe

    assert csv_safe("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    for prefix in "+-@\t\r":
        assert csv_safe(prefix + "1").startswith("'")
    assert csv_safe("alice") == "alice"


@pytest.mark.asyncio
async def test_audit_csv_export_escapes_usernames(app_client, mock_db):
    _create_admin_user(mock_db._storage, username="=cmd|'/c calc'!A1")
    token = _create_jwt(ADMIN_ID, "=cmd|'/c calc'!A1", True)
    mock_db._storage.setdefault("server_audit", []).append({
        "id": "AUD00000000000000000000001", "user_id": ADMIN_ID,
        "action": "@SUM(1)", "timestamp": 1_700_000_000_000,
        "request_hash": None, "commit_seq_range": None,
        "client_signature": b"\x00" * 64, "client_ip": None,
    })
    original = MockCursor.execute

    async def with_join(self, query, args=()):
        await original(self, query, args)
        if "FROM server_audit sa" in query:
            # The mock has no JOIN; emulate the username column.
            self._results = [
                (r["id"], r["user_id"], "=cmd|'/c calc'!A1", r["action"], r["timestamp"],
                 r["request_hash"], r["commit_seq_range"], r["client_ip"])
                for r in mock_db._storage["server_audit"]
            ]

    import tests.test_server_spec as spec
    spec.MockCursor.execute = with_join
    try:
        response = await app_client.get("/api/audit/csv", headers=_auth(token))
    finally:
        spec.MockCursor.execute = original
    assert response.status_code == 200
    assert "'@SUM(1)" in response.text
    assert "'=cmd|" in response.text


# -- S7: case-folded usernames are not an enumeration oracle ----------------

@pytest.fixture
def case_insensitive_usernames(monkeypatch):
    """Emulate MariaDB's case-insensitive utf8mb4 collation in the mock."""
    original = MockCursor._row_matches_where

    def matches(self, row, where_clause, args):
        if "username = %s" in where_clause:
            row = {**row, "username": str(row.get("username", "")).lower()}
            args = tuple(a.lower() if isinstance(a, str) else a for a in args)
        return original(self, row, where_clause, args)

    monkeypatch.setattr(MockCursor, "_row_matches_where", matches)


@pytest.mark.asyncio
async def test_meta_case_alias_looks_like_unknown_user(
    app_client, mock_db, case_insensitive_usernames
):
    _create_admin_user(mock_db._storage)
    real = (await app_client.get("/api/meta?username=admin")).json()
    alias = (await app_client.get("/api/meta?username=ADMIN")).json()
    unknown = (await app_client.get("/api/meta?username=nobody")).json()

    assert real["argon2_salt"] == (b"\x00" * 16).hex()
    assert alias["argon2_salt"] != real["argon2_salt"]
    assert len(alias["argon2_salt"]) == len(unknown["argon2_salt"])


@pytest.mark.asyncio
async def test_verify_rejects_case_alias(app_client, mock_db, case_insensitive_usernames):
    sk, _ = _create_admin_user(mock_db._storage)
    challenge = (await app_client.post(
        "/api/auth/challenge", json={"username": "ADMIN"}
    )).json()["challenge"]
    response = await app_client.post("/api/auth/verify", json={
        "username": "ADMIN",
        "challenge": challenge,
        "signature": sk.sign(bytes.fromhex(challenge)).signature.hex(),
    })
    assert response.status_code == 401


# -- S8: periodic maintenance runs in one worker only -----------------------

@pytest.mark.asyncio
async def test_periodic_cleanup_skips_without_maintenance_lock(monkeypatch):
    from server.app import main
    from server.app.config import ServerConfig

    calls = []
    for name in ("_cleanup_spent_challenges", "_cleanup_revoked_tokens",
                 "_cleanup_expired_shares", "_cleanup_tombstones"):
        async def record(*_args, _name=name):
            calls.append(_name)
        monkeypatch.setattr(main, name, record)

    class FakeDb:
        def __init__(self, leader):
            self.leader = leader

        async def hold_maintenance_lock(self):
            return self.leader

    async def stop(_seconds):
        raise asyncio.CancelledError

    monkeypatch.setattr(main.asyncio, "sleep", stop)
    config = ServerConfig(hmac_server_secret="x" * 32)

    with pytest.raises(asyncio.CancelledError):
        await main._periodic_cleanup(FakeDb(leader=False), config)
    assert calls == []

    with pytest.raises(asyncio.CancelledError):
        await main._periodic_cleanup(FakeDb(leader=True), config)
    assert len(calls) == 4


class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, sql, args=()):
        self._conn.sql.append(sql)

    async def fetchone(self):
        return (self._conn.lock_result,)


class _FakeConn:
    def __init__(self, lock_result):
        self.lock_result = lock_result
        self.sql = []
        self.closed = False

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        self.closed = True


class _FakePool:
    def __init__(self, conn):
        self.conn = conn
        self.released = 0

    async def acquire(self):
        return self.conn

    def release(self, _conn):
        self.released += 1


@pytest.mark.asyncio
async def test_maintenance_lock_is_held_on_a_dedicated_connection():
    from server.app.config import ServerConfig
    from server.app.database import Database

    db = Database(ServerConfig(hmac_server_secret="x" * 32))
    leader_conn = _FakeConn(lock_result=1)
    db._pool = _FakePool(leader_conn)

    assert await db.hold_maintenance_lock() is True
    assert db._pool.released == 0  # kept: the lock lives with the session
    assert await db.hold_maintenance_lock() is True
    assert "IS_USED_LOCK" in leader_conn.sql[-1]

    follower = Database(ServerConfig(hmac_server_secret="x" * 32))
    follower._pool = _FakePool(_FakeConn(lock_result=0))
    assert await follower.hold_maintenance_lock() is False
    assert follower._pool.released == 1


# -- S9: the ciphertext is wiped after the last allowed view ----------------

@pytest.mark.asyncio
async def test_share_blob_wiped_after_last_view(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    now_ms = int(time.time() * 1000)
    for share_id, max_views in (("A" * 43, 1), ("B" * 43, 2)):
        mock_db._storage["shared_links"].append({
            "id": share_id, "encrypted_blob": b"secret", "created_by": ADMIN_ID,
            "created_at": now_ms, "expires_at": now_ms + 3_600_000,
            "max_views": max_views, "view_count": 0, "pin_hash": None,
            "pin_attempts": 0, "is_locked": 0, "notify_on_view": 0,
        })

    assert (await app_client.post(f"/api/share/{'A' * 43}", json={})).status_code == 200
    assert (await app_client.post(f"/api/share/{'B' * 43}", json={})).status_code == 200
    rows = {row["id"]: row for row in mock_db._storage["shared_links"]}
    assert rows["A" * 43]["encrypted_blob"] == b""
    assert rows["B" * 43]["encrypted_blob"] == b"secret"
