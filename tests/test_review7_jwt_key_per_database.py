"""Review 7c10379 (server, medium): a wiped database took revoked JWTs again.

The revoked tokens and the token epochs live in the database, the JWT key in
jwt_key.bin. A server whose database was wiped (or set up anew) with the key
file kept took every unexpired token it had revoked again. Each database now
has a random id (server_instance) and the JWT key is derived from the file's
key and that id, so a new database refuses every token of the old one.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import jwt
import pytest
from nacl.signing import SigningKey

from server.app import main
from server.app.auth import create_jwt, verify_jwt
from server.app.config import JWTKeyManager, ServerConfig
from server.app.database import Database
from server.app.dependencies import get_jwt_manager


class _Cursor:
    def __init__(self, storage: dict):
        self._storage = storage
        self._row = None
        self._rows: list = []

    async def execute(self, query, args=()):
        q = " ".join(query.split())
        self._row, self._rows = None, []
        if q.startswith(("SELECT GET_LOCK", "SELECT RELEASE_LOCK", "SELECT COUNT(*) FROM information_schema")):
            self._row = (1,)
        elif q.startswith("INSERT IGNORE INTO server_instance"):
            self._storage.setdefault("instance_id", args[0])
        elif q.startswith("SELECT instance_id FROM server_instance"):
            self._row = (self._storage["instance_id"],)
        elif q.startswith("SHOW COLLATION LIKE"):
            self._rows = [(args[0],)]  # a fresh database on a server that has it (R11 #1)

    async def fetchone(self):
        return self._row

    async def fetchall(self):
        return self._rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _database(storage: dict) -> Database:
    db = Database(MagicMock())

    @asynccontextmanager
    async def acquire():
        conn = MagicMock()
        conn.cursor = lambda: _Cursor(storage)

        async def commit():
            return None

        conn.commit = commit
        yield conn

    db.acquire = acquire
    return db


@pytest.mark.asyncio
async def test_each_database_keeps_one_random_id():
    kept, wiped = {}, {}
    first = _database(kept)
    await first.create_schema()
    again = _database(kept)
    await again.create_schema()
    fresh = _database(wiped)
    await fresh.create_schema()
    assert first.instance_id == again.instance_id and len(first.instance_id) == 32
    assert fresh.instance_id != first.instance_id


def test_a_token_of_another_database_is_refused(tmp_path):
    key_file = tmp_path / "jwt_key.bin"
    key_file.write_bytes(bytes(SigningKey.generate()))
    old = JWTKeyManager(str(key_file))
    old.bind_database(b"a" * 32)
    token = create_jwt(old.signing_key, "USER0000000000000000000001", "alice", False)

    same = JWTKeyManager(str(key_file))
    same.bind_database(b"a" * 32)
    assert verify_jwt(token, same.verify_key_bytes)["sub"] == "USER0000000000000000000001"

    for other in (b"b" * 32, None):
        new = JWTKeyManager(str(key_file))
        if other is not None:
            new.bind_database(other)
        with pytest.raises(jwt.InvalidTokenError):
            verify_jwt(token, new.verify_key_bytes)


@pytest.mark.asyncio
async def test_the_server_signs_with_the_key_of_its_database(tmp_path, monkeypatch):
    key_file = tmp_path / "jwt_key.bin"
    monkeypatch.setattr(ServerConfig, "from_env", classmethod(
        lambda cls: ServerConfig(jwt_signing_key_path=str(key_file), hmac_server_secret="s" * 32)
    ))

    async def _idle(*_args, **_kwargs):
        return None

    monkeypatch.setattr(main, "_periodic_cleanup", _idle)
    monkeypatch.setattr(main, "_db_watchdog", _idle)

    async def _token_of(storage: dict) -> tuple[str, bytes]:
        async def connect(self):
            return None

        async def close(self):
            return None

        monkeypatch.setattr(main, "Database", lambda config: _database(storage))
        monkeypatch.setattr(Database, "connect", connect)
        monkeypatch.setattr(Database, "close", close)
        async with main.lifespan(main.app):
            mgr = get_jwt_manager()
            return create_jwt(mgr.signing_key, "USER0000000000000000000001", "alice", False), mgr.verify_key_bytes

    token, _ = await _token_of({})
    _, wiped_key = await _token_of({})  # same jwt_key.bin, a new database
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, wiped_key)
