"""Comprehensive specification tests for the Sezam server.

Tests the FastAPI server against the spec using httpx.AsyncClient + ASGITransport.
Uses an in-memory mock database (no real MariaDB needed).

Covers:
  - Auth (spec 2.7): challenge-response, JWT, logout, refresh, scoped tokens, recovery
  - Users (spec 8.6): invitation, registration, approval, key rotation, revocation
  - Sync (spec 8.2): push/pull, signatures, versioning, conflicts, write_acl, meta
  - Share (spec 6): create, consume, PIN, expiry, locking, admin ops
  - Security headers (spec 2.9): CSP, HSTS, X-Content-Type-Options, Referrer-Policy
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac as hmac_mod
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey, VerifyKey

# ---------------------------------------------------------------------------
# In-memory mock database that behaves like aiomysql
# ---------------------------------------------------------------------------

# NOT NULL DEFAULT columns from server/app/database.py that some INSERTs omit.
_COLUMN_DEFAULTS = {
    "sync_state": {"last_push_seq": 0, "last_pull_seq": 0, "key_epoch": 0},
}

class MockCursor:
    """In-memory cursor that supports a realistic subset of SQL for testing."""

    def __init__(self, storage: dict[str, list[dict]]):
        self._storage = storage
        self._results: list[tuple] = []
        self._pos = 0
        self.rowcount = 0
        self._last_table: str | None = None

    async def execute(self, query: str, args: tuple = ()) -> None:
        q = query.strip()
        # Substitute %s placeholders with actual values for parsing
        q_filled = q
        if args:
            for a in args:
                q_filled = q_filled.replace("%s", repr(a), 1)

        q_upper = q.upper().strip()

        # --- CREATE TABLE IF NOT EXISTS ---
        if q_upper.startswith("CREATE TABLE"):
            m = re.search(r"CREATE TABLE IF NOT EXISTS\s+(\w+)", q, re.IGNORECASE)
            if m:
                tname = m.group(1)
                if tname not in self._storage:
                    self._storage[tname] = []
            self._results = []
            self.rowcount = 0
            return

        # --- INSERT ---
        if q_upper.startswith("INSERT"):
            m = re.search(r"INSERT\s+(?:IGNORE\s+)?INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)", q, re.IGNORECASE)
            if m:
                tname = m.group(1)
                cols = [c.strip() for c in m.group(2).split(",")]
                val_tokens = [v.strip() for v in m.group(3).split(",")]
                if tname not in self._storage:
                    self._storage[tname] = []
                row = {}
                arg_idx = 0
                for i, col in enumerate(cols):
                    token = val_tokens[i] if i < len(val_tokens) else "%s"
                    if token == "%s":
                        row[col] = args[arg_idx] if arg_idx < len(args) else None
                        arg_idx += 1
                    elif token.startswith("'") and token.endswith("'"):
                        row[col] = token[1:-1]  # SQL string literal
                    else:
                        # Numeric literal
                        try:
                            row[col] = int(token)
                        except ValueError:
                            try:
                                row[col] = float(token)
                            except ValueError:
                                row[col] = token
                for col, default in _COLUMN_DEFAULTS.get(tname, {}).items():
                    row.setdefault(col, default)

                is_ignore = "IGNORE" in q_upper.split("INTO")[0]
                # Handle ON DUPLICATE KEY UPDATE
                on_dup = "ON DUPLICATE KEY UPDATE" in q_upper
                # Determine PK
                pk_col = self._get_pk(tname)
                existing_idx = None
                if pk_col and pk_col in row:
                    for idx, existing_row in enumerate(self._storage[tname]):
                        if existing_row.get(pk_col) == row[pk_col]:
                            existing_idx = idx
                            break
                # Also check composite PKs for write_acl
                if tname == "write_acl":
                    for idx, existing_row in enumerate(self._storage[tname]):
                        if (existing_row.get("user_id") == row.get("user_id")
                                and existing_row.get("node_id") == row.get("node_id")):
                            existing_idx = idx
                            break

                if tname == "users" and existing_idx is None and any(
                    u.get("username") == row.get("username") for u in self._storage[tname]
                ):
                    raise Exception(f"Duplicate entry '{row.get('username')}' for key 'username'")

                if existing_idx is not None:
                    if on_dup:
                        # Parse VALUES(col) updates
                        dup_match = re.search(r"ON DUPLICATE KEY UPDATE\s+(.+)$", q, re.IGNORECASE)
                        if dup_match:
                            updates = dup_match.group(1)
                            for part in updates.split(","):
                                part = part.strip()
                                col_m = re.match(r"(\w+)\s*=\s*VALUES\((\w+)\)", part)
                                if col_m:
                                    self._storage[tname][existing_idx][col_m.group(1)] = row.get(col_m.group(2))
                                else:
                                    col_m2 = re.match(r"(\w+)\s*=\s*(.+)", part)
                                    if col_m2:
                                        self._storage[tname][existing_idx][col_m2.group(1)] = row.get(col_m2.group(1))
                        self.rowcount = 1
                    elif is_ignore:
                        self.rowcount = 0
                    else:
                        # Duplicate key error for non-IGNORE
                        raise Exception(f"Duplicate key: {pk_col}={row.get(pk_col)}")
                else:
                    self._storage[tname].append(row)
                    self.rowcount = 1
                self._results = []
                return

        # --- SELECT ---
        if q_upper.startswith("SELECT"):
            m_from = re.search(r"FROM\s+(\w+)", q, re.IGNORECASE)
            if not m_from:
                # Subquery like SELECT next_seq - 1 FROM commit_counter
                m_from2 = re.search(r"FROM\s+(\w+)", q, re.IGNORECASE)
                if m_from2:
                    tname = m_from2.group(1)
                else:
                    self._results = []
                    return
            else:
                tname = m_from.group(1)
            self._last_table = tname

            if tname not in self._storage:
                self._storage[tname] = []

            rows = list(self._storage[tname])

            # Parse SELECT columns
            select_part = q[:q_upper.index("FROM")].replace("SELECT", "", 1).strip()
            if select_part.upper().startswith("DISTINCT"):
                select_part = select_part[8:].strip()

            # Handle WHERE
            where_match = re.search(
                r"WHERE\s+(.+?)(?:\s+ORDER\s|\s+FOR\s|\s+LOCK\s|\s+LIMIT\s|$)", q, re.IGNORECASE
            )
            if where_match:
                where_clause = where_match.group(1).strip()
                rows = self._apply_where(rows, where_clause, args, q)

            order_match = re.search(r"ORDER BY\s+(\w+)", q, re.IGNORECASE)
            if order_match:
                rows.sort(key=lambda row: row.get(order_match.group(1)) or 0)
            limit_match = re.search(r"LIMIT\s+(%s|\d+)", q, re.IGNORECASE)
            if limit_match:
                limit = args[-1] if limit_match.group(1) == "%s" else int(limit_match.group(1))
                rows = rows[:limit]

            if select_part.upper() == "COUNT(*)":
                self._results = [(len(rows),)]
                return

            # Handle MAX(commit_seq) or similar aggregates
            if "MAX(" in select_part.upper():
                m_max = re.search(r"MAX\((\w+)\)", select_part, re.IGNORECASE)
                if m_max:
                    col_name = m_max.group(1)
                    max_val = None
                    for r in rows:
                        v = r.get(col_name)
                        if v is not None:
                            if max_val is None or v > max_val:
                                max_val = v
                    self._results = [(max_val,)]
                    return

            # Handle expressions like "next_seq - 1"
            if re.search(r"\w+\s*-\s*\d+", select_part):
                m_expr = re.match(r"(\w+)\s*-\s*(\d+)", select_part.strip())
                if m_expr:
                    col_name = m_expr.group(1)
                    offset = int(m_expr.group(2))
                    if rows:
                        self._results = [(rows[0].get(col_name, 0) - offset,)]
                    else:
                        self._results = []
                    return

            # Parse column names
            if select_part.strip() == "1":
                self._results = [(1,) for _ in rows]
                return

            cols = [c.strip() for c in select_part.split(",")]
            result_rows = []
            for r in rows:
                vals = []
                for c in cols:
                    c_clean = c.strip().strip("`")
                    m_len = re.fullmatch(r"LENGTH\((\w+)\)", c_clean, re.IGNORECASE)
                    if m_len:
                        vals.append(len(r.get(m_len.group(1)) or b""))
                        continue
                    vals.append(r.get(c_clean))
                result_rows.append(tuple(vals))
            self._results = result_rows
            return

        # --- UPDATE ---
        if q_upper.startswith("UPDATE"):
            m = re.search(r"UPDATE\s+(\w+)\s+SET\s+(.+?)(?:\s+WHERE\s+(.+))?$", q, re.IGNORECASE | re.DOTALL)
            if m:
                tname = m.group(1)
                set_clause = m.group(2)
                where_clause = m.group(3)

                if tname not in self._storage:
                    self._storage[tname] = []

                rows = self._storage[tname]
                # Determine which args go to SET and which to WHERE
                # Count %s in SET clause
                set_placeholder_count = set_clause.count("%s")
                set_args = args[:set_placeholder_count]
                where_args = args[set_placeholder_count:]

                matched_indices = []
                if where_clause:
                    for idx, row in enumerate(rows):
                        if self._row_matches_where(row, where_clause, where_args):
                            matched_indices.append(idx)
                else:
                    matched_indices = list(range(len(rows)))

                # Parse SET assignments
                set_assignments = self._parse_set_clause(set_clause, set_args)

                for idx in matched_indices:
                    for col, val in set_assignments.items():
                        if val == "__INCREMENT__":
                            self._storage[tname][idx][col] = (self._storage[tname][idx].get(col) or 0) + 1
                        elif val == "__DECREMENT__":
                            self._storage[tname][idx][col] = (self._storage[tname][idx].get(col) or 0) - 1
                        else:
                            self._storage[tname][idx][col] = val

                self.rowcount = len(matched_indices)
                self._results = []
                return

        # --- DELETE ---
        if q_upper.startswith("DELETE"):
            m = re.search(r"DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?$", q, re.IGNORECASE)
            if m:
                tname = m.group(1)
                where_clause = m.group(2)
                if tname not in self._storage:
                    self._storage[tname] = []
                    self.rowcount = 0
                    return

                if where_clause:
                    original_len = len(self._storage[tname])
                    remaining = []
                    for row in self._storage[tname]:
                        if not self._row_matches_where(row, where_clause, args):
                            remaining.append(row)
                    self._storage[tname] = remaining
                    self.rowcount = original_len - len(remaining)
                else:
                    self.rowcount = len(self._storage[tname])
                    self._storage[tname] = []
                self._results = []
                return

        # Fallback
        self._results = []
        self.rowcount = 0

    def _get_pk(self, tname: str) -> str | None:
        pks = {
            "users": "id",
            "user_key_archives": "id",
            "user_key_material_archive": "id",
            "recovery_name_limits": "name_hmac",
            "recovery_ip_limits": "ip_hmac",
            "recovery_probe_slots": "slot_key",
            "recovery_name_rations": "limit_id",
            "vault_objects": "id",
            "collected_objects": "id",
            "shared_links": "id",
            "share_views": "id",
            "share_pin_rate_limits": "ip_hmac",
            "server_audit": "id",
            "provisioning_tokens": "token_hash",
            "invitation_tokens": "token_hash",
            "spent_challenges": "challenge_hash",
            "auth_challenge_limits": "user_id",
            "sync_push_claims": "user_id",
            "sync_staged_gate": "id",
            "sync_staged_queue": "user_id",
            "org_recovery_rate_limits": "ip_hmac",
            "revoked_tokens": "token_hash",
            "commit_counter": "id",
            "sync_state": "user_id",
            "org_recovery_blobs": "id",
            "team_log": "seq",
            "ai_anchors": "anchor_key",
        }
        return pks.get(tname)

    def _apply_where(self, rows: list[dict], where_clause: str, args: tuple, full_q: str) -> list[dict]:
        """Simple WHERE evaluation using positional args."""
        # Count how many %s appear BEFORE the WHERE in the full query
        where_pos = full_q.upper().find("WHERE")
        pre_where = full_q[:where_pos]
        pre_count = pre_where.count("%s")
        where_args = args[pre_count:]

        result = []
        for row in rows:
            if self._row_matches_where(row, where_clause, where_args):
                result.append(row)
        return result

    def _row_matches_where(self, row: dict, where_clause: str, args: tuple) -> bool:
        """Evaluate a WHERE clause against a row."""
        # Split on AND
        conditions = re.split(r"\s+AND\s+", where_clause, flags=re.IGNORECASE)
        arg_idx = 0
        for cond in conditions:
            cond = cond.strip()
            # Handle col = %s
            m = re.match(r"(\w+)\s*=\s*%s", cond)
            if m:
                col = m.group(1)
                if arg_idx < len(args):
                    if row.get(col) != args[arg_idx]:
                        return False
                    arg_idx += 1
                continue
            # Handle col > %s
            m = re.match(r"(\w+)\s*>\s*%s", cond)
            if m:
                col = m.group(1)
                if arg_idx < len(args):
                    val = row.get(col)
                    if val is None or val <= args[arg_idx]:
                        return False
                    arg_idx += 1
                continue
            # Handle col <= %s
            m = re.match(r"(\w+)\s*<=\s*%s", cond)
            if m:
                col = m.group(1)
                if arg_idx < len(args):
                    val = row.get(col)
                    if val is None or val > args[arg_idx]:
                        return False
                    arg_idx += 1
                continue
            # Handle col < %s
            m = re.match(r"(\w+)\s*<\s*%s", cond)
            if m:
                col = m.group(1)
                if arg_idx < len(args):
                    val = row.get(col)
                    if val is None or val >= args[arg_idx]:
                        return False
                    arg_idx += 1
                continue
            # Handle col = 'literal'
            m = re.match(r"(\w+)\s*=\s*'([^']*)'", cond)
            if m:
                col = m.group(1)
                expected = m.group(2)
                if row.get(col) != expected:
                    return False
                continue
            # Handle numeric literals such as is_deleted = 0.
            m = re.match(r"(\w+)\s*=\s*(-?\d+)", cond)
            if m:
                if row.get(m.group(1)) != int(m.group(2)):
                    return False
                continue
            # Handle status = 'active' AND other forms already handled above

        return True

    def _parse_set_clause(self, set_clause: str, args: tuple) -> dict:
        """Parse SET col1 = %s, col2 = col2 + 1, ..."""
        result = {}
        # Split carefully on commas (not inside function calls)
        parts = []
        depth = 0
        current = ""
        for ch in set_clause:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(current.strip())
                current = ""
                continue
            current += ch
        if current.strip():
            parts.append(current.strip())

        arg_idx = 0
        for part in parts:
            m = re.match(r"(\w+)\s*=\s*(.+)", part.strip())
            if not m:
                continue
            col = m.group(1)
            val_expr = m.group(2).strip()
            if val_expr == "%s":
                if arg_idx < len(args):
                    result[col] = args[arg_idx]
                    arg_idx += 1
            elif re.match(r"\w+\s*\+\s*\d+", val_expr):
                # col = col + 1 → mark as increment
                result[col] = "__INCREMENT__"
            elif re.match(r"\w+\s*-\s*1$", val_expr):
                result[col] = "__DECREMENT__"
            elif val_expr.startswith("'") and val_expr.endswith("'"):
                # SQL string literal: strip quotes
                result[col] = val_expr[1:-1]
            elif val_expr == "1":
                result[col] = 1
            elif val_expr == "0":
                result[col] = 0
            else:
                # Might be VALUES(col) or literal
                result[col] = val_expr

        return result

    async def fetchone(self) -> tuple | None:
        if self._results:
            row = self._results[0]
            self._results = self._results[1:]
            return row
        return None

    async def fetchall(self) -> list[tuple]:
        rows = list(self._results)
        self._results = []
        return rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class MockConnection:
    """Mock aiomysql connection.

    Emulates real transactional semantics: begin() snapshots storage,
    rollback() restores it, commit() makes changes permanent. Without this,
    uncommitted writes leaked past a raised exception and masked real
    rollback bugs (e.g. share PIN-lockout being discarded on HTTPException).
    """

    def __init__(self, storage: dict):
        self._storage = storage
        self._snapshot = None

    def cursor(self):
        return MockCursor(self._storage)

    async def begin(self):
        self._snapshot = copy.deepcopy(self._storage)

    async def commit(self):
        self._snapshot = None

    async def rollback(self):
        if self._snapshot is not None:
            # Restore contents in place so existing references stay valid.
            self._storage.clear()
            self._storage.update(self._snapshot)
            self._snapshot = None


class MockDatabase:
    """In-memory Database replacement with dict-based storage."""

    def __init__(self):
        self._storage: dict[str, list[dict]] = {}

    async def connect(self):
        pass

    async def close(self):
        pass

    async def create_schema(self):
        """Initialize all tables and commit_counter."""
        tables = [
            "users", "user_key_archives", "user_key_material_archive", "vault_objects",
            "shared_links", "share_views",
            "share_pin_rate_limits", "server_audit", "provisioning_tokens", "invitation_tokens",
            "spent_challenges", "auth_challenge_limits", "org_recovery_rate_limits",
            "recovery_ip_limits", "recovery_probe_slots", "recovery_name_rations", "revoked_tokens", "write_acl", "commit_counter", "sync_state",
            "org_recovery_blobs",
        ]
        for t in tables:
            if t not in self._storage:
                self._storage[t] = []
        # Init commit_counter
        if not self._storage["commit_counter"]:
            self._storage["commit_counter"].append({
                "id": 1, "next_seq": 1, "gc_floor_seq": 0,
            })

    @asynccontextmanager
    async def acquire(self):
        yield MockConnection(self._storage)

    @asynccontextmanager
    async def transaction(self):
        conn = MockConnection(self._storage)
        await conn.begin()
        try:
            yield conn
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_ed25519_keypair() -> tuple[SigningKey, bytes]:
    """Generate Ed25519 keypair. Returns (signing_key, public_key_bytes)."""
    sk = SigningKey.generate()
    return sk, bytes(sk.verify_key)


def _sign_challenge(sk: SigningKey, challenge_bytes: bytes) -> bytes:
    """Sign a challenge with Ed25519."""
    return sk.sign(challenge_bytes).signature


def _sign_sync_object(
    sk: SigningKey,
    obj_id: str,
    object_type: str,
    parent_ref: str | None,
    target_user_id: str | None,
    is_deleted: int,
    version: int,
    payload_hash: str,
) -> str:
    """Create a valid Ed25519 signature for a sync object (spec 8.2 canonical form)."""
    id_bytes = obj_id.encode("utf-8").ljust(26, b"\x00")[:26]
    ot_bytes = object_type.encode("utf-8")
    parent_bytes = parent_ref.encode("utf-8").ljust(26, b"\x00")[:26] if parent_ref else b"\x00" * 26
    target_bytes = target_user_id.encode("utf-8").ljust(26, b"\x00")[:26] if target_user_id else b"\x00" * 26
    payload_hash_bytes = bytes.fromhex(payload_hash)

    canonical = (
        id_bytes
        + bytes([len(ot_bytes)]) + ot_bytes
        + parent_bytes
        + target_bytes
        + bytes([is_deleted])
        + version.to_bytes(4, "big")
        + payload_hash_bytes
    )

    return sk.sign(canonical).signature.hex()


def _sign_server_audit(
    sk: SigningKey,
    audit_id: str,
    user_id: str,
    action: str,
    timestamp: int,
    request_hash: str,
) -> str:
    canonical = (
        audit_id.encode("ascii")
        + user_id.encode("ascii")
        + action.encode("utf-8")
        + timestamp.to_bytes(8, "big")
        + bytes.fromhex(request_hash)
    )
    return sk.sign(canonical).signature.hex()


def _with_server_base(objects: list[dict]) -> list[dict]:
    """Name the mock server's current copy as the base of every update that has none."""
    from server.app.dependencies import get_db

    stored = {o["id"]: o for o in get_db()._storage.get("vault_objects", [])}
    for obj in objects:
        current = stored.get(obj["id"])
        if current is not None and "base_version" not in obj:
            obj["base_version"] = current["version"]
            obj["base_payload_hash"] = current["payload_hash"]
    return objects


async def _push_object(
    client, token, sk, obj_id, object_type, parent_ref, version, payload: bytes,
    is_deleted: int = 0, write_policy: str | None = "owner_only",
):
    """Helper: sign and push a single sync object; returns the response.

    Pass write_policy=None to OMIT the field entirely (simulating a
    desktop/mobile client that doesn't send it). The change builds on the
    server's current copy, as a client in step with the server would.
    """
    p_b64 = base64.b64encode(payload).decode("ascii")
    p_hash = hashlib.sha256(payload).hexdigest()
    sig = _sign_sync_object(sk, obj_id, object_type, parent_ref, None, is_deleted, version, p_hash)
    obj = {
        "id": obj_id, "object_type": object_type, "payload": p_b64,
        "parent_ref": parent_ref, "version": version, "is_deleted": is_deleted,
        "payload_hash": p_hash, "signature": sig,
    }
    _with_server_base([obj])
    if write_policy is not None:
        obj["write_policy"] = write_policy
    return await client.post("/api/sync", json={
        "objects": [obj],
        "atomic_batch": False,
    }, headers={"Authorization": f"Bearer {token}"})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# JWT key for testing
_jwt_sk = SigningKey.generate()


@pytest_asyncio.fixture
async def mock_db():
    """Create a fresh mock database for each test."""
    db = MockDatabase()
    await db.create_schema()
    return db


@pytest_asyncio.fixture
async def app_client(mock_db: MockDatabase, tmp_path):
    """Create a test client with mock DB and real JWT keys."""
    from server.app.config import JWTKeyManager, ServerConfig
    from server.app.dependencies import set_globals
    from server.app.main import app

    config = ServerConfig(
        jwt_expiry_seconds=3600,
        jwt_onboarding_expiry_seconds=900,
        hmac_server_secret="test-server-secret-key-12345",
        recovery_ip_max_failures_per_hour=10,
        recovery_max_total=10,
    )

    # Write a test JWT key file
    key_file = tmp_path / "jwt_test_key.bin"
    key_file.write_bytes(bytes(_jwt_sk))
    jwt_mgr = JWTKeyManager(str(key_file))

    set_globals(config, mock_db, jwt_mgr)

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


def _create_admin_user(storage: dict, user_id: str = "ADMIN000000000000000000001",
                       username: str = "admin") -> tuple[SigningKey, bytes]:
    """Insert an active admin user into mock storage. Returns (signing_key, pk_bytes)."""
    sk, pk = _make_ed25519_keypair()
    enc_sk = SigningKey.generate()
    enc_pk = bytes(enc_sk.verify_key)
    fingerprint = hashlib.sha256(pk + enc_pk).hexdigest()
    now_ms = int(time.time() * 1000)
    storage.setdefault("users", []).append({
        "id": user_id,
        "username": username,
        "signing_pk": pk,
        "encryption_pk": enc_pk,
        "key_fingerprint": fingerprint,
        "status": "active",
        "is_admin": 1,
        "encrypted_keypair": b"\x00" * 64,
        "argon2_salt": b"\x00" * 16,
        "auth_salt": b"\x00" * 16,
        "verify_salt": None,
        "auth_proof_hash": None,
        "recovery_locked": 0,
        "recovery_attempts": 0,
        "recovery_attempts_hour": 0,
        "last_recovery_attempt": None,
        "created_at": now_ms,
    })
    return sk, pk


def _create_regular_user(storage: dict, user_id: str = "USER0000000000000000000001",
                         username: str = "alice") -> tuple[SigningKey, bytes]:
    """Insert an active regular user. Returns (signing_key, pk_bytes)."""
    sk, pk = _make_ed25519_keypair()
    enc_sk = SigningKey.generate()
    enc_pk = bytes(enc_sk.verify_key)
    fingerprint = hashlib.sha256(pk + enc_pk).hexdigest()
    now_ms = int(time.time() * 1000)
    storage.setdefault("users", []).append({
        "id": user_id,
        "username": username,
        "signing_pk": pk,
        "encryption_pk": enc_pk,
        "key_fingerprint": fingerprint,
        "status": "active",
        "is_admin": 0,
        "encrypted_keypair": b"\x00" * 64,
        "argon2_salt": b"\x00" * 16,
        "auth_salt": b"\x00" * 16,
        "verify_salt": None,
        "auth_proof_hash": None,
        "recovery_locked": 0,
        "recovery_attempts": 0,
        "recovery_attempts_hour": 0,
        "last_recovery_attempt": None,
        "created_at": now_ms,
    })
    return sk, pk


def _create_jwt(user_id: str, username: str, is_admin: bool,
                expiry: int = 3600, scope: str | None = None,
                token_epoch: int = 0) -> str:
    """Create a valid JWT for testing."""
    from server.app.auth import create_jwt
    return create_jwt(
        _jwt_sk, user_id, username, is_admin, expiry, scope, token_epoch=token_epoch
    )


async def _signed_challenge_fields(client: AsyncClient, sk: SigningKey, username: str) -> dict:
    """Fresh challenge + signature fields for key-replacing endpoints."""
    resp = await client.post("/api/auth/challenge", json={"username": username})
    challenge = resp.json()["challenge"]
    return {
        "challenge": challenge,
        "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
    }


async def _do_challenge_verify(client: AsyncClient, storage: dict,
                               sk: SigningKey, username: str) -> str:
    """Complete the challenge-response flow and return a JWT token."""
    # Step 1: challenge
    resp = await client.post("/api/auth/challenge", json={"username": username})
    assert resp.status_code == 200
    data = resp.json()
    challenge_hex = data["challenge"]
    challenge_bytes = bytes.fromhex(challenge_hex)

    # Step 2: sign and verify
    sig = _sign_challenge(sk, challenge_bytes)
    resp = await client.post("/api/auth/verify", json={
        "username": username,
        "challenge": challenge_hex,
        "signature": sig.hex(),
    })
    assert resp.status_code == 200
    return resp.json()["token"]


async def _do_signed_refresh(
    client: AsyncClient, token: str, sk: SigningKey, username: str
):
    challenge_resp = await client.post(
        "/api/auth/challenge", json={"username": username}
    )
    challenge = challenge_resp.json()["challenge"]
    signature = _sign_challenge(sk, bytes.fromhex(challenge)).hex()
    return await client.post(
        "/api/auth/refresh",
        json={"challenge": challenge, "signature": signature},
        headers={"Authorization": f"Bearer {token}"},
    )


# =====================================================================
# AUTH TESTS (spec 2.7)
# =====================================================================

class TestBootstrap:
    @pytest.mark.asyncio
    async def test_jwt_key_failure_does_not_create_partial_admin(self, mock_db):
        from server.app.models.schemas import BootstrapRequest
        from server.app.routers.auth import bootstrap

        class FailingJWTKeyManager:
            @property
            def signing_key(self):
                raise PermissionError("JWT key is not writable")

        request = BootstrapRequest(
            username="admin",
            signing_pk="11" * 32,
            encryption_pk="22" * 32,
        )

        with pytest.raises(PermissionError, match="JWT key is not writable"):
            await bootstrap(
                request,
                MagicMock(client=MagicMock(host="198.51.100.1")),
                db=mock_db,
                jwt_mgr=FailingJWTKeyManager(),
                config=MagicMock(
                    jwt_onboarding_expiry_seconds=900, hmac_server_secret="k" * 32,
                    bootstrap_disabled=False,
                ),
            )

        assert mock_db._storage["users"] == []


class TestAuthChallenge:
    """Tests for POST /api/auth/challenge."""

    @pytest.mark.asyncio
    async def test_challenge_returns_32b_random_plus_timestamp(self, app_client, mock_db):
        """Challenge must be 32B random + 8B timestamp = 40B total."""
        _create_admin_user(mock_db._storage)
        resp = await app_client.post("/api/auth/challenge", json={"username": "admin"})
        assert resp.status_code == 200
        data = resp.json()
        challenge_hex = data["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)
        # 32 bytes random + 8 bytes timestamp = 40 bytes
        assert len(challenge_bytes) == 40
        # Timestamp should be recent (within 5 seconds)
        ts = int.from_bytes(challenge_bytes[-8:], "big")
        now_ms = int(time.time() * 1000)
        assert abs(now_ms - ts) < 5000

    @pytest.mark.asyncio
    async def test_challenge_returns_timestamp_field(self, app_client, mock_db):
        """Response must include timestamp field."""
        _create_admin_user(mock_db._storage)
        resp = await app_client.post("/api/auth/challenge", json={"username": "admin"})
        data = resp.json()
        assert "timestamp" in data
        assert isinstance(data["timestamp"], int)
        assert data["timestamp"] > 0

    @pytest.mark.asyncio
    async def test_challenge_for_nonexistent_user_still_returns_challenge(self, app_client, mock_db):
        """Non-existent users get a challenge too (prevent enumeration)."""
        resp = await app_client.post("/api/auth/challenge", json={"username": "nonexistent"})
        assert resp.status_code == 200
        data = resp.json()
        assert "challenge" in data
        assert len(bytes.fromhex(data["challenge"])) == 40

    @pytest.mark.asyncio
    async def test_anonymous_challenge_flood_cannot_lock_out_user(
        self, app_client, mock_db
    ):
        """Review #11: issuing is stateless, so flooding writes nothing and the
        real user can still log in with the challenge they receive."""
        sk, _ = _create_admin_user(mock_db._storage)
        for _ in range(50):
            response = await app_client.post(
                "/api/auth/challenge", json={"username": "admin"}
            )
            assert response.status_code == 200
        assert mock_db._storage["spent_challenges"] == []
        assert mock_db._storage["auth_challenge_limits"] == []

        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        assert token

    @pytest.mark.asyncio
    async def test_challenge_is_bound_to_username_and_unforgeable(
        self, app_client, mock_db
    ):
        sk, _ = _create_admin_user(mock_db._storage)
        other = await app_client.post("/api/auth/challenge", json={"username": "mallory"})
        challenge = other.json()["challenge"]
        resp = await app_client.post("/api/auth/verify", json={
            "username": "admin",
            "challenge": challenge,
            "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
        })
        assert resp.status_code == 401

        forged = os.urandom(32) + int(time.time() * 1000).to_bytes(8, "big")
        resp = await app_client.post("/api/auth/verify", json={
            "username": "admin",
            "challenge": forged.hex(),
            "signature": _sign_challenge(sk, forged).hex(),
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_challenge_cleanup_removes_expired_rows_and_limiters(self, mock_db):
        from server.app.main import _cleanup_spent_challenges

        now_ms = int(time.time() * 1000)
        mock_db._storage["spent_challenges"].extend([
            {"challenge_hash": "old", "used_at": now_ms - 301_000},
            {"challenge_hash": "new", "used_at": now_ms},
        ])
        mock_db._storage["auth_challenge_limits"].extend([
            {"user_id": "old", "window_started_at": now_ms - 301_000, "issue_count": 10},
            {"user_id": "new", "window_started_at": now_ms, "issue_count": 1},
        ])
        mock_db._storage["org_recovery_rate_limits"].extend([
            {"ip_hmac": "old", "window_started_at": now_ms - 3_601_000, "attempt_count": 5},
            {"ip_hmac": "new", "window_started_at": now_ms, "attempt_count": 1},
        ])

        await _cleanup_spent_challenges(mock_db, 300)

        assert [row["challenge_hash"] for row in mock_db._storage["spent_challenges"]] == ["new"]
        assert [row["user_id"] for row in mock_db._storage["auth_challenge_limits"]] == ["new"]
        assert [row["ip_hmac"] for row in mock_db._storage["org_recovery_rate_limits"]] == ["new"]


class TestAuthVerify:
    """Tests for POST /api/auth/verify."""

    @pytest.mark.asyncio
    async def test_valid_signature_returns_jwt(self, app_client, mock_db):
        """Valid Ed25519 signature on challenge must yield a JWT."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        assert token
        # Decode and verify JWT fields
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["sub"] == "ADMIN000000000000000000001"
        assert decoded["username"] == "admin"
        assert decoded["is_admin"] is True
        assert "exp" in decoded

    @pytest.mark.asyncio
    async def test_jwt_contains_correct_fields(self, app_client, mock_db):
        """JWT must contain sub, username, is_admin, exp."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert "sub" in decoded
        assert "username" in decoded
        assert "is_admin" in decoded
        assert "exp" in decoded
        assert "iat" in decoded

    @pytest.mark.asyncio
    async def test_jwt_expiry_is_approximately_1h(self, app_client, mock_db):
        """JWT expiry should be ~1 hour (3600 seconds)."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        ttl = decoded["exp"] - decoded["iat"]
        assert 3590 <= ttl <= 3610

    @pytest.mark.asyncio
    async def test_invalid_signature_returns_401(self, app_client, mock_db):
        """Invalid Ed25519 signature must return 401."""
        _create_admin_user(mock_db._storage)
        # Get challenge
        resp = await app_client.post("/api/auth/challenge", json={"username": "admin"})
        challenge_hex = resp.json()["challenge"]
        # Sign with a DIFFERENT key (wrong key)
        wrong_sk = SigningKey.generate()
        bad_sig = _sign_challenge(wrong_sk, bytes.fromhex(challenge_hex))
        resp = await app_client.post("/api/auth/verify", json={
            "username": "admin",
            "challenge": challenge_hex,
            "signature": bad_sig.hex(),
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_spent_challenge_reuse_fails(self, app_client, mock_db):
        """A consumed challenge must not be reusable."""
        sk, _ = _create_admin_user(mock_db._storage)
        # First: challenge + verify succeeds
        resp = await app_client.post("/api/auth/challenge", json={"username": "admin"})
        challenge_hex = resp.json()["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)
        sig = _sign_challenge(sk, challenge_bytes)
        resp = await app_client.post("/api/auth/verify", json={
            "username": "admin",
            "challenge": challenge_hex,
            "signature": sig.hex(),
        })
        assert resp.status_code == 200

        # Second attempt with same challenge should fail
        resp = await app_client.post("/api/auth/verify", json={
            "username": "admin",
            "challenge": challenge_hex,
            "signature": sig.hex(),
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_challenge_timestamp_replay_protection(self, app_client, mock_db):
        """Challenge older than 30s should fail verification."""
        sk, pk = _create_admin_user(mock_db._storage)
        # Create an old challenge manually (>30s old)
        old_ts_ms = int(time.time() * 1000) - 35000  # 35 seconds ago
        random_part = os.urandom(32)
        old_challenge = random_part + old_ts_ms.to_bytes(8, "big")

        # Store in spent_challenges so it's "found"
        ch = hashlib.sha256(old_challenge + b"admin").hexdigest()
        mock_db._storage["spent_challenges"].append({
            "challenge_hash": ch,
            "used_at": int(time.time() * 1000),
        })

        sig = _sign_challenge(sk, old_challenge)
        resp = await app_client.post("/api/auth/verify", json={
            "username": "admin",
            "challenge": old_challenge.hex(),
            "signature": sig.hex(),
        })
        # Should fail because challenge timestamp is too old
        assert resp.status_code == 401


class TestAuthLogout:
    """Tests for POST /api/auth/logout."""

    @pytest.mark.asyncio
    async def test_logout_revokes_jwt(self, app_client, mock_db):
        """Logout should add the token to revoked_tokens."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")

        resp = await app_client.post(
            "/api/auth/logout",
            json={"token": token},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Token should now be revoked in storage
        from server.app.auth import token_revocation_key
        token_h = token_revocation_key(pyjwt.decode(token, options={"verify_signature": False}))
        revoked = [r for r in mock_db._storage["revoked_tokens"] if r["token_hash"] == token_h]
        assert len(revoked) == 1

    @pytest.mark.asyncio
    async def test_revoked_jwt_returns_401(self, app_client, mock_db):
        """Using a revoked JWT should return 401."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")

        # Logout to revoke
        await app_client.post(
            "/api/auth/logout",
            json={"token": token},
            headers={"Authorization": f"Bearer {token}"},
        )

        # Try to use the revoked token
        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


class TestAuthRefresh:
    """Tests for POST /api/auth/refresh."""

    @pytest.mark.asyncio
    async def test_refresh_returns_new_jwt_and_revokes_old(self, app_client, mock_db):
        """Refresh must issue a new JWT and revoke the old one."""
        sk, _ = _create_admin_user(mock_db._storage)
        old_token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")

        # Wait just over 1 second so the new JWT gets a different iat/exp
        # (EdDSA signatures are deterministic, so same claims = same token)
        await asyncio.sleep(1.1)

        resp = await _do_signed_refresh(app_client, old_token, sk, "admin")
        assert resp.status_code == 200
        new_token = resp.json()["token"]
        assert new_token != old_token

        # Old token should be revoked
        from server.app.auth import token_revocation_key
        old_hash = token_revocation_key(pyjwt.decode(old_token, options={"verify_signature": False}))
        revoked = [r for r in mock_db._storage["revoked_tokens"] if r["token_hash"] == old_hash]
        assert len(revoked) == 1

        # New token should work
        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_refresh_requires_current_signing_key(self, app_client, mock_db):
        """A stolen JWT without the user's Ed25519 key cannot be refreshed."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        challenge_resp = await app_client.post(
            "/api/auth/challenge", json={"username": "admin"}
        )
        challenge = challenge_resp.json()["challenge"]
        wrong_signature = _sign_challenge(
            SigningKey.generate(), bytes.fromhex(challenge)
        ).hex()

        resp = await app_client.post(
            "/api/auth/refresh",
            json={"challenge": challenge, "signature": wrong_signature},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code == 401
        still_valid = await app_client.get(
            "/api/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert still_valid.status_code == 200

    @pytest.mark.asyncio
    async def test_refresh_challenge_is_single_use(self, app_client, mock_db):
        """A consumed refresh challenge cannot mint a second token."""
        sk, _ = _create_admin_user(mock_db._storage)
        old_token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        challenge_resp = await app_client.post(
            "/api/auth/challenge", json={"username": "admin"}
        )
        challenge = challenge_resp.json()["challenge"]
        signature = _sign_challenge(sk, bytes.fromhex(challenge)).hex()
        await asyncio.sleep(1.1)

        first = await app_client.post(
            "/api/auth/refresh",
            json={"challenge": challenge, "signature": signature},
            headers={"Authorization": f"Bearer {old_token}"},
        )
        assert first.status_code == 200
        second = await app_client.post(
            "/api/auth/refresh",
            json={"challenge": challenge, "signature": signature},
            headers={"Authorization": f"Bearer {first.json()['token']}"},
        )
        assert second.status_code == 401


class TestScopedJWT:
    """Tests for scoped JWT tokens (keypair_upload)."""

    @pytest.mark.asyncio
    async def test_scoped_jwt_cannot_access_other_endpoints(self, app_client, mock_db):
        """A keypair_upload scoped JWT must not access non-keypair endpoints."""
        _create_admin_user(mock_db._storage)
        scoped_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True,
            scope="keypair_upload",
        )

        # Try to access users list — should fail with 403
        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {scoped_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_scoped_jwt_cannot_create_share(self, app_client, mock_db):
        """Onboarding scope must not create encrypted share blobs."""
        _create_admin_user(mock_db._storage)
        scoped_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True,
            scope="keypair_upload",
        )

        response = await app_client.post("/api/share", json={
            "id": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="),
            "encrypted_blob": base64.b64encode(b"ciphertext").decode("ascii"),
            "expires_at": int(time.time() * 1000) + 60_000,
            "max_views": 1,
        }, headers={"Authorization": f"Bearer {scoped_token}"})

        assert response.status_code == 403
        assert mock_db._storage["shared_links"] == []

    @pytest.mark.asyncio
    async def test_scoped_admin_jwt_cannot_store_org_recovery(self, app_client, mock_db):
        """DB-derived admin state must not expand onboarding token authority."""
        _create_admin_user(mock_db._storage)
        scoped_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True,
            scope="keypair_upload",
        )

        response = await app_client.post("/api/org-recovery/store", json={
            "wrapped_kek": os.urandom(72).hex(),
            "recovery_signing_pk": os.urandom(32).hex(),
            "threshold": 3,
            "total_shares": 5,
        }, headers={"Authorization": f"Bearer {scoped_token}"})

        assert response.status_code == 403
        assert mock_db._storage["org_recovery_blobs"] == []

    @pytest.mark.asyncio
    async def test_scoped_jwt_can_upload_keypair(self, app_client, mock_db):
        """A keypair_upload scoped JWT may do the FIRST upload only (review #9)."""
        _create_admin_user(mock_db._storage)
        mock_db._storage["users"][0]["encrypted_keypair"] = None
        scoped_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True,
            scope="keypair_upload",
        )
        body = {
            "encrypted_keypair": os.urandom(64).hex(),
            "argon2_salt": os.urandom(16).hex(),
            "auth_salt": os.urandom(16).hex(),
            "auth_proof": os.urandom(32).hex(),
            "argon2_params": {"time_cost": 3, "memory_cost": 131072, "parallelism": 4},
        }

        resp = await app_client.put(
            "/api/me/keypair", json=body,
            headers={"Authorization": f"Bearer {scoped_token}"},
        )
        assert resp.status_code == 200

        # A leaked onboarding token cannot overwrite the uploaded key material.
        again = await app_client.put(
            "/api/me/keypair", json={**body, "encrypted_keypair": os.urandom(64).hex()},
            headers={"Authorization": f"Bearer {scoped_token}"},
        )
        assert again.status_code == 403
        assert mock_db._storage["users"][0]["encrypted_keypair"] == bytes.fromhex(
            body["encrypted_keypair"]
        )

    @pytest.mark.asyncio
    async def test_full_jwt_keypair_replace_needs_signed_challenge(self, app_client, mock_db):
        """Review #9: a stolen bearer token alone cannot upload key material,
        and a successful upload revokes every older token (token_epoch).
        Review 2052248 #1: existing key material is never replaced here."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")
        original = mock_db._storage["users"][0]["encrypted_keypair"]
        body = {
            "encrypted_keypair": os.urandom(64).hex(),
            "argon2_salt": os.urandom(16).hex(),
            "auth_salt": os.urandom(16).hex(),
            "auth_proof": os.urandom(32).hex(),
            "argon2_params": {"time_cost": 3, "memory_cost": 131072, "parallelism": 4},
        }
        headers = {"Authorization": f"Bearer {token}"}

        unsigned = await app_client.put("/api/me/keypair", json=body, headers=headers)
        assert unsigned.status_code == 401

        # Review 2052248 #1: even correctly signed, existing key material is
        # replaced only by an epoch-advancing sync push (key_rotation).
        challenge = (await app_client.post(
            "/api/auth/challenge", json={"username": "admin"}
        )).json()["challenge"]
        replace = await app_client.put("/api/me/keypair", json={
            **body, "challenge": challenge,
            "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
        }, headers=headers)
        assert replace.status_code == 409
        assert mock_db._storage["users"][0]["encrypted_keypair"] == original

        # Finishing an interrupted onboarding (no key material yet) needs the
        # account's signing key, not just the bearer token.
        mock_db._storage["users"][0]["encrypted_keypair"] = None
        challenge = (await app_client.post(
            "/api/auth/challenge", json={"username": "admin"}
        )).json()["challenge"]
        wrong_sk, _ = _make_ed25519_keypair()
        forged = await app_client.put("/api/me/keypair", json={
            **body, "challenge": challenge,
            "signature": _sign_challenge(wrong_sk, bytes.fromhex(challenge)).hex(),
        }, headers=headers)
        assert forged.status_code == 401
        assert mock_db._storage["users"][0]["encrypted_keypair"] is None

        challenge = (await app_client.post(
            "/api/auth/challenge", json={"username": "admin"}
        )).json()["challenge"]
        ok = await app_client.put("/api/me/keypair", json={
            **body, "challenge": challenge,
            "signature": _sign_challenge(sk, bytes.fromhex(challenge)).hex(),
        }, headers=headers)
        assert ok.status_code == 200
        assert mock_db._storage["users"][0]["encrypted_keypair"] == bytes.fromhex(
            body["encrypted_keypair"]
        )
        new_token = ok.json()["token"]

        old = await app_client.get("/api/users/ADMIN000000000000000000001/keys", headers=headers)
        assert old.status_code == 401
        fresh = await app_client.get(
            "/api/users/ADMIN000000000000000000001/keys",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        assert fresh.status_code == 200

    @pytest.mark.asyncio
    async def test_scoped_jwt_cannot_refresh(self, app_client, mock_db):
        """Scoped JWTs should not be refreshable."""
        _create_admin_user(mock_db._storage)
        scoped_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True,
            scope="keypair_upload",
        )

        resp = await app_client.post(
            "/api/auth/refresh",
            json={"challenge": "00", "signature": "00"},
            headers={"Authorization": f"Bearer {scoped_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_scoped_jwt_cannot_push_sync(self, app_client, mock_db):
        """Scoped JWT must not access sync push (require_full_jwt guard)."""
        _create_admin_user(mock_db._storage)
        scoped_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True,
            scope="keypair_upload",
        )

        resp = await app_client.post(
            "/api/sync",
            json={"objects": [], "atomic_batch": False},
            headers={"Authorization": f"Bearer {scoped_token}"},
        )
        assert resp.status_code == 403


class TestRecoveryRateLimiting:
    """Tests for recovery rate limiting (spec 2.7)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("auth_proof", ["zz" * 32, "00" * 31, "00" * 33])
    async def test_malformed_auth_proof_is_bounded_before_db_mutation(
        self, app_client, mock_db, auth_proof
    ):
        _create_admin_user(mock_db._storage)

        response = await app_client.post(
            "/api/auth/recover",
            json={"username": "admin", "auth_proof": auth_proof},
        )

        assert response.status_code == 422
        assert mock_db._storage["users"][0]["recovery_attempts"] == 0

    @pytest.mark.asyncio
    async def test_missing_account_and_unconfigured_recovery_are_indistinguishable(
        self, app_client, mock_db
    ):
        _create_admin_user(mock_db._storage)
        proof = os.urandom(32).hex()

        missing = await app_client.post(
            "/api/auth/recover",
            json={"username": "missing", "auth_proof": proof},
        )
        unconfigured = await app_client.post(
            "/api/auth/recover",
            json={"username": "admin", "auth_proof": proof},
        )

        assert missing.status_code == unconfigured.status_code == 401
        assert missing.json() == unconfigured.json() == {"detail": "Recovery failed"}
        assert mock_db._storage["users"][0]["recovery_attempts"] == 0

    @pytest.mark.asyncio
    async def test_success_returns_user_id_for_keypair_aad(self, app_client, mock_db):
        _create_admin_user(mock_db._storage)
        auth_proof = os.urandom(32)
        verify_salt = os.urandom(32)
        user_row = mock_db._storage["users"][0]
        user_row["verify_salt"] = verify_salt
        user_row["auth_proof_hash"] = hmac_mod.new(
            verify_salt, auth_proof, hashlib.sha256
        ).hexdigest()

        with patch(
            "server.app.routers.auth.hmac.compare_digest",
            wraps=hmac_mod.compare_digest,
        ) as compare_digest:
            response = await app_client.post("/api/auth/recover", json={
                "username": "admin",
                "auth_proof": auth_proof.hex(),
            })

        assert response.status_code == 200
        assert response.json()["user_id"] == user_row["id"]
        compare_digest.assert_called_once()

    @pytest.mark.asyncio
    async def test_recovery_increments_attempts(self, app_client, mock_db):
        """Wrong auth_proof should increment recovery counters."""
        sk, pk = _create_admin_user(mock_db._storage)
        # Set up verify_salt and auth_proof_hash
        verify_salt = os.urandom(32)
        auth_proof = os.urandom(32)
        auth_proof_hash = hmac_mod.new(verify_salt, auth_proof, hashlib.sha256).hexdigest()

        user_row = mock_db._storage["users"][0]
        user_row["verify_salt"] = verify_salt
        user_row["auth_proof_hash"] = auth_proof_hash

        # Wrong auth_proof
        wrong_proof = os.urandom(32).hex()
        resp = await app_client.post("/api/auth/recover", json={
            "username": "admin",
            "auth_proof": wrong_proof,
        })
        assert resp.status_code == 401

        # Check counter incremented
        assert mock_db._storage["users"][0]["recovery_attempts"] == 1

    @pytest.mark.asyncio
    async def test_recovery_locks_after_max_total(self, app_client, mock_db):
        """After 10 total failures, recovery should be locked."""
        sk, pk = _create_admin_user(mock_db._storage)
        verify_salt = os.urandom(32)
        auth_proof = os.urandom(32)
        auth_proof_hash = hmac_mod.new(verify_salt, auth_proof, hashlib.sha256).hexdigest()

        user_row = mock_db._storage["users"][0]
        user_row["verify_salt"] = verify_salt
        user_row["auth_proof_hash"] = auth_proof_hash
        # Set attempts to 9 so next failure locks
        user_row["recovery_attempts"] = 9
        user_row["recovery_attempts_hour"] = 0
        user_row["last_recovery_attempt"] = None

        wrong_proof = os.urandom(32).hex()
        resp = await app_client.post("/api/auth/recover", json={
            "username": "admin",
            "auth_proof": wrong_proof,
        })
        assert resp.status_code == 423  # Locked
        assert mock_db._storage["users"][0]["recovery_locked"] == 1

    @pytest.mark.asyncio
    async def test_recovery_rate_limited_per_hour(self, app_client, mock_db):
        """After 10 failures within 1 hour from one address it is rate-limited
        (lockout review #7: per address, not per name)."""
        sk, pk = _create_admin_user(mock_db._storage)
        verify_salt = os.urandom(32)
        auth_proof = os.urandom(32)
        auth_proof_hash = hmac_mod.new(verify_salt, auth_proof, hashlib.sha256).hexdigest()

        user_row = mock_db._storage["users"][0]
        user_row["verify_salt"] = verify_salt
        user_row["auth_proof_hash"] = auth_proof_hash
        for _ in range(10):
            await app_client.post("/api/auth/recover", json={
                "username": "ghost", "auth_proof": os.urandom(32).hex(),
            })

        wrong_proof = os.urandom(32).hex()
        resp = await app_client.post("/api/auth/recover", json={
            "username": "admin",
            "auth_proof": wrong_proof,
        })
        assert resp.status_code == 429  # Too many requests

    @pytest.mark.asyncio
    async def test_recovery_locked_returns_423(self, app_client, mock_db):
        """Locked account should return 423 immediately."""
        _create_admin_user(mock_db._storage)
        mock_db._storage["users"][0]["recovery_locked"] = 1
        mock_db._storage["users"][0]["verify_salt"] = os.urandom(32)
        mock_db._storage["users"][0]["auth_proof_hash"] = "somehash"

        resp = await app_client.post("/api/auth/recover", json={
            "username": "admin",
            "auth_proof": os.urandom(32).hex(),
        })
        assert resp.status_code == 423

    @pytest.mark.asyncio
    async def test_recovery_lock_expires_and_admin_can_clear_it(self, app_client, mock_db):
        """Review #11: anonymous wrong proofs must not lock recovery forever."""
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        user = mock_db._storage["users"][1]
        user.update({
            "recovery_locked": 1, "recovery_attempts": 10,
            "verify_salt": os.urandom(32), "auth_proof_hash": "somehash",
            "last_recovery_attempt": int(time.time() * 1000) - 86_401_000,
        })
        resp = await app_client.post("/api/auth/recover", json={
            "username": "alice", "auth_proof": os.urandom(32).hex(),
        })
        assert resp.status_code != 423
        assert user["recovery_locked"] == 0

        user.update({"recovery_locked": 1, "recovery_attempts": 10,
                     "last_recovery_attempt": int(time.time() * 1000)})
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        cleared = await app_client.post(
            "/api/users/USER0000000000000000000001/unlock-recovery",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert cleared.status_code == 200
        assert user["recovery_locked"] == 0 and user["recovery_attempts"] == 0

        user_token = _create_jwt("USER0000000000000000000001", "alice", False)
        denied = await app_client.post(
            "/api/users/USER0000000000000000000001/unlock-recovery",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert denied.status_code == 403


class TestOrgRecoveryProof:
    """H8 regression: keypair release requires reconstructed recovery key."""

    @staticmethod
    def _configure_recovery(mock_db, recovery_sk):
        mock_db._storage["org_recovery_blobs"].append({
            "id": 1,
            "wrapped_kek": os.urandom(72),
            "recovery_signing_pk": bytes(recovery_sk.verify_key),
            "threshold": 3,
            "total_shares": 5,
            "created_by": "ADMIN000000000000000000001",
            "created_at": int(time.time() * 1000),
        })

    @pytest.mark.asyncio
    async def test_reconstructed_key_signature_releases_keypair_once(
        self, app_client, mock_db
    ):
        _create_admin_user(mock_db._storage)
        recovery_sk = SigningKey.generate()
        self._configure_recovery(mock_db, recovery_sk)

        challenge_resp = await app_client.post("/api/org-recovery/challenge", json={})
        assert challenge_resp.status_code == 200
        challenge = challenge_resp.json()["challenge"]
        signature = recovery_sk.sign(bytes.fromhex(challenge)).signature.hex()
        proof = {"challenge": challenge, "signature": signature}

        response = await app_client.post("/api/org-recovery/keypair", json=proof)
        assert response.status_code == 200
        assert response.json()["encrypted_keypair"] == (b"\x00" * 64).hex()

        replay = await app_client.post("/api/org-recovery/keypair", json=proof)
        assert replay.status_code == 401

    @pytest.mark.asyncio
    async def test_public_blob_holder_cannot_forge_recovery_proof(
        self, app_client, mock_db
    ):
        _create_admin_user(mock_db._storage)
        recovery_sk = SigningKey.generate()
        self._configure_recovery(mock_db, recovery_sk)

        challenge_resp = await app_client.post("/api/org-recovery/challenge", json={})
        challenge = challenge_resp.json()["challenge"]
        attacker_sk = SigningKey.generate()
        forged = attacker_sk.sign(bytes.fromhex(challenge)).signature.hex()

        response = await app_client.post("/api/org-recovery/keypair", json={
            "challenge": challenge,
            "signature": forged,
        })
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_keypair_limit_is_shared_through_database(self, app_client, mock_db):
        """A worker must honor the recovery budget persisted by another worker."""
        from server.app.auth import compute_ip_hmac

        ip_hmac = compute_ip_hmac("test-server-secret-key-12345", "127.0.0.1")
        mock_db._storage["org_recovery_rate_limits"].append({
            "ip_hmac": ip_hmac,
            "window_started_at": int(time.time() * 1000),
            "attempt_count": 5,
        })

        response = await app_client.post(
            "/api/org-recovery/keypair",
            json={"challenge": "invalid", "signature": "invalid"},
        )

        assert response.status_code == 429
        assert mock_db._storage["org_recovery_rate_limits"][0]["attempt_count"] == 5

    @pytest.mark.asyncio
    async def test_keypair_limit_survives_requests_and_resets_expired_window(
        self, app_client, mock_db
    ):
        from server.app.auth import compute_ip_hmac

        invalid_proof = {"challenge": "invalid", "signature": "invalid"}
        for _ in range(5):
            response = await app_client.post(
                "/api/org-recovery/keypair", json=invalid_proof
            )
            assert response.status_code == 401

        limited = await app_client.post(
            "/api/org-recovery/keypair", json=invalid_proof
        )
        assert limited.status_code == 429
        assert mock_db._storage["org_recovery_rate_limits"][0]["attempt_count"] == 5

        ip_hmac = compute_ip_hmac("test-server-secret-key-12345", "127.0.0.1")
        mock_db._storage["org_recovery_rate_limits"][0] = {
            "ip_hmac": ip_hmac,
            "window_started_at": int(time.time() * 1000) - 3_601_000,
            "attempt_count": 5,
        }
        reset = await app_client.post(
            "/api/org-recovery/keypair", json=invalid_proof
        )

        assert reset.status_code == 401
        assert mock_db._storage["org_recovery_rate_limits"][0]["attempt_count"] == 1


# =====================================================================
# USERS TESTS (spec 8.6)
# =====================================================================

class TestInvitation:
    """Tests for POST /api/users/invite."""

    @pytest.mark.asyncio
    async def test_invitation_generates_128bit_token(self, app_client, mock_db):
        """Invitation token should be 128 bits (16 bytes = 32 hex chars)."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        inv_token = data["invitation_token"]
        assert len(inv_token) == 32  # 16 bytes in hex = 32 chars

    @pytest.mark.asyncio
    async def test_invitation_has_72h_expiry(self, app_client, mock_db):
        """Invitation expires_at should be ~72 hours from now."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        data = resp.json()
        now_ms = int(time.time() * 1000)
        expected_72h = 72 * 3600 * 1000
        # Should be within 5 seconds of 72h from now
        assert abs(data["expires_at"] - now_ms - expected_72h) < 5000


class TestRegistration:
    """Tests for POST /api/users/register."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("uploaded", [False, True])
    async def test_resume_requires_current_key_and_only_issues_scoped_token(self, app_client, mock_db, uploaded):
        sk, _ = _create_regular_user(mock_db._storage)
        user = mock_db._storage["users"][0]
        user.update(status="pending", token_epoch=7, encrypted_keypair=b"stored carrier" if uploaded else None)
        endpoint = "/api/auth/registration-resume"
        proof = {"username": "alice", **await _signed_challenge_fields(app_client, SigningKey.generate(), "alice")}
        assert (await app_client.post(endpoint, json=proof)).status_code == 401
        proof = {"username": "alice", **await _signed_challenge_fields(app_client, sk, "alice")}
        result = await app_client.post(endpoint, json=proof)
        assert result.status_code == 200, result.text
        data = result.json()
        assert data["user_id"] == user["id"]
        assert data["key_material_hash"] == (hashlib.sha256(b"stored carrier").hexdigest() if uploaded else None)
        import jwt
        claims = jwt.decode(data["token"], options={"verify_signature": False})
        assert claims["scope"] == "keypair_upload"
        assert claims["tep"] == 7
        assert (await app_client.post(endpoint, json=proof)).status_code == 401
        assert (await app_client.post("/api/auth/verify", json=proof)).status_code == 401
        headers = {"Authorization": f"Bearer {data['token']}"}
        assert (await app_client.get("/api/sync", headers=headers)).status_code == 403
        user = mock_db._storage["users"][0]
        user["status"] = "revoked"
        fresh = {"username": "alice", **await _signed_challenge_fields(app_client, sk, "alice")}
        assert (await app_client.post(endpoint, json=fresh)).status_code == 401
        assert user["encrypted_keypair"] == (b"stored carrier" if uploaded else None)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("race", ["uploaded", "revoked"])
    async def test_resumed_upload_rechecks_locked_account(self, app_client, mock_db, monkeypatch, race):
        sk, _ = _create_regular_user(mock_db._storage)
        mock_db._storage["users"][0].update(status="pending", encrypted_keypair=None)
        proof = {"username": "alice", **await _signed_challenge_fields(app_client, sk, "alice")}
        resumed = await app_client.post("/api/auth/registration-resume", json=proof)
        assert resumed.status_code == 200
        transaction = mock_db.transaction

        @asynccontextmanager
        async def raced_transaction():
            user = mock_db._storage["users"][0]
            if race == "uploaded":
                user["encrypted_keypair"] = b"concurrent accepted carrier"
            else:
                user["status"] = "revoked"
            async with transaction() as conn:
                yield conn

        monkeypatch.setattr(mock_db, "transaction", raced_transaction)
        response = await app_client.put("/api/me/keypair", json={
            "encrypted_keypair": os.urandom(64).hex(), "argon2_salt": os.urandom(16).hex(),
            "auth_salt": os.urandom(16).hex(), "auth_proof": os.urandom(32).hex(),
            "argon2_params": {"time_cost": 3, "memory_cost": 131072, "parallelism": 4},
        }, headers={"Authorization": f"Bearer {resumed.json()['token']}"})
        assert response.status_code == (409 if race == "uploaded" else 401), response.text
        assert mock_db._storage["users"][0]["encrypted_keypair"] == (b"concurrent accepted carrier" if race == "uploaded" else None)

    @pytest.mark.asyncio
    async def test_register_consumes_invitation(self, app_client, mock_db):
        """Registering with valid invitation should create pending user and return onboarding JWT."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Create invitation
        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        inv_token = resp.json()["invitation_token"]

        # Register
        new_sk, new_pk = _make_ed25519_keypair()
        enc_sk, enc_pk = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "bob",
            "signing_pk": new_pk.hex(),
            "encryption_pk": enc_pk.hex(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "user_id" in data
        assert "token" in data

        # User should be pending
        users_named_bob = [u for u in mock_db._storage["users"] if u["username"] == "bob"]
        assert len(users_named_bob) == 1
        assert users_named_bob[0]["status"] == "pending"

    @pytest.mark.asyncio
    async def test_register_returns_onboarding_jwt(self, app_client, mock_db):
        """Registration should return a scoped keypair_upload JWT."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        inv_token = resp.json()["invitation_token"]

        new_sk, new_pk = _make_ed25519_keypair()
        enc_sk, enc_pk = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "charlie",
            "signing_pk": new_pk.hex(),
            "encryption_pk": enc_pk.hex(),
        })
        token = resp.json()["token"]
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["scope"] == "keypair_upload"
        # Onboarding JWT should have shorter expiry (~15 min)
        ttl = decoded["exp"] - decoded["iat"]
        assert 890 <= ttl <= 910  # ~15 min

    @pytest.mark.asyncio
    async def test_used_invitation_fails(self, app_client, mock_db):
        """Already-used invitation should fail registration."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        inv_token = resp.json()["invitation_token"]

        # First registration succeeds
        sk1, pk1 = _make_ed25519_keypair()
        ek1, epk1 = _make_ed25519_keypair()
        await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "first_user",
            "signing_pk": pk1.hex(),
            "encryption_pk": epk1.hex(),
        })

        # Second attempt with same invitation should fail
        sk2, pk2 = _make_ed25519_keypair()
        ek2, epk2 = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "second_user",
            "signing_pk": pk2.hex(),
            "encryption_pk": epk2.hex(),
        })
        assert resp.status_code == 410

    @pytest.mark.asyncio
    async def test_expired_invitation_fails(self, app_client, mock_db):
        """Expired invitation should fail registration."""
        _create_admin_user(mock_db._storage)
        # Insert an expired invitation directly
        inv_token = os.urandom(16).hex()
        token_hash = hashlib.sha256(inv_token.encode("utf-8")).hexdigest()
        now_ms = int(time.time() * 1000)
        mock_db._storage["invitation_tokens"].append({
            "token_hash": token_hash,
            "created_by": "ADMIN000000000000000000001",
            "created_at": now_ms - 100000000,  # Long ago
            "expires_at": now_ms - 1000,  # Expired
            "is_used": 0,
        })

        sk, pk = _make_ed25519_keypair()
        ek, epk = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "late_user",
            "signing_pk": pk.hex(),
            "encryption_pk": epk.hex(),
        })
        assert resp.status_code == 410


class TestOneTimeConsumeH6:
    """H6: one-time provisioning/invitation tokens must consume atomically."""

    def _insert_provisioning_token(self, storage, user_id, token):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now_ms = int(time.time() * 1000)
        storage.setdefault("provisioning_tokens", []).append({
            "token_hash": token_hash,
            "user_id": user_id,
            "created_at": now_ms,
            "expires_at": now_ms + 600_000,  # 10 min
            "is_used": 0,
        })

    @pytest.mark.asyncio
    async def test_provisioning_wrong_username_does_not_consume_token(self, app_client, mock_db):
        """A wrong-username provision attempt must NOT burn the one-time token."""
        _create_regular_user(mock_db._storage, username="alice")
        token = os.urandom(16).hex()
        self._insert_provisioning_token(
            mock_db._storage, "USER0000000000000000000001", token)

        # Wrong username → 404 and token stays unused.
        resp = await app_client.post("/api/auth/provision", json={
            "token": token,
            "username": "mallory",
        })
        assert resp.status_code == 404
        assert mock_db._storage["provisioning_tokens"][0]["is_used"] == 0

        # Legitimate retry with the correct username still works.
        resp = await app_client.post("/api/auth/provision", json={
            "token": token,
            "username": "alice",
        })
        assert resp.status_code == 200
        assert resp.json()["user_id"] == "USER0000000000000000000001"
        assert mock_db._storage["provisioning_tokens"][0]["is_used"] == 1

    @pytest.mark.asyncio
    async def test_provisioning_token_is_single_use(self, app_client, mock_db):
        """A provisioning token must be redeemable exactly once."""
        _create_regular_user(mock_db._storage, username="alice")
        token = os.urandom(16).hex()
        self._insert_provisioning_token(
            mock_db._storage, "USER0000000000000000000001", token)

        resp = await app_client.post("/api/auth/provision", json={
            "token": token, "username": "alice",
        })
        assert resp.status_code == 200

        # Second redemption must be rejected.
        resp = await app_client.post("/api/auth/provision", json={
            "token": token, "username": "alice",
        })
        assert resp.status_code == 410

    @pytest.mark.asyncio
    async def test_used_invitation_does_not_create_second_user(self, app_client, mock_db):
        """Reusing an invitation must be rejected AND must not create a 2nd user."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        inv_token = resp.json()["invitation_token"]

        sk1, pk1 = _make_ed25519_keypair()
        ek1, epk1 = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "first_user",
            "signing_pk": pk1.hex(),
            "encryption_pk": epk1.hex(),
        })
        assert resp.status_code == 200

        sk2, pk2 = _make_ed25519_keypair()
        ek2, epk2 = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "second_user",
            "signing_pk": pk2.hex(),
            "encryption_pk": epk2.hex(),
        })
        assert resp.status_code == 410
        # The rejected registration must not have leaked a user row.
        assert not [u for u in mock_db._storage["users"] if u["username"] == "second_user"]


class TestApproval:
    """Tests for PATCH /api/users/:id/approve."""

    @pytest.mark.asyncio
    async def test_approve_requires_keypair_uploaded(self, app_client, mock_db):
        """Cannot approve user who hasn't uploaded keypair."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Create a pending user WITHOUT keypair
        pending_id = "PENDINGX000000000000000001"
        sk, pk = _make_ed25519_keypair()
        ek, epk = _make_ed25519_keypair()
        mock_db._storage["users"].append({
            "id": pending_id,
            "username": "pending_user",
            "signing_pk": pk,
            "encryption_pk": epk,
            "key_fingerprint": hashlib.sha256(pk + epk).hexdigest(),
            "status": "pending",
            "is_admin": 0,
            "encrypted_keypair": None,  # No keypair uploaded
            "argon2_salt": None,
            "auth_salt": None,
            "verify_salt": None,
            "auth_proof_hash": None,
            "recovery_locked": 0,
            "recovery_attempts": 0,
            "recovery_attempts_hour": 0,
            "last_recovery_attempt": None,
            "created_at": int(time.time() * 1000),
        })

        resp = await app_client.patch(
            f"/api/users/{pending_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400
        assert "keypair" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_approve_changes_pending_to_active(self, app_client, mock_db):
        """Approving a pending user with keypair changes status to active."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        pending_id = "PENDING0000000000000000002"
        sk, pk = _make_ed25519_keypair()
        ek, epk = _make_ed25519_keypair()
        mock_db._storage["users"].append({
            "id": pending_id,
            "username": "approved_user",
            "signing_pk": pk,
            "encryption_pk": epk,
            "key_fingerprint": hashlib.sha256(pk + epk).hexdigest(),
            "status": "pending",
            "is_admin": 0,
            "encrypted_keypair": b"\x00" * 64,  # Has keypair
            "argon2_salt": b"\x00" * 16,
            "auth_salt": b"\x00" * 16,
            "verify_salt": None,
            "auth_proof_hash": None,
            "recovery_locked": 0,
            "recovery_attempts": 0,
            "recovery_attempts_hour": 0,
            "last_recovery_attempt": None,
            "created_at": int(time.time() * 1000),
        })

        resp = await app_client.patch(
            f"/api/users/{pending_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

        user = [u for u in mock_db._storage["users"] if u["id"] == pending_id][0]
        assert user["status"] == "active"


class TestRotateKeys:
    """PATCH /api/users/:id/rotate-keys is disabled; archived keys stay readable."""

    @pytest.mark.asyncio
    async def test_rotate_keys_is_disabled(self, app_client, mock_db):
        """Lockout review #11: it swapped the public keys while encrypted_keypair
        kept the old private keys, so the next device opened keys the server no
        longer vouched for. Now 410 with nothing changed."""
        from server.app.auth import key_rotation_message

        sk, pk = _create_admin_user(mock_db._storage)
        old_enc_pk = mock_db._storage["users"][0]["encryption_pk"]
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        new_sk, new_pk = _make_ed25519_keypair()
        _, new_enc_pk = _make_ed25519_keypair()
        certificate = new_sk.sign(key_rotation_message(
            "ADMIN000000000000000000001", pk, old_enc_pk, new_pk, new_enc_pk,
        )).signature

        resp = await app_client.patch(
            "/api/users/ADMIN000000000000000000001/rotate-keys",
            json={
                "new_signing_pk": new_pk.hex(),
                "new_encryption_pk": new_enc_pk.hex(),
                **(await _signed_challenge_fields(app_client, sk, "admin")),
                "rotation_signature": certificate.hex(),
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 410
        user = mock_db._storage["users"][0]
        assert user["signing_pk"] == pk
        assert user.get("token_epoch", 0) == 0
        assert not mock_db._storage.get("user_key_archives")

    @pytest.mark.asyncio
    async def test_certified_archives_are_served(self, app_client, mock_db):
        from server.app.auth import key_rotation_message

        sk, pk = _create_admin_user(mock_db._storage)
        enc_pk = mock_db._storage["users"][0]["encryption_pk"]
        _, old_pk = _make_ed25519_keypair()
        _, old_enc_pk = _make_ed25519_keypair()
        certificate = sk.sign(key_rotation_message(
            "ADMIN000000000000000000001", old_pk, old_enc_pk, pk, enc_pk,
        )).signature
        fingerprint = hashlib.sha256(old_pk + old_enc_pk).hexdigest()
        mock_db._storage.setdefault("user_key_archives", []).append({
            "id": "ARCHIVE0000000000000000002", "user_id": "ADMIN000000000000000000001",
            "signing_pk": old_pk, "encryption_pk": old_enc_pk,
            "key_fingerprint": fingerprint, "archived_at": 5,
            "successor_signing_pk": pk, "rotation_signature": certificate,
            "authorization_signature": None, "retired_seq": 7,
        })
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        keys = await app_client.get(
            "/api/users/ADMIN000000000000000000001/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert keys.status_code == 200
        assert keys.json()["archived_keys"] == [{
            "signing_pk": old_pk.hex(), "encryption_pk": old_enc_pk.hex(),
            "key_fingerprint": fingerprint, "archived_at": 5,
            "successor_signing_pk": pk.hex(), "rotation_signature": certificate.hex(),
            "authorization_signature": None, "retired_seq": 7,
        }]

    @pytest.mark.asyncio
    async def test_uncertified_legacy_archives_are_not_served(self, app_client, mock_db):
        _create_admin_user(mock_db._storage)
        _, legacy_pk = _make_ed25519_keypair()
        mock_db._storage.setdefault("user_key_archives", []).append({
            "id": "ARCHIVE0000000000000000001", "user_id": "ADMIN000000000000000000001",
            "signing_pk": legacy_pk, "encryption_pk": legacy_pk,
            "key_fingerprint": hashlib.sha256(legacy_pk + legacy_pk).hexdigest(),
            "archived_at": 1, "successor_signing_pk": None, "rotation_signature": None,
        })
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        keys = await app_client.get(
            "/api/users/ADMIN000000000000000000001/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert keys.status_code == 200
        assert keys.json()["archived_keys"] == []


class TestRevokeUser:
    """Tests for DELETE /api/users/:id."""

    @pytest.mark.asyncio
    async def test_revoke_changes_status(self, app_client, mock_db):
        """Revoking a user should set status to 'revoked'."""
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        resp = await app_client.delete(
            "/api/users/USER0000000000000000000001",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

        user = [u for u in mock_db._storage["users"] if u["id"] == "USER0000000000000000000001"][0]
        assert user["status"] == "revoked"

    @pytest.mark.asyncio
    async def test_revoke_retry_is_idempotent(self, app_client, mock_db):
        """A crash after DELETE must allow the persisted web journal to retry it."""
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        headers = {"Authorization": f"Bearer {admin_token}"}

        first = await app_client.delete(
            "/api/users/USER0000000000000000000001", headers=headers
        )
        second = await app_client.delete(
            "/api/users/USER0000000000000000000001", headers=headers
        )

        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_revoke_immediately_blocks_existing_jwt_and_refresh(self, app_client, mock_db):
        """Revocation invalidates already-issued JWTs before their expiry."""
        _create_admin_user(mock_db._storage)
        user_sk, _ = _create_regular_user(mock_db._storage)
        user_token = await _do_challenge_verify(
            app_client, mock_db._storage, user_sk, "alice"
        )
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        revoked = await app_client.delete(
            "/api/users/USER0000000000000000000001",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert revoked.status_code == 200

        request_after_revoke = await app_client.get(
            "/api/users/USER0000000000000000000001/keys",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert request_after_revoke.status_code == 401

        refresh_after_revoke = await app_client.post(
            "/api/auth/refresh",
            json={"challenge": "00", "signature": "00"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert refresh_after_revoke.status_code == 401

    @pytest.mark.asyncio
    async def test_revoke_removes_write_acl(self, app_client, mock_db):
        """Revoking a user should remove all their write_acl entries."""
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Add write_acl entry for user
        mock_db._storage["write_acl"].append({
            "user_id": "USER0000000000000000000001",
            "node_id": "NODE0000000000000000000001",
            "granted_at": int(time.time() * 1000),
        })

        resp = await app_client.delete(
            "/api/users/USER0000000000000000000001",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

        # write_acl entries for user should be gone
        user_acls = [a for a in mock_db._storage["write_acl"]
                     if a["user_id"] == "USER0000000000000000000001"]
        assert len(user_acls) == 0

    @pytest.mark.asyncio
    async def test_cannot_revoke_yourself(self, app_client, mock_db):
        """Admin should not be able to revoke themselves."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        resp = await app_client.delete(
            "/api/users/ADMIN000000000000000000001",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400
        assert "yourself" in resp.json()["detail"].lower()


# =====================================================================
# SERVER AUDIT TESTS (spec 4.2, content-blind 2.1/2.9)
# =====================================================================

class TestServerAudit:
    @pytest.mark.asyncio
    async def test_client_audit_is_content_blind_and_canonically_signed(
        self, app_client, mock_db
    ):
        user_id = "01H7A5ER000000000000000000"
        audit_id = "01H7A0D1T00000000000000000"
        sk, pk = _create_regular_user(mock_db._storage, user_id=user_id)
        token = _create_jwt(user_id, "alice", False)
        timestamp = int(time.time() * 1000)
        request_hash = hashlib.sha256(b"field_show").hexdigest()
        signature = _sign_server_audit(
            sk, audit_id, user_id, "field_show", timestamp, request_hash
        )

        resp = await app_client.post(
            "/api/audit/log",
            json={
                "id": audit_id,
                "action": "field_show",
                "timestamp": timestamp,
                "request_hash": request_hash,
                "signature": signature,
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code == 200
        assert len(mock_db._storage["server_audit"]) == 1
        row = mock_db._storage["server_audit"][0]
        assert row["id"] == audit_id
        assert row["request_hash"] == request_hash
        assert row["commit_seq_range"] is None
        VerifyKey(pk).verify(
            audit_id.encode("ascii")
            + user_id.encode("ascii")
            + b"field_show"
            + timestamp.to_bytes(8, "big")
            + bytes.fromhex(request_hash),
            row["client_signature"],
        )
        assert "entry" not in row and "details" not in row

    @pytest.mark.asyncio
    async def test_client_audit_rejects_proxy_signature_and_plaintext_details(
        self, app_client, mock_db
    ):
        user_id = "01H7A5ER000000000000000000"
        audit_id = "01H7A0D1T00000000000000000"
        sk, _ = _create_regular_user(mock_db._storage, user_id=user_id)
        token = _create_jwt(user_id, "alice", False)
        timestamp = int(time.time() * 1000)
        request_hash = hashlib.sha256(b"field_copy").hexdigest()
        headers = {"Authorization": f"Bearer {token}"}
        body = {
            "id": audit_id,
            "action": "field_copy",
            "timestamp": timestamp,
            "request_hash": request_hash,
            "signature": sk.sign(b"unrelated sync object").signature.hex(),
        }

        invalid_sig = await app_client.post("/api/audit/log", json=body, headers=headers)
        assert invalid_sig.status_code == 400
        assert not mock_db._storage["server_audit"]

        wrong_hash = hashlib.sha256(b"different event").hexdigest()
        body["request_hash"] = wrong_hash
        body["signature"] = _sign_server_audit(
            sk, audit_id, user_id, "field_copy", timestamp, wrong_hash
        )
        mismatched_hash = await app_client.post(
            "/api/audit/log", json=body, headers=headers
        )
        assert mismatched_hash.status_code == 400
        assert not mock_db._storage["server_audit"]

        body["request_hash"] = request_hash
        body["signature"] = _sign_server_audit(
            sk, audit_id, user_id, "field_copy", timestamp, request_hash
        )
        body["details"] = {"entry": "Production", "field": "password"}
        plaintext = await app_client.post("/api/audit/log", json=body, headers=headers)
        assert plaintext.status_code == 422
        assert not mock_db._storage["server_audit"]


# =====================================================================
# SYNC TESTS (spec 8.2)
# =====================================================================

class TestSyncPush:
    """Tests for POST /api/sync."""

    def _make_push_payload(self) -> tuple[str, str]:
        """Create a test payload and its hash."""
        payload = b"encrypted test data"
        payload_b64 = base64.b64encode(payload).decode("ascii")
        payload_hash = hashlib.sha256(payload).hexdigest()
        return payload_b64, payload_hash

    @staticmethod
    def _seed_dek(mock_db, dek_id: str, node_id: str) -> None:
        payload = b"wrapped dek"
        mock_db._storage["vault_objects"].append({
            "id": dek_id, "object_type": "dek", "payload": payload,
            "owner_id": "ADMIN000000000000000000001", "write_policy": "owner_only",
            "access_level": None, "target_user_id": None, "parent_ref": node_id,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(payload).hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("field", "value"), [
        ("version", -1),
        ("version", 2**32),
        ("is_deleted", -1),
        ("is_deleted", 2),
    ])
    async def test_unbounded_sync_scalars_return_422_without_db_mutation(
        self, app_client, mock_db, field, value
    ):
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        payload_b64, payload_hash = self._make_push_payload()
        obj = {
            "id": "BOUND000000000000000000001",
            "object_type": "dek",
            "payload": payload_b64,
            "version": 1,
            "is_deleted": 0,
            "payload_hash": payload_hash,
            "signature": "00" * 64,
        }
        obj[field] = value
        commit_counter_before = [dict(row) for row in mock_db._storage["commit_counter"]]

        response = await app_client.post(
            "/api/sync",
            json={"objects": [obj], "atomic_batch": False},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 422
        assert mock_db._storage["vault_objects"] == []
        assert mock_db._storage["sync_state"] == []
        assert mock_db._storage["commit_counter"] == commit_counter_before

    @pytest.mark.asyncio
    async def test_push_new_object_assigns_commit_seq(self, app_client, mock_db):
        """Pushing a new object should assign a commit_seq."""
        sk, pk = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        payload_b64, payload_hash = self._make_push_payload()

        obj_id = "OBJ00000000000000000000001"
        signature = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, payload_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id,
                "object_type": "dek",
                "payload": payload_b64,
                "version": 1,
                "is_deleted": 0,
                "payload_hash": payload_hash,
                "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["accepted"]) == 1
        assert data["accepted"][0]["commit_seq"] is not None
        assert data["accepted"][0]["commit_seq"] >= 1
        # A sync-object signature covers a different canonical payload and must
        # never be copied into server_audit as if it signed an audit record.
        assert not mock_db._storage["server_audit"]

    @pytest.mark.asyncio
    async def test_key_epoch_advance_is_atomic_and_stale_push_is_rejected(
        self, app_client, mock_db
    ):
        sk, _ = _create_admin_user(mock_db._storage)
        user_id = "ADMIN000000000000000000001"
        token = _create_jwt(user_id, "admin", True)
        payload_b64, payload_hash = self._make_push_payload()
        obj_id = "EPOCH000000000000000000001"
        signature = _sign_sync_object(
            sk, obj_id, "dek", None, None, 0, 1, payload_hash
        )
        obj = {
            "id": obj_id,
            "object_type": "dek",
            "payload": payload_b64,
            "version": 1,
            "is_deleted": 0,
            "payload_hash": payload_hash,
            "signature": signature,
        }

        rotation_challenge = (await app_client.post(
            "/api/auth/challenge", json={"username": "admin"}
        )).json()["challenge"]
        advanced = await app_client.post(
            "/api/sync",
            json={
                "objects": [obj], "atomic_batch": True, "key_epoch": 1,
                "key_rotation": {
                    "encrypted_keypair": "010107" + "00" * 194,  # KEYPAIR_WRAP header
                    "argon2_salt": "ab" * 16,
                    "auth_salt": "ab" * 16,
                    "auth_proof": "cd" * 32,
                    "argon2_params": {"time_cost": 3, "memory_cost": 131072, "parallelism": 4},
                    "challenge": rotation_challenge,
                    "signature": _sign_challenge(sk, bytes.fromhex(rotation_challenge)).hex(),
                },
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert advanced.status_code == 200
        assert mock_db._storage["sync_state"][0]["key_epoch"] == 1
        token = advanced.json()["token"]

        stale = await app_client.post(
            "/api/sync",
            json={"objects": [], "atomic_batch": False, "key_epoch": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert stale.status_code == 409
        assert "Stale key epoch" in stale.json()["detail"]

        non_atomic = await app_client.post(
            "/api/sync",
            json={"objects": [obj], "atomic_batch": False, "key_epoch": 2},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert non_atomic.status_code == 409
        assert "atomic DEK rewrap" in non_atomic.json()["detail"]
        assert mock_db._storage["sync_state"][0]["key_epoch"] == 1

        self._seed_dek(
            mock_db,
            "EPOCH000000000000000000002",
            "NODEX000000000000000000001",
        )
        incomplete = await app_client.post(
            "/api/sync",
            json={"objects": [obj], "atomic_batch": True, "key_epoch": 2},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert incomplete.status_code == 409
        assert "every active DEK" in incomplete.json()["detail"]
        assert mock_db._storage["sync_state"][0]["key_epoch"] == 1

    @pytest.mark.asyncio
    async def test_push_invalid_signature_rejected(self, app_client, mock_db):
        """Pushing with invalid Ed25519 signature should be rejected."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        payload_b64, payload_hash = self._make_push_payload()

        # Sign with a different key
        wrong_sk = SigningKey.generate()
        obj_id = "OBJ00000000000000000000002"
        bad_signature = _sign_sync_object(wrong_sk, obj_id, "dek", None, None, 0, 1, payload_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id,
                "object_type": "dek",
                "payload": payload_b64,
                "version": 1,
                "is_deleted": 0,
                "payload_hash": payload_hash,
                "signature": bad_signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["conflicts"]) == 1
        assert "invalid signature" in data["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_push_payload_hash_mismatch_rejected(self, app_client, mock_db):
        """A valid signature over a declared hash must not bless different payload bytes."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        declared_payload = b"signed payload"
        actual_payload = b"tampered payload"
        declared_hash = hashlib.sha256(declared_payload).hexdigest()
        obj_id = "HASH0000000000000000000001"
        signature = _sign_sync_object(
            sk, obj_id, "dek", None, None, 0, 1, declared_hash
        )

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "dek",
                "payload": base64.b64encode(actual_payload).decode("ascii"),
                "version": 1, "is_deleted": 0,
                "payload_hash": declared_hash, "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["conflicts"][0]["error"] == "payload hash mismatch"
        assert not mock_db._storage["vault_objects"]

    @pytest.mark.asyncio
    async def test_push_hash_over_base64_text_rejected(self, app_client, mock_db):
        """M1 golden vector: payload_hash MUST be SHA-256 of the RAW payload bytes.

        The web client historically hashed the base64 TEXT of the payload
        (sha256(payloadB64)) instead of the raw bytes. After the server C2 fix
        this is rejected. This pins the cross-client convention so a regression
        to base64-text hashing (on any client) fails in CI.
        """
        sk, _ = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        payload = b"encrypted test data"
        payload_b64 = base64.b64encode(payload).decode("ascii")

        raw_hash = hashlib.sha256(payload).hexdigest()
        b64_text_hash = hashlib.sha256(payload_b64.encode("ascii")).hexdigest()
        # The two conventions must actually differ, else the test proves nothing.
        assert raw_hash != b64_text_hash

        obj_id = "M1B64000000000000000000001"
        # Sign over the WRONG (base64-text) hash, exactly as the old web did.
        signature = _sign_sync_object(
            sk, obj_id, "dek", None, None, 0, 1, b64_text_hash
        )
        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "dek", "payload": payload_b64,
                "version": 1, "is_deleted": 0,
                "payload_hash": b64_text_hash, "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["conflicts"][0]["error"] == "payload hash mismatch"
        assert not mock_db._storage["vault_objects"]

        # The correct raw-bytes hash (what the fixed web now sends) is accepted.
        obj_id2 = "M1RAW000000000000000000001"
        good_sig = _sign_sync_object(sk, obj_id2, "dek", None, None, 0, 1, raw_hash)
        resp2 = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id2, "object_type": "dek", "payload": payload_b64,
                "version": 1, "is_deleted": 0,
                "payload_hash": raw_hash, "signature": good_sig,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 200
        assert len(resp2.json()["accepted"]) == 1

    @pytest.mark.asyncio
    async def test_push_newer_version_accepted(self, app_client, mock_db):
        """Pushing a newer version of an existing object should be accepted."""
        sk, pk = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        obj_id = "OBJ00000000000000000000003"

        # Push version 1
        payload1 = b"v1 data"
        p1_b64 = base64.b64encode(payload1).decode("ascii")
        p1_hash = hashlib.sha256(payload1).hexdigest()
        sig1 = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, p1_hash)

        await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "dek", "payload": p1_b64,
                         "version": 1, "is_deleted": 0, "payload_hash": p1_hash,
                         "signature": sig1}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        # Push version 2
        payload2 = b"v2 data"
        p2_b64 = base64.b64encode(payload2).decode("ascii")
        p2_hash = hashlib.sha256(payload2).hexdigest()
        sig2 = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 2, p2_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "dek", "payload": p2_b64,
                         "version": 2, "is_deleted": 0, "payload_hash": p2_hash,
                         "signature": sig2}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["accepted"]) == 1

    @pytest.mark.asyncio
    async def test_push_same_version_same_hash_idempotent(self, app_client, mock_db):
        """Pushing same version + same hash should be idempotent OK."""
        sk, pk = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        obj_id = "OBJ00000000000000000000004"
        payload = b"idempotent data"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        sig = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, p_hash)

        obj_json = {"id": obj_id, "object_type": "dek", "payload": p_b64,
                     "version": 1, "is_deleted": 0, "payload_hash": p_hash,
                     "signature": sig}

        # First push
        await app_client.post("/api/sync", json={"objects": [obj_json], "atomic_batch": False},
                              headers={"Authorization": f"Bearer {token}"})

        # Second push (same version, same hash) — should be accepted
        resp = await app_client.post("/api/sync", json={"objects": [obj_json], "atomic_batch": False},
                                     headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["accepted"]) == 1
        assert len(data["conflicts"]) == 0

    @pytest.mark.asyncio
    async def test_push_same_version_different_hash_conflict(self, app_client, mock_db):
        """Pushing same version but different hash should cause 409 conflict."""
        sk, pk = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        obj_id = "OBJ00000000000000000000005"
        payload1 = b"original data"
        p1_b64 = base64.b64encode(payload1).decode("ascii")
        p1_hash = hashlib.sha256(payload1).hexdigest()
        sig1 = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, p1_hash)

        # First push
        await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "dek", "payload": p1_b64,
                         "version": 1, "is_deleted": 0, "payload_hash": p1_hash,
                         "signature": sig1}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        # Second push same version, different data
        payload2 = b"different data"
        p2_b64 = base64.b64encode(payload2).decode("ascii")
        p2_hash = hashlib.sha256(payload2).hexdigest()
        sig2 = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, p2_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "dek", "payload": p2_b64,
                         "version": 1, "is_deleted": 0, "payload_hash": p2_hash,
                         "signature": sig2}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["conflicts"]) == 1
        assert "conflict" in data["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_push_older_version_conflict(self, app_client, mock_db):
        """Pushing an older version than what server has should conflict."""
        sk, pk = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        obj_id = "OBJ00000000000000000000006"

        # Push version 2 first
        payload = b"v2 data"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        sig = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 2, p_hash)

        # Manually insert as v2
        mock_db._storage["vault_objects"].append({
            "id": obj_id, "object_type": "dek", "payload": payload,
            "owner_id": "ADMIN000000000000000000001",
            "target_user_id": None, "parent_ref": None,
            "version": 2, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": p_hash, "client_signature": bytes.fromhex(sig),
            "modified_at": int(time.time() * 1000),
        })

        # Now push version 1 (older)
        payload_old = b"v1 old data"
        po_b64 = base64.b64encode(payload_old).decode("ascii")
        po_hash = hashlib.sha256(payload_old).hexdigest()
        sig_old = _sign_sync_object(sk, obj_id, "dek", None, None, 0, 1, po_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "dek", "payload": po_b64,
                         "version": 1, "is_deleted": 0, "payload_hash": po_hash,
                         "signature": sig_old}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["conflicts"]) == 1

    @pytest.mark.asyncio
    async def test_non_admin_can_manage_only_own_personal_dek(self, app_client, mock_db):
        """A regular user may create a metadata-free personal DEK, but cannot
        change another user's DEK or turn a personal DEK into shared metadata."""
        alice_sk, _ = _create_regular_user(mock_db._storage)
        bob_sk, _ = _create_regular_user(
            mock_db._storage, "USER0000000000000000000002", "bob"
        )
        alice_token = _create_jwt("USER0000000000000000000001", "alice", False)
        bob_token = _create_jwt("USER0000000000000000000002", "bob", False)

        alice_dek = "DEKALICE000000000000000001"
        resp = await _push_object(
            app_client, alice_token, alice_sk, alice_dek, "dek", None, 1, b"alice dek"
        )
        assert len(resp.json()["accepted"]) == 1
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == alice_dek][0]
        assert stored["owner_id"] == "USER0000000000000000000001"
        assert stored["write_policy"] == "owner_only"

        shared_dek = "DEKSHARED00000000000000001"
        resp = await _push_object(
            app_client, alice_token, alice_sk, shared_dek, "dek", None, 1,
            b"shared dek", write_policy="shared",
        )
        assert "invalid personal DEK metadata" in resp.json()["conflicts"][0]["error"]

        bob_dek = "DEKBOB00000000000000000001"
        resp = await _push_object(
            app_client, bob_token, bob_sk, bob_dek, "dek", None, 1, b"bob dek"
        )
        assert len(resp.json()["accepted"]) == 1
        resp = await _push_object(
            app_client, alice_token, alice_sk, bob_dek, "dek", None, 2, b"stolen dek"
        )
        assert "not owner" in resp.json()["conflicts"][0]["error"]
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == bob_dek][0]
        assert stored["version"] == 1

    @pytest.mark.asyncio
    async def test_non_admin_cannot_push_envelope(self, app_client, mock_db):
        """Non-admin cannot push envelope objects."""
        sk, pk = _create_regular_user(mock_db._storage)
        token = _create_jwt("USER0000000000000000000001", "alice", False)

        payload = b"envelope data"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        obj_id = "OBJ00000000000000000000008"
        sig = _sign_sync_object(sk, obj_id, "envelope", None, None, 0, 1, p_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "envelope", "payload": p_b64,
                         "version": 1, "is_deleted": 0, "payload_hash": p_hash,
                         "signature": sig}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        data = resp.json()
        assert len(data["conflicts"]) == 1
        assert "admin only" in data["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_non_admin_without_write_acl_denied(self, app_client, mock_db):
        """Non-admin pushing a node without write_acl should be denied."""
        sk, pk = _create_regular_user(mock_db._storage)
        token = _create_jwt("USER0000000000000000000001", "alice", False)

        payload = b"node data"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        obj_id = "OBJ00000000000000000000009"
        parent_ref = "PARENT00000000000000000001"
        sig = _sign_sync_object(sk, obj_id, "node", parent_ref, None, 0, 1, p_hash)

        # No write_acl entry for alice on this parent
        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "node", "payload": p_b64,
                         "parent_ref": parent_ref,
                         "version": 1, "is_deleted": 0, "payload_hash": p_hash,
                         "signature": sig}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        data = resp.json()
        assert len(data["conflicts"]) == 1
        assert "write_acl denied" in data["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_stale_acl_cannot_write_below_deleted_parent(self, app_client, mock_db):
        user_id = "USER0000000000000000000001"
        sk, _ = _create_regular_user(mock_db._storage, user_id, "alice")
        token = _create_jwt(user_id, "alice", False)
        parent = "DELETEDPARENT0000000000001"
        mock_db._storage["vault_objects"].append({
            "id": parent, "object_type": "node", "payload": b"deleted",
            "owner_id": user_id, "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": None, "access_level": None,
            "version": 2, "commit_seq": 2, "is_deleted": 1,
            "payload_hash": hashlib.sha256(b"deleted").hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 2,
        })
        mock_db._storage["write_acl"].append({
            "user_id": user_id, "node_id": parent, "granted_at": 1,
        })

        resp = await _push_object(
            app_client, token, sk, "ORPHANENTRY000000000000001",
            "entry", parent, 1, b"must be rejected",
        )
        assert "write_acl denied" in resp.json()["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_owner_can_write_recursively_below_personal_folder(self, app_client, mock_db):
        """Personal-folder ownership replaces share ACL only for its owner."""
        alice_id = "USER0000000000000000000001"
        bob_id = "USER0000000000000000000002"
        alice_sk, _ = _create_regular_user(mock_db._storage, alice_id, "alice")
        bob_sk, _ = _create_regular_user(mock_db._storage, bob_id, "bob")
        alice_token = _create_jwt(alice_id, "alice", False)
        bob_token = _create_jwt(bob_id, "bob", False)
        personal_root = "PERSONALROOT00000000000001"
        mock_db._storage["vault_objects"].append({
            "id": "SHAREDROOT0000000000000001", "object_type": "node",
            "payload": b"vault root", "owner_id": "ADMIN000000000000000000001",
            "signature_user_id": "ADMIN000000000000000000001",
            "write_policy": "owner_only", "target_user_id": None,
            "parent_ref": None, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"vault root").hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        # Review a159e97 H8: a personal tree's top folder is sealed with her DEK.
        alice_dek = "ALICEDEK000000000000000001"
        sealed_root = bytes([1, 1, 2]) + alice_dek.encode("ascii") + b"\x00" * 24 + b"c" * 32
        mock_db._storage["vault_objects"].append({
            "id": alice_dek, "object_type": "dek", "payload": b"k" * 72,
            "owner_id": alice_id, "signature_user_id": alice_id,
            "write_policy": "owner_only", "target_user_id": None,
            "parent_ref": None, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"k" * 72).hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        mock_db._storage["vault_objects"].append({
            "id": personal_root, "object_type": "node", "payload": sealed_root,
            "owner_id": alice_id, "signature_user_id": alice_id,
            "write_policy": "owner_only", "target_user_id": None,
            "parent_ref": "SHAREDROOT0000000000000001", "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"encrypted root").hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })

        child = "PERSONALCHILD0000000000001"
        grandchild = "PERSONALGRAND0000000000001"
        entry = "PERSONALENTRY0000000000001"
        for obj_id, obj_type, parent in (
            (child, "node", personal_root),
            (grandchild, "node", child),
            (entry, "entry", grandchild),
        ):
            resp = await _push_object(
                app_client, alice_token, alice_sk, obj_id, obj_type, parent, 1,
                f"encrypted {obj_id}".encode(),
            )
            assert len(resp.json()["accepted"]) == 1, resp.json()

        resp = await _push_object(
            app_client, alice_token, alice_sk, entry, "entry", grandchild, 2,
            b"encrypted tombstone", is_deleted=1,
        )
        assert len(resp.json()["accepted"]) == 1

        resp = await _push_object(
            app_client, bob_token, bob_sk, "BOBENTRY000000000000000001",
            "entry", grandchild, 1, b"bob cannot enter",
        )
        assert "write_acl denied" in resp.json()["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_existing_object_type_is_immutable(self, app_client, mock_db):
        """A signed request cannot reinterpret a stored node as another object class."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        obj_id = "TYPE0000000000000000000001"
        original = b"node payload"
        mock_db._storage["vault_objects"].append({
            "id": obj_id, "object_type": "node", "payload": original,
            "owner_id": "ADMIN000000000000000000001", "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": None, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(original).hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        replacement = b"spoofed payload"
        replacement_hash = hashlib.sha256(replacement).hexdigest()
        signature = _sign_sync_object(
            sk, obj_id, "entry", None, None, 0, 2, replacement_hash
        )

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "entry",
                "payload": base64.b64encode(replacement).decode("ascii"),
                "version": 2, "is_deleted": 0,
                "payload_hash": replacement_hash, "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.json()["conflicts"][0]["error"] == "object_type is immutable"
        assert mock_db._storage["vault_objects"][0]["payload"] == original

    @pytest.mark.asyncio
    async def test_update_checks_stored_and_destination_parent_acl(self, app_client, mock_db):
        """Changing parent cannot bypass ACL on the object's stored folder."""
        sk, _ = _create_regular_user(mock_db._storage)
        user_id = "USER0000000000000000000001"
        token = _create_jwt(user_id, "alice", False)
        old_parent = "OLDPARENT00000000000000001"
        new_parent = "NEWPARENT00000000000000001"
        obj_id = "MOVE0000000000000000000001"
        original = b"original"
        mock_db._storage["vault_objects"].append({
            "id": obj_id, "object_type": "entry", "payload": original,
            "owner_id": user_id, "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": old_parent, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(original).hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        mock_db._storage["write_acl"].append({
            "user_id": user_id, "node_id": new_parent, "granted_at": 1,
        })
        replacement = b"moved"
        replacement_hash = hashlib.sha256(replacement).hexdigest()
        signature = _sign_sync_object(
            sk, obj_id, "entry", new_parent, None, 0, 2, replacement_hash
        )

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "entry", "parent_ref": new_parent,
                "payload": base64.b64encode(replacement).decode("ascii"),
                "version": 2, "is_deleted": 0,
                "payload_hash": replacement_hash, "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.json()["conflicts"][0]["error"] == "write_acl denied"
        assert mock_db._storage["vault_objects"][0]["parent_ref"] == old_parent

    @pytest.mark.asyncio
    async def test_update_persists_signed_parent_ref(self, app_client, mock_db):
        """An authorized move persists the signed destination topology."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        obj_id = "TOPO0000000000000000000001"
        old_parent = "OLDPARENT00000000000000002"
        new_parent = "NEWPARENT00000000000000002"
        original = b"original"
        mock_db._storage["vault_objects"].append({
            "id": obj_id, "object_type": "entry", "payload": original,
            "owner_id": "ADMIN000000000000000000001", "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": old_parent, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(original).hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        # Review d150605 K1: a live object needs a live parent on the server.
        mock_db._storage["vault_objects"].append({
            "id": new_parent, "object_type": "node", "payload": b"folder",
            "owner_id": "ADMIN000000000000000000001", "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": None, "access_level": None,
            "version": 1, "commit_seq": 2, "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"folder").hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        replacement = b"moved"
        replacement_hash = hashlib.sha256(replacement).hexdigest()
        signature = _sign_sync_object(
            sk, obj_id, "entry", new_parent, None, 0, 2, replacement_hash
        )

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "entry", "parent_ref": new_parent,
                "payload": base64.b64encode(replacement).decode("ascii"),
                "version": 2, "is_deleted": 0,
                "base_version": 1, "base_payload_hash": hashlib.sha256(original).hexdigest(),
                "payload_hash": replacement_hash, "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert len(resp.json()["accepted"]) == 1
        assert mock_db._storage["vault_objects"][0]["parent_ref"] == new_parent

    @pytest.mark.asyncio
    async def test_admin_rekey_preserves_owner_and_exposes_latest_signer(self, app_client, mock_db):
        """A revocation re-key keeps ownership but lets clients verify the admin signature."""
        admin_id = "ADMIN000000000000000000001"
        owner_id = "USER0000000000000000000001"
        admin_sk, _ = _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        token = _create_jwt(admin_id, "admin", True)
        obj_id = "REKEY000000000000000000001"
        original = b"owner ciphertext"
        mock_db._storage["vault_objects"].append({
            "id": obj_id, "object_type": "entry", "payload": original,
            "owner_id": owner_id, "signature_user_id": owner_id,
            "write_policy": "owner_only", "target_user_id": None,
            "parent_ref": None, "access_level": None, "version": 1,
            "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(original).hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        replacement = b"admin re-keyed ciphertext"
        replacement_hash = hashlib.sha256(replacement).hexdigest()
        signature = _sign_sync_object(
            admin_sk, obj_id, "entry", None, None, 0, 2, replacement_hash
        )

        pushed = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "entry",
                "payload": base64.b64encode(replacement).decode("ascii"),
                "version": 2, "is_deleted": 0,
                "base_version": 1, "base_payload_hash": hashlib.sha256(original).hexdigest(),
                "payload_hash": replacement_hash, "signature": signature,
            }],
            "atomic_batch": True,
        }, headers={"Authorization": f"Bearer {token}"})

        assert pushed.status_code == 200
        stored = mock_db._storage["vault_objects"][0]
        assert stored["owner_id"] == owner_id
        assert stored["signature_user_id"] == admin_id

        pulled = await app_client.get(
            "/api/sync?since_commit_seq=0&full_resync=true",
            headers={"Authorization": f"Bearer {token}"},
        )
        pulled_obj = next(obj for obj in pulled.json()["objects"] if obj["id"] == obj_id)
        assert pulled_obj["owner_id"] == owner_id
        assert pulled_obj["signature_user_id"] == admin_id

    @pytest.mark.asyncio
    async def test_atomic_batch_all_or_nothing(self, app_client, mock_db):
        """Atomic batch: if any object conflicts, ALL should be rejected (409)."""
        sk, pk = _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Create an existing object at version 2
        obj_id_1 = "BATCH000000000000000000001"
        payload1 = b"existing"
        mock_db._storage["vault_objects"].append({
            "id": obj_id_1, "object_type": "dek", "payload": payload1,
            "owner_id": "ADMIN000000000000000000001",
            "target_user_id": None, "parent_ref": None,
            "version": 2, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(payload1).hexdigest(),
            "client_signature": b"\x00" * 64,
            "modified_at": int(time.time() * 1000),
        })

        # New object (should succeed on its own)
        obj_id_2 = "BATCH000000000000000000002"
        payload2 = b"new data"
        p2_b64 = base64.b64encode(payload2).decode("ascii")
        p2_hash = hashlib.sha256(payload2).hexdigest()
        sig2 = _sign_sync_object(sk, obj_id_2, "dek", None, None, 0, 1, p2_hash)

        # Conflicting object (try to push version 1 when server has version 2)
        payload_old = b"old conflict"
        po_b64 = base64.b64encode(payload_old).decode("ascii")
        po_hash = hashlib.sha256(payload_old).hexdigest()
        sig_old = _sign_sync_object(sk, obj_id_1, "dek", None, None, 0, 1, po_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [
                {"id": obj_id_2, "object_type": "dek", "payload": p2_b64,
                 "version": 1, "is_deleted": 0, "payload_hash": p2_hash,
                 "signature": sig2},
                {"id": obj_id_1, "object_type": "dek", "payload": po_b64,
                 "version": 1, "is_deleted": 0, "payload_hash": po_hash,
                 "signature": sig_old},
            ],
            "atomic_batch": True,
        }, headers={"Authorization": f"Bearer {token}"})

        # Should get 409 because of atomic batch with conflict
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_envelope_push_auto_creates_write_acl(self, app_client, mock_db):
        """Pushing an envelope object should auto-create write_acl for target_user."""
        sk, pk = _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        obj_id = "ENV00000000000000000000001"
        dek_id = "DEK00000000000000000000001"
        node_id = "NODE0000000000000000000001"
        self._seed_dek(mock_db, dek_id, node_id)
        target_user = "USER0000000000000000000001"
        payload = b"envelope data"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        sig = _sign_sync_object(sk, obj_id, "envelope", dek_id, target_user, 0, 1, p_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "envelope", "payload": p_b64,
                         "parent_ref": dek_id, "target_user_id": target_user,
                         "access_level": "write",
                         "version": 1, "is_deleted": 0, "payload_hash": p_hash,
                         "signature": sig}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        # Check write_acl was created
        acls = [a for a in mock_db._storage["write_acl"]
                if a["user_id"] == target_user and a["node_id"] == node_id]
        assert len(acls) == 1

    @pytest.mark.asyncio
    async def test_read_envelope_does_not_create_write_acl(self, app_client, mock_db):
        """A read-only envelope must never grant server write permission."""
        sk, _ = _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        obj_id = "READENV0000000000000000001"
        dek_id = "DEK00000000000000000000003"
        node_id = "NODE0000000000000000000003"
        self._seed_dek(mock_db, dek_id, node_id)
        target_user = "USER0000000000000000000001"
        payload = b"read envelope"
        payload_hash = hashlib.sha256(payload).hexdigest()
        signature = _sign_sync_object(
            sk, obj_id, "envelope", dek_id, target_user, 0, 1, payload_hash
        )

        resp = await app_client.post("/api/sync", json={
            "objects": [{
                "id": obj_id, "object_type": "envelope",
                "payload": base64.b64encode(payload).decode("ascii"),
                "parent_ref": dek_id, "target_user_id": target_user,
                "access_level": "read", "version": 1, "is_deleted": 0,
                "payload_hash": payload_hash, "signature": signature,
            }],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert len(resp.json()["accepted"]) == 1
        assert not [
            acl for acl in mock_db._storage["write_acl"]
            if acl["user_id"] == target_user and acl["node_id"] == node_id
        ]

    @pytest.mark.asyncio
    async def test_tombstone_envelope_removes_write_acl(self, app_client, mock_db):
        """Pushing a tombstone envelope should remove write_acl."""
        sk, pk = _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        target_user = "USER0000000000000000000001"
        dek_id = "DEK00000000000000000000002"
        node_id = "NODE0000000000000000000002"
        self._seed_dek(mock_db, dek_id, node_id)

        # First, grant write_acl
        mock_db._storage["write_acl"].append({
            "user_id": target_user, "node_id": node_id,
            "granted_at": int(time.time() * 1000),
        })

        # Push tombstone envelope
        obj_id = "ENV00000000000000000000002"
        payload = b"tombstone"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        sig = _sign_sync_object(sk, obj_id, "envelope", dek_id, target_user, 1, 1, p_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "envelope", "payload": p_b64,
                         "parent_ref": dek_id, "target_user_id": target_user,
                         "access_level": "write",
                         "version": 1, "is_deleted": 1, "payload_hash": p_hash,
                         "signature": sig}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        # write_acl should be removed
        acls = [a for a in mock_db._storage["write_acl"]
                if a["user_id"] == target_user and a["node_id"] == node_id]
        assert len(acls) == 0


class TestSyncPull:
    """Tests for GET /api/sync."""

    @pytest.mark.asyncio
    async def test_pull_returns_objects_after_since(self, app_client, mock_db):
        """Pull should return objects with commit_seq > since_commit_seq."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Insert objects directly
        mock_db._storage["vault_objects"].append({
            "id": "PULL0000000000000000000001",
            "object_type": "dek",
            "payload": b"data1",
            "owner_id": "ADMIN000000000000000000001",
            "parent_ref": None,
            "target_user_id": None,
            "version": 1,
            "commit_seq": 5,
            "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"data1").hexdigest(),
            "client_signature": b"\x00" * 64,
            "modified_at": int(time.time() * 1000),
        })
        mock_db._storage["vault_objects"].append({
            "id": "PULL0000000000000000000002",
            "object_type": "dek",
            "payload": b"data2",
            "owner_id": "ADMIN000000000000000000001",
            "parent_ref": None,
            "target_user_id": None,
            "version": 1,
            "commit_seq": 10,
            "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"data2").hexdigest(),
            "client_signature": b"\x00" * 64,
            "modified_at": int(time.time() * 1000),
        })

        resp = await app_client.get(
            "/api/sync?since_commit_seq=6",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Only object with commit_seq=10 should be returned (>6)
        assert len(data["objects"]) == 1
        assert data["objects"][0]["id"] == "PULL0000000000000000000002"

    @pytest.mark.asyncio
    async def test_pull_has_no_etag_and_never_answers_304(self, app_client, mock_db):
        """Sync redesign S2: the client's checkpoint is its only pull state.

        The server sets no ETag and ignores If-None-Match, so a device that
        kept a stale ETag can never freeze its pulls with 304."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        mock_db._storage["vault_objects"].append({
            "id": "ETAG0000000000000000000001",
            "object_type": "dek",
            "payload": b"data",
            "owner_id": "ADMIN000000000000000000001",
            "parent_ref": None,
            "target_user_id": None,
            "version": 1,
            "commit_seq": 42,
            "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"data").hexdigest(),
            "client_signature": b"\x00" * 64,
            "modified_at": int(time.time() * 1000),
        })

        resp = await app_client.get(
            "/api/sync?since_commit_seq=0",
            headers={
                "Authorization": f"Bearer {token}",
                "If-None-Match": '"42"',
            },
        )
        assert resp.status_code == 200
        assert "ETag" not in resp.headers
        assert [o["id"] for o in resp.json()["objects"]] == ["ETAG0000000000000000000001"]

    @pytest.mark.asyncio
    async def test_pull_below_gc_floor_returns_410(self, app_client, mock_db):
        """since_commit_seq < gc_floor should return 410 Gone."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Set gc_floor_seq to 100
        mock_db._storage["commit_counter"][0]["gc_floor_seq"] = 100

        resp = await app_client.get(
            "/api/sync?since_commit_seq=50",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 410

    @pytest.mark.asyncio
    async def test_explicit_full_resync_bypasses_gc_floor_and_returns_snapshot(
        self, app_client, mock_db
    ):
        """H1: an explicit confirmed full resync must work after tombstone GC."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        mock_db._storage["commit_counter"][0]["gc_floor_seq"] = 100
        mock_db._storage["vault_objects"].append({
            "id": "FULL0000000000000000000001",
            "object_type": "dek",
            "payload": b"snapshot",
            "owner_id": "ADMIN000000000000000000001",
            "parent_ref": None,
            "target_user_id": None,
            "version": 1,
            "commit_seq": 120,
            "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"snapshot").hexdigest(),
            "client_signature": b"\x00" * 64,
            "modified_at": int(time.time() * 1000),
        })

        resp = await app_client.get(
            "/api/sync?since_commit_seq=0&full_resync=true",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert [obj["id"] for obj in resp.json()["objects"]] == [
            "FULL0000000000000000000001"
        ]

    @pytest.mark.asyncio
    async def test_full_resync_is_paginated_with_continuation_cursor(
        self, app_client, mock_db
    ):
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        now_ms = int(time.time() * 1000)
        for seq in range(1, 1201):
            payload = f"object-{seq}".encode()
            mock_db._storage["vault_objects"].append({
                "id": f"PAGE{seq:022d}",
                "object_type": "dek",
                "payload": payload,
                "owner_id": "ADMIN000000000000000000001",
                "parent_ref": None,
                "target_user_id": None,
                "version": 1,
                "commit_seq": seq,
                "is_deleted": 0,
                "payload_hash": hashlib.sha256(payload).hexdigest(),
                "client_signature": b"\x00" * 64,
                "modified_at": now_ms,
            })

        cursor = None
        received = []
        page_sizes = []
        while True:
            suffix = "" if cursor is None else f"&cursor={cursor}"
            response = await app_client.get(
                f"/api/sync?since_commit_seq=0&full_resync=true{suffix}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            page = response.json()
            page_sizes.append(len(page["objects"]))
            received.extend(obj["commit_seq"] for obj in page["objects"])
            if not page["has_more"]:
                assert page["next_cursor"] is None
                break
            cursor = page["next_cursor"]
            assert cursor == received[-1]

        assert received == list(range(1, 1201))
        assert max(page_sizes) == 250
        assert len(page_sizes) == 5

    @pytest.mark.asyncio
    async def test_pull_page_enforces_payload_byte_budget(self, app_client, mock_db):
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        payload = b"x" * (1024 * 1024)
        for seq in range(1, 6):
            mock_db._storage["vault_objects"].append({
                "id": f"BYTES{seq:021d}",
                "object_type": "dek",
                "payload": payload,
                "owner_id": "ADMIN000000000000000000001",
                "parent_ref": None,
                "target_user_id": None,
                "version": 1,
                "commit_seq": seq,
                "is_deleted": 0,
                "payload_hash": hashlib.sha256(payload).hexdigest(),
                "client_signature": b"\x00" * 64,
                "modified_at": int(time.time() * 1000),
            })

        response = await app_client.get(
            "/api/sync?since_commit_seq=0&full_resync=true",
            headers={"Authorization": f"Bearer {token}"},
        )
        page = response.json()

        assert response.status_code == 200
        assert len(response.content) < 4 * 1024 * 1024
        assert len(page["objects"]) == 2
        assert page["has_more"] is True
        assert page["next_cursor"] == 2

    @pytest.mark.asyncio
    async def test_full_resync_flag_requires_zero_baseline(self, app_client, mock_db):
        """The bypass cannot be combined with an arbitrary delta baseline."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        resp = await app_client.get(
            "/api/sync?since_commit_seq=1&full_resync=true",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400


class TestMeta:
    """Tests for GET /api/meta."""

    @pytest.mark.asyncio
    async def test_meta_returns_argon2_params(self, app_client, mock_db):
        """Meta without username should return argon2 web params."""
        resp = await app_client.get("/api/meta")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0"
        assert "argon2_web_params" in data
        params = data["argon2_web_params"]
        assert params == {
            "time_cost": 3,
            "memory_cost": 131072,
            "parallelism": 4,
            "hash_len": 64,
        }

    @pytest.mark.asyncio
    async def test_meta_with_username_returns_salts(self, app_client, mock_db):
        """Meta with existing username should return real salts."""
        _create_admin_user(mock_db._storage)
        resp = await app_client.get("/api/meta?username=admin")
        assert resp.status_code == 200
        data = resp.json()
        assert data["argon2_salt"] is not None
        assert len(data["argon2_salt"]) > 0

    @pytest.mark.asyncio
    async def test_meta_with_nonexistent_username_returns_fake_salt(self, app_client, mock_db):
        """Meta with non-existent username should return a deterministic fake salt."""
        resp1 = await app_client.get("/api/meta?username=ghost_user")
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["argon2_salt"] is not None

        # Same username should produce same fake salt (deterministic)
        resp2 = await app_client.get("/api/meta?username=ghost_user")
        data2 = resp2.json()
        assert data1["argon2_salt"] == data2["argon2_salt"]

        # Different username should produce different fake salt
        resp3 = await app_client.get("/api/meta?username=other_ghost")
        data3 = resp3.json()
        assert data1["argon2_salt"] != data3["argon2_salt"]

    @pytest.mark.asyncio
    async def test_meta_fake_salt_same_format(self, app_client, mock_db):
        """Fake salt should be same format as real salt (hex string)."""
        _create_admin_user(mock_db._storage)

        # Real salt
        resp_real = await app_client.get("/api/meta?username=admin")
        real_salt = resp_real.json()["argon2_salt"]

        # Fake salt
        resp_fake = await app_client.get("/api/meta?username=nonexistent")
        fake_salt = resp_fake.json()["argon2_salt"]

        # Both should be valid hex strings
        bytes.fromhex(real_salt)
        bytes.fromhex(fake_salt)

        # Both should have auth_salt too
        assert resp_fake.json()["auth_salt"] is not None


# =====================================================================
# SHARE TESTS (spec 6)
# =====================================================================

class TestShareRecipientPage:
    """G4-01: public recipient route and same-origin browser decrypt assets."""

    @pytest.mark.asyncio
    async def test_canonical_recipient_route_serves_isolated_decrypt_shell(self, app_client):
        share_id = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")

        response = await app_client.get(f"/s/{share_id}")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["content-security-policy"] == (
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        # Each asset's URL carries its content's hash (review c78fd19, web).
        web = Path(__file__).resolve().parents[1] / "web"
        for script in ("js/share.js", "js/i18n.js", "js/vendor/libsodium-sumo.min.js",
                       "js/vendor/libsodium-wrappers.min.js"):
            digest = hashlib.sha256((web / "static" / script).read_bytes()).hexdigest()[:16]
            assert f'src="/static/{script}?v={digest}"' in response.text
        assert "https://" not in response.text
        assert "<script>" not in response.text

        for asset in (
            "/static/css/app.css",
            "/static/js/vendor/libsodium-sumo.min.js",
            "/static/js/vendor/libsodium-wrappers.min.js",
            "/static/js/i18n.js",
            "/static/js/share.js",
        ):
            assert (await app_client.get(asset)).status_code == 200
        script = await app_client.get("/static/js/share.js")
        assert "crypto_aead_xchacha20poly1305_ietf_decrypt" in script.text


class TestShareCreate:
    """Tests for POST /api/share."""

    @pytest.mark.asyncio
    async def test_create_share_with_256bit_id(self, app_client, mock_db):
        """Creating a share should use the client-provided 256-bit ID."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # 256-bit = 32 bytes = 43 chars base64url (without padding)
        share_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        blob = base64.b64encode(b"secret share data").decode("ascii")
        expires_at = int(time.time() * 1000) + 3600 * 1000

        resp = await app_client.post("/api/share", json={
            "id": share_id,
            "encrypted_blob": blob,
            "expires_at": expires_at,
            "max_views": 5,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert resp.json()["id"] == share_id
        stored = mock_db._storage["shared_links"][0]
        assert stored["notify_on_view"] == 1

    @pytest.mark.asyncio
    async def test_create_share_can_disable_view_notifications(self, app_client, mock_db):
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", True)
        share_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")

        resp = await app_client.post("/api/share", json={
            "id": share_id,
            "encrypted_blob": base64.b64encode(b"ciphertext").decode("ascii"),
            "expires_at": int(time.time() * 1000) + 3600 * 1000,
            "notify_on_view": False,
        }, headers={"Authorization": f"Bearer {token}"})

        assert resp.status_code == 200
        assert mock_db._storage["shared_links"][0]["notify_on_view"] == 0

    def test_share_create_rejects_malformed_and_unbounded_inputs(self):
        """M3: validate share IDs, blobs, expiry, views, and PIN hash format."""
        from pydantic import ValidationError
        from server.app.models.schemas import ShareCreateRequest

        valid = {
            "id": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="),
            "encrypted_blob": base64.b64encode(b"ciphertext").decode("ascii"),
            "expires_at": int(time.time() * 1000) + 3600 * 1000,
            "max_views": 1,
        }
        invalid_updates = [
            {"id": "short"},
            {"encrypted_blob": "not base64!"},
            {"expires_at": int(time.time() * 1000) - 1},
            {"expires_at": int(time.time() * 1000) + 366 * 24 * 3600 * 1000},
            {"max_views": 0},
            {"max_views": 11},
            {"pin_hash": hashlib.sha256(b"123456").hexdigest()},
        ]

        for update in invalid_updates:
            with pytest.raises(ValidationError):
                ShareCreateRequest(**(valid | update))

        import argon2
        valid_pin_hash = argon2.PasswordHasher().hash("123456")
        assert ShareCreateRequest(**(valid | {"pin_hash": valid_pin_hash})).pin_hash == valid_pin_hash
        for costly_params in (
            "m=262144,t=3,p=4",
            "m=65536,t=10,p=4",
            "m=65536,t=3,p=8",
        ):
            costly_hash = valid_pin_hash.replace("m=65536,t=3,p=4", costly_params)
            with pytest.raises(ValidationError, match="server Argon2id PIN policy"):
                ShareCreateRequest(**(valid | {"pin_hash": costly_hash}))

        oversized = base64.b64encode(b"x" * (10 * 1024 * 1024 + 1)).decode("ascii")
        with pytest.raises(ValidationError):
            ShareCreateRequest(**(valid | {"encrypted_blob": oversized}))


class TestShareConsume:
    """Tests for POST /api/share/:id."""

    def _insert_share(self, storage, share_id, user_id="ADMIN000000000000000000001",
                      expires_in_ms=3600000, max_views=5, pin_hash=None,
                      view_count=0, is_locked=False, pin_attempts=0,
                      notify_on_view=True):
        """Helper to insert a share into mock storage."""
        now_ms = int(time.time() * 1000)
        storage["shared_links"].append({
            "id": share_id,
            "encrypted_blob": b"secret data",
            "created_by": user_id,
            "created_at": now_ms,
            "expires_at": now_ms + expires_in_ms,
            "max_views": max_views,
            "view_count": view_count,
            "pin_hash": pin_hash,
            "pin_attempts": pin_attempts,
            "is_locked": 1 if is_locked else 0,
            "notify_on_view": 1 if notify_on_view else 0,
        })

    @pytest.mark.asyncio
    async def test_consume_share_success(self, app_client, mock_db):
        """Consuming a valid share should return encrypted_blob."""
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000001"
        self._insert_share(mock_db._storage, share_id)

        resp = await app_client.post(f"/api/share/{share_id}", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "encrypted_blob" in data
        assert data["view_count"] == 1

    @pytest.mark.asyncio
    async def test_view_notification_is_owner_only_and_claimed_once(
        self, app_client, mock_db
    ):
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        share_id = "SHARE000000000000000000101"
        self._insert_share(mock_db._storage, share_id, notify_on_view=True)

        consumed = await app_client.post(f"/api/share/{share_id}", json={})
        assert consumed.status_code == 200
        event = mock_db._storage["share_views"][0]
        assert event["owner_id"] == "ADMIN000000000000000000001"
        assert event["notification_pending"] == 1
        assert event["viewer_ip_hmac"]
        assert event["user_agent_hmac"]

        other_token = _create_jwt(
            "USER0000000000000000000001", "alice", False
        )
        other = await app_client.get(
            "/api/share-notifications",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert other.status_code == 200
        assert other.json() == []
        assert event["notification_pending"] == 1

        owner_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True
        )
        owner = await app_client.get(
            "/api/share-notifications",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert owner.status_code == 200
        assert owner.json() == [{
            "id": event["id"],
            "share_id": share_id,
            "viewed_at": event["viewed_at"],
        }]
        assert event["notification_pending"] == 0

        repeated = await app_client.get(
            "/api/share-notifications",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert repeated.status_code == 200
        assert repeated.json() == []

    @pytest.mark.asyncio
    async def test_notify_opt_out_records_view_without_pending_delivery(
        self, app_client, mock_db
    ):
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000102"
        self._insert_share(mock_db._storage, share_id, notify_on_view=False)

        consumed = await app_client.post(f"/api/share/{share_id}", json={})
        assert consumed.status_code == 200
        assert mock_db._storage["share_views"][0]["notification_pending"] == 0

        owner_token = _create_jwt(
            "ADMIN000000000000000000001", "admin", True
        )
        polled = await app_client.get(
            "/api/share-notifications",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        assert polled.status_code == 200
        assert polled.json() == []

    @pytest.mark.asyncio
    async def test_expired_share_returns_410_and_deleted(self, app_client, mock_db):
        """Expired share should return 410 and be deleted."""
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000002"
        self._insert_share(mock_db._storage, share_id, expires_in_ms=-1000)  # Already expired

        resp = await app_client.post(f"/api/share/{share_id}", json={})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}

        # Share should be deleted
        remaining = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id]
        assert len(remaining) == 0

    @pytest.mark.asyncio
    async def test_max_views_reached_returns_410(self, app_client, mock_db):
        """Share at max views should return 410."""
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000003"
        self._insert_share(mock_db._storage, share_id, max_views=3, view_count=3)

        resp = await app_client.post(f"/api/share/{share_id}", json={})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}

    @pytest.mark.asyncio
    async def test_pin_required_when_pin_hash_set(self, app_client, mock_db):
        """Share with pin_hash requires PIN in request body."""
        import argon2
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000004"
        pin_hash = argon2.PasswordHasher().hash("1234")
        self._insert_share(mock_db._storage, share_id, pin_hash=pin_hash)

        resp = await app_client.post(f"/api/share/{share_id}", json={})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}

    @pytest.mark.asyncio
    async def test_correct_pin_succeeds(self, app_client, mock_db):
        """Correct PIN should allow consuming the share."""
        import argon2
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000005"
        pin_hash = argon2.PasswordHasher().hash("5678")
        self._insert_share(mock_db._storage, share_id, pin_hash=pin_hash)

        resp = await app_client.post(f"/api/share/{share_id}", json={"pin": "5678"})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_pin_argon2_runs_off_loop_and_success_refunds_ip_budget(
        self, app_client, mock_db, monkeypatch
    ):
        """Review #10: PIN Argon2 runs in a worker thread, and correct PINs
        do not use up the per-IP failure budget."""
        import argon2
        from server.app.routers import share as share_router

        offloaded = []
        real_to_thread = asyncio.to_thread

        async def tracking_to_thread(func, *args):
            offloaded.append(func)
            return await real_to_thread(func, *args)

        monkeypatch.setattr(share_router.asyncio, "to_thread", tracking_to_thread)
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000015"
        pin_hash = argon2.PasswordHasher().hash("5678")
        self._insert_share(mock_db._storage, share_id, pin_hash=pin_hash, max_views=5)

        for _ in range(4):
            resp = await app_client.post(f"/api/share/{share_id}", json={"pin": "5678"})
            assert resp.status_code == 200
        assert offloaded
        assert mock_db._storage["share_pin_rate_limits"][0]["failure_count"] == 0

    @pytest.mark.asyncio
    async def test_wrong_pin_increments_attempts(self, app_client, mock_db):
        """Wrong PIN should increment pin_attempts."""
        import argon2
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000006"
        pin_hash = argon2.PasswordHasher().hash("correct")
        self._insert_share(mock_db._storage, share_id, pin_hash=pin_hash)

        resp = await app_client.post(f"/api/share/{share_id}", json={"pin": "wrong"})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}

        # Check attempts incremented
        share = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id][0]
        assert share["pin_attempts"] == 1
        assert mock_db._storage["share_pin_rate_limits"][0]["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_10th_wrong_pin_locks_share(self, app_client, mock_db):
        """10th wrong PIN attempt should lock the share."""
        import argon2
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000007"
        pin_hash = argon2.PasswordHasher().hash("secret")
        self._insert_share(mock_db._storage, share_id, pin_hash=pin_hash, pin_attempts=9)

        resp = await app_client.post(f"/api/share/{share_id}", json={"pin": "wrong"})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}

        share = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id][0]
        assert share["is_locked"] == 1

    @pytest.mark.asyncio
    async def test_locked_share_is_indistinguishable(self, app_client, mock_db):
        """A locked share uses the same public failure as every other error."""
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000008"
        self._insert_share(mock_db._storage, share_id, is_locked=True)

        resp = await app_client.post(f"/api/share/{share_id}", json={})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}

    @pytest.mark.asyncio
    async def test_unavailable_errors_run_dummy_argon2_and_share_timing_floor(
        self, app_client, mock_db, monkeypatch
    ):
        import server.app.routers.share as share_router

        _create_admin_user(mock_db._storage)
        locked_id = "SHARE000000000000000000042"
        self._insert_share(mock_db._storage, locked_id, is_locked=True)
        monkeypatch.setattr(share_router, "_SHARE_ERROR_MIN_SECONDS", 0.02)

        responses = []
        elapsed = []
        with patch.object(share_router, "_run_dummy_pin_check") as dummy_check:
            for share_id in ("MISSING0000000000000000000", locked_id):
                started_at = time.perf_counter()
                responses.append(
                    await app_client.post(f"/api/share/{share_id}", json={})
                )
                elapsed.append(time.perf_counter() - started_at)

        assert [response.status_code for response in responses] == [404, 404]
        assert [response.json() for response in responses] == [
            {"detail": "Share unavailable"},
            {"detail": "Share unavailable"},
        ]
        assert all(duration >= 0.018 for duration in elapsed)
        assert dummy_check.call_count == 2

    @pytest.mark.asyncio
    async def test_malformed_pin_hash_locks_share_instead_of_500(self, app_client, mock_db):
        """M3: corrupt legacy hashes fail closed without an internal error."""
        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000009"
        self._insert_share(mock_db._storage, share_id, pin_hash="malformed")

        resp = await app_client.post(f"/api/share/{share_id}", json={"pin": "1234"})

        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}
        share = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id][0]
        assert share["is_locked"] == 1
        assert share["view_count"] == 0

    @pytest.mark.asyncio
    async def test_legacy_costly_pin_hash_is_locked_without_argon2_work(
        self, app_client, mock_db
    ):
        """G5-02: stored creator-controlled costs never reach Argon2 verify."""
        import argon2

        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000011"
        normal_hash = argon2.PasswordHasher().hash("correct")
        costly_hash = normal_hash.replace(
            "m=65536,t=3,p=4", "m=262144,t=10,p=8"
        )
        self._insert_share(mock_db._storage, share_id, pin_hash=costly_hash)

        with patch("argon2.PasswordHasher.verify") as verify:
            resp = await app_client.post(
                f"/api/share/{share_id}", json={"pin": "wrong"}
            )

        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}
        verify.assert_called_once()
        assert verify.call_args.args[0] != costly_hash
        share = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id][0]
        assert share["is_locked"] == 1
        assert share["view_count"] == 0

    @pytest.mark.asyncio
    async def test_pin_rate_limit_is_shared_through_database(self, app_client, mock_db):
        """M3: a worker must honor failures persisted by another worker."""
        import argon2
        from server.app.auth import compute_ip_hmac

        _create_admin_user(mock_db._storage)
        share_id = "SHARE000000000000000000010"
        pin_hash = argon2.PasswordHasher().hash("correct")
        self._insert_share(mock_db._storage, share_id, pin_hash=pin_hash)
        ip_hmac = compute_ip_hmac("test-server-secret-key-12345", "127.0.0.1")
        mock_db._storage["share_pin_rate_limits"].append({
            "ip_hmac": ip_hmac,
            "window_started_at": int(time.time() * 1000),
            "failure_count": 3,
        })

        resp = await app_client.post(
            f"/api/share/{share_id}", json={"pin": "correct"}
        )

        assert resp.status_code == 404
        assert resp.json() == {"detail": "Share unavailable"}
        assert mock_db._storage["shared_links"][0]["view_count"] == 0

    @pytest.mark.asyncio
    async def test_cleanup_removes_stale_pin_rate_limits(self, mock_db):
        from server.app.main import _cleanup_expired_shares

        now_ms = int(time.time() * 1000)
        mock_db._storage["share_pin_rate_limits"].extend([
            {"ip_hmac": "old", "window_started_at": now_ms - 901_000, "failure_count": 3},
            {"ip_hmac": "recent", "window_started_at": now_ms, "failure_count": 1},
        ])

        await _cleanup_expired_shares(mock_db)

        assert [row["ip_hmac"] for row in mock_db._storage["share_pin_rate_limits"]] == ["recent"]


class TestShareAdmin:
    """Tests for PATCH /api/share/:id and DELETE /api/share/:id."""

    def _insert_share(self, storage, share_id, user_id="ADMIN000000000000000000001",
                      is_locked=False):
        now_ms = int(time.time() * 1000)
        storage["shared_links"].append({
            "id": share_id,
            "encrypted_blob": b"data",
            "created_by": user_id,
            "created_at": now_ms,
            "expires_at": now_ms + 3600000,
            "max_views": 5,
            "view_count": 0,
            "pin_hash": None,
            "pin_attempts": 5,
            "is_locked": 1 if is_locked else 0,
        })

    @pytest.mark.asyncio
    async def test_admin_unlock_share(self, app_client, mock_db):
        """Admin should be able to unlock a locked share."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        share_id = "ADMSH000000000000000000001"
        self._insert_share(mock_db._storage, share_id, is_locked=True)

        resp = await app_client.patch(
            f"/api/share/{share_id}",
            json={"action": "unlock"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

        share = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id][0]
        assert share["is_locked"] == 0
        assert share["pin_attempts"] == 0

    @pytest.mark.asyncio
    async def test_admin_deactivate_share(self, app_client, mock_db):
        """Admin should be able to deactivate a share (set expires_at to now)."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        share_id = "ADMSH000000000000000000002"
        self._insert_share(mock_db._storage, share_id)

        resp = await app_client.patch(
            f"/api/share/{share_id}",
            json={"action": "deactivate"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

        share = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id][0]
        now_ms = int(time.time() * 1000)
        # expires_at should be approximately now
        assert abs(share["expires_at"] - now_ms) < 5000

    @pytest.mark.asyncio
    async def test_owner_can_delete_share(self, app_client, mock_db):
        """Share owner can delete their own share."""
        _create_admin_user(mock_db._storage)
        token = _create_jwt("ADMIN000000000000000000001", "admin", False)

        # Create admin as non-admin owner
        share_id = "DELSH000000000000000000001"
        self._insert_share(mock_db._storage, share_id)

        resp = await app_client.delete(
            f"/api/share/{share_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        remaining = [s for s in mock_db._storage["shared_links"] if s["id"] == share_id]
        assert len(remaining) == 0

    @pytest.mark.asyncio
    async def test_admin_can_delete_any_share(self, app_client, mock_db):
        """Admin can delete any share regardless of ownership."""
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # Share owned by regular user
        share_id = "DELSH000000000000000000002"
        self._insert_share(mock_db._storage, share_id, user_id="USER0000000000000000000001")

        resp = await app_client.delete(
            f"/api/share/{share_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_non_owner_non_admin_cannot_delete(self, app_client, mock_db):
        """Non-owner non-admin should get 403 when trying to delete a share."""
        _create_admin_user(mock_db._storage)
        _create_regular_user(mock_db._storage)
        user_token = _create_jwt("USER0000000000000000000001", "alice", False)

        # Share owned by admin
        share_id = "DELSH000000000000000000003"
        self._insert_share(mock_db._storage, share_id, user_id="ADMIN000000000000000000001")

        resp = await app_client.delete(
            f"/api/share/{share_id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert resp.status_code == 403


# =====================================================================
# SERVER BOUNDARY LIMIT TESTS
# =====================================================================

class TestServerBoundaryLimits:
    """E1: server startup and request parsing must fail closed."""

    @pytest.mark.parametrize("secret", ["", "   "])
    def test_empty_hmac_secret_is_rejected(self, secret):
        from server.app.config import ServerConfig

        with patch.dict(os.environ, {"SEZAM_HMAC_SECRET": secret}):
            with pytest.raises(ValueError, match="SEZAM_HMAC_SECRET"):
                ServerConfig.from_env()

    @pytest.mark.asyncio
    async def test_oversized_request_body_is_rejected(self, app_client):
        response = await app_client.post(
            "/api/auth/challenge",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(16 * 1024 * 1024 + 1),
            },
        )

        assert response.status_code == 413

    def test_sync_batch_and_payload_have_explicit_limits(self):
        from pydantic import ValidationError
        from server.app.models.schemas import PushRequest, SyncObject

        sync_object = {
            "id": "LIMIT000000000000000000001",
            "object_type": "entry",
            "payload": base64.b64encode(b"x").decode("ascii"),
            "version": 1,
            "payload_hash": hashlib.sha256(b"x").hexdigest(),
            "signature": "00" * 64,
        }
        with pytest.raises(ValidationError) as batch_error:
            PushRequest.model_validate({"objects": [sync_object] * 1001})
        assert any(
            error["loc"] == ("objects",) and error["type"] == "too_long"
            for error in batch_error.value.errors()
        )

        oversized_payload = base64.b64encode(
            b"x" * (1024 * 1024 + 1)
        ).decode("ascii")
        with pytest.raises(ValidationError) as payload_error:
            SyncObject.model_validate({**sync_object, "payload": oversized_payload})
        assert any(
            error["loc"] == ("payload",)
            and "exceeds 1 MiB" in error["msg"]
            for error in payload_error.value.errors()
        )

    def test_auth_fields_have_explicit_limits(self):
        from pydantic import ValidationError
        from server.app.models.schemas import ChallengeRequest, KeypairUploadRequest

        with pytest.raises(ValidationError):
            ChallengeRequest(username="a" * 256)
        with pytest.raises(ValidationError):
            KeypairUploadRequest(
                encrypted_keypair="a" * 4097,
                argon2_salt="00" * 16,
                auth_salt="00" * 16,
                auth_proof="00" * 32,
            )


# =====================================================================
# SECURITY HEADERS TESTS (spec 2.9)
# =====================================================================

class TestSecurityHeaders:
    """Tests for security response headers."""

    @pytest.mark.asyncio
    async def test_csp_header(self, app_client, mock_db):
        """Response should include Content-Security-Policy."""
        resp = await app_client.get("/health")
        assert resp.status_code == 200
        csp = resp.headers.get("content-security-policy")
        assert csp is not None
        assert "default-src 'self'" in csp

    @pytest.mark.asyncio
    async def test_share_csp_disallows_external_scripts(self, app_client, mock_db):
        """M4: Secure Share responses must use the isolated spec 6.3 CSP."""
        resp = await app_client.get("/api/shares")
        csp = resp.headers.get("content-security-policy")
        assert csp == (
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        assert "cdn.jsdelivr.net" not in csp

        general_resp = await app_client.get("/health")
        general_csp = general_resp.headers.get("content-security-policy")
        script_src = general_csp.split("script-src", 1)[1].split(";", 1)[0].split()
        # Review 2052248: jsDelivr builds the minified files on demand, so SRI
        # hashes of CDN URLs can break; the libraries are self-hosted and no
        # third-party script origin is allowed at all.
        assert script_src == ["'self'", "'wasm-unsafe-eval'"]
        index_html = (Path(__file__).parents[1] / "web" / "templates" / "index.html").read_text(encoding="utf-8")
        scripts = re.findall(r'<script src="([^"]+)"(?:\s+integrity="sha384-([^"]+)")?', index_html)
        assert all(src.startswith("/static/") for src, _ in scripts)
        vendored = {src: sri for src, sri in scripts if "/vendor/" in src}
        assert len(vendored) == 4  # libsodium (sumo + wrappers), argon2, the shared sync core (S4b)
        static_root = Path(__file__).parents[1] / "web"
        for src, sri in vendored.items():
            body = (static_root / src.lstrip("/")).read_bytes()
            assert sri == base64.b64encode(hashlib.sha384(body).digest()).decode(), src

    @pytest.mark.asyncio
    async def test_web_vault_is_served_with_wasm_capable_csp(self, app_client, mock_db):
        """Review 22: '/' serves index.html; libsodium/Argon2 WASM (incl. the
        worker, which gets its own CSP) may compile, but plain eval may not."""
        index = await app_client.get("/")
        assert index.status_code == 200
        assert index.headers["content-type"].startswith("text/html")
        assert 'id="login-screen"' in index.text

        for path in ("/", "/s/abc", "/static/js/argon2-worker.js"):
            resp = await app_client.get(path)
            assert resp.status_code == 200, path
            csp = resp.headers["content-security-policy"]
            script_src = csp.split("script-src", 1)[1].split(";", 1)[0]
            assert "'wasm-unsafe-eval'" in script_src, path
            assert "'unsafe-eval'" not in script_src, path

    def test_argon2_worker_uses_vendored_same_origin_bundle(self):
        """M4: importScripts cannot use SRI, so the worker dependency is local."""
        static_js = Path(__file__).parents[1] / "web" / "static" / "js"
        worker_source = (static_js / "argon2-worker.js").read_text(encoding="utf-8")
        assert "importScripts('/static/js/vendor/argon2-bundled.min.js')" in worker_source
        assert "https://" not in worker_source
        vendor_bundle = (static_js / "vendor" / "argon2-bundled.min.js").read_bytes()
        vendor_sri = base64.b64encode(hashlib.sha384(vendor_bundle).digest()).decode()
        assert vendor_sri == (
            "XOR3aNvHciLPIf6r+2glkrmbBbLmIJ1EChMXjw8eBKBf8gE0rDq1TyUNuRdorOqi"
        )

    @pytest.mark.asyncio
    async def test_csp_includes_worker_src(self, app_client, mock_db):
        """CSP must include worker-src directive."""
        resp = await app_client.get("/health")
        csp = resp.headers.get("content-security-policy")
        assert "worker-src" in csp

    @pytest.mark.asyncio
    async def test_csp_includes_connect_src(self, app_client, mock_db):
        """CSP must include connect-src directive."""
        resp = await app_client.get("/health")
        csp = resp.headers.get("content-security-policy")
        assert "connect-src" in csp

    @pytest.mark.asyncio
    async def test_csp_includes_frame_ancestors(self, app_client, mock_db):
        """CSP must include frame-ancestors 'none' (clickjacking protection)."""
        resp = await app_client.get("/health")
        csp = resp.headers.get("content-security-policy")
        assert "frame-ancestors 'none'" in csp

    @pytest.mark.asyncio
    async def test_hsts_header(self, app_client, mock_db):
        """Response should include Strict-Transport-Security."""
        resp = await app_client.get("/health")
        hsts = resp.headers.get("strict-transport-security")
        assert hsts is not None
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts

    @pytest.mark.asyncio
    async def test_x_content_type_options(self, app_client, mock_db):
        """Response should include X-Content-Type-Options: nosniff."""
        resp = await app_client.get("/health")
        xcto = resp.headers.get("x-content-type-options")
        assert xcto == "nosniff"

    @pytest.mark.asyncio
    async def test_referrer_policy(self, app_client, mock_db):
        """Response should include Referrer-Policy: no-referrer."""
        resp = await app_client.get("/health")
        rp = resp.headers.get("referrer-policy")
        assert rp == "no-referrer"

    @pytest.mark.asyncio
    async def test_security_headers_on_api_endpoints(self, app_client, mock_db):
        """Security headers should be present on API endpoints too, not just health."""
        resp = await app_client.get("/api/meta")
        assert resp.headers.get("content-security-policy") is not None
        assert resp.headers.get("strict-transport-security") is not None
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("referrer-policy") == "no-referrer"


# =====================================================================
# ADDITIONAL NEGATIVE / SECURITY TESTS
# =====================================================================

class TestSecurityNegative:
    """Additional negative tests that try to break security properties."""

    @pytest.mark.asyncio
    async def test_missing_auth_header_returns_401(self, app_client, mock_db):
        """Requests without Authorization header should get 401 (not 500)."""
        _create_admin_user(mock_db._storage)
        resp = await app_client.get("/api/users")
        assert resp.status_code in (401, 422)  # 422 for missing header validation

    @pytest.mark.asyncio
    async def test_malformed_jwt_returns_401(self, app_client, mock_db):
        """Malformed JWT should return 401."""
        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_jwt_signed_with_wrong_key_returns_401(self, app_client, mock_db):
        """JWT signed with a different key should return 401."""
        wrong_sk = SigningKey.generate()
        from server.app.auth import create_jwt
        fake_token = create_jwt(wrong_sk, "fake_id", "hacker", True, 3600)

        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {fake_token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_non_admin_cannot_invite(self, app_client, mock_db):
        """Non-admin users should not be able to create invitations."""
        _create_regular_user(mock_db._storage)
        user_token = _create_jwt("USER0000000000000000000001", "alice", False)

        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_non_admin_cannot_approve(self, app_client, mock_db):
        """Non-admin users should not be able to approve users."""
        _create_regular_user(mock_db._storage)
        user_token = _create_jwt("USER0000000000000000000001", "alice", False)

        resp = await app_client.patch(
            "/api/users/someid/approve",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_non_admin_cannot_revoke(self, app_client, mock_db):
        """Non-admin users should not be able to revoke users."""
        _create_regular_user(mock_db._storage)
        user_token = _create_jwt("USER0000000000000000000001", "alice", False)

        resp = await app_client.delete(
            "/api/users/someid",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_verify_for_revoked_user_fails(self, app_client, mock_db):
        """Challenge-response for a revoked user should fail."""
        sk, pk = _create_admin_user(mock_db._storage, "REVOKED0000000000000000001", "revoked_user")
        # Set status to revoked
        user = [u for u in mock_db._storage["users"] if u["id"] == "REVOKED0000000000000000001"][0]
        user["status"] = "revoked"

        resp = await app_client.post("/api/auth/challenge", json={"username": "revoked_user"})
        challenge_hex = resp.json()["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)
        sig = _sign_challenge(sk, challenge_bytes)

        resp = await app_client.post("/api/auth/verify", json={
            "username": "revoked_user",
            "challenge": challenge_hex,
            "signature": sig.hex(),
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_verify_for_pending_user_fails(self, app_client, mock_db):
        """Challenge-response for a pending user should fail."""
        sk, pk = _create_admin_user(mock_db._storage, "PENDING0000000000000000001", "pending_user")
        user = [u for u in mock_db._storage["users"] if u["id"] == "PENDING0000000000000000001"][0]
        user["status"] = "pending"
        user["is_admin"] = 0

        resp = await app_client.post("/api/auth/challenge", json={"username": "pending_user"})
        challenge_hex = resp.json()["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)
        sig = _sign_challenge(sk, challenge_bytes)

        resp = await app_client.post("/api/auth/verify", json={
            "username": "pending_user",
            "challenge": challenge_hex,
            "signature": sig.hex(),
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_non_admin_cannot_patch_share(self, app_client, mock_db):
        """Non-admin users should not be able to unlock/deactivate shares."""
        _create_regular_user(mock_db._storage)
        user_token = _create_jwt("USER0000000000000000000001", "alice", False)

        resp = await app_client.patch(
            "/api/share/someid",
            json={"action": "unlock"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_non_admin_top_level_node_push_denied(self, app_client, mock_db):
        """Non-admin pushing top-level node (no parent_ref) should be denied."""
        sk, pk = _create_regular_user(mock_db._storage)
        token = _create_jwt("USER0000000000000000000001", "alice", False)

        payload = b"top-level node"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        obj_id = "TOPND000000000000000000001"
        sig = _sign_sync_object(sk, obj_id, "node", None, None, 0, 1, p_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "node", "payload": p_b64,
                         "version": 1, "is_deleted": 0, "payload_hash": p_hash,
                         "signature": sig}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        data = resp.json()
        assert len(data["conflicts"]) == 1
        assert "write_acl denied" in data["conflicts"][0]["error"]

    @pytest.mark.asyncio
    async def test_non_admin_with_write_acl_can_push(self, app_client, mock_db):
        """Non-admin WITH write_acl on parent should be able to push nodes."""
        sk, pk = _create_regular_user(mock_db._storage)
        # TL7 (review 1141a20 R9-F): a member's top-level node is their
        # personal root, closed to every other account; a shared folder is
        # the admin's.
        _create_admin_user(mock_db._storage)
        token = _create_jwt("USER0000000000000000000001", "alice", False)

        parent_ref = "PARENT00000000000000000002"
        mock_db._storage["vault_objects"].append({
            "id": parent_ref, "object_type": "node", "payload": b"parent",
            "owner_id": "ADMIN000000000000000000001", "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": None, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"parent").hexdigest(),
            "client_signature": b"x" * 64, "modified_at": 1,
        })
        # Grant write_acl
        mock_db._storage["write_acl"].append({
            "user_id": "USER0000000000000000000001",
            "node_id": parent_ref,
            "granted_at": int(time.time() * 1000),
        })

        payload = b"authorized node"
        p_b64 = base64.b64encode(payload).decode("ascii")
        p_hash = hashlib.sha256(payload).hexdigest()
        obj_id = "ACLND000000000000000000001"
        sig = _sign_sync_object(sk, obj_id, "node", parent_ref, None, 0, 1, p_hash)

        resp = await app_client.post("/api/sync", json={
            "objects": [{"id": obj_id, "object_type": "node", "payload": p_b64,
                         "parent_ref": parent_ref,
                         "version": 1, "is_deleted": 0, "payload_hash": p_hash,
                         "signature": sig}],
            "atomic_batch": False,
        }, headers={"Authorization": f"Bearer {token}"})

        data = resp.json()
        assert len(data["accepted"]) == 1
        assert len(data["conflicts"]) == 0


class TestOwnershipACL:
    """Spec 3.4: write_policy ownership model.

    Default 'owner_only' — only the creator (or admin) may edit; everyone else
    with folder access is read-only. 'shared' — anyone with folder write_acl may
    edit. Enforced server-side on update, independent of DEK possession.
    """

    def _setup_two_users_one_folder(self, storage):
        """alice (001) + bob (002), both granted write_acl on the same folder."""
        sk_a, _ = _create_regular_user(storage, "USER0000000000000000000001", "alice")
        sk_b, _ = _create_regular_user(storage, "USER0000000000000000000002", "bob")
        # TL7: a shared folder is an admin's, not a member's personal root.
        _create_admin_user(storage, "ADMIN000000000000000000002", "orgadmin")
        parent = "FOLDER00000000000000000001"
        now_ms = int(time.time() * 1000)
        storage["vault_objects"].append({
            "id": parent, "object_type": "node", "payload": b"folder",
            "owner_id": "ADMIN000000000000000000002", "write_policy": "owner_only",
            "target_user_id": None, "parent_ref": None, "access_level": None,
            "version": 1, "commit_seq": 1, "is_deleted": 0,
            "payload_hash": hashlib.sha256(b"folder").hexdigest(),
            "client_signature": b"x" * 64, "modified_at": now_ms,
        })
        for uid in ("USER0000000000000000000001", "USER0000000000000000000002"):
            storage["write_acl"].append(
                {"user_id": uid, "node_id": parent, "granted_at": now_ms}
            )
        token_a = _create_jwt("USER0000000000000000000001", "alice", False)
        token_b = _create_jwt("USER0000000000000000000002", "bob", False)
        return sk_a, token_a, sk_b, token_b, parent

    @pytest.mark.asyncio
    async def test_owner_only_default_persisted(self, app_client, mock_db):
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYOWNER0000000000000001"
        resp = await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"secret v1")
        assert len(resp.json()["accepted"]) == 1
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id][0]
        assert stored["owner_id"] == "USER0000000000000000000002"
        assert stored["write_policy"] == "owner_only"

    @pytest.mark.asyncio
    async def test_owner_can_edit_own_entry(self, app_client, mock_db):
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYOWNER0000000000000002"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"secret v1")
        resp = await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 2, b"secret v2")
        data = resp.json()
        assert len(data["accepted"]) == 1
        assert len(data["conflicts"]) == 0

    @pytest.mark.asyncio
    async def test_non_owner_cannot_edit_owner_only_entry(self, app_client, mock_db):
        """The core rule: alice has folder write_acl but is NOT the owner —
        she must NOT be able to edit bob's owner_only entry."""
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYOWNER0000000000000003"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"bob secret")
        resp = await _push_object(app_client, token_a, sk_a, obj_id, "entry", parent, 2, b"alice edit")
        data = resp.json()
        assert len(data["accepted"]) == 0
        assert len(data["conflicts"]) == 1
        assert "not owner" in data["conflicts"][0]["error"]
        # Stored payload must be unchanged (still v1, bob's)
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id][0]
        assert stored["version"] == 1

    @pytest.mark.asyncio
    async def test_non_owner_can_edit_shared_entry(self, app_client, mock_db):
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYSHARED000000000000001"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"team v1",
                           write_policy="shared")
        resp = await _push_object(app_client, token_a, sk_a, obj_id, "entry", parent, 2, b"team v2",
                                  write_policy="shared")
        data = resp.json()
        assert len(data["accepted"]) == 1
        assert len(data["conflicts"]) == 0

    @pytest.mark.asyncio
    async def test_admin_can_edit_owner_only_entry(self, app_client, mock_db):
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        sk_admin, _ = _create_admin_user(mock_db._storage)
        token_admin = _create_jwt("ADMIN000000000000000000001", "admin", True)
        obj_id = "ENTRYOWNER0000000000000004"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"bob secret")
        resp = await _push_object(app_client, token_admin, sk_admin, obj_id, "entry", parent, 2, b"admin edit")
        data = resp.json()
        assert len(data["accepted"]) == 1
        assert len(data["conflicts"]) == 0

    @pytest.mark.asyncio
    async def test_non_owner_cannot_flip_shared_to_owner_only(self, app_client, mock_db):
        """A non-owner editing a shared entry must not be able to change the
        policy (which would lock out the real owner)."""
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYSHARED000000000000002"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"team v1",
                           write_policy="shared")
        # alice edits and tries to set owner_only
        resp = await _push_object(app_client, token_a, sk_a, obj_id, "entry", parent, 2, b"team v2",
                                  write_policy="owner_only")
        assert len(resp.json()["accepted"]) == 1
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id][0]
        assert stored["write_policy"] == "shared"  # policy preserved

    @pytest.mark.asyncio
    async def test_owner_edit_without_policy_preserves_shared(self, app_client, mock_db):
        """Regression: owner re-saving a 'shared' entry WITHOUT sending
        write_policy (as desktop/mobile do) must NOT reset it to owner_only."""
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYSHARED000000000000003"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"team v1",
                           write_policy="shared")
        # Owner edits again but OMITS write_policy (desktop/mobile behaviour)
        resp = await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 2, b"team v2",
                                  write_policy=None)
        assert len(resp.json()["accepted"]) == 1
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id][0]
        assert stored["write_policy"] == "shared"  # preserved, not clobbered

    @pytest.mark.asyncio
    async def test_admin_edit_without_policy_preserves_shared(self, app_client, mock_db):
        """Regression: admin (desktop) re-saving a 'shared' entry WITHOUT sending
        write_policy must preserve it, not clobber to owner_only."""
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        sk_admin, _ = _create_admin_user(mock_db._storage)
        token_admin = _create_jwt("ADMIN000000000000000000001", "admin", True)
        obj_id = "ENTRYSHARED000000000000004"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"team v1",
                           write_policy="shared")
        resp = await _push_object(app_client, token_admin, sk_admin, obj_id, "entry", parent, 2,
                                  b"admin edit", write_policy=None)
        assert len(resp.json()["accepted"]) == 1
        stored = [o for o in mock_db._storage["vault_objects"] if o["id"] == obj_id][0]
        assert stored["write_policy"] == "shared"

    @pytest.mark.asyncio
    async def test_pull_exposes_write_policy(self, app_client, mock_db):
        sk_a, token_a, sk_b, token_b, parent = self._setup_two_users_one_folder(mock_db._storage)
        obj_id = "ENTRYOWNER0000000000000005"
        await _push_object(app_client, token_b, sk_b, obj_id, "entry", parent, 1, b"bob secret")
        resp = await app_client.get(
            "/api/sync?since_commit_seq=0",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        objs = {o["id"]: o for o in resp.json()["objects"]}
        assert objs[obj_id]["write_policy"] == "owner_only"
        assert objs[obj_id]["owner_id"] == "USER0000000000000000000002"


# =====================================================================
# INTEGRATION: Full auth flow
# =====================================================================

class TestFullAuthFlow:
    """End-to-end integration test of the complete auth flow."""

    @pytest.mark.asyncio
    async def test_full_challenge_verify_logout_flow(self, app_client, mock_db):
        """Full flow: challenge -> verify -> use token -> logout -> token rejected."""
        sk, _ = _create_admin_user(mock_db._storage)
        token = await _do_challenge_verify(app_client, mock_db._storage, sk, "admin")

        # Use token successfully
        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Logout
        await app_client.post(
            "/api/auth/logout",
            json={"token": token},
            headers={"Authorization": f"Bearer {token}"},
        )

        # Token should now be rejected
        resp = await app_client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_full_invite_register_approve_flow(self, app_client, mock_db):
        """Full flow: admin invites -> user registers -> uploads keypair -> admin approves."""
        _create_admin_user(mock_db._storage)
        admin_token = _create_jwt("ADMIN000000000000000000001", "admin", True)

        # 1. Admin creates invitation
        resp = await app_client.post(
            "/api/users/invite",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        inv_token = resp.json()["invitation_token"]

        # 2. New user registers
        new_sk, new_pk = _make_ed25519_keypair()
        enc_sk, enc_pk = _make_ed25519_keypair()
        resp = await app_client.post("/api/users/register", json={
            "invitation_token": inv_token,
            "username": "new_employee",
            "signing_pk": new_pk.hex(),
            "encryption_pk": enc_pk.hex(),
        })
        assert resp.status_code == 200
        user_id = resp.json()["user_id"]
        onboarding_token = resp.json()["token"]

        # Verify user is pending
        users = [u for u in mock_db._storage["users"] if u["id"] == user_id]
        assert users[0]["status"] == "pending"

        # 3. User uploads keypair with onboarding token
        resp = await app_client.put("/api/me/keypair", json={
            "encrypted_keypair": os.urandom(64).hex(),
            "argon2_salt": os.urandom(16).hex(),
            "auth_salt": os.urandom(16).hex(),
            "auth_proof": os.urandom(32).hex(),
            "argon2_params": {"time_cost": 3, "memory_cost": 131072, "parallelism": 4},
        }, headers={"Authorization": f"Bearer {onboarding_token}"})
        assert resp.status_code == 200

        # 4. Admin approves
        resp = await app_client.patch(
            f"/api/users/{user_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200

        # Verify user is now active
        users = [u for u in mock_db._storage["users"] if u["id"] == user_id]
        assert users[0]["status"] == "active"
