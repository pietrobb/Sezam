"""Follow-up review 2052248, server medium findings (R-G)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os

import pytest

from server.app.models.schemas import DEFAULT_ACCOUNT_KDF
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    MockCursor,
    _create_admin_user,
    _create_jwt,
    _create_regular_user,
    app_client,
    mock_db,
)

DESKTOP_KDF = {"time_cost": 3, "memory_cost": 262_144, "parallelism": 4, "hash_len": 64}
CLIENT_KDFS = [DEFAULT_ACCOUNT_KDF, DESKTOP_KDF]


def _with_proof(user_row: dict) -> None:
    verify_salt = os.urandom(32)
    user_row["verify_salt"] = verify_salt
    user_row["auth_proof_hash"] = hmac.new(
        verify_salt, os.urandom(32), hashlib.sha256
    ).hexdigest()


async def _recover_statuses(app_client, username: str, attempts: int) -> list[int]:
    statuses = []
    for _ in range(attempts):
        resp = await app_client.post("/api/auth/recover", json={
            "username": username, "auth_proof": os.urandom(32).hex(),
        })
        statuses.append(resp.status_code)
    return statuses


@pytest.mark.asyncio
async def test_recovery_of_unknown_name_escalates_like_a_real_account(app_client, mock_db):
    """A real account went 401 → 429 (→ 423) while an unknown name stayed 401."""
    _create_admin_user(mock_db._storage)
    _with_proof(mock_db._storage["users"][0])

    real = await _recover_statuses(app_client, "admin", 5)
    ghost = await _recover_statuses(app_client, "ghost", 5)
    assert real == [401, 401, 401, 401, 401]  # lockout review #7: no per-name 3/h
    assert ghost == real


@pytest.mark.asyncio
async def test_recovery_of_account_without_key_material_matches_real_one(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    _with_proof(mock_db._storage["users"][0])
    _create_regular_user(mock_db._storage, username="pending")  # no verify_salt

    assert await _recover_statuses(app_client, "pending", 5) == await _recover_statuses(
        app_client, "admin", 5
    )


@pytest.mark.asyncio
async def test_recovery_lock_of_unknown_name_matches_real_account(app_client, mock_db):
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    _with_proof(row)
    row.update(recovery_attempts=9, recovery_attempts_hour=0, last_recovery_attempt=None)
    # Review 688edcb V2: a locked name verifies one proof per window (429 after).
    assert await _recover_statuses(app_client, "admin", 2) == [423, 429]

    await _recover_statuses(app_client, "ghost", 1)
    shadow = mock_db._storage["recovery_name_limits"][0]
    shadow.update(recovery_attempts=9, recovery_attempts_hour=0, last_recovery_attempt=None)
    assert await _recover_statuses(app_client, "ghost", 2) == [423, 429]
    # Only a MAC of the probed name is stored, never the name.
    assert "ghost" not in json.dumps(mock_db._storage["recovery_name_limits"])


@pytest.mark.asyncio
async def test_meta_kdf_params_of_unknown_names_look_like_real_accounts(app_client, mock_db):
    """Every desktop account has non-default params; a fixed default for
    unknown names told them apart."""
    _create_admin_user(mock_db._storage)
    row = mock_db._storage["users"][0]
    row["argon2_salt"] = os.urandom(16)
    row["argon2_params"] = json.dumps(DESKTOP_KDF, sort_keys=True)

    real = (await app_client.get("/api/meta", params={"username": "admin"})).json()
    assert real["argon2_params"] == DESKTOP_KDF

    seen = []
    for i in range(40):
        resp = await app_client.get("/api/meta", params={"username": f"nobody{i}"})
        seen.append(resp.json()["argon2_params"])
    assert DESKTOP_KDF in seen
    assert all(params in CLIENT_KDFS for params in seen)
    # Stable per name, like a real account.
    again = await app_client.get("/api/meta", params={"username": "nobody0"})
    assert again.json()["argon2_params"] == seen[0]


@pytest.mark.asyncio
async def test_audit_csv_export_survives_an_extreme_timestamp(app_client, mock_db, monkeypatch):
    _create_admin_user(mock_db._storage)
    admin_id = mock_db._storage["users"][0]["id"]
    token = _create_jwt(admin_id, "admin", True)
    audit = mock_db._storage.setdefault("server_audit", [])
    for i, ts in enumerate((1_700_000_000_000, 10**15)):
        audit.append({
            "id": f"AUD0000000000000000000000{i}", "user_id": admin_id,
            "action": "push", "timestamp": ts, "request_hash": None,
            "commit_seq_range": None, "client_signature": b"\x00" * 64, "client_ip": None,
        })
    original = MockCursor.execute

    async def with_join(self, query, args=()):
        await original(self, query, args)
        if "FROM server_audit sa" in query:  # the mock has no JOIN
            self._results = [
                (r["id"], r["user_id"], "admin", r["action"], r["timestamp"],
                 r["request_hash"], r["commit_seq_range"], r["client_ip"])
                for r in audit
            ]

    monkeypatch.setattr(MockCursor, "execute", with_join)
    resp = await app_client.get(
        "/api/audit/csv", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert "2023-11-14 22:13:20" in resp.text
    assert f"{10**15} ms" in resp.text


@pytest.mark.asyncio
async def test_unknown_share_ids_cost_argon2_only_within_the_ip_limit(
    app_client, mock_db, monkeypatch
):
    """A nonexistent share ran a dummy Argon2 (~64 MiB) on every request with
    no limit: an anonymous CPU/memory DoS."""
    from server.app.routers import share

    runs = []
    monkeypatch.setattr(share, "_run_dummy_pin_check", lambda pin: runs.append(pin))
    monkeypatch.setattr(share, "_SHARE_ERROR_MIN_SECONDS", 0)
    for i in range(8):
        resp = await app_client.post(f"/api/share/missing-{i}", json={"pin": "1234"})
        assert resp.status_code == 404
    assert len(runs) == share._PIN_MAX_PER_IP


@pytest.mark.parametrize("field,value", [
    ("id", "0" * 26 + "EXTRA"),            # VARCHAR(26): was stored truncated
    ("id", "not-a-ulid"),
    ("parent_ref", "P" * 40),
    ("target_user_id", "U" * 27),
    ("version", 2**31),                    # INTEGER: was clamped
])
def test_push_object_fields_that_would_be_truncated_are_rejected(field, value):
    from pydantic import ValidationError

    from server.app.models.schemas import SyncObject

    good = {
        "id": "01J0000000000000000000000A", "object_type": "entry", "payload": "AA==",
        "version": 1, "payload_hash": "0" * 64, "signature": "0" * 128,
    }
    SyncObject(**good)
    with pytest.raises(ValidationError):
        SyncObject(**{**good, field: value})


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/s/abc", "/api/shares", "/api/share/missing"])
async def test_share_pages_cannot_be_framed(app_client, path):
    """Review 2052248: the share CSP had no frame-ancestors (clickjacking)."""
    resp = await app_client.get(path)
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]

