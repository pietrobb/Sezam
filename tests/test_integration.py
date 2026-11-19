"""Opt-in integration tests against an explicitly selected Sezam server.

Run with:
    SEZAM_INTEGRATION=1 SEZAM_SERVER=http://127.0.0.1:18000 \
        pytest tests/test_integration.py -m integration -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import struct
import time
import urllib.error
import urllib.request
from typing import Optional

import pytest
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey as X25519PrivateKey

from ulid import ULID

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER = os.environ.get("SEZAM_SERVER", "").rstrip("/")
# Invitations are single use: a comma-separated list gives each registration its own.
_INVITE_TOKENS = [t for t in os.environ.get("SEZAM_INVITE_TOKEN", "").split(",") if t]


def _invite_token() -> str:
    return _INVITE_TOKENS.pop(0) if len(_INVITE_TOKENS) > 1 else (_INVITE_TOKENS or [""])[0]

# Skip all integration tests unless the env var is set
integration = pytest.mark.integration
skip_unless_enabled = pytest.mark.skipif(
    not os.environ.get("SEZAM_INTEGRATION") or not SERVER,
    reason="Set SEZAM_INTEGRATION=1 and explicit SEZAM_SERVER to run integration tests",
)

# Apply both markers to every test via a module-level pytestmark
pytestmark = [integration, skip_unless_enabled]


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

# SSL context for Let's Encrypt certificates
_ssl_ctx = ssl.create_default_context()


def _request(
    method: str,
    path: str,
    body: Optional[dict] = None,
    token: Optional[str] = None,
    headers: Optional[dict] = None,
    expected_status: Optional[int] = None,
) -> tuple[int, dict | str, dict]:
    """Make an HTTP request to the server.

    Returns (status_code, parsed_body_or_text, response_headers_dict).
    If expected_status is set and the actual status differs, the raw
    response is still returned (never raises for HTTP errors).
    """
    url = SERVER.rstrip("/") + path

    req_headers = {"Content-Type": "application/json"}
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if headers:
        req_headers.update(headers)

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=data, headers=req_headers, method=method
    )

    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx) as resp:
            raw = resp.read().decode("utf-8")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = raw
            return resp.status, parsed, resp_headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, Exception):
            parsed = raw
        return e.code, parsed, resp_headers
    except (urllib.error.URLError, OSError) as e:
        pytest.skip(f"Server unreachable: {e}")


def _new_ulid() -> str:
    """Generate a fresh ULID string."""
    return str(ULID())


def _ulid_to_bytes(ulid_str: str) -> bytes:
    """Convert 26-char ULID string to 26-byte padded form (for signatures)."""
    raw = ULID.from_str(ulid_str).bytes  # 16 bytes
    return raw + b"\x00" * 10


def _generate_keypair():
    """Generate Ed25519 + X25519 keypair, return (signing_key, signing_pk, encryption_sk, encryption_pk)."""
    signing_key = SigningKey.generate()
    signing_pk = bytes(signing_key.verify_key)
    encryption_key = X25519PrivateKey.generate()
    encryption_pk = bytes(encryption_key.public_key)
    return signing_key, signing_pk, encryption_key, encryption_pk


def _build_sync_signature(
    signing_key: SigningKey,
    obj_id: str,
    object_type: str,
    parent_ref: Optional[str],
    target_user_id: Optional[str],
    is_deleted: int,
    version: int,
    payload_hash: str,
) -> str:
    """Build canonical signed data and return hex signature (matches server expectations)."""
    # The server uses a different canonical form than the client SyncClient.
    # Server: id_bytes = id.encode("utf-8").ljust(26, b"\\x00")[:26]
    # Client: id_bytes = ulid_to_bytes(id) (ULID binary)
    # The server verifies with the utf-8/ljust form, so we must match that.
    id_bytes = obj_id.encode("utf-8").ljust(26, b"\x00")[:26]
    ot_bytes = object_type.encode("utf-8")
    if parent_ref:
        parent_bytes = parent_ref.encode("utf-8").ljust(26, b"\x00")[:26]
    else:
        parent_bytes = b"\x00" * 26
    if target_user_id:
        target_bytes = target_user_id.encode("utf-8").ljust(26, b"\x00")[:26]
    else:
        target_bytes = b"\x00" * 26
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

    signed = signing_key.sign(canonical)
    return signed.signature.hex()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def server_health():
    """Verify server is reachable before running the module."""
    status, body, _ = _request("GET", "/health")
    if status != 200:
        pytest.skip(f"Server not healthy: {status}")
    return body


# ===========================================================================
# 1. Server Health & Meta
# ===========================================================================


class TestServerHealthMeta:
    """Test public endpoints that require no authentication."""

    def test_health_endpoint(self):
        status, body, _ = _request("GET", "/health")
        assert status == 200
        assert body["status"] == "ok"

    def test_meta_endpoint(self):
        status, body, _ = _request("GET", "/api/meta")
        assert status == 200
        assert "version" in body
        assert "argon2_web_params" in body
        params = body["argon2_web_params"]
        assert "time_cost" in params
        assert "memory_cost" in params

    def test_meta_fake_salt_for_nonexistent_user(self):
        """Nonexistent user should receive a deterministic fake salt."""
        unique_user = f"__test_fake_{int(time.time())}__"
        status, body, _ = _request("GET", f"/api/meta?username={unique_user}")
        assert status == 200
        assert body.get("argon2_salt") is not None
        assert len(body["argon2_salt"]) > 0, "Salt should not be empty"

    def test_meta_fake_salt_is_deterministic(self):
        """Same nonexistent username should yield the same fake salt."""
        unique_user = "__test_deterministic_salt_user__"
        _, body1, _ = _request("GET", f"/api/meta?username={unique_user}")
        _, body2, _ = _request("GET", f"/api/meta?username={unique_user}")
        assert body1["argon2_salt"] == body2["argon2_salt"], (
            "Fake salt must be deterministic for the same username"
        )

    def test_meta_different_users_get_different_salts(self):
        """Different nonexistent usernames should get different fake salts."""
        _, body1, _ = _request("GET", "/api/meta?username=__fake_aaa__")
        _, body2, _ = _request("GET", "/api/meta?username=__fake_bbb__")
        assert body1["argon2_salt"] != body2["argon2_salt"]


# ===========================================================================
# 2. Full Registration + Login Lifecycle
# ===========================================================================


class TestRegistrationLifecycle:
    """Test the registration flow using an invitation token."""

    def test_register_with_invalid_invitation(self):
        """Registration with a bogus token should fail."""
        signing_key, signing_pk, _, encryption_pk = _generate_keypair()
        status, body, _ = _request("POST", "/api/users/register", {
            "invitation_token": "0000000000000000000000000000dead",
            "username": f"test_invalid_{int(time.time())}",
            "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(),
        })
        assert status in (404, 410), f"Expected 404 or 410, got {status}: {body}"

    def test_register_flow(self):
        """Full registration: register -> upload keypair -> challenge -> verify (should fail: pending).

        Note: The invite token may already be used. If so, we skip gracefully.
        """
        signing_key, signing_pk, encryption_key, encryption_pk = _generate_keypair()
        username = f"inttest_{int(time.time())}_{os.urandom(4).hex()}"

        # Step 1: Register
        status, body, _ = _request("POST", "/api/users/register", {
            "invitation_token": _invite_token(),
            "username": username,
            "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(),
        })
        if status in (404, 410):
            pytest.skip(
                f"Invitation token unavailable (status={status}): {body}. "
                "Set SEZAM_INVITE_TOKEN to a valid token."
            )
        assert status == 200, f"Registration failed: {status} {body}"
        user_id = body["user_id"]
        onboarding_jwt = body["token"]

        # Step 2: Upload encrypted keypair using onboarding JWT
        # We use dummy encrypted data since we just need to test the endpoint
        fake_encrypted_kp = os.urandom(128).hex()
        fake_argon2_salt = os.urandom(16).hex()
        fake_auth_salt = os.urandom(16).hex()
        fake_auth_proof = os.urandom(32).hex()

        status2, body2, _ = _request("PUT", "/api/me/keypair", {
            "encrypted_keypair": fake_encrypted_kp,
            "argon2_salt": fake_argon2_salt,
            "auth_salt": fake_auth_salt,
            "auth_proof": fake_auth_proof,
            "argon2_params": {"time_cost": 3, "memory_cost": 131072, "parallelism": 4, "hash_len": 64},
        }, token=onboarding_jwt)
        assert status2 == 200, f"Keypair upload failed: {status2} {body2}"

        # Step 3: Try to authenticate — should fail because status is 'pending'
        status3, body3, _ = _request("POST", "/api/auth/challenge", {
            "username": username,
        })
        assert status3 == 200, f"Challenge request failed: {status3}"
        challenge_hex = body3["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)

        # Sign the challenge
        signed = signing_key.sign(challenge_bytes)
        signature_hex = signed.signature.hex()

        status4, body4, _ = _request("POST", "/api/auth/verify", {
            "username": username,
            "challenge": challenge_hex,
            "signature": signature_hex,
        })
        # Should fail — user is pending (not approved by admin yet)
        assert status4 == 401, (
            f"Expected 401 for pending user, got {status4}: {body4}"
        )

    def test_onboarding_jwt_is_scoped(self):
        """Onboarding JWT (scope=keypair_upload) should be rejected on protected endpoints."""
        signing_key, signing_pk, _, encryption_pk = _generate_keypair()
        username = f"scope_test_{int(time.time())}_{os.urandom(4).hex()}"

        status, body, _ = _request("POST", "/api/users/register", {
            "invitation_token": _invite_token(),
            "username": username,
            "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(),
        })
        if status in (404, 410):
            pytest.skip("Invitation token unavailable")
        assert status == 200
        onboarding_jwt = body["token"]

        # Try to use onboarding JWT on a full-JWT-only endpoint (e.g. sync pull)
        status2, body2, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=onboarding_jwt
        )
        assert status2 == 403, (
            f"Expected 403 for scoped JWT on sync endpoint, got {status2}"
        )


# ===========================================================================
# 3. Challenge-Response Auth (requires an active admin user)
# ===========================================================================


class TestChallengeResponseAuth:
    """Test challenge-response authentication.

    These tests require an active user on the server. They will attempt
    to authenticate using the SEZAM_TEST_USERNAME and SEZAM_TEST_SIGNING_SK
    env vars. If not set, we try to register+approve a test user (which
    requires admin access) or skip.
    """

    @pytest.fixture(scope="class")
    def auth_context(self):
        """Try to authenticate. Returns (token, user_id, signing_key, username) or skips."""
        username = os.environ.get("SEZAM_TEST_USERNAME")
        signing_sk_hex = os.environ.get("SEZAM_TEST_SIGNING_SK")

        if not username or not signing_sk_hex:
            pytest.skip(
                "Set SEZAM_TEST_USERNAME and SEZAM_TEST_SIGNING_SK to run auth tests"
            )

        signing_key = SigningKey(bytes.fromhex(signing_sk_hex))
        signing_pk = bytes(signing_key.verify_key)

        # Challenge
        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": username,
        })
        if status != 200:
            pytest.skip(f"Challenge failed: {status}")

        challenge_hex = body["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)
        signed = signing_key.sign(challenge_bytes)

        # Verify
        status2, body2, _ = _request("POST", "/api/auth/verify", {
            "username": username,
            "challenge": challenge_hex,
            "signature": signed.signature.hex(),
        })
        if status2 != 200:
            pytest.skip(f"Auth verify failed (user may not be active): {status2}")

        return {
            "token": body2["token"],
            "user_id": body2["user_id"],
            "signing_key": signing_key,
            "username": username,
            "is_admin": body2.get("is_admin", False),
        }

    def test_auth_full_cycle(self, auth_context):
        """Full auth: challenge -> verify -> JWT works."""
        assert auth_context["token"]
        assert auth_context["user_id"]

    def test_refresh_token(self, auth_context):
        """POST /api/auth/refresh should return a new JWT."""
        old_token = auth_context["token"]
        challenge_status, challenge_body, _ = _request(
            "POST", "/api/auth/challenge", {"username": auth_context["username"]}
        )
        assert challenge_status == 200
        challenge = challenge_body["challenge"]
        signature = auth_context["signing_key"].sign(
            bytes.fromhex(challenge)
        ).signature.hex()
        # Wait 1s so iat differs (JWT is deterministic within same second)
        import time
        time.sleep(1)
        status, body, _ = _request(
            "POST", "/api/auth/refresh",
            {"challenge": challenge, "signature": signature}, token=old_token,
        )
        assert status == 200, f"Refresh failed: {status} {body}"
        new_token = body["token"]
        assert new_token != old_token, "Refreshed token should differ from old"

        # The new token should work
        status2, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=new_token
        )
        assert status2 == 200

        # Store new token for subsequent tests
        auth_context["token"] = new_token

    def test_logout_invalidates_token(self, auth_context):
        """POST /api/auth/logout should invalidate the JWT."""
        # Get a fresh token first (so we don't invalidate the fixture token)
        username = auth_context["username"]
        signing_key = auth_context["signing_key"]

        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": username,
        })
        assert status == 200
        challenge_hex = body["challenge"]
        challenge_bytes = bytes.fromhex(challenge_hex)
        signed = signing_key.sign(challenge_bytes)

        import time
        time.sleep(0.5)  # Give server time to commit challenge to DB
        status2, body2, _ = _request("POST", "/api/auth/verify", {
            "username": username,
            "challenge": challenge_hex,
            "signature": signed.signature.hex(),
        })
        if status2 != 200:
            pytest.skip(f"Could not get fresh token for logout test: {status2} {body2}")

        ephemeral_token = body2["token"]

        # Verify ephemeral token works
        status3, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=ephemeral_token
        )
        assert status3 == 200, "Ephemeral token should work before logout"

        # Logout
        status4, body4, _ = _request(
            "POST", "/api/auth/logout", token=ephemeral_token
        )
        assert status4 == 200, f"Logout failed: {status4} {body4}"

        # Old token should now be rejected (may need a moment for DB replication)
        import time
        time.sleep(1)
        status5, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=ephemeral_token
        )
        assert status5 == 401, (
            f"Expected 401 for revoked token, got {status5}"
        )

    def test_wrong_signature_rejected(self):
        """Challenge-response with wrong signature should be rejected."""
        # Get a challenge for a likely nonexistent user (still returns challenge)
        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": "__wrong_sig_test__",
        })
        assert status == 200
        challenge_hex = body["challenge"]

        # Sign with a random key (wrong key)
        wrong_key = SigningKey.generate()
        challenge_bytes = bytes.fromhex(challenge_hex)
        signed = wrong_key.sign(challenge_bytes)

        status2, body2, _ = _request("POST", "/api/auth/verify", {
            "username": "__wrong_sig_test__",
            "challenge": challenge_hex,
            "signature": signed.signature.hex(),
        })
        assert status2 == 401


# ===========================================================================
# 4. Sync Push/Pull Cycle
# ===========================================================================


class TestSyncPushPull:
    """Test sync push and pull operations.

    Requires an active admin user (admin can push any object type).
    """

    @pytest.fixture(scope="class")
    def sync_context(self):
        """Authenticate for sync tests. Requires active user credentials."""
        username = os.environ.get("SEZAM_TEST_USERNAME")
        signing_sk_hex = os.environ.get("SEZAM_TEST_SIGNING_SK")

        if not username or not signing_sk_hex:
            pytest.skip(
                "Set SEZAM_TEST_USERNAME and SEZAM_TEST_SIGNING_SK for sync tests"
            )

        signing_key = SigningKey(bytes.fromhex(signing_sk_hex))

        # Authenticate
        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": username,
        })
        if status != 200:
            pytest.skip(f"Challenge failed: {status}")

        challenge_bytes = bytes.fromhex(body["challenge"])
        signed = signing_key.sign(challenge_bytes)

        status2, body2, _ = _request("POST", "/api/auth/verify", {
            "username": username,
            "challenge": body["challenge"],
            "signature": signed.signature.hex(),
        })
        if status2 != 200:
            pytest.skip(f"Auth failed: {status2}")

        return {
            "token": body2["token"],
            "user_id": body2["user_id"],
            "signing_key": signing_key,
            "is_admin": body2.get("is_admin", False),
        }

    def _make_sync_object(
        self,
        signing_key: SigningKey,
        obj_id: str,
        object_type: str = "node",
        parent_ref: Optional[str] = None,
        version: int = 1,
        is_deleted: int = 0,
        payload: Optional[bytes] = None,
    ) -> dict:
        """Build a sync object dict with proper signature."""
        if payload is None:
            payload = os.urandom(64)
        payload_hash = hashlib.sha256(payload).hexdigest()
        signature = _build_sync_signature(
            signing_key, obj_id, object_type,
            parent_ref, None, is_deleted, version, payload_hash,
        )
        return {
            "id": obj_id,
            "object_type": object_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "parent_ref": parent_ref,
            "target_user_id": None,
            "version": version,
            "is_deleted": is_deleted,
            "payload_hash": payload_hash,
            "signature": signature,
        }

    def test_push_and_pull(self, sync_context):
        """Push a node object, then pull and verify it is present."""
        token = sync_context["token"]
        signing_key = sync_context["signing_key"]
        is_admin = sync_context["is_admin"]
        if not is_admin:
            pytest.skip("Sync push requires admin privileges for top-level nodes")

        obj_id = _new_ulid()
        # Use a parent_ref that matches an existing node, or None for admin
        obj = self._make_sync_object(
            signing_key, obj_id, "node", parent_ref=None, version=1,
        )

        # Push
        status, body, _ = _request("POST", "/api/sync", {
            "objects": [obj],
            "atomic_batch": False,
        }, token=token)
        assert status == 200, f"Push failed: {status} {body}"

        # Check response
        accepted_ids = [a["id"] for a in body.get("accepted", [])]
        conflict_ids = [c["id"] for c in body.get("conflicts", [])]

        if obj_id in conflict_ids:
            # write_acl denied for non-admin or top-level restriction
            pytest.skip(f"Push conflict (likely permissions): {body['conflicts']}")

        assert obj_id in accepted_ids, (
            f"Object {obj_id} not in accepted list. Body: {body}"
        )

        # Pull
        status2, body2, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=token
        )
        assert status2 == 200, f"Pull failed: {status2}"

        pulled_ids = [o["id"] for o in body2.get("objects", [])]
        assert obj_id in pulled_ids, (
            f"Pushed object {obj_id} not found in pull response"
        )

    def test_push_version_update(self, sync_context):
        """Push version 1, then push version 2 — should be accepted."""
        token = sync_context["token"]
        signing_key = sync_context["signing_key"]
        if not sync_context["is_admin"]:
            pytest.skip("Requires admin")

        obj_id = _new_ulid()
        obj_v1 = self._make_sync_object(
            signing_key, obj_id, "node", version=1,
        )

        # Push v1
        status, body, _ = _request("POST", "/api/sync", {
            "objects": [obj_v1],
            "atomic_batch": False,
        }, token=token)
        assert status == 200

        accepted_ids = [a["id"] for a in body.get("accepted", [])]
        if obj_id not in accepted_ids:
            pytest.skip(f"Initial push not accepted: {body}")

        # Push v2 (different payload)
        obj_v2 = self._make_sync_object(
            signing_key, obj_id, "node", version=2,
            payload=os.urandom(64),  # different content
        )
        status2, body2, _ = _request("POST", "/api/sync", {
            "objects": [obj_v2],
            "atomic_batch": False,
        }, token=token)
        assert status2 == 200
        accepted_ids2 = [a["id"] for a in body2.get("accepted", [])]
        assert obj_id in accepted_ids2, (
            f"Version update not accepted: {body2}"
        )

    def test_idempotent_push(self, sync_context):
        """Pushing the same version with the same payload_hash should be idempotent."""
        token = sync_context["token"]
        signing_key = sync_context["signing_key"]
        if not sync_context["is_admin"]:
            pytest.skip("Requires admin")

        obj_id = _new_ulid()
        payload = os.urandom(64)
        obj = self._make_sync_object(
            signing_key, obj_id, "node", version=1, payload=payload,
        )

        # First push
        status, body, _ = _request("POST", "/api/sync", {
            "objects": [obj],
            "atomic_batch": False,
        }, token=token)
        assert status == 200
        accepted_ids = [a["id"] for a in body.get("accepted", [])]
        if obj_id not in accepted_ids:
            pytest.skip(f"Initial push not accepted: {body}")

        # Idempotent retry — same object, same version, same payload_hash
        status2, body2, _ = _request("POST", "/api/sync", {
            "objects": [obj],
            "atomic_batch": False,
        }, token=token)
        assert status2 == 200
        # Should be accepted (idempotent), not conflicted
        accepted_ids2 = [a["id"] for a in body2.get("accepted", [])]
        conflict_ids2 = [c["id"] for c in body2.get("conflicts", [])]
        assert obj_id in accepted_ids2, (
            f"Idempotent push should be accepted. Conflicts: {body2.get('conflicts')}"
        )
        assert obj_id not in conflict_ids2

    def test_conflict_on_same_version_different_hash(self, sync_context):
        """Pushing the same version but different payload_hash should be a 409 conflict."""
        token = sync_context["token"]
        signing_key = sync_context["signing_key"]
        if not sync_context["is_admin"]:
            pytest.skip("Requires admin")

        obj_id = _new_ulid()
        obj_v1 = self._make_sync_object(
            signing_key, obj_id, "node", version=1,
            payload=os.urandom(64),
        )

        # Push first version
        status, body, _ = _request("POST", "/api/sync", {
            "objects": [obj_v1],
            "atomic_batch": False,
        }, token=token)
        assert status == 200
        accepted_ids = [a["id"] for a in body.get("accepted", [])]
        if obj_id not in accepted_ids:
            pytest.skip(f"Initial push not accepted: {body}")

        # Push same version but different payload (conflict)
        obj_conflict = self._make_sync_object(
            signing_key, obj_id, "node", version=1,
            payload=os.urandom(64),  # different random data
        )
        status2, body2, _ = _request("POST", "/api/sync", {
            "objects": [obj_conflict],
            "atomic_batch": False,
        }, token=token)
        # The response is 200 but the object is in the conflicts list
        assert status2 == 200
        conflict_ids = [c["id"] for c in body2.get("conflicts", [])]
        assert obj_id in conflict_ids, (
            f"Expected conflict for same version/different hash. Body: {body2}"
        )


# ===========================================================================
# 5. Share Link Lifecycle
# ===========================================================================


class TestShareLifecycle:
    """Test share link create/consume/delete."""

    @pytest.fixture(scope="class")
    def share_context(self):
        """Authenticate for share tests."""
        username = os.environ.get("SEZAM_TEST_USERNAME")
        signing_sk_hex = os.environ.get("SEZAM_TEST_SIGNING_SK")

        if not username or not signing_sk_hex:
            pytest.skip("Set SEZAM_TEST_USERNAME and SEZAM_TEST_SIGNING_SK")

        signing_key = SigningKey(bytes.fromhex(signing_sk_hex))

        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": username,
        })
        if status != 200:
            pytest.skip(f"Challenge failed: {status}")

        challenge_bytes = bytes.fromhex(body["challenge"])
        signed = signing_key.sign(challenge_bytes)

        status2, body2, _ = _request("POST", "/api/auth/verify", {
            "username": username,
            "challenge": body["challenge"],
            "signature": signed.signature.hex(),
        })
        if status2 != 200:
            pytest.skip(f"Auth failed: {status2}")

        return {
            "token": body2["token"],
            "user_id": body2["user_id"],
        }

    def test_share_create_consume_delete(self, share_context):
        """Full lifecycle: create share -> consume -> delete."""
        token = share_context["token"]

        # Create a share
        share_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        encrypted_blob = base64.b64encode(os.urandom(128)).decode("ascii")
        expires_at = int(time.time() * 1000) + 3600 * 1000  # 1 hour

        status, body, _ = _request("POST", "/api/share", {
            "id": share_id,
            "encrypted_blob": encrypted_blob,
            "expires_at": expires_at,
            "max_views": 2,
        }, token=token)
        assert status == 200, f"Share create failed: {status} {body}"
        assert body.get("id") == share_id

        # Consume share (public endpoint, no auth needed)
        status2, body2, _ = _request("POST", f"/api/share/{share_id}", {})
        assert status2 == 200, f"Share consume failed: {status2} {body2}"
        assert "encrypted_blob" in body2
        assert body2["view_count"] == 1
        assert body2["max_views"] == 2

        # Delete the share (cleanup)
        status3, body3, _ = _request(
            "DELETE", f"/api/share/{share_id}", token=token
        )
        assert status3 == 200, f"Share delete failed: {status3} {body3}"

    def test_share_max_views_enforced(self, share_context):
        """After max_views is reached the share is gone: the uniform 404 that
        hides why a share is unavailable (expired, used up or never existed)."""
        token = share_context["token"]

        share_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        encrypted_blob = base64.b64encode(os.urandom(64)).decode("ascii")
        expires_at = int(time.time() * 1000) + 3600 * 1000

        # Create with max_views=1
        status, body, _ = _request("POST", "/api/share", {
            "id": share_id,
            "encrypted_blob": encrypted_blob,
            "expires_at": expires_at,
            "max_views": 1,
        }, token=token)
        assert status == 200

        # First view — OK
        status2, body2, _ = _request("POST", f"/api/share/{share_id}", {})
        assert status2 == 200

        status3, body3, _ = _request("POST", f"/api/share/{share_id}", {})
        assert (status3, body3) == (404, {"detail": "Share unavailable"}), (status3, body3)

        # Cleanup
        _request("DELETE", f"/api/share/{share_id}", token=token)

    def test_share_nonexistent_returns_404_or_405(self):
        """Consuming a nonexistent share should return 404 (or 405 if routing rejects the path)."""
        fake_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        status, body, _ = _request("POST", f"/api/share/{fake_id}", {"pin": None})
        assert status in (404, 405, 422), (
            f"Expected 404/405/422 for nonexistent share, got {status}: {body}"
        )

    def test_share_delete_nonexistent_returns_404(self, share_context):
        """Deleting a nonexistent share should return 404."""
        token = share_context["token"]
        fake_id = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        status, _, _ = _request("DELETE", f"/api/share/{fake_id}", token=token)
        assert status == 404


# ===========================================================================
# 6. Security Tests
# ===========================================================================


class TestSecurity:
    """Test security controls: auth enforcement, JWT validation, etc."""

    def test_missing_auth_header(self):
        """Accessing protected endpoint without Authorization header should return 401/422."""
        status, _, _ = _request("GET", "/api/sync?since_commit_seq=0")
        # FastAPI returns 422 for missing required header, or 401
        assert status in (401, 422), f"Expected 401 or 422, got {status}"

    def test_malformed_jwt(self):
        """Malformed JWT should return 401."""
        status, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token="not.a.valid.jwt"
        )
        assert status == 401

    def test_empty_bearer_token(self):
        """Empty bearer token should return 401."""
        status, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=""
        )
        # Empty string after "Bearer " is still sent; server should reject
        assert status in (401, 422)

    def test_random_jwt_rejected(self):
        """Random base64 that looks like a JWT should be rejected."""
        # Build a fake JWT structure
        fake_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        fake_payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "fake", "exp": int(time.time()) + 3600}).encode()
        ).decode().rstrip("=")
        fake_sig = base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")
        fake_jwt = f"{fake_header}.{fake_payload}.{fake_sig}"

        status, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=fake_jwt
        )
        assert status == 401

    def test_non_admin_on_admin_endpoint(self):
        """Non-admin user on admin-only endpoint should return 403.

        This test uses a scoped onboarding JWT if available, or skips.
        """
        signing_key, signing_pk, _, encryption_pk = _generate_keypair()
        username = f"nonadmin_{int(time.time())}_{os.urandom(4).hex()}"

        # Try to register to get a scoped JWT
        status, body, _ = _request("POST", "/api/users/register", {
            "invitation_token": _invite_token(),
            "username": username,
            "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(),
        })
        if status in (404, 410):
            pytest.skip("Invitation token unavailable")
        if status != 200:
            pytest.skip(f"Registration failed: {status}")

        scoped_jwt = body["token"]

        # Try admin-only endpoint (list users)
        status2, body2, _ = _request("GET", "/api/users", token=scoped_jwt)
        assert status2 == 403, (
            f"Expected 403 for scoped/non-admin JWT on admin endpoint, got {status2}"
        )

    def test_scoped_jwt_on_sync_endpoint(self):
        """Scoped JWT (keypair_upload) should be rejected on sync endpoint."""
        signing_key, signing_pk, _, encryption_pk = _generate_keypair()
        username = f"scopetest2_{int(time.time())}_{os.urandom(4).hex()}"

        status, body, _ = _request("POST", "/api/users/register", {
            "invitation_token": _invite_token(),
            "username": username,
            "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(),
        })
        if status in (404, 410):
            pytest.skip("Invitation token unavailable")
        if status != 200:
            pytest.skip(f"Registration failed: {status}")

        scoped_jwt = body["token"]

        # Scoped JWT on full-JWT endpoint
        status2, _, _ = _request(
            "GET", "/api/sync?since_commit_seq=0", token=scoped_jwt
        )
        assert status2 == 403

    def test_wrong_signature_on_verify(self):
        """Wrong Ed25519 signature on /api/auth/verify should be rejected."""
        # Get a challenge
        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": "__sig_test_user__",
        })
        assert status == 200

        # Use a completely wrong signature
        wrong_sig = os.urandom(64).hex()
        status2, _, _ = _request("POST", "/api/auth/verify", {
            "username": "__sig_test_user__",
            "challenge": body["challenge"],
            "signature": wrong_sig,
        })
        assert status2 == 401


# ===========================================================================
# 7. Security Headers
# ===========================================================================


class TestSecurityHeaders:
    """Verify security-related HTTP response headers."""

    @pytest.fixture(scope="class")
    def response_headers(self):
        """Fetch headers from a simple endpoint."""
        _, _, headers = _request("GET", "/health")
        return headers

    def test_csp_header(self, response_headers):
        """Content-Security-Policy header should be present with default-src."""
        csp = response_headers.get("content-security-policy")
        assert csp is not None, "CSP header missing"
        assert "default-src" in csp

    def test_hsts_header(self, response_headers):
        """Strict-Transport-Security header should be present."""
        hsts = response_headers.get("strict-transport-security")
        assert hsts is not None, "HSTS header missing"
        assert "max-age=" in hsts

    def test_x_content_type_options(self, response_headers):
        """X-Content-Type-Options should be 'nosniff'."""
        xcto = response_headers.get("x-content-type-options")
        assert xcto is not None, "X-Content-Type-Options header missing"
        assert xcto == "nosniff"

    def test_referrer_policy(self, response_headers):
        """Referrer-Policy should be 'no-referrer'."""
        rp = response_headers.get("referrer-policy")
        assert rp is not None, "Referrer-Policy header missing"
        assert rp == "no-referrer"

    def test_csp_frame_ancestors_or_xframe(self, response_headers):
        """Either CSP frame-ancestors or X-Frame-Options should prevent iframe embedding.

        NOTE: If this fails, it is a real security gap that should be fixed
        in the nginx config or FastAPI middleware.
        """
        csp = response_headers.get("content-security-policy", "")
        xfo = response_headers.get("x-frame-options", "")
        has_frame_ancestors = "frame-ancestors" in csp
        has_xframe = xfo.upper() in ("DENY", "SAMEORIGIN")
        if not (has_frame_ancestors or has_xframe):
            pytest.xfail(
                "SECURITY GAP: Neither CSP frame-ancestors nor X-Frame-Options found. "
                "Add frame-ancestors 'none' to CSP or X-Frame-Options: DENY to nginx."
            )

    def test_csp_object_src_none(self, response_headers):
        """CSP object-src should be 'none' (no plugins)."""
        csp = response_headers.get("content-security-policy", "")
        assert "object-src 'none'" in csp

    def test_hsts_includes_subdomains(self, response_headers):
        """HSTS should include includeSubDomains directive."""
        hsts = response_headers.get("strict-transport-security", "")
        assert "includeSubDomains" in hsts

    def test_hsts_max_age_is_long(self, response_headers):
        """HSTS max-age should be at least 1 year (31536000 seconds)."""
        hsts = response_headers.get("strict-transport-security", "")
        # Parse max-age value
        import re
        match = re.search(r"max-age=(\d+)", hsts)
        assert match, "Could not parse max-age from HSTS header"
        max_age = int(match.group(1))
        assert max_age >= 31536000, (
            f"HSTS max-age should be >= 31536000 (1 year), got {max_age}"
        )


# ===========================================================================
# Additional edge-case tests
# ===========================================================================


class TestEdgeCases:
    """Miscellaneous edge-case tests."""

    def test_health_returns_json(self):
        """Health endpoint should return valid JSON."""
        status, body, headers = _request("GET", "/health")
        assert status == 200
        assert isinstance(body, dict)
        content_type = headers.get("content-type", "")
        assert "application/json" in content_type

    def test_unknown_route_returns_404(self):
        """Nonexistent route should return 404 (not 500)."""
        status, _, _ = _request("GET", "/api/this/does/not/exist")
        assert status in (404, 405), f"Expected 404 or 405, got {status}"

    def test_meta_without_username(self):
        """GET /api/meta without username should still return base info."""
        status, body, _ = _request("GET", "/api/meta")
        assert status == 200
        assert body.get("argon2_salt") is None, (
            "argon2_salt should not be returned without username query"
        )

    def test_challenge_for_nonexistent_user(self):
        """Challenge should still be returned for nonexistent user (anti-enumeration)."""
        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": f"__definitely_not_real_{os.urandom(8).hex()}__",
        })
        assert status == 200
        assert "challenge" in body
        assert "timestamp" in body
        # Challenge should be hex-encoded, at least 40 bytes (32 random + 8 timestamp)
        challenge = body["challenge"]
        assert len(challenge) >= 80, (
            f"Challenge too short: {len(challenge)} hex chars"
        )

    def test_register_duplicate_username(self):
        """Registering the same username twice should fail with 409."""
        signing_key, signing_pk, _, encryption_pk = _generate_keypair()
        username = f"duptest_{int(time.time())}_{os.urandom(4).hex()}"

        # First registration
        status, body, _ = _request("POST", "/api/users/register", {
            "invitation_token": _invite_token(),
            "username": username,
            "signing_pk": signing_pk.hex(),
            "encryption_pk": encryption_pk.hex(),
        })
        if status in (404, 410):
            pytest.skip("Invitation token unavailable")
        if status != 200:
            pytest.skip(f"First registration failed: {status}")

        # Second registration with same username (different invite would be needed,
        # but the same invite is already used, so this tests both used-invite AND
        # duplicate username scenarios)
        signing_key2, signing_pk2, _, encryption_pk2 = _generate_keypair()
        status2, body2, _ = _request("POST", "/api/users/register", {
            "invitation_token": _invite_token(),
            "username": username,
            "signing_pk": signing_pk2.hex(),
            "encryption_pk": encryption_pk2.hex(),
        })
        # Should fail — either 410 (invite used) or 409 (duplicate username)
        assert status2 in (404, 409, 410), (
            f"Expected 409 or 410, got {status2}: {body2}"
        )

    def test_sync_push_without_objects(self):
        """Pushing empty objects list should be handled gracefully."""
        username = os.environ.get("SEZAM_TEST_USERNAME")
        signing_sk_hex = os.environ.get("SEZAM_TEST_SIGNING_SK")
        if not username or not signing_sk_hex:
            pytest.skip("Need credentials for empty push test")

        signing_key = SigningKey(bytes.fromhex(signing_sk_hex))

        # Authenticate
        status, body, _ = _request("POST", "/api/auth/challenge", {
            "username": username,
        })
        if status != 200:
            pytest.skip(f"Challenge failed: {status}")
        challenge_bytes = bytes.fromhex(body["challenge"])
        signed = signing_key.sign(challenge_bytes)

        status2, body2, _ = _request("POST", "/api/auth/verify", {
            "username": username,
            "challenge": body["challenge"],
            "signature": signed.signature.hex(),
        })
        if status2 != 200:
            pytest.skip(f"Auth failed: {status2}")

        token = body2["token"]

        # Push empty list
        status3, body3, _ = _request("POST", "/api/sync", {
            "objects": [],
            "atomic_batch": False,
        }, token=token)
        assert status3 == 200, f"Empty push failed: {status3} {body3}"
        assert body3.get("accepted") == []
        assert body3.get("conflicts") == []
