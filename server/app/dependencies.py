"""FastAPI dependencies — DB, auth, JWT verification."""

from __future__ import annotations

import time
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException

from .auth import token_revocation_key, verify_jwt
from .config import JWTKeyManager, ServerConfig
from .database import Database
from . import authority, team_log
from .errors import IDENTITY_KEY_RETIRED, TOKEN_INVALID, TOKEN_REVOKED, ApiError

# The session of an account whose key the team log retired (capability run 294).
KEY_ROTATION_SCOPE = "key_rotation"
KEY_RETIRED_SCOPE = "key_retired"

# Singletons (initialized in main.py lifespan)
_config: Optional[ServerConfig] = None
_db: Optional[Database] = None
_jwt_mgr: Optional[JWTKeyManager] = None


def set_globals(config: ServerConfig, db: Database, jwt_mgr: JWTKeyManager) -> None:
    global _config, _db, _jwt_mgr
    _config = config
    _db = db
    _jwt_mgr = jwt_mgr


def get_config() -> ServerConfig:
    assert _config is not None
    return _config


def get_db() -> Database:
    assert _db is not None
    return _db


def get_jwt_manager() -> JWTKeyManager:
    assert _jwt_mgr is not None
    return _jwt_mgr


async def _authenticate_user(
    authorization: Annotated[str, Header()],
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
) -> dict:
    """Extract and verify JWT from Authorization header.

    Returns decoded JWT payload: {sub, username, is_admin, scope?, ...}
    Raises 401 if invalid/expired/revoked.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]

    # Verify signature first (before DB lookup)
    try:
        payload = verify_jwt(token, jwt_mgr.verify_key_bytes)
    except Exception:
        raise ApiError(401, TOKEN_INVALID, "Invalid or expired token")

    # Check revocation (after signature verification)
    token_h = token_revocation_key(payload)
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM revoked_tokens WHERE token_hash = %s", (token_h,)
            )
            if await cur.fetchone():
                raise ApiError(401, TOKEN_REVOKED, "Token revoked")
            await cur.execute(
                "SELECT username, is_admin, status, token_epoch, signing_pk, key_reset_until "
                "FROM users WHERE id = %s",
                (payload.get("sub"),),
            )
            current_user = await cur.fetchone()
            # Capability run 294: a server restored from before an identity
            # rotation gets its member.keys back from the devices, while the
            # account still signs in with the key that record retired. Its
            # session (old tokens too: the restore brought their epoch back)
            # may only read and send the rotation to the log's keys.
            # Capability run 300: and read objects only when its login also
            # proved the log's current key (the rotating device); the lost
            # device that holds the retired key alone reads the log and keys.
            retired = None
            if current_user is not None and not payload.get("scope") and current_user[4] is not None:
                state = await team_log.load_state(cur)
                if team_log.key_retired(state, payload.get("sub"), bytes(current_user[4])):
                    member = state.members.get(payload.get("sub"))
                    proved = member is not None and payload.get("kcur") == member.signing_pk
                    # Review 8595ec1 (R10-F): the member lost the device with
                    # the log's key too. An admin's key-reset grant lets the
                    # account rotate to fresh keys (readmitted by the admin).
                    granted = current_user[5] is not None and int(current_user[5]) > int(time.time() * 1000)
                    retired = KEY_ROTATION_SCOPE if proved or granted else KEY_RETIRED_SCOPE
            # INV-1 (R15-F1-S2): the team log says who the admin is; the
            # users row is its cache, the answer only without a log.
            admin = current_user is not None and await authority.team_admin(
                cur, payload.get("sub"), cached=bool(current_user[1]),
            )
    if retired:
        payload["scope"] = retired

    if not current_user or current_user[2] == "revoked":
        raise HTTPException(status_code=401, detail="User is not active")
    if int(payload.get("tep") or 0) != int(current_user[3] or 0):
        raise ApiError(401, TOKEN_REVOKED, "Token revoked")
    if current_user[2] != "active" and payload.get("scope") != "keypair_upload":
        raise HTTPException(status_code=401, detail="User is not active")

    # Security-sensitive claims always come from current DB state.
    payload["username"] = current_user[0]
    payload["is_admin"] = admin

    return payload


async def get_current_user(
    authorization: Annotated[str, Header()],
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
) -> dict:
    """Require an unscoped JWT for every normal authenticated endpoint."""
    user = await _authenticate_user(authorization, db, jwt_mgr)
    if user.get("scope"):
        raise HTTPException(
            status_code=403,
            detail=f"Scoped JWT ({user['scope']}) not allowed on this endpoint",
        )
    return user


async def get_keypair_upload_user(
    authorization: Annotated[str, Header()],
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
) -> dict:
    """Allow a full JWT or the single onboarding scope for keypair upload."""
    user = await _authenticate_user(authorization, db, jwt_mgr)
    if user.get("scope") not in (None, "keypair_upload"):
        raise HTTPException(status_code=403, detail="Invalid token scope")
    return user


async def require_full_jwt(user: dict = Depends(get_current_user)) -> dict:
    """Require a full JWT (not onboarding scope-limited token)."""
    if user.get("scope"):
        raise HTTPException(
            status_code=403,
            detail=f"Scoped JWT ({user['scope']}) not allowed on this endpoint",
        )
    return user


async def get_rotation_user(
    authorization: Annotated[str, Header()],
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
) -> dict:
    """A full JWT, or a retired key's session that proved the log's current key:
    pull, read keys, push its rotation."""
    user = await _authenticate_user(authorization, db, jwt_mgr)
    if user.get("scope") == KEY_RETIRED_SCOPE:
        raise ApiError(
            403, IDENTITY_KEY_RETIRED,
            "This key was retired by an identity rotation. If the device with the new key is lost: "
            "an admin runs 'sezam allow-key-reset', you 'sezam rotate-identity', then the admin "
            "'sezam team-log readmit' (with your new fingerprint).",
        )
    if user.get("scope") not in (None, KEY_ROTATION_SCOPE):
        raise HTTPException(status_code=403, detail="Invalid token scope")
    return user


async def get_team_log_reader(
    authorization: Annotated[str, Header()],
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
) -> dict:
    """Any retired key's session too: the team log and public keys only."""
    user = await _authenticate_user(authorization, db, jwt_mgr)
    if user.get("scope") not in (None, KEY_ROTATION_SCOPE, KEY_RETIRED_SCOPE):
        raise HTTPException(status_code=403, detail="Invalid token scope")
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Require admin privileges."""
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin required")
    if user.get("scope"):
        raise HTTPException(status_code=403, detail="Scoped JWT not allowed")
    return user
