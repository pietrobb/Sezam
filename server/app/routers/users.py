"""User management endpoints.

Spec 8.6:
  POST   /api/users/invite
  POST   /api/users/register
  GET    /api/users
  PATCH  /api/users/:id/approve
  PATCH  /api/users/:id/rotate-keys   (disabled → 410)
  DELETE /api/users/:id
  PATCH  /api/users/:id/reactivate
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import authority, key_vouchers, team_log
from ..auth import create_jwt, unlock_code_hash
from ..config import JWTKeyManager, ServerConfig
from ..errors import TEAM_LOG_REQUIRED, ApiError
from ..database import Database
from ..dependencies import (
    get_config, get_db, get_jwt_manager, get_rotation_user, get_team_log_reader, require_admin, require_full_jwt,
)
from ..models.schemas import (
    InviteResponse,
    KeyVoucherList,
    RegisterRequest,
    RegisterResponse,
    UserInfo,
)
from .auth import _request_network_mac, drop_keyless_account, keyless_account_left_no_trace

router = APIRouter(prefix="/api/users", tags=["users"])


@router.post("/invite", response_model=InviteResponse)
async def create_invitation(
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: generate invitation token (128-bit, 72h, one-time)."""
    token = os.urandom(16).hex()  # 128-bit
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now_ms = int(time.time() * 1000)
    expires_at = now_ms + 72 * 3600 * 1000  # 72h

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "INSERT INTO invitation_tokens (token_hash, created_by, created_at, expires_at, is_used) "
                "VALUES (%s, %s, %s, %s, 0)",
                (token_hash, admin["sub"], now_ms, expires_at),
            )
        await conn.commit()

    return InviteResponse(invitation_token=token, expires_at=expires_at)


@router.post("/register", response_model=RegisterResponse)
async def register_user(
    req: RegisterRequest,
    request: Request,
    db: Database = Depends(get_db),
    jwt_mgr: JWTKeyManager = Depends(get_jwt_manager),
    config: ServerConfig = Depends(get_config),
):
    """Register new user via invitation token. Returns onboarding JWT (15min)."""
    token_hash = hashlib.sha256(req.invitation_token.encode("utf-8")).hexdigest()
    now_ms = int(time.time() * 1000)

    # Create user (rely on UNIQUE constraint for race-safe uniqueness check)
    from ulid import ULID
    user_id = str(ULID())
    signing_pk = bytes.fromhex(req.signing_pk)
    encryption_pk = bytes.fromhex(req.encryption_pk)
    fingerprint = hashlib.sha256(signing_pk + encryption_pk).hexdigest()

    # H6: validate and consume the one-time invitation inside a single locked
    # transaction. SELECT ... FOR UPDATE serializes concurrent redemptions and
    # the UPDATE carries an is_used=0 predicate + rowcount guard so a second
    # redemption (even with a different username) cannot reuse the invitation.
    try:
        async with db.transaction() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT expires_at, is_used FROM invitation_tokens "
                    "WHERE token_hash = %s FOR UPDATE",
                    (token_hash,),
                )
                row = await cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Invalid invitation")
                if row[1]:
                    raise HTTPException(status_code=410, detail="Invitation already used")
                if now_ms > row[0]:
                    raise HTTPException(status_code=410, detail="Invitation expired")

                # Atomic single-use consume.
                await cur.execute(
                    "UPDATE invitation_tokens SET is_used = 1 "
                    "WHERE token_hash = %s AND is_used = 0",
                    (token_hash,),
                )
                if cur.rowcount != 1:
                    raise HTTPException(status_code=410, detail="Invitation already used")

                # Lockout review #10: a registration whose keypair upload
                # never happened kept the username forever (pending without
                # key material, onboarding token long expired). Such an
                # account can never be completed, so the name is free again.
                # Review 7c10379 (R7-H): a locking read of a name nobody holds
                # took a gap lock on users.username, and two registrations of
                # new names in the same gap then deadlocked on their INSERTs
                # (MariaDB: 10 of 20 parallel registrations failed with 500).
                # Only an existing holder is locked, by its primary key; a free
                # name is left to the UNIQUE constraint of the INSERT below.
                await cur.execute(
                    "SELECT id FROM users WHERE username = %s", (req.username,)
                )
                found = await cur.fetchone()
                holder = None
                if found:
                    await cur.execute(
                        "SELECT id, status, encrypted_keypair, created_at FROM users "
                        "WHERE id = %s AND username = %s FOR UPDATE",
                        (found[0], req.username),
                    )
                    holder = await cur.fetchone()
                cutoff_ms = now_ms - config.jwt_onboarding_expiry_seconds * 1000
                if (
                    holder
                    and holder[1] == "pending"
                    and not holder[2]
                    and (holder[3] or 0) <= cutoff_ms
                    and await keyless_account_left_no_trace(cur, holder[0])
                ):
                    await drop_keyless_account(cur, holder[0])

                # Insert user (UNIQUE on username — atomic check)
                # Capability run 88: the network that redeemed the invitation
                # is the owner's and skips the locked-name recovery ration.
                await cur.execute(
                    "INSERT INTO users (id, username, signing_pk, encryption_pk, key_fingerprint, "
                    "status, is_admin, created_at, recovery_trusted_nets) "
                    "VALUES (%s, %s, %s, %s, %s, 'pending', 0, %s, %s)",
                    (user_id, req.username, signing_pk, encryption_pk, fingerprint, now_ms,
                     json.dumps([_request_network_mac(request, config)])),
                )
    except HTTPException:
        raise
    except Exception as e:
        if "Duplicate entry" in str(e) or "UNIQUE" in str(e) or "Duplicate key" in str(e):
            raise HTTPException(status_code=409, detail="Username already exists")
        raise

    # Onboarding JWT (15min, scope=keypair_upload)
    token = create_jwt(
        jwt_mgr.signing_key,
        user_id,
        req.username,
        is_admin=False,
        expiry_seconds=config.jwt_onboarding_expiry_seconds,
        scope="keypair_upload",
    )

    return RegisterResponse(user_id=user_id, token=token)


@router.get("", response_model=list[UserInfo])
async def list_users(
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: list all users (including pending)."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, username, status, is_admin, key_fingerprint, "
                "signing_pk, encryption_pk, created_at "
                "FROM users ORDER BY created_at"
            )
            rows = await cur.fetchall()

    return [
        UserInfo(
            id=r[0], username=r[1], status=r[2], is_admin=bool(r[3]),
            key_fingerprint=r[4],
            signing_pk=r[5].hex() if r[5] else None,
            encryption_pk=r[6].hex() if r[6] else None,
            created_at=r[7],
        )
        for r in rows
    ]


UNLOCK_CODE_SECONDS = 24 * 3600


@router.post("/{user_id}/unlock-recovery")
async def unlock_recovery(
    user_id: str,
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: clear a password-recovery lockout and its failure counters.

    Review e4cd15a: clearing the counters alone lasted until the attacker's
    next 10 guesses (or 3 networks) re-locked the name, so an owner on a new
    network never got through. The admin now also gets a one-time code for
    the owner: it lets one /recover verify the password from any network,
    whatever the locked name's rations say, until it is used or expires."""
    code = secrets.token_hex(10)
    until = int(time.time() * 1000) + UNLOCK_CODE_SECONDS * 1000
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE users SET recovery_locked = 0, recovery_attempts = 0, "
                "recovery_attempts_hour = 0, recovery_unlock_hash = %s, "
                "recovery_unlock_until = %s WHERE id = %s",
                (unlock_code_hash(code), until, user_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
        await conn.commit()
    return {"status": "ok", "unlock_code": code, "expires_at": until}


KEY_RESET_GRANT_SECONDS = 3600


@router.post("/{user_id}/allow-key-reset")
async def allow_key_reset(
    user_id: str,
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: let the user replace the key material once without the current
    password (review 688edcb K1), e.g. after an org recovery on the desktop.
    An admin cannot grant it to themselves: a stolen admin keypair must not
    be enough to take the admin account over."""
    if user_id == admin["sub"]:
        raise HTTPException(status_code=403, detail="Ask another admin for a key reset")
    until = int(time.time() * 1000) + KEY_RESET_GRANT_SECONDS * 1000
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE users SET key_reset_until = %s, key_reset_by = %s "
                "WHERE id = %s AND status = 'active'",
                (until, admin["sub"], user_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
        await conn.commit()
    return {"status": "ok", "expires_at": until}


@router.get("/{user_id}/keys")
async def get_user_keys(
    user_id: str,
    db: Database = Depends(get_db),
    user: dict = Depends(get_team_log_reader),
):
    """Get a user's public keys (for signature verification on pull)."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT signing_pk, encryption_pk FROM users WHERE id = %s",
                (user_id,),
            )
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")

            await cur.execute(
                "SELECT signing_pk, encryption_pk, key_fingerprint, archived_at, "
                "successor_signing_pk, rotation_signature, authorization_signature, "
                "retired_seq "
                "FROM user_key_archives WHERE user_id = %s "
                "ORDER BY archived_at DESC LIMIT 64",
                (user_id,),
            )
            archive_rows = list(await cur.fetchall())

    # Clients trust an archived key only through its rotation certificate
    # (signed by the successor key), so uncertified legacy rows are omitted.
    archived_keys = []
    seen_signing_keys = set()
    for (signing_pk, encryption_pk, fingerprint, archived_at,
         successor_pk, rotation_signature, authorization_signature,
         retired_seq) in archive_rows:
        if (
            not signing_pk
            or not encryption_pk
            or len(signing_pk) != 32
            or len(encryption_pk) != 32
            or not successor_pk
            or not rotation_signature
            or signing_pk in seen_signing_keys
        ):
            continue
        seen_signing_keys.add(signing_pk)
        archived_keys.append(
            {
                "signing_pk": bytes(signing_pk).hex(),
                "encryption_pk": bytes(encryption_pk).hex(),
                "key_fingerprint": fingerprint,
                "archived_at": archived_at,
                "successor_signing_pk": bytes(successor_pk).hex(),
                "rotation_signature": bytes(rotation_signature).hex(),
                # Review 688edcb V4: the old key's own consent, and the last
                # commit_seq clients accept its signatures for.
                "authorization_signature": (
                    bytes(authorization_signature).hex() if authorization_signature else None
                ),
                "retired_seq": retired_seq,
            }
        )
        if len(archived_keys) == 64:
            break

    return {
        "signing_pk": row[0].hex() if row[0] else None,
        "encryption_pk": row[1].hex() if row[1] else None,
        "archived_keys": archived_keys,
    }


async def _current_signing_pk(cur, user_id: str) -> bytes:
    await cur.execute("SELECT signing_pk FROM users WHERE id = %s", (user_id,))
    row = await cur.fetchone()
    if not row or not row[0]:
        raise HTTPException(status_code=404, detail="User not found")
    return bytes(row[0])


@router.get("/{user_id}/key-vouchers")
async def get_key_vouchers(
    user_id: str,
    after: str = Query(default="", pattern=r"^(?:[0-9A-Za-z]{26})?$"),
    db: Database = Depends(get_db),
    user: dict = Depends(get_team_log_reader),
):
    """Goal #443: the voucher lists of the account's current key, the only
    ones under which clients take a retired key's signature. R17-N10: paged;
    ``next`` is the ``after`` of the next page ("" at the end)."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            signing_pk = await _current_signing_pk(cur, user_id)
            lists, next_after = await key_vouchers.lists_of(cur, user_id, signing_pk, after)
    return {"signing_pk": signing_pk.hex(), "lists": lists, "next": next_after}


@router.post("/me/key-vouchers")
async def post_key_vouchers(
    body: KeyVoucherList,
    db: Database = Depends(get_db),
    user: dict = Depends(get_rotation_user),
):
    """Goal #443: add a voucher list signed by the account's current key (a
    rotation from before #443 gets its list on the next sync)."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            signing_pk = await _current_signing_pk(cur, user["sub"])
    (checked_list,) = await key_vouchers.checked(user["sub"], signing_pk, [body.model_dump()])
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            # The key may have rotated meanwhile: keep the list only under the key that signed it.
            await cur.execute("SELECT signing_pk FROM users WHERE id = %s FOR UPDATE", (user["sub"],))
            row = await cur.fetchone()
            if not row or bytes(row[0] or b"") != signing_pk:
                raise HTTPException(status_code=409, detail="The account's key changed; send the list again")
            await key_vouchers.store(cur, user["sub"], signing_pk, checked_list, int(time.time() * 1000))
    return {"status": "ok"}


SIGNED_OBJECTS_PAGE = 1000


@router.get("/me/signed-objects")
async def get_signed_objects(
    after: str = Query(default="", pattern=r"^(?:[0-9A-Za-z]{26})?$"),
    db: Database = Depends(get_db),
    user: dict = Depends(get_rotation_user),
):
    """Goal #443: the live versions the caller's account signed, without
    payloads: what its next voucher list may name. Paged by id."""
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, object_type, parent_ref, target_user_id, is_deleted, version, "
                "payload_hash, client_signature, commit_seq FROM vault_objects "
                "WHERE signature_user_id = %s AND id > %s ORDER BY id LIMIT %s",
                (user["sub"], after, SIGNED_OBJECTS_PAGE),
            )
            rows = list(await cur.fetchall())
    objects = [
        {
            "id": obj_id, "object_type": object_type, "parent_ref": parent_ref,
            "target_user_id": target_user_id, "is_deleted": int(is_deleted or 0),
            "version": version, "payload_hash": payload_hash,
            "signature": bytes(signature).hex() if signature else None, "commit_seq": commit_seq,
        }
        for (obj_id, object_type, parent_ref, target_user_id, is_deleted, version,
             payload_hash, signature, commit_seq) in rows
    ]
    return {"objects": objects, "more": len(rows) == SIGNED_OBJECTS_PAGE}


@router.patch("/{user_id}/approve")
async def approve_user(
    user_id: str,
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: approve pending user → status='active'.

    Verifies that user has uploaded their keypair first.
    """
    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            # Check user exists and is pending
            await cur.execute(
                "SELECT status, encrypted_keypair, argon2_salt FROM users WHERE id = %s",
                (user_id,),
            )
            row = await cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if row[0] != "pending":
        raise HTTPException(status_code=400, detail="User is not pending")
    if not row[1] or not row[2]:
        raise HTTPException(
            status_code=400,
            detail="User has not uploaded their keypair yet. Cannot approve.",
        )

    async with db.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE users SET status = 'active' WHERE id = %s AND status = 'pending'",
                (user_id,),
            )
        await conn.commit()

    return {"status": "ok"}


@router.patch("/{user_id}/rotate-keys")
async def rotate_keys(user_id: str, user: dict = Depends(require_full_jwt)):
    """Disabled (lockout review #11).

    It replaced signing_pk/encryption_pk in place while encrypted_keypair kept
    the OLD private keys, so the next device that opened the stored keypair
    held keys the server no longer vouched for. No client calls it; public
    key rotation needs to ship together with the matching key material.
    """
    raise HTTPException(
        status_code=410,
        detail="Public key rotation is disabled: it must replace the encrypted keypair too",
    )


@router.delete("/{user_id}")
async def revoke_user(
    user_id: str,
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: revoke user → status='revoked', removes write_acl, triggers re-key.

    Lockout review #12: two admins revoking each other at the same time both
    passed the per-request "caller is an active admin" check and left the
    organisation without an admin. The active admin rows are now locked and
    re-read inside the transaction (the same scan for every revoke, so the
    second one waits and then sees its caller revoked). The caller is never
    the target, so it remains as an active admin. token_epoch is bumped so a later reactivation
    does not revive tokens issued before the revocation.
    """
    if admin["sub"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot revoke yourself")

    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id FROM users WHERE is_admin = %s AND status = %s FOR UPDATE",
                (1, "active"),
            )
            await cur.fetchall()  # the lock: two revokes of each other run in turn
            if not await authority.team_admin(cur, admin["sub"]):  # re-read under the lock
                raise HTTPException(status_code=403, detail="Admin required")
            await cur.execute(
                "SELECT status FROM users WHERE id = %s FOR UPDATE", (user_id,)
            )
            if not await cur.fetchone():
                raise HTTPException(status_code=404, detail="User not found")
            # With a team log, membership is what the log says: a member is
            # removed by a signed member.remove record (which also revokes the
            # account here), never by this unsigned call alone.
            state = await team_log.load_state(cur)
            member = state.members.get(user_id) if state is not None else None
            if member is not None and member.active:
                raise ApiError(
                    409, TEAM_LOG_REQUIRED,
                    "This account is a team member: remove it with a member.remove "
                    "team log record.",
                )
            await cur.execute(
                "UPDATE users SET status = 'revoked', token_epoch = token_epoch + 1 "
                "WHERE id = %s",
                (user_id,),
            )

            # Remove all write_acl entries for the revoked user (spec 4.2 rule 5)
            await cur.execute(
                "DELETE FROM write_acl WHERE user_id = %s",
                (user_id,),
            )
            # Review 8595ec1: their share links end with them.
            await cur.execute("DELETE FROM shared_links WHERE created_by = %s", (user_id,))

    return {"status": "ok", "note": "Re-key required for affected folders"}


@router.patch("/{user_id}/reactivate")
async def reactivate_user(
    user_id: str,
    db: Database = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Admin: undo a revocation → status='active' (lockout review #12).

    Revocation used to be final. The account keeps its identity and key
    material, so it can sign in again; write access and folder shares are
    NOT restored (revocation dropped write_acl and triggered re-keys) and
    must be granted again. Tokens from before the revocation stay dead
    (token_epoch was bumped by the revoke).
    """
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT status, encrypted_keypair FROM users WHERE id = %s FOR UPDATE",
                (user_id,),
            )
            row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            if row[0] != "revoked":
                raise HTTPException(status_code=400, detail="User is not revoked")
            if not row[1]:
                raise HTTPException(
                    status_code=400,
                    detail="User has no key material; onboard the account again",
                )
            # Review 1141a20 (R9-F): a member the signed log removed came back
            # here unsigned. Only a member.add record brings them back.
            state = await team_log.load_state(cur)
            if state is not None and user_id in state.members:
                raise ApiError(
                    409, TEAM_LOG_REQUIRED,
                    "The team log removed this account: add it again with a member.add "
                    "team log record.",
                )
            await cur.execute(
                "UPDATE users SET status = 'active' WHERE id = %s AND status = 'revoked'",
                (user_id,),
            )

    return {"status": "ok", "note": "Write access and shares must be granted again"}
