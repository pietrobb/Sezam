"""Sync client — delta push/pull with the server.

Spec 8.2: Server-assigned commit_seq, idempotent retry,
rollback protection (sync checkpoint + state_hash).

Spec 8.3: Sync checkpoint with state_hash for rollback detection.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Optional

import urllib.request
import urllib.error

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from ..crypto.kdf import Argon2Params
from ..crypto.keys import KeyPair
from ..usernames import normalize_username
from . import oplock, pending_states
from .db import VaultDB
from .key_rotation import (
    open_auth_proof,
    open_current_auth_proof,
    open_old_keypair,
    open_recovery_secret,
    org_recovery_rewrap_message,
    org_recovery_server_wrap,
    org_recovery_signing_key,
)

if TYPE_CHECKING:
    from .crud import Vault
    from .dek import DEKManager

from .sync_common import (
    _CHECKPOINT_META_KEY,
    AccountLostOnServer,
    COMMIT_ANCHOR_META,
    compute_state_hash,
    CONFIRMED_MEMBER_KEYS_META,
    FULL_RESYNC_HINT,
    IDENTITY_KEY_ROTATED,
    KDF_REPORTED_META_KEY,
    key_rotation_message,
    KeyEpochStale,
    logger,
    pull_warnings,
    RESEED_ARCHIVES_META,
    _rotated_account_name,
    server_error,
    SERVER_KEY_MATERIAL_META,
    SERVER_ROLLBACK_META,
    ServerError,
    auth_verify_body,
    sign_auth_challenge,
    SyncRollbackWarning,
    TOKEN_INVALID,
    TOKEN_REVOKED,
    TofuKeyChangeError,
    unsent_envelope_count,
)
from .sync_apply import ApplyMixin
from .sync_pull import PullMixin
from .sync_push import PushMixin
from .sync_rekey import RekeyMixin
from .sync_resync import ResyncMixin
from .sync_state import SyncStateMixin
from .sync_writers import WritersMixin
from .team_log_local import TeamLogMixin

# Re-exported: callers import these from sync_client.
__all__ = [
    "_CHECKPOINT_META_KEY",
    "COMMIT_ANCHOR_META",
    "CONFIRMED_MEMBER_KEYS_META",
    "KeyEpochStale",
    "RESEED_ARCHIVES_META",
    "SERVER_ROLLBACK_META",
    "ServerError",
    "SyncClient",
    "SyncRollbackWarning",
    "TofuKeyChangeError",
    "compute_state_hash",
    "key_rotation_message",
    "pull_warnings",
    "unsent_envelope_count",
]


class SyncClient(
    PushMixin, RekeyMixin, PullMixin, ApplyMixin, ResyncMixin, SyncStateMixin, WritersMixin,
    TeamLogMixin,
):
    """Handles sync operations with the Sezam server."""

    def __init__(self, db: VaultDB, server_url: str, keypair: KeyPair, user_id: str):
        self._db = db
        self._server_url = server_url.rstrip("/")
        self._keypair = keypair
        self._user_id = user_id
        self._token: Optional[str] = None
        self._push_cache: dict[str, dict] = {}  # id -> serialized sync object
        self._dek_mgr: Optional[DEKManager] = None
        self._equivocations: list[dict] = []
        # The server's tombstone GC floor as of the pull being applied.
        self._gc_floor = 0
        self._tofu_checked_user_ids: set[str] = set()
        self._tofu_warnings: list[dict] = []
        self._signing_key_rings: dict[str, tuple[bytes, ...]] = {}
        self._archive_bounds: dict[str, dict[bytes, int]] = {}
        # The server's key for this account that signed this device's pending
        # identity rotation (it is current there until the rotation lands).
        self._rotation_authorizer: Optional[bytes] = None
        # commit_seq the running pull asked to start after.
        self._verify_since_seq = 0
        self._pulled_dek_ids: list[str] = []
        self._pulled_archive_successors: set[str] = set()
        self._new_unbound_dek_ids: set[str] = set()

    @property
    def token(self) -> Optional[str]:
        return self._token

    @token.setter
    def token(self, value: str) -> None:
        self._token = value

    def set_dek_manager(self, dek_mgr: DEKManager) -> None:
        """Set the DEK manager for checkpoint encryption.

        Must be called before pull() to enable encrypted checkpoint storage.
        """
        self._dek_mgr = dek_mgr

    def _require_current_kek(self) -> None:
        """Review 7c10379: a process whose KEK the password moved past judged
        ownership by it, so DEKs of the new KEK went on the foreign list for
        good. Raises KeyChangedElsewhere before any sync touches the vault."""
        if self._dek_mgr is not None:
            self._dek_mgr._wrapping_kek_id()
        self._db.require_generation()

    # ── Authentication ──

    def authenticate(self) -> str:
        """Perform challenge-response auth, get JWT.

        While an identity rotation of this device waits for the server, the
        server still knows the old key: log in with it, then with the new one
        (the rotation landed but its response was lost).
        """
        old_keypair = self._pending_old_keypair()
        keypairs = [old_keypair, self._keypair] if old_keypair else [self._keypair]
        old_key_retired = False
        try:
            for index, keypair in enumerate(keypairs):
                # Step 1: Get challenge
                resp = self._request("POST", "/api/auth/challenge", {
                    "username": self._get_username(),
                })
                challenge_hex = resp["challenge"]

                # Step 2: Sign challenge (the old key also proves the log's: ours)
                body = auth_verify_body(
                    self._get_username(), challenge_hex, keypair.to_nacl_signing_key(),
                    self._keypair.to_nacl_signing_key() if keypair is old_keypair else None,
                )
                # Step 3: Verify (send challenge and signature as separate fields)
                try:
                    resp = self._request("POST", "/api/auth/verify", body)
                except RuntimeError as exc:
                    # 409 'Identity key rotated' for the journal's old key: the
                    # rotation landed and only its response was lost (review
                    # 688edcb), so the new key logs in; it is not a rival device.
                    retired = server_error(exc, 409, IDENTITY_KEY_ROTATED)
                    refused = server_error(exc, 401)
                    if index + 1 < len(keypairs) and (refused or retired):
                        old_key_retired = old_key_retired or retired
                        continue
                    if retired or (old_key_retired and refused):
                        # Another device rotated the identity: the new keypair
                        # is taken over like a password change made elsewhere.
                        # A renamed account is taken over under its current
                        # name, not the old one another account holds now
                        # (review 526419e N8).
                        current_name = _rotated_account_name(exc)
                        if current_name:
                            self._db.set_meta("username", current_name)
                        raise KeyEpochStale() from exc
                    if refused and pending_states.last_pushed_key_epoch(self._db) > 0:
                        # Stateful test SM14: the server lost an identity
                        # rotation it had taken (restored from a backup) and
                        # knows only the key from before. The way out is the
                        # key material it holds now, opened with the password
                        # (/auth/recover needs no login).
                        raise KeyEpochStale() from exc
                    if refused and self._named_by_team_log(keypair):
                        raise AccountLostOnServer() from exc
                    raise
                break
        finally:
            if old_keypair is not None:
                old_keypair.zeroize()
        self._token = resp["token"]
        # Review e4cd15a (low): the server's name migration may have moved
        # this account off the stored name; the answer carries the current one.
        current_name = resp.get("username")
        if current_name and current_name != self._get_username():
            self._db.set_meta("username", current_name)
        self._report_legacy_kdf_params()
        return self._token

    def _pending_identity(self) -> Optional[dict]:
        """Journal of this device's identity rotation the server has not taken."""
        journal = pending_states.key_change_journal(self._db)
        if "identity" not in journal:
            return None
        if int(journal.get("epoch", -1)) <= pending_states.last_pushed_key_epoch(self._db):
            return None
        return journal

    def _pending_old_keypair(self) -> Optional[KeyPair]:
        journal = self._pending_identity()
        if journal is None or self._dek_mgr is None:
            return None
        private = open_old_keypair(journal, self._dek_mgr._kek, self._db.get_meta("user_id"))
        try:
            return KeyPair.from_private_only(bytes(private))
        finally:
            private[:] = b"\x00" * len(private)

    def _report_legacy_kdf_params(self) -> None:
        """Hand the server the KDF params of an account kept without them.

        Lockout review N2: such an account is reported with the 128 MiB
        default, so a new web/mobile/desktop device derives a KEK that opens
        nothing when this vault created it with other params. This vault
        holds the real ones while its salt is the server's; once the server
        agrees (or refuses for good) the salt is remembered and not asked again.
        """
        from urllib.parse import quote

        local_salt = self._db.get_meta("argon2_salt")
        local_params = self._db.get_meta_json("argon2_params")
        if not local_salt or not local_params:
            return
        if self._db.get_meta(KDF_REPORTED_META_KEY) == local_salt:
            return
        try:
            meta = self._request(
                "GET", f"/api/meta?username={quote(self._get_username())}"
            ) or {}
            if str(meta.get("argon2_salt") or "").lower() != local_salt.lower():
                return
            params = Argon2Params.from_dict(local_params).account_dict()
            if meta.get("argon2_params") != params:
                challenge_hex, signature_hex = self._signed_challenge()
                try:
                    self._request("PUT", "/api/me/kdf-params", {
                        "argon2_salt": local_salt,
                        "argon2_params": params,
                        "challenge": challenge_hex,
                        "signature": signature_hex,
                    }, auth=True)
                except RuntimeError as exc:
                    if not (server_error(exc, 409) or server_error(exc, 422)):
                        raise
                    logger.warning("Server keeps other KDF params for this account: %s", exc)
            self._db.set_meta(KDF_REPORTED_META_KEY, local_salt)
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("Could not report the account KDF params: %s", exc)

    def _signed_challenge(self) -> tuple[str, str]:
        """Fresh server challenge signed by the current signing key."""
        resp = self._request("POST", "/api/auth/challenge", {
            "username": self._get_username(),
        })
        challenge_hex = resp["challenge"]
        return challenge_hex, sign_auth_challenge(self._keypair.to_nacl_signing_key(), challenge_hex)

    def list_users(self) -> list[dict]:
        """List server users through the admin endpoint."""
        if not self._token:
            self.authenticate()
        return self._request("GET", "/api/users", auth=True)

    def create_invitation(self) -> dict:
        """Create an invitation anchored only by this device's trusted log."""
        self.require_trusted_team_log()
        state = self.team_state()
        if not self._token:
            self.authenticate()
        response = self._request("POST", "/api/users/invite", auth=True)
        return {**response, "genesis_hash": state.genesis_hash if state is not None else None}

    def create_provisioning_token(self) -> dict:
        """One-time device token anchored only by this device's trusted log."""
        self.require_trusted_team_log()
        state = self.team_state()
        if not self._token:
            self.authenticate()
        response = self._request("POST", "/api/auth/provisioning-token", auth=True)
        return {**response, "genesis_hash": state.genesis_hash if state is not None else None}

    def approve_user(self, user_id: str) -> dict:
        """Approve a pending user through the admin endpoint."""
        if not self._token:
            self.authenticate()
        return self._request("PATCH", f"/api/users/{user_id}/approve", auth=True)

    def allow_key_reset(self, user_id: str) -> dict:
        """Admin: let the user replace the key material once without the
        current password (e.g. after an org recovery)."""
        if not self._token:
            self.authenticate()
        return self._request("POST", f"/api/users/{user_id}/allow-key-reset", auth=True)

    def unlock_recovery(self, user_id: str) -> dict:
        """Admin: clear a password lockout; returns the one-time unlock code."""
        if not self._token:
            self.authenticate()
        return self._request("POST", f"/api/users/{user_id}/unlock-recovery", auth=True)

    def verified_encryption_pk(self, user_id: str) -> bytes:
        """A member's X25519 key, pinned (TOFU) together with its signing key.

        A key that changed since it was pinned raises TofuKeyChangeError: a
        folder DEK is never sealed for a key the server swapped in.
        """
        if user_id == self._user_id:
            raise ValueError("Use the local keypair for the current user")
        if not self._token:
            self.authenticate()
        if self._get_signing_pk(user_id) is None:
            raise RuntimeError(f"No public keys are known for user {user_id}")
        row = self._db.fetchone(
            "SELECT encryption_pk FROM known_keys WHERE user_id = ?", (user_id,)
        )
        if row is None or len(bytes(row["encryption_pk"])) != 32:
            raise RuntimeError(f"No verified encryption key for user {user_id}")
        return bytes(row["encryption_pk"])

    def unpin_member_key(self, user_id: str) -> None:
        """Forget a member's pinned keys; the next contact pins them anew."""
        self._db.execute("DELETE FROM known_keys WHERE user_id = ?", (user_id,))
        self._tofu_checked_user_ids.discard(user_id)
        self._signing_key_rings.pop(user_id, None)

    def pin_envelope_holder_keys(
        self, exclude: tuple[str, ...] = (), former_sks: tuple[bytes, ...] = ()
    ) -> None:
        """Pin the keys of the members this account sealed folders for.

        Stateful test SM46: a device of the admin account that never synced a
        record of a member (the grant was made on another device) had no
        pinned key for them, so a re-key or an identity rotation there failed
        for good ('Missing verified encryption key'). The server's key is
        taken only when it opens one of the account's own envelopes for the
        member: then it is the key the granting device confirmed. ``former_sks``
        are identities this device held before (stateful test SM83: an
        envelope sealed under one opens with it, not with an identity rotated
        on another device and taken over here).
        """
        holders = self._db.fetchall(
            "SELECT DISTINCT user_id FROM access_envelopes "
            "WHERE created_by = ? AND user_id != ? "
            "AND user_id NOT IN (SELECT user_id FROM known_keys)",
            (self._user_id, self._user_id),
        )
        if not holders:
            return
        from ..crypto.envelope_crypto import open_envelope

        own_sks = (self._keypair.to_nacl_private_key().encode(), *former_sks)
        for holder in holders:
            user_id = holder["user_id"]
            if user_id in exclude:
                continue
            try:
                encryption_pk = self.verified_encryption_pk(user_id)
            except (RuntimeError, OSError) as exc:
                logger.warning("No key for member %s from the server: %s", user_id, exc)
                continue
            proven = False
            for env in self._db.fetchall(
                "SELECT encrypted_dek FROM access_envelopes WHERE created_by = ? AND user_id = ?",
                (self._user_id, user_id),
            ):
                for own_sk in own_sks:
                    try:
                        dek = open_envelope(bytes(env["encrypted_dek"]), bytes(own_sk), encryption_pk)
                    except Exception:
                        continue
                    dek[:] = b"\x00" * len(dek)
                    proven = True
                    break
                if proven:
                    break
            if not proven:
                # Left unpinned: whatever needs this member's key (and only
                # that) stops at 'Missing verified encryption key'.
                self.unpin_member_key(user_id)
                logger.warning(
                    "The server's key for member %s does not open the folders this account "
                    "shared with them; not pinned", user_id,
                )

    def _revoked_unpinned_holders(self, dek_ids: list[str], revoked_user_id: str) -> set[str]:
        """The members a re-key gives no envelope on the new DEK.

        Stateful test SM52: the rebase pulled an envelope another device
        granted on the revoked DEK; its member's key was never pinned here, so
        the rebase stopped on every push ('Missing verified encryption key').
        Their key is pinned as SM46 does; a member revoked on the server
        meanwhile gets nothing (the server refuses that envelope, and their
        own re-key would drop it).
        """
        marks = ",".join("?" * len(dek_ids))
        unpinned = {
            row["user_id"] for row in self._db.fetchall(
                f"SELECT DISTINCT user_id FROM access_envelopes WHERE dek_id IN ({marks}) "
                "AND user_id NOT IN (SELECT user_id FROM known_keys) AND user_id NOT IN (?, ?)",
                (*dek_ids, revoked_user_id, self._user_id),
            )
        }
        if not unpinned:
            return {revoked_user_id}
        self.pin_envelope_holder_keys(exclude=(revoked_user_id,))
        revoked = {u.get("id") for u in self.list_users() if u.get("status") == "revoked"}
        return {revoked_user_id} | (unpinned & revoked)

    def revoke_user(self, user_id: str) -> dict:
        """Revoke a user through the spec-defined admin endpoint."""
        if not self._token:
            self.authenticate()
        return self._request("DELETE", f"/api/users/{user_id}", auth=True)

    def list_shares(self) -> list[dict]:
        """List active Secure Share links through the admin endpoint."""
        if not self._token:
            self.authenticate()
        return self._request("GET", "/api/shares", auth=True)

    def revoke_share(self, share_id: str) -> dict:
        """Revoke a Secure Share link through the owner/admin endpoint."""
        if not self._token:
            self.authenticate()
        return self._request("DELETE", f"/api/share/{share_id}", auth=True)

    def poll_share_notifications(self) -> list[dict]:
        """Claim pending Secure Share view notifications for this user."""
        if not self._token:
            self.authenticate()
        return self._request("GET", "/api/share-notifications", auth=True)

    def get_ai_policy(self) -> Optional[dict]:
        """The account's signed remote AI kill switch, or None if never set.

        Untrusted: the caller verifies it (sezam.mcp.remote_policy).
        """
        if not self._token:
            self.authenticate()
        try:
            resp = self._request("GET", "/api/ai-policy", auth=True)
        except RuntimeError as exc:
            if not server_error(exc, 401):
                raise
            self.authenticate()  # the token expired
            resp = self._request("GET", "/api/ai-policy", auth=True)
        return (resp or {}).get("policy")

    def put_ai_policy(self, enabled: bool, epoch: int, signature_hex: str) -> dict:
        """Publish a signed remote AI kill switch for this account."""
        if not self._token:
            self.authenticate()
        return self._request(
            "PUT", "/api/ai-policy",
            {"enabled": enabled, "epoch": epoch, "signature": signature_hex},
            auth=True,
        )

    # ── Push ──

    @oplock.held
    def adopt_rotated_key_material(self, vault: "Vault", account_password: str) -> int:
        """Take over a password change made on another device (review 2052248 #1).

        The server's DEKs are wrapped under the KEK of the current account
        password, so this device derives it from the server-held salt and
        params, proves it via /auth/recover, opens the account keypair with it
        and re-wraps everything local under that KEK. The vault then unlocks
        with the account password and holds the server's key_epoch. A wrong
        password changes nothing. Returns the adopted key_epoch.
        """
        from urllib.parse import quote

        from .crud import open_server_keypair, recover_with_password, server_account_kdf

        username = self._get_username()
        meta = self._request("GET", f"/api/meta?username={quote(username)}") or {}
        if not meta.get("argon2_salt"):
            raise RuntimeError("Server did not return the account KDF parameters")
        salt = bytes.fromhex(meta["argon2_salt"])
        params = server_account_kdf(meta, self._db)
        try:
            kek, resp = recover_with_password(
                lambda body: self._request("POST", "/api/auth/recover", body),
                username, account_password, salt, params,
            )
        except RuntimeError as exc:
            if server_error(exc, 401) or server_error(exc, 403):
                raise RuntimeError("Wrong current account password") from exc
            raise
        server_keypair = None
        try:
            if resp.get("user_id") != self._db.get_meta("user_id"):
                raise RuntimeError("Server returned a different account")
            if bytes.fromhex(resp.get("argon2_salt") or "") != salt:
                raise RuntimeError("Server changed the account salt during recovery")
            server_keypair = open_server_keypair(resp, kek)
            if server_keypair is None:
                raise RuntimeError("Server holds no account keypair")
            key_epoch = int(resp.get("key_epoch") or 0)
            if self._server_lost_own_rotation(server_keypair, vault.keypair):
                # Capability run 277: the server went back to a backup from
                # before this device's identity rotation, which its team log
                # holds (member.keys). Its keypair is retired there; taking it
                # over left the device out of the team. The rotation goes out
                # again from the server's key material instead.
                vault.adopt_account_kek(kek, salt, params, key_epoch=key_epoch)
                proof = vault.change_password(
                    account_password, account_password,
                    rotate_identity=True, rotation_from=server_keypair,
                )
                proof[:] = b"\x00" * len(proof)
                server_keypair = None
                self._token = None
                self._push_cache.clear()
                logger.warning("The server lost this device's identity rotation; it is sent again")
                return key_epoch
            # SM61: the server's keypair is this device's own unconfirmed
            # identity rotation: it landed, its reply was lost.
            own_rotation_landed = bool(
                pending_states.rekey_batch(self._db).get("identity_rotation")
            ) and (server_keypair.signing_pk, server_keypair.encryption_pk) == (
                vault.keypair.signing_pk, vault.keypair.encryption_pk
            )
            vault.adopt_account_kek(
                kek, salt, params, key_epoch=key_epoch, own_rotation_landed=own_rotation_landed
            )
            self._db.set_meta(SERVER_KEY_MATERIAL_META, hashlib.sha256(
                bytes.fromhex(resp["encrypted_keypair"])
            ).hexdigest())
        finally:
            kek[:] = b"\x00" * len(kek)
        local = vault.keypair
        former_sk = None
        if (server_keypair.signing_pk, server_keypair.encryption_pk) != (
            local.signing_pk, local.encryption_pk
        ):
            # Org recovery replaced the account keypair; it opened under the
            # account KEK, so it is the account's own.
            former_sk = bytearray(local.to_nacl_private_key().encode())
            vault.rebind_server_identity(resp["user_id"], server_keypair)
            self._keypair = vault.keypair
            # Stateful test SM11: the ring loaded before held only the old
            # key, so the records just re-signed with the new one were
            # refused as forged on every push of this session.
            self._signing_key_rings.pop(resp["user_id"], None)
        else:
            server_keypair.zeroize()
        # The rotation bumped token_epoch; a token issued before it is dead.
        self._token = None
        # Cached push objects hold DEK wraps under the superseded KEK at the
        # same version (the re-wrap keeps versions); resending one would put
        # a DEK on the server that no device can open.
        self._push_cache.clear()
        if former_sk is not None:
            # Stateful test SM83: this device's envelopes are still sealed
            # under the identity it held; only that one proves the members'
            # keys, which a re-key or the next rotation here seals for.
            try:
                self.pin_envelope_holder_keys(former_sks=(former_sk,))
            except (RuntimeError, OSError) as exc:
                logger.warning("Member keys not pinned: %s", exc)
            finally:
                former_sk[:] = b"\x00" * len(former_sk)
        return key_epoch

    def prepare_key_change(self) -> None:
        """Log in and pull before a password, KDF or identity change.

        The change re-wraps every folder key this device holds, at its next
        version, and the server takes it only together with every active one
        (stateful test SM15). Built on folder keys another device changed or
        added since the last pull (a rotation taken over without a pull, a new
        folder), it was refused with 409 on every push. Raises before any
        local change when the device cannot log in or pull.
        """
        self.authenticate()
        result = self.pull()
        if result.get("rollback_warning") or self._db.get_meta(SERVER_ROLLBACK_META) is not None:
            # Stateful test SM19: the server was restored from a backup. Its
            # folder keys are older than this device's, so the change built on
            # them was refused with 409 on every push, while a full resync is
            # not allowed with the change pending.
            raise RuntimeError(
                "The server went back to an older state (restored from a backup?). "
                f"{FULL_RESYNC_HINT} Then change the keys again."
            )
        try:
            self.pin_envelope_holder_keys()  # an identity rotation re-seals them (SM46)
        except Exception as exc:  # a password change does not need them
            logger.warning("Member keys not pinned: %s", exc)

    def has_pending_key_change(self) -> bool:
        return pending_states.key_change_pending(self._db)

    @oplock.held
    def abandon_pending_change(self, vault: "Vault", account_password: str) -> int:
        """Drop this device's unsent password/key change for the server's (review e4cd15a #2).

        A change the server will never take (its journal predates the proof
        the server now asks for, proves a password the server no longer has,
        or lost to a rotation elsewhere) blocked every push and every new
        change for good. This takes the server's key material over with the
        password the server has now, as after a change made on another device;
        the local journal goes with it. Returns the adopted key_epoch.
        """
        pending_states.refuse_if_blocked(self._db, pending_states.ABANDON_KEY_CHANGE)
        return self.adopt_rotated_key_material(vault, account_password)

    @oplock.held
    def finish_pending_change(self, vault: "Vault", account_password: str) -> None:
        """Add the proof of the server's password to a change of an older
        version that kept none (review 4acfdde R11), so the next push sends it."""
        from .pre_proof_change import finish_pending_change

        finish_pending_change(self, vault, account_password)

    def _check_key_epoch(self, resp: dict) -> None:
        """Raise KeyEpochStale when the server holds key material we lack.

        A newer epoch always means another device rotated. At the SAME epoch
        only a device with an unpushed rotation can differ: its own rotation
        targeted that epoch, so if the server's key material is not the one
        this device holds, a rival rotation won the race (capability finding,
        run 10). Without the check the device pulled DEKs it cannot unwrap.
        """
        server_key_epoch = int(resp.get("key_epoch", 0))
        local_key_epoch = int(self._db.get_meta("key_epoch") or "0")
        if server_key_epoch > local_key_epoch:
            raise KeyEpochStale(server_key_epoch)
        last_pushed = pending_states.last_pushed_key_epoch(self._db)
        if "key_epoch" in resp and server_key_epoch < last_pushed:
            # Stateful test SM12: the server lost a key change it had taken
            # (restored from a backup). Its DEKs are wrapped under the KEK of
            # the password it has now; this device went on wrapping new ones
            # under its newer KEK, which no other device could ever open.
            raise KeyEpochStale(server_key_epoch)
        server_hash = resp.get("key_material_hash")
        local_keypair = self._db.get_meta("encrypted_keypair")
        # Review e4cd15a #2c: an org recovery on top of an unpushed change puts
        # this device two epochs ahead, so a rival rotation that moved the
        # server past what this device last pushed sits BELOW the local epoch.
        # Stateful test SM30: the server lost this device's change to epoch N
        # (restored from a backup) and another device's change then took N
        # again. With nothing pending here the epochs all matched, and the
        # DEKs that device wrapped since were pulled and could not be opened.
        known_hash = self._db.get_meta(SERVER_KEY_MATERIAL_META)
        if (
            server_key_epoch == last_pushed == local_key_epoch
            and server_hash and known_hash and server_hash != known_hash
        ):
            raise KeyEpochStale(server_key_epoch)
        if (
            last_pushed < server_key_epoch <= local_key_epoch
            and server_hash and local_keypair
            and server_hash != hashlib.sha256(bytes.fromhex(local_keypair)).hexdigest()
        ):
            raise KeyEpochStale(server_key_epoch)

    def _key_rotation_payload(self, key_epoch: int) -> dict:
        """New key material for the push that advances the server key_epoch.

        The server applies it in the same transaction as the DEK rewrap batch
        and the epoch, so no other device ever sees one without the other.
        """
        journal = pending_states.key_change_journal(self._db)
        if int(journal.get("epoch", -1)) != key_epoch:
            # Review e4cd15a #2b: the old advice (run change-password again)
            # proved the NEW password to the server and counted towards the lock.
            raise RuntimeError(
                "The password change of this device has no pending server journal; "
                "run 'sezam abandon-pending-change' to drop it and take over the "
                "account password the server has."
            )
        if self._dek_mgr is None:
            raise RuntimeError("Unlocked vault required to send a password change")
        argon2_salt = self._db.get_meta("argon2_salt")
        encrypted_keypair = self._db.get_meta("encrypted_keypair")
        if not argon2_salt or not encrypted_keypair:
            raise RuntimeError("Local password key material is incomplete")
        raw_params = self._db.get_meta("argon2_params")
        kdf_params = Argon2Params.from_dict(json.loads(raw_params)) if raw_params else Argon2Params()
        user_id = self._db.get_meta("user_id")
        auth_proof = open_auth_proof(journal, self._dek_mgr._kek, user_id)
        current_proof = open_current_auth_proof(journal, self._dek_mgr._kek, user_id)
        try:
            # With an identity rotation this is the new key, as the server expects.
            challenge_hex, signature_hex = self._signed_challenge()
            payload = {
                "encrypted_keypair": encrypted_keypair,
                "argon2_salt": argon2_salt,
                "auth_salt": argon2_salt,
                "auth_proof": auth_proof.hex(),
                "argon2_params": kdf_params.account_dict(),
                "challenge": challenge_hex,
                "signature": signature_hex,
            }
            if "identity" in journal and not getattr(self, "_identity_landed", False):
                payload["identity"] = dict(journal["identity"])
            if current_proof is not None:
                payload["current_auth_proof"] = current_proof.hex()
            payload.update(self._recovery_proof(journal, user_id))
            return payload
        finally:
            auth_proof[:] = b"\x00" * len(auth_proof)
            if current_proof is not None:
                current_proof[:] = b"\x00" * len(current_proof)

    def _recovery_proof(self, journal: dict, user_id: str) -> dict:
        """Org recovery's reset proof (review e4cd15a #1): a fresh server
        challenge signed by the key derived from the rebuilt recovery secret.
        It authorizes the change without the old password or another admin;
        empty when the journal has no secret or the server has no recovery."""
        secret = open_recovery_secret(journal, self._dek_mgr._kek, user_id)
        if secret is None:
            return {}
        try:
            try:
                challenge = self._request("POST", "/api/org-recovery/challenge", {})["challenge"]
            except RuntimeError as exc:
                logger.warning("No org recovery proof for the password change: %s", exc)
                return {}
            signature = org_recovery_signing_key(secret).sign(bytes.fromhex(challenge)).signature
            return {"recovery_challenge": challenge, "recovery_signature": signature.hex()}
        finally:
            secret[:] = b"\x00" * len(secret)

    def _restore_org_recovery_blob(self, journal: dict, key_epoch: int) -> None:
        """After an org recovery's change landed, wrap the new KEK into the
        server blob under the same recovery key, so the shares keep working
        (web too) and the server does not report the recovery stale."""
        user_id = self._db.get_meta("user_id")
        secret = open_recovery_secret(journal, self._dek_mgr._kek, user_id)
        if secret is None:
            return
        try:
            wrapped = org_recovery_server_wrap(self._dek_mgr._kek, secret)
            signing_key = org_recovery_signing_key(secret)
            threshold = int(self._db.get_meta("org_recovery_threshold") or "2")
            total = int(self._db.get_meta("org_recovery_shares") or "2")
            body = {
                "wrapped_kek": wrapped.hex(),
                "recovery_signing_pk": bytes(signing_key.verify_key).hex(),
                "threshold": threshold,
                "total_shares": total,
                "key_epoch": key_epoch,
                # Review d615826: without the password the server takes the
                # same recovery key's blob only signed by that key.
                "recovery_signature": signing_key.sign(org_recovery_rewrap_message(
                    user_id, key_epoch, threshold, total, wrapped,
                )).signature.hex(),
            }
        finally:
            secret[:] = b"\x00" * len(secret)
        # Capability run 316: the team log carries it too (next push).
        self._db.set_meta_json("org_recovery_server_wrap", {k: v for k, v in body.items() if k != "recovery_signature"})
        # Review 526419e N5: a failed re-wrap left the old KEK's blob on the server for
        # good once the journal was gone, so the body is kept and every push retries it.
        pending_states.set_org_recovery_rewrap(self._db, body)
        self.retry_org_recovery_rewrap()

    def retry_org_recovery_rewrap(self) -> bool:
        """Send a server blob re-wrap that failed before. True when none waits."""
        body = pending_states.org_recovery_rewrap(self._db)
        if body is None:
            return True
        try:
            self._request("POST", "/api/org-recovery/store", body, auth=True)
        except RuntimeError as exc:
            if server_error(exc, 409) or server_error(exc, 403):
                # The account moved on (another password change or another
                # admin's recovery): this wrap is void; unlock reports that the
                # server lacks this vault's recovery key (review 526419e V5).
                # 403: a body saved before review d615826 carries no recovery
                # signature, and the server never takes it without one.
                pending_states.clear_org_recovery_rewrap(self._db)
            logger.warning("Could not re-wrap the server org recovery blob: %s", exc)
            return False
        pending_states.clear_org_recovery_rewrap(self._db)
        return True

    @classmethod
    def register_org_recovery(
        cls, vault: "Vault", password: str, *, replace_other_admin: bool = False,
    ) -> bool:
        """Register the recovery key the vault just set up on its server
        (review e4cd15a #1). False when the vault is not connected; raises
        ValueError for a wrong password, RuntimeError when the server refuses.
        ``replace_other_admin`` replaces another admin's recovery (review 526419e S3)."""
        server_url = vault.db.get_meta("server_url")
        user_id = vault.db.get_meta("user_id")
        body = pending_states.org_recovery_registration(vault.db)
        if not server_url or not user_id or body is None:
            return False
        if replace_other_admin:
            body = {**body, "replace_other_admin": True}
        proof = vault.current_auth_proof(password)
        try:
            client = cls(vault.db, server_url, vault.keypair, user_id)
            client.set_dek_manager(vault.dek_mgr)
            client.store_org_recovery(body, proof)
        finally:
            proof[:] = b"\x00" * len(proof)
        pending_states.clear_org_recovery_registration(vault.db)
        return True

    @classmethod
    def org_recovery_after_connect(cls, vault: "Vault", password: str) -> Optional[str]:
        """Capability review run 91: an org recovery set up before 'connect'
        is registered now. Returns what to tell the user, or None when org
        recovery is not set up on this vault."""
        if not vault.org_recovery_configured() or not vault.db.get_meta("server_url"):
            return None
        from .org_recovery_server import LOG_ADMIN_NOTE, OTHER_ADMIN_NOTE, _log_admin, server_status, superseded_note

        status = server_status(vault)
        owner = status.get("created_by") if status.get("configured") else None
        if owner and owner != vault.db.get_meta("user_id"):
            # Review 526419e S3: a registration (or '--replace') only gets a 409.
            return LOG_ADMIN_NOTE if _log_admin(vault) else OTHER_ADMIN_NOTE
        if note := superseded_note(vault.db, status):  # review c78fd19 R13-10
            return note
        try:
            if cls.register_org_recovery(vault, password):
                return ("The server knows this vault's org recovery: after 'sezam "
                        "org-recovery' it accepts the new password without the old one.")
        except (RuntimeError, ValueError) as exc:
            if note := superseded_note(vault.db, exc=exc):
                return note
            return (f"Warning: the server did not take this vault's org recovery ({exc}). "
                    "Run 'sezam org-recovery-setup --replace' and hand out the new shares.")
        if owner and not status.get("stale"):
            return None
        return ("Warning: the server does not know this vault's org recovery (it was set "
                "up before the vault took the server's account key). The shares would "
                "reset this vault, but the server would refuse the new password. Run "
                "'sezam org-recovery-setup --replace' and hand out the new shares.")

    def store_org_recovery(self, body: dict, current_auth_proof: bytes) -> None:
        """Register this vault's org recovery key on the server (review e4cd15a #1)."""
        if not self._token:
            self.authenticate()
        self._request(
            "POST", "/api/org-recovery/store",
            {**body, "current_auth_proof": bytes(current_auth_proof).hex()}, auth=True,
        )

    def server_org_recovery_stale(self) -> bool:
        """True when this account's org recovery on the server wraps an old KEK.

        The blob is sealed under a recovery key only the share holders can
        rebuild, so no client can re-wrap it after a password change: an
        admin has to set org recovery up again.
        """
        try:
            status = self._request("GET", "/api/org-recovery/status") or {}
        except RuntimeError:
            return False
        return bool(status.get("stale")) and status.get("created_by") == self._user_id

    def _signer_id(self, obj: dict) -> str:
        """The account whose key ``_verify_object_signature`` checks.

        Ownership remains stable across admin re-key; the latest version's
        signer is verified."""
        return (
            obj.get("signature_user_id")
            or obj.get("owner_id")
            or obj.get("user_id")
            or self._user_id
        )

    def _verify_object_signature(self, obj: dict) -> bool:
        """Verify the client_signature on a pulled object using known_keys cache."""
        signature_hex = obj.get("signature") or obj.get("client_signature")
        if not signature_hex:
            return False

        signer_id = self._signer_id(obj)
        signing_pks = self._get_signing_pks(signer_id)
        if not signing_pks:
            return False

        try:
            payload = base64.b64decode(obj["payload"], validate=True)
            actual_payload_hash = hashlib.sha256(payload).hexdigest()
            payload_hash = obj.get("payload_hash")
            if not payload_hash or payload_hash.lower() != actual_payload_hash:
                return False

            canonical = self._build_signature_payload(
                id=obj["id"],
                object_type=obj["object_type"],
                parent_ref=obj.get("parent_ref"),
                target_user_id=obj.get("target_user_id"),
                is_deleted=obj.get("is_deleted", 0),
                version=obj.get("version", 1),
                payload_hash=payload_hash,
            )
            signature_bytes = bytes.fromhex(signature_hex)
            commit_seq = obj.get("commit_seq")
            for signing_pk in signing_pks:
                bound = self._archive_bound(signer_id, signing_pk)
                if bound is None and self._log_retired_key(signer_id, signing_pk):
                    continue
                if bound is not None and not (
                    isinstance(commit_seq, int)
                    and self._verify_since_seq < commit_seq <= bound
                ):
                    # An archived key vouches only for what was committed
                    # before its rotation (review 688edcb V4); a delta can
                    # not carry objects at or below the seq it started after.
                    continue
                try:
                    VerifyKey(signing_pk).verify(canonical, signature_bytes)
                    return True
                except (BadSignatureError, ValueError):
                    continue
            return False
        except (ValueError, KeyError) as exc:
            logger.warning("Signature verification failed for %s: %s", obj.get("id"), exc)
            return False

    def confirm_tofu_key_change(
        self, change: TofuKeyChangeError, verified_fingerprint: str
    ) -> None:
        """Persist a changed peer key only after its fingerprint was verified."""
        detected_fingerprint = hashlib.sha256(
            change.signing_pk + change.encryption_pk
        ).hexdigest()
        if (
            verified_fingerprint != change.new_fingerprint
            or change.new_fingerprint != detected_fingerprint
        ):
            raise ValueError("Verified fingerprint does not match the detected key change")

        existing = self._db.fetchone(
            "SELECT fingerprint FROM known_keys WHERE user_id = ?",
            (change.user_id,),
        )
        if existing is None or existing["fingerprint"] != change.old_fingerprint:
            raise RuntimeError("Pinned key changed while confirmation was pending")

        self._db.execute(
            "UPDATE known_keys SET signing_pk = ?, encryption_pk = ?, fingerprint = ?, "
            "last_verified = ? WHERE user_id = ?",
            (
                change.signing_pk,
                change.encryption_pk,
                change.new_fingerprint,
                int(time.time() * 1000),
                change.user_id,
            ),
        )
        # The caller verified this fingerprint, so sharing needs no second ask.
        confirmed = dict(self._db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
        confirmed[change.user_id] = change.new_fingerprint
        self._db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
        self._tofu_checked_user_ids.add(change.user_id)
        ring = change.signing_key_ring
        if not ring or ring[0] != change.signing_pk:
            ring = (change.signing_pk,)
        self._signing_key_rings[change.user_id] = ring

    @staticmethod
    def _key_ring_from_response(
        user_id: str,
        current_signing_pk: bytes,
        current_encryption_pk: bytes,
        response: dict,
    ) -> tuple[bytes, ...]:
        """Current key plus archived keys reachable by rotation certificates.

        An archived key is trusted only if its successor key (the current one
        or an already trusted archive) signed key_rotation_message(), so the
        server cannot inject "historical" keys to forge old records. When the
        server has the old key's authorization of that rotation (rotations
        since review 688edcb V4), it must verify too. Which objects an archived
        key may still vouch for is bounded separately (_archive_bound).
        """
        archives = response.get("archived_keys", [])
        if not isinstance(archives, list):
            raise ValueError("Malformed archived key list")

        candidates = []
        for archive in archives:
            if not isinstance(archive, dict):
                raise ValueError("Malformed archived key")
            fields = [archive.get(name) for name in (
                "signing_pk", "encryption_pk", "key_fingerprint",
                "successor_signing_pk", "rotation_signature",
            )]
            if not all(isinstance(value, str) for value in fields):
                continue  # uncertified legacy archive: never trusted
            signing_pk, encryption_pk = bytes.fromhex(fields[0]), bytes.fromhex(fields[1])
            if len(signing_pk) != 32 or len(encryption_pk) != 32:
                raise ValueError("Archived public keys must be 32 bytes")
            if hashlib.sha256(signing_pk + encryption_pk).hexdigest() != fields[2]:
                raise ValueError("Archived key fingerprint mismatch")
            authorization = archive.get("authorization_signature")
            if authorization is not None and not isinstance(authorization, str):
                raise ValueError("Malformed archived key authorization")
            candidates.append((
                signing_pk, encryption_pk, bytes.fromhex(fields[3]), bytes.fromhex(fields[4]),
                bytes.fromhex(authorization) if authorization else None,
            ))

        trusted = {current_signing_pk: current_encryption_pk}
        keys = [current_signing_pk]
        progress = True
        while progress:
            progress = False
            for signing_pk, encryption_pk, successor_pk, cert, authorization in candidates:
                if signing_pk in trusted or successor_pk not in trusted:
                    continue
                message = key_rotation_message(
                    user_id, signing_pk, encryption_pk, successor_pk, trusted[successor_pk]
                )
                try:
                    VerifyKey(successor_pk).verify(message, cert)
                    if authorization is not None:
                        VerifyKey(signing_pk).verify(message, authorization)
                except Exception:
                    continue
                trusted[signing_pk] = encryption_pk
                keys.append(signing_pk)
                progress = True
        return tuple(keys)

    _ARCHIVE_BOUNDS_META = "archived_key_bounds"

    def _remember_archive_bounds(self, user_id: str, response: dict) -> None:
        """Review 688edcb V4: an archived key vouches only for objects
        committed before its rotation (``retired_seq``). The first bound this
        device sees is pinned, so a server holding the leaked key cannot later
        stretch it over objects it signs now. An archive without a bound (a
        server from before V4) vouches for no pulled object at all.
        """
        pinned_all = self._db.get_meta_json(self._ARCHIVE_BOUNDS_META) or {}
        pinned = dict(pinned_all.get(user_id) or {})
        bounds: dict[bytes, int] = {}
        archives = response.get("archived_keys")
        for archive in archives if isinstance(archives, list) else []:
            if not isinstance(archive, dict) or not isinstance(archive.get("signing_pk"), str):
                continue
            key_hex = archive["signing_pk"].lower()
            served = archive.get("retired_seq")
            served = served if isinstance(served, int) and not isinstance(served, bool) else None
            known = pinned.get(key_hex)
            if served is not None and (known is None or served < known):
                pinned[key_hex] = known = served
            bounds[bytes.fromhex(key_hex)] = known if known is not None else 0
        self._archive_bounds[user_id] = bounds
        if pinned != (pinned_all.get(user_id) or {}):
            pinned_all[user_id] = pinned
            self._db.set_meta_json(self._ARCHIVE_BOUNDS_META, pinned_all)

    def _archive_bound(self, user_id: str, signing_pk: bytes) -> Optional[int]:
        """Last commit_seq ``signing_pk`` may sign for, or None for a current key."""
        return self._archive_bounds.get(user_id, {}).get(bytes(signing_pk))

    def _authorized_our_rotation(self, signing_pk: bytes, encryption_pk: bytes) -> bool:
        """Whether these keys signed this device's pending identity rotation."""
        journal = self._pending_identity()
        if journal is None:
            return False
        identity = journal["identity"]
        if (
            identity.get("new_signing_pk") != self._keypair.signing_pk.hex()
            or identity.get("new_encryption_pk") != self._keypair.encryption_pk.hex()
        ):
            return False
        message = key_rotation_message(
            self._user_id, signing_pk, encryption_pk,
            self._keypair.signing_pk, self._keypair.encryption_pk,
        )
        try:
            VerifyKey(signing_pk).verify(
                message, bytes.fromhex(identity["authorization_signature"])
            )
        except Exception:
            return False
        return True

    def _get_signing_pks(self, user_id: str) -> tuple[bytes, ...]:
        cached = self._signing_key_rings.get(user_id)
        if cached is not None:
            return cached

        if user_id == self._user_id:
            try:
                response = self._request("GET", f"/api/users/{user_id}/keys", auth=True)
                signing_pk = bytes.fromhex(response["signing_pk"])
                encryption_pk = bytes.fromhex(response["encryption_pk"])
                ring = self._key_ring_from_response(
                    user_id, signing_pk, encryption_pk, response
                )
                self._remember_archive_bounds(user_id, response)
                if (
                    signing_pk != self._keypair.signing_pk
                    or encryption_pk != self._keypair.encryption_pk
                ):
                    # Until a rotation of this device lands, the server's key
                    # is the old one: the one that authorized the new key.
                    if not self._authorized_our_rotation(signing_pk, encryption_pk):
                        if self._pending_identity() is None:
                            # Stateful test SM14: the account's key is not
                            # this device's and no rotation of it is pending
                            # (rotated elsewhere, or a restored server lost
                            # this device's rotation). Verifying its records
                            # against the local key alone failed every sync;
                            # the way out is the key material the server holds.
                            raise KeyEpochStale()
                        raise ValueError("Server current key does not match local identity")
                    self._rotation_authorizer = bytes(signing_pk)
                    ring = (self._keypair.signing_pk,) + ring
                self._signing_key_rings[user_id] = ring
                return ring
            except KeyEpochStale:
                raise
            except Exception as exc:
                logger.warning("Could not load historical keys for current user: %s", exc)
                return (self._keypair.signing_pk,)

        signing_pk = self._get_signing_pk(user_id)
        if signing_pk is None:
            return ()
        return self._signing_key_rings.get(user_id, (signing_pk,))

    def _get_signing_pk(self, user_id: str) -> Optional[bytes]:
        """Resolve and TOFU-check a user's current Ed25519 signing public key."""
        if user_id == self._user_id:
            return self._keypair.signing_pk

        existing = self._db.fetchone(
            "SELECT signing_pk, encryption_pk, fingerprint, first_seen, last_verified "
            "FROM known_keys WHERE user_id = ?",
            (user_id,),
        )
        if existing and user_id in self._tofu_checked_user_ids:
            return bytes(existing["signing_pk"])

        try:
            resp = self._request("GET", f"/api/users/{user_id}/keys", auth=True)
            if resp and resp.get("signing_pk") and resp.get("encryption_pk"):
                signing_pk = bytes.fromhex(resp["signing_pk"])
                encryption_pk = bytes.fromhex(resp["encryption_pk"])
                fingerprint = hashlib.sha256(signing_pk + encryption_pk).hexdigest()
                now_ms = int(time.time() * 1000)

                if existing:
                    keys_changed = (
                        bytes(existing["signing_pk"]) != signing_pk
                        or bytes(existing["encryption_pk"]) != encryption_pk
                    )
                    if keys_changed:
                        warning = {
                            "user_id": user_id,
                            "old_fingerprint": existing["fingerprint"],
                            "new_fingerprint": fingerprint,
                        }
                        self._tofu_warnings.append(warning)
                        logger.warning(
                            "TOFU WARNING: public keys changed for user %s! "
                            "Possible MITM attack or legitimate key rotation. "
                            "Old fingerprint: %s, new: %s",
                            user_id,
                            warning["old_fingerprint"],
                            warning["new_fingerprint"],
                        )
                        try:
                            ring = self._key_ring_from_response(
                                user_id, signing_pk, encryption_pk, resp
                            )
                            self._remember_archive_bounds(user_id, resp)
                        except Exception:
                            ring = (signing_pk,)
                        raise TofuKeyChangeError(
                            user_id,
                            warning["old_fingerprint"],
                            warning["new_fingerprint"],
                            signing_pk,
                            encryption_pk,
                            ring,
                        )
                    first_seen = existing["first_seen"]
                    last_verified = existing["last_verified"]
                else:
                    first_seen = now_ms
                    last_verified = now_ms

                self._db.execute(
                    "INSERT OR REPLACE INTO known_keys "
                    "(user_id, signing_pk, encryption_pk, fingerprint, first_seen, last_verified) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        signing_pk,
                        encryption_pk,
                        fingerprint,
                        first_seen,
                        last_verified,
                    ),
                )
                self._signing_key_rings[user_id] = self._key_ring_from_response(
                    user_id, signing_pk, encryption_pk, resp
                )
                self._remember_archive_bounds(user_id, resp)
                self._tofu_checked_user_ids.add(user_id)
                return signing_pk
        except TofuKeyChangeError:
            raise
        except Exception:
            logger.warning("Could not refresh signing key for user %s", user_id)

        self._tofu_checked_user_ids.add(user_id)
        if existing:
            return bytes(existing["signing_pk"])
        return None

    # ── HTTP helpers ──

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        auth: bool = False,
        extra_headers: Optional[dict[str, str]] = None,
        relogin: bool = True,
    ) -> Optional[dict]:
        """Make HTTP request to server."""
        url = self._server_url + path

        headers = {"Content-Type": "application/json"}
        if auth and not self._token and relogin:
            # A failed re-login (below) leaves no session; a caller that
            # tolerated that error must not go on without one.
            self.authenticate()
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if extra_headers:
            headers.update(extra_headers)

        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error = ServerError(e.code, e.read().decode("utf-8", errors="replace"))
            if (
                e.code == 401 and auth and self._token and relogin
                and error.code in (TOKEN_REVOKED, TOKEN_INVALID)
            ):
                # Stateful test SM10: a password change or identity rotation on
                # another device (or the token's age) ended this session. The
                # server refused before doing anything, so logging in again
                # and repeating is safe; the new login says what changed.
                self._token = None
                self.authenticate()
                return self._request(method, path, body, auth, extra_headers, relogin=False)
            raise error

    def _get_username(self) -> str:
        """Get username from vault metadata."""
        # N3: a vault created before the CLI trimmed may hold " alice".
        return normalize_username(self._db.get_meta("username") or "") or "admin"
