"""Pydantic schemas for API request/response validation."""

from __future__ import annotations

import base64
import json
import time
from typing import Annotated, Any, Literal, Optional

import sezam_sync_core
from argon2 import Type, extract_parameters
from argon2.exceptions import InvalidHashError
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
MAX_SYNC_OBJECTS = 1_000
MAX_SYNC_PAYLOAD_BYTES = 1024 * 1024
MAX_SYNC_PAYLOAD_B64_LENGTH = 4 * ((MAX_SYNC_PAYLOAD_BYTES + 2) // 3)
# Review d150605 #3: an all-or-nothing batch over one request's limits (a key
# epoch advance re-wraps every DEK) is staged in parts and applied at once.
MAX_STAGED_OBJECTS = 100_000
MAX_STAGED_BYTES = 256 * 1024 * 1024
MAX_USERNAME_LENGTH = 255
# Lockout review N3: " alice" and "alice " are the account "alice" on every
# request, so surrounding whitespace never creates a second account or fails
# a login against the one that exists. Review 688edcb N3: the trimmed set is
# the union of what every client trims (Python str.strip, JS/Dart trim: NBSP,
# BOM, NEL, \x1c-\x1f, zero-width space), and the name is NFC, so "Šimon"
# typed as NFD on one device and NFC on another is one account, not two
# identical-looking ones. The core's rule (docs/CORE_UNIFICATION.md U6), the
# same bytes as every client and the reseed signature.


def normalize_username(value: str) -> str:
    out = json.loads(sezam_sync_core.call("normalize_username", json.dumps({"value": value})))
    if "error" in out:
        raise ValueError(out["error"])
    return out["ok"]


Username = Annotated[
    str,
    BeforeValidator(lambda v: normalize_username(v) if isinstance(v, str) else v),
    StringConstraints(min_length=1, max_length=MAX_USERNAME_LENGTH),
]
SHARE_PIN_ARGON2_MEMORY_COST = 65_536
SHARE_PIN_ARGON2_TIME_COST = 3
SHARE_PIN_ARGON2_PARALLELISM = 4
SHARE_PIN_ARGON2_SALT_LENGTH = 16
SHARE_PIN_ARGON2_HASH_LENGTH = 32
# Whole bytes of hex: bytes.fromhex() on these can never raise (no 500s).
HEX_BYTES = r"^(?:[0-9a-fA-F]{2})+$"
HEX_KEY = r"^[0-9a-fA-F]{64}$"
HEX_CHALLENGE = r"^[0-9a-fA-F]{80}$"
HEX_SIGNATURE = r"^[0-9a-fA-F]{128}$"
# Object ids are ULIDs and fit VARCHAR(26) exactly: anything else used to be
# truncated silently by INSERT IGNORE (review 2052248).
OBJECT_ID = r"^[0-9A-Za-z]{26}$"


def validate_share_pin_hash(value: str) -> str:
    try:
        params = extract_parameters(value)
    except InvalidHashError as exc:
        raise ValueError("pin_hash must be an encoded Argon2id hash") from exc
    if params.type is not Type.ID or params.version != 19:
        raise ValueError("pin_hash must use Argon2id version 19")
    if (
        params.memory_cost != SHARE_PIN_ARGON2_MEMORY_COST
        or params.time_cost != SHARE_PIN_ARGON2_TIME_COST
        or params.parallelism != SHARE_PIN_ARGON2_PARALLELISM
        or params.salt_len != SHARE_PIN_ARGON2_SALT_LENGTH
        or params.hash_len != SHARE_PIN_ARGON2_HASH_LENGTH
    ):
        raise ValueError("pin_hash must use the server Argon2id PIN policy")
    return value


# ── Auth ──

class ChallengeRequest(BaseModel):
    username: Username

class ChallengeResponse(BaseModel):
    challenge: str  # hex-encoded 32B random + server_timestamp
    timestamp: int  # server_timestamp (Unix ms)

class VerifyRequest(BaseModel):
    username: Username
    challenge: str = Field(min_length=1, max_length=80, pattern=HEX_BYTES)
    signature: str = Field(min_length=1, max_length=128, pattern=HEX_BYTES)
    # The team log's current key over the same challenge (capability run 300).
    current_key_signature: Optional[str] = Field(default=None, max_length=128, pattern=HEX_BYTES)

class VerifyResponse(BaseModel):
    token: str  # JWT
    user_id: str
    # The account's current name: a device signed in under the name the
    # migration moved it off stores this one (review e4cd15a, low).
    username: Optional[str] = None
    is_admin: bool
    # SHA-256 of the account's current encrypted_keypair: a browser that
    # signed in with a cached copy checks it is still the account's (N5).
    key_material_hash: Optional[str] = None

class RefreshRequest(BaseModel):
    challenge: str = Field(pattern=HEX_CHALLENGE)  # from /auth/challenge
    signature: str = Field(pattern=HEX_SIGNATURE)  # Ed25519 over challenge

class LogoutRequest(BaseModel):
    token: str

class ProvisionRequest(BaseModel):
    token: str  # provisioning token (plain, will be hashed)
    username: Username

class ProvisioningTokenResponse(BaseModel):
    token: str
    username: str
    expires_at: int

class ProvisionResponse(BaseModel):
    encrypted_keypair: str  # hex
    argon2_salt: str  # hex
    user_id: str  # canonical KEYPAIR_WRAP object_id
    argon2_params: Optional[dict] = None

class RecoverRequest(BaseModel):
    username: Username
    auth_proof: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")
    # The params the proof was derived with. An account stored before
    # per-account params (NULL) adopts them once the proof matches (N2).
    argon2_params: Optional["AccountKdfParams"] = None
    # One-time code from an admin unlock (review e4cd15a): this proof is
    # verified even when the locked name's rations are used up.
    unlock_code: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{20}$")


ACCOUNT_KDF_MAX_MEMORY_KIB = 262_144  # 256 MiB


class AccountKdfParams(BaseModel):
    """Argon2id parameters that derive an account's KEK + auth proof.

    Stored per user so every client derives the same KEK regardless of which
    device created the account (desktop/web/mobile use different defaults).
    """

    model_config = ConfigDict(extra="ignore")

    time_cost: int = Field(ge=2, le=20)
    # One cap for the server and every client (lockout review #6): mobile
    # cannot derive above 256 MiB, so an account stored with more locked it out.
    memory_cost: int = Field(ge=65_536, le=ACCOUNT_KDF_MAX_MEMORY_KIB)  # KiB
    parallelism: int = Field(ge=1, le=8)
    hash_len: Literal[64] = 64


class StoredAccountKdfParams(AccountKdfParams):
    """Read side: params stored before the 256 MiB cap are still reported as
    they are (any other value would derive a KEK that opens nothing)."""

    memory_cost: int = Field(ge=65_536, le=1_048_576)


DEFAULT_ACCOUNT_KDF = {
    "time_cost": 3,
    "memory_cost": 131_072,
    "parallelism": 4,
    "hash_len": 64,
}


# Account KDF params each client creates accounts with (web/mobile, desktop).
# A name without an account answers with one of them, picked per name.
CLIENT_DEFAULT_ACCOUNT_KDFS = (
    DEFAULT_ACCOUNT_KDF,
    {"time_cost": 3, "memory_cost": 262_144, "parallelism": 4, "hash_len": 64},
)


def account_kdf_params(stored: Optional[str]) -> dict:
    """Stored per-account KDF JSON → validated dict (legacy NULL → default)."""
    if stored:
        try:
            return StoredAccountKdfParams.model_validate_json(stored).model_dump()
        except ValueError:
            pass
    return dict(DEFAULT_ACCOUNT_KDF)

class RecoverResponse(BaseModel):
    encrypted_keypair: str  # hex
    argon2_salt: str  # hex
    user_id: str  # canonical KEYPAIR_WRAP object_id
    argon2_params: dict = Field(default_factory=lambda: dict(DEFAULT_ACCOUNT_KDF))
    # Epoch of the key material above; a device that opened it adopts this epoch.
    key_epoch: int = 0

class KeypairUploadRequest(BaseModel):
    encrypted_keypair: str = Field(min_length=1, max_length=4096, pattern=HEX_BYTES)
    argon2_salt: str = Field(pattern=r"^[0-9a-fA-F]{32}$")  # hex
    auth_salt: str = Field(pattern=r"^[0-9a-fA-F]{32}$")  # hex
    auth_proof: str = Field(pattern=r"^[0-9a-fA-F]{64}$")  # hex
    # Required (lockout review N2): key material stored without its params
    # leaves every other device guessing the KDF of the account. Optional in
    # the schema only so an older client gets 426 with a reason (review
    # 688edcb N2), not a 422; routers.auth.require_kdf_params_json refuses None.
    argon2_params: Optional[AccountKdfParams] = None
    # Required with a full JWT: fresh /auth/challenge signed by the current
    # signing key, so a stolen bearer token alone cannot replace key material.
    challenge: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{80}$")
    signature: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{128}$")


RecoverRequest.model_rebuild()


class KeyVoucherList(BaseModel):
    """Goal #443: object versions a retired identity key still vouches for,
    as [id, version, payload_hash], signed by the account's current key
    (src/sezam/key_vouchers.py checks the entries and the signature)."""

    signing_pk: str = Field(pattern=HEX_KEY)
    entries: list[list[Any]] = Field(max_length=200_000)
    signature: str = Field(pattern=HEX_SIGNATURE)


class IdentityRotation(BaseModel):
    """New identity keys (idea #11: a leaked signing/encryption key is replaced).

    Both keys sign key_rotation_message(user, old keys, new keys): the new one
    as the rotation certificate clients use to trust the archived old key, the
    old one as the authorization of its successor.
    """

    new_signing_pk: str = Field(pattern=HEX_KEY)
    new_encryption_pk: str = Field(pattern=HEX_KEY)
    rotation_signature: str = Field(pattern=HEX_SIGNATURE)
    authorization_signature: str = Field(pattern=HEX_SIGNATURE)
    # Goal #443: signed by the NEW key; the old key's objects verify under
    # them only. Stored in the push's transaction.
    key_vouchers: list[KeyVoucherList] = Field(default_factory=list, max_length=64)


class KeyRotationRequest(KeypairUploadRequest):
    # Set when the key epoch advance also replaces the identity keypair: the
    # batch objects are then signed by the new key, the challenge by the old.
    identity: Optional[IdentityRotation] = None
    # Review 688edcb K1: the push proves the CURRENT password, otherwise the
    # identity key alone (the thing a rotation is for when it leaked) replaces
    # the password. Instead of it: a challenge signed by the org recovery key
    # (the recovery admin's reset) or an admin's key-reset grant.
    current_auth_proof: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    recovery_challenge: Optional[str] = Field(default=None, pattern=HEX_CHALLENGE)
    recovery_signature: Optional[str] = Field(default=None, pattern=HEX_SIGNATURE)


class KdfParamsBackfillRequest(BaseModel):
    """A device holding the account's key material reports the KDF params of
    an account stored without them (lockout review N2)."""

    argon2_salt: str = Field(pattern=r"^[0-9a-fA-F]{32}$")  # hex, must be current
    argon2_params: AccountKdfParams
    challenge: str = Field(pattern=r"^[0-9a-fA-F]{80}$")
    signature: str = Field(pattern=r"^[0-9a-fA-F]{128}$")


class KeyMaterialArchiveRequest(BaseModel):
    """Review 688edcb: reading or purging the archived key material (keypair
    under OLD passwords) needs the current password, not just a token."""

    auth_proof: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


# ── Bootstrap ──

class BootstrapStatusResponse(BaseModel):
    needs_setup: bool
    # Set when an unfinished first-admin setup exists that this network may
    # not redo: the explanation to show instead of a login nobody can pass.
    unfinished_setup: Optional[str] = None

class BootstrapRequest(BaseModel):
    username: Username
    signing_pk: str = Field(pattern=HEX_KEY)
    encryption_pk: str = Field(pattern=HEX_KEY)
    # Reseed (`sezam server reseed`): keep an existing identity on an empty
    # server. All four ride together and the signature (over a fresh
    # /auth/challenge, see auth.reseed_message) proves the identity key.
    user_id: Optional[str] = Field(default=None, pattern=OBJECT_ID)
    key_epoch: int = Field(default=0, ge=0, le=2**31 - 1)
    challenge: Optional[str] = Field(default=None, pattern=HEX_CHALLENGE)
    signature: Optional[str] = Field(default=None, pattern=HEX_SIGNATURE)

class BootstrapResponse(BaseModel):
    user_id: str
    token: str  # onboarding JWT (scope=keypair_upload)

class RejoinRequest(BaseModel):
    """`sezam server rejoin`: a member the team log names, whose account a
    restored backup lost, comes back under that id (review 8595ec1 #1)."""
    username: Username
    user_id: str = Field(pattern=OBJECT_ID)
    signing_pk: str = Field(pattern=HEX_KEY)
    encryption_pk: str = Field(pattern=HEX_KEY)
    key_epoch: int = Field(default=0, ge=0, le=2**31 - 1)
    challenge: str = Field(pattern=HEX_CHALLENGE)
    signature: str = Field(pattern=HEX_SIGNATURE)


# ── Users ──

class InviteResponse(BaseModel):
    invitation_token: str  # plain text (client shows to user)
    expires_at: int

class RegisterRequest(BaseModel):
    invitation_token: str = Field(min_length=1, max_length=256)
    username: Username
    signing_pk: str = Field(pattern=HEX_KEY)
    encryption_pk: str = Field(pattern=HEX_KEY)

class RegisterResponse(BaseModel):
    user_id: str
    token: str  # onboarding JWT (15min, scope=keypair_upload)

class UserInfo(BaseModel):
    id: str
    username: str
    status: str
    is_admin: bool
    key_fingerprint: str
    signing_pk: Optional[str] = None      # hex-encoded Ed25519 public key
    encryption_pk: Optional[str] = None   # hex-encoded X25519 public key
    created_at: int

# ── Remote AI kill switch ──

class AIPolicyPut(BaseModel):
    enabled: bool
    epoch: int = Field(ge=1, le=2**63 - 1)
    signature: str = Field(pattern=HEX_SIGNATURE)  # Ed25519 hex


class AIPolicy(BaseModel):
    user_id: str
    enabled: bool
    epoch: int
    signature: str
    updated_at: int


class AIPolicyResponse(BaseModel):
    policy: Optional[AIPolicy] = None


class AIAnchor(BaseModel):
    """Review c78fd19 R13-11: the highest 'off' epoch one vault's broker saw,
    opaque to the server (the id and MAC are keyed by the vault's KEK)."""
    anchor: str = Field(pattern=HEX_KEY)
    epoch: int = Field(ge=1, le=2**63 - 1)
    mac: str = Field(pattern=HEX_KEY)


class AIAnchorPut(AIAnchor):
    """Review 8bc70f7 R14-M3: signed by the account's signing key, so the
    account's JWT alone (an agent holding a token) can neither push an
    anchor out nor bury it under a higher epoch."""
    signature: str = Field(pattern=HEX_SIGNATURE)  # Ed25519 hex


class AIAnchorResponse(BaseModel):
    anchor: Optional[AIAnchor] = None


# ── Sync ──

class SyncObject(BaseModel):
    id: str = Field(pattern=OBJECT_ID)
    object_type: Literal["node", "entry", "dek", "dek_archive", "envelope", "audit"]
    payload: str = Field(max_length=MAX_SYNC_PAYLOAD_B64_LENGTH)  # base64-encoded blob
    parent_ref: Optional[str] = Field(default=None, pattern=OBJECT_ID)
    target_user_id: Optional[str] = Field(default=None, pattern=OBJECT_ID)
    # vault_objects.version is a signed INTEGER.
    version: int = Field(ge=0, le=2**31 - 1)
    # The server version this change was made on (unsigned, folders and
    # entries). Several offline edits raise `version` by several steps, so
    # "newer version wins" let them overwrite another device's edit made in
    # the meantime. With base_version the server takes the change only over
    # the copy it was made on. None = an older client: newer version wins.
    base_version: Optional[int] = Field(default=None, ge=0, le=2**31 - 1)
    # payload_hash of that copy. After tombstone GC another device can send a
    # different write under the same version (stateful test SM20): the change
    # is taken only over the very copy it was made on. None = version only.
    base_payload_hash: Optional[str] = Field(default=None, pattern=HEX_KEY)
    is_deleted: int = Field(default=0, ge=0, le=1)
    payload_hash: str = Field(pattern=HEX_KEY)  # SHA-256 hex
    signature: str = Field(pattern=HEX_SIGNATURE)  # Ed25519 hex
    # None = client omitted it → server preserves existing (update) or defaults
    # to 'owner_only' (create). Explicit 'owner_only'/'shared' set the policy.
    write_policy: Optional[Literal["owner_only", "shared"]] = None
    access_level: Optional[Literal["read", "write"]] = None  # envelope ACL only
    # DEK type label (dek objects only, unsigned): lets a full resync tell
    # the root/audit/tier-2 DEKs apart. None keeps the stored label.
    scope: Optional[Literal["root", "folder", "tier2", "share", "audit", "personal"]] = None

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, value: str) -> str:
        try:
            payload = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            return value  # The sync endpoint reports malformed encoding per object.
        if len(payload) > MAX_SYNC_PAYLOAD_BYTES:
            raise ValueError("sync payload exceeds 1 MiB")
        return value

class TeamLogRecord(BaseModel):
    """A signed team log record (docs/DESIGN_TEAM_LOG.md §3); the body is its exact canonical text."""
    model_config = ConfigDict(extra="forbid")
    body: str = Field(max_length=4096)
    sig: str = Field(pattern=r"^[0-9a-f]{128}$")

class TeamLogAppend(BaseModel):
    records: list[TeamLogRecord] = Field(min_length=1, max_length=1000)

class TeamLogHead(BaseModel):
    seq: int
    hash: str
    genesis_hash: str

class TeamLogResponse(BaseModel):
    records: list[TeamLogRecord]
    head: Optional[TeamLogHead] = None

class PushRequest(BaseModel):
    objects: list[SyncObject] = Field(max_length=MAX_SYNC_OBJECTS)
    # Team log records that land with this push in one transaction, onto the head.
    team_log: Optional[list[TeamLogRecord]] = Field(default=None, max_length=1000)
    atomic_batch: bool = False
    key_epoch: int = Field(default=0, ge=0)
    # Password/KEK rotation: the new key material travels with the DEK rewrap
    # batch and the epoch advance, so the server applies all three in one
    # transaction (never a new password with DEKs still under the old KEK).
    key_rotation: Optional[KeyRotationRequest] = None
    # Review d150605 #3: the first staged_count objects of this atomic batch
    # were sent earlier to /api/sync/stage under staged_batch_id.
    staged_batch_id: Optional[str] = Field(default=None, pattern=OBJECT_ID)
    staged_count: int = Field(default=0, ge=0, le=MAX_STAGED_OBJECTS)
    # Stateful test SM7: the highest commit this device knows and its token.
    # A server that holds a different token for it refuses the push (409).
    check_seq: Optional[int] = Field(default=None, ge=0)
    check_token: Optional[str] = Field(default=None, max_length=64)

class StageRequest(BaseModel):
    batch_id: str = Field(pattern=OBJECT_ID)
    start: int = Field(ge=0, lt=MAX_STAGED_OBJECTS)
    objects: list[SyncObject] = Field(min_length=1, max_length=MAX_SYNC_OBJECTS)

class StageResponse(BaseModel):
    staged: int

class PushObjectResult(BaseModel):
    id: str
    commit_seq: Optional[int] = None
    error: Optional[str] = None
    # Stable code of the refusal (app/errors.py); `error` is the human text.
    code: Optional[str] = None
    server_version: Optional[int] = None
    server_payload_hash: Optional[str] = None
    # FOLDER_MOVE_CYCLE: the folder as the server keeps it, signed (its parent).
    stored_object: Optional[PullObject] = None

class PushResponse(BaseModel):
    accepted: list[PushObjectResult]
    conflicts: list[PushObjectResult]
    # Set when key_rotation replaced the key material: older tokens are revoked.
    token: Optional[str] = None
    # Stateful test SM7: the token of this push's commits (None if it committed nothing).
    commit_token: Optional[str] = None

class PullObject(BaseModel):
    id: str
    object_type: str
    payload: str  # base64
    owner_id: str
    signature_user_id: Optional[str] = None
    write_policy: str = "owner_only"
    access_level: Optional[str] = None
    scope: Optional[str] = None  # DEK type label, dek objects only
    parent_ref: Optional[str] = None
    target_user_id: Optional[str] = None
    version: int
    commit_seq: int
    is_deleted: int
    payload_hash: str
    client_signature: Optional[str] = None
    modified_at: int

PushObjectResult.model_rebuild()
PushResponse.model_rebuild()

class PullResponse(BaseModel):
    objects: list[PullObject]
    max_commit_seq: int
    key_epoch: int = 0
    # SHA-256 of the account's current encrypted_keypair: identifies WHICH
    # rotation key_epoch belongs to, so a device whose own rotation targeted
    # the same epoch can tell a rival rotation from its own lost response.
    key_material_hash: Optional[str] = None
    has_more: bool = False
    next_cursor: Optional[int] = None
    # Current server head, so a client can tell when the server went back
    # behind its own checkpoint (rollback); max_commit_seq never decreases.
    head_commit_seq: int = 0
    # Highest commit_seq of a tombstone GC removed (review d150605 #4): a
    # client checking a full pull against its checkpoint knows tombstones up
    # to here may be gone.
    gc_floor_seq: int = 0
    # Tokens of the push transactions that committed the request's check_seq
    # and max_commit_seq (stateful test SM7). A device keeps the token of the
    # highest commit it knows: a different check_token means that commit_seq
    # was handed out again by a server restored from a backup. None for
    # commits from before the server logged tokens.
    check_token: Optional[str] = None
    max_token: Optional[str] = None
    # The team log head (None while the organisation has no log): a client
    # whose own copy is behind fetches GET /api/team-log?since=<its head>.
    team_log_head: Optional[TeamLogHead] = None


# ── Meta ──

class MetaResponse(BaseModel):
    version: str = "1.0"
    argon2_web_params: Optional[dict] = None
    # Per-user fields (only when username query param provided)
    argon2_salt: Optional[str] = None  # hex
    auth_salt: Optional[str] = None  # hex
    argon2_params: Optional[dict] = None  # account KDF params


# ── Share ──

class ShareCreateRequest(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    encrypted_blob: str = Field(min_length=1, max_length=13_981_016)
    expires_at: int = Field(gt=0)
    max_views: int = Field(default=1, ge=1, le=10)
    pin_hash: Optional[str] = Field(default=None, max_length=255)
    notify_on_view: bool = True

    model_config = ConfigDict(extra="forbid")

    @field_validator("id")
    @classmethod
    def validate_share_id(cls, value: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(value + "=")
        except (ValueError, TypeError) as exc:
            raise ValueError("share ID must be canonical base64url") from exc
        canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        if len(raw) != 32 or canonical != value:
            raise ValueError("share ID must encode exactly 256 bits")
        return value

    @field_validator("encrypted_blob")
    @classmethod
    def validate_encrypted_blob(cls, value: str) -> str:
        try:
            blob = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("encrypted_blob must be valid base64") from exc
        if not blob or len(blob) > 10 * 1024 * 1024:
            raise ValueError("encrypted_blob must be between 1 byte and 10 MiB")
        return value

    @field_validator("pin_hash")
    @classmethod
    def validate_pin_hash(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return validate_share_pin_hash(value)

    @model_validator(mode="after")
    def validate_expiry(self) -> ShareCreateRequest:
        now_ms = int(time.time() * 1000)
        if self.expires_at <= now_ms:
            raise ValueError("expires_at must be in the future")
        if self.expires_at > now_ms + 365 * 24 * 60 * 60 * 1000:
            raise ValueError("expires_at must be within 365 days")
        return self

class ShareViewRequest(BaseModel):
    pin: Optional[str] = Field(default=None, min_length=1, max_length=128)

    model_config = ConfigDict(extra="forbid")

class ShareUpdateRequest(BaseModel):
    action: Literal["unlock", "deactivate"]

class ShareResponse(BaseModel):
    encrypted_blob: str  # base64
    view_count: int
    max_views: int

class ShareInfo(BaseModel):
    id: str
    created_by: str
    created_at: int
    expires_at: int
    max_views: int
    view_count: int
    is_locked: bool
    notify_on_view: bool


class ShareNotification(BaseModel):
    id: str
    share_id: str
    viewed_at: int


# ── Audit ──

class AuditLogRequest(BaseModel):
    """Dedicated §4.2 audit record; content details never cross this API."""
    id: str = Field(min_length=26, max_length=26)
    action: str = Field(min_length=1, max_length=50)
    timestamp: int = Field(ge=0)
    request_hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    signature: str = Field(pattern=r"^[0-9a-fA-F]{128}$")

    model_config = ConfigDict(extra="forbid")

class AuditEntry(BaseModel):
    id: str
    user_id: str
    username: str
    action: str
    timestamp: int
    request_hash: Optional[str] = None
    commit_seq_range: Optional[str] = None
    client_signature: str
    client_ip: Optional[str] = None

class AuditResponse(BaseModel):
    entries: list[AuditEntry]
    total: int
    limit: int = 200
    offset: int = 0


# ── Org Recovery (Shamir) ──

class OrgRecoveryStoreRequest(BaseModel):
    wrapped_kek: str = Field(max_length=8192, pattern=HEX_BYTES)
    recovery_signing_pk: str = Field(pattern=HEX_KEY)  # from the recovery key
    threshold: int = Field(ge=2, le=255, default=3)
    total_shares: int = Field(ge=2, le=255, default=5)
    # Replacing another admin's setup voids every share they handed out.
    replace_other_admin: bool = False
    # Key epoch of the KEK the client wrapped (review 688edcb #3b); None
    # from a client that does not report it.
    key_epoch: Optional[int] = Field(default=None, ge=0)
    # Review e4cd15a #1: a recovery key authorizes replacing the key material,
    # so registering a NEW one proves the current account password; the
    # identity key alone (a stolen one) must not plant its own.
    current_auth_proof: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    # Review d615826: re-storing the account's own recovery key without the
    # password needs the recovery key's signature over
    # routers.recovery.org_recovery_rewrap_message.
    recovery_signature: Optional[str] = Field(default=None, pattern=HEX_SIGNATURE)
    # Review c78fd19 R13-10: a registration sent later (desktop offline or
    # before unlock) names the recovery key it replaces (null: none). Sent at
    # all, the server stores it only while that is still the current one.
    expected_signing_pk: Optional[str] = Field(default=None, pattern=HEX_KEY)

class OrgRecoveryStatusResponse(BaseModel):
    configured: bool
    threshold: Optional[int] = None
    total_shares: Optional[int] = None
    created_at: Optional[int] = None
    created_by: Optional[str] = None
    # The owner's KEK changed after setup: the shares recover a dead KEK.
    stale: bool = False
    # Review 8595ec1 #4: the owner's desktop adopts a recovery set up on the
    # web once the team log names this key (the server alone is not trusted).
    recovery_signing_pk: Optional[str] = None

class OrgRecoveryBlobResponse(BaseModel):
    wrapped_kek: str  # hex-encoded
    stale: bool = False

class OrgRecoveryKeypairRequest(BaseModel):
    # Malformed proofs still burn the per-IP budget; the route answers 401.
    challenge: str = Field(max_length=80)  # hex one-time challenge
    signature: str = Field(max_length=128)  # hex, by the recovery signing key

class OrgRecoveryKeypairResponse(BaseModel):
    encrypted_keypair: str  # hex-encoded
    argon2_salt: str  # hex-encoded
    user_id: str
    username: str
    signing_pk: str  # hex-encoded
