"""Constants, helpers and errors shared by the sync client modules."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

from nacl.signing import VerifyKey

from . import outbox, pending_states, sync_core

# Kept under the original module name (log filters, review 6 R6-H split).
logger = logging.getLogger("sezam.vault.sync_client")

# Meta key for storing the encrypted sync checkpoint
_CHECKPOINT_META_KEY = "sync_checkpoint"
# Archived DEK ids `sezam server reseed` still has to push.
RESEED_ARCHIVES_META = "reseed_archive_ids"
# Salt whose KDF params the server already holds (lockout review N2).
KDF_REPORTED_META_KEY = "kdf_params_reported_salt"
# {user_id: fingerprint} this admin confirmed out of band before sharing.
CONFIRMED_MEMBER_KEYS_META = "confirmed_member_keys"
# The org_recovery_pk the server is known to hold (review 526419e V5).


# Review d150605 #5: the server head was seen behind this device's checkpoint.
SERVER_ROLLBACK_META = "server_rollback_head"
# {seq, token}: the highest commit this device saw (pushed or pulled) and the
# server's token for it (stateful test SM7).
COMMIT_ANCHOR_META = "commit_anchor"
# Base of a change built on no server copy (stateful test SM42): version 0
# names no server copy, so the server takes it only as a new object.
NO_SERVER_COPY_HASH = "0" * 64
# DEKs this account signed that arrived wrapped under a KEK it no longer has
# (an older copy the server kept); a delta pull never sends the current one.
STALE_OWN_WRAPS_META = "stale_own_dek_wraps"
FULL_RESYNC_HINT = (
    "If the server was restored from a backup, run 'sezam pull --full-resync': "
    "items this device has and the server lost are kept and sent again."
)


def queued_for_removal(db) -> set[str]:
    """Members this account revoked whose removal re-key has not been made yet.

    Review a159e97: c494af0 let a re-key seal the new key to them and relied
    on the server refusing the envelope. They are revoked here whatever the
    server says, so no path that seals a key gives them one.
    """
    from . import pending_states

    from .team_log_local import queued_changes, set_aside_changes

    queued = queued_changes(db) + [item["change"] for item in set_aside_changes(db)]
    removals = {data["user_id"] for kind, data in queued if kind == "member.remove"}
    # The member whose removal re-key is built but not landed (S3 3.5).
    rekeying = pending_states.rekey_batch(db).get("revoked_user_id")
    if rekeying:
        removals.add(rekeying)
    return set(pending_states.revocation_queue(db)) | removals


def reseal_key_row(db, user_id: str, created_by: Optional[str], own_user_id: str):
    """The pinned key a re-key may seal a folder's new DEK to, or None.

    Review 7c10379 H2: a re-key sealed the new key to every holder of an
    envelope under the old one, whoever made it. An envelope the server made up
    (an account 'Eve' it created, signing her own grant) got the new key. Only
    a grant this account made (``created_by`` is the verified signer) or a
    member whose fingerprint this admin confirmed out of band keeps access,
    and never a member queued for removal.
    """
    if user_id in queued_for_removal(db):
        logger.warning("Re-key: member %s is queued for removal and gets no new key", user_id)
        return None
    key_row = db.fetchone(
        "SELECT encryption_pk, fingerprint FROM known_keys WHERE user_id = ?", (user_id,)
    )
    if created_by == own_user_id:
        return key_row
    confirmed = db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {}
    if key_row is not None and confirmed.get(user_id) == key_row["fingerprint"]:
        return key_row
    logger.warning(
        "Re-key: member %s was granted by %s and their key is not confirmed here; "
        "they get no envelope on the new key (share the folder again to restore access)",
        user_id, created_by or "an unknown account",
    )
    return None


def vouched_access_level(db, envelope_id: str, level: Optional[str]) -> str:
    """The access level a new envelope may carry over from ``envelope_id``.

    Review a159e97 H3: an envelope's access_level is not signed. A server that
    turned a member's 'read' into 'write' had it copied into the envelope this
    account sealed on the next re-key, so the escalation stayed after the
    server stopped lying. 'write' carries over only from an envelope made on
    this device (pull never overwrites its level); anything else is 'read'.
    """
    if level == "write" and not db.fetchone(
        "SELECT 1 FROM pulled_envelopes WHERE envelope_id = ?", (envelope_id,)
    ):
        return "write"
    if level == "write":
        logger.warning(
            "Envelope %s says 'write', which this device cannot vouch for (access "
            "levels are not signed); the new envelope grants 'read' - share the "
            "folder again with write access if that is right", envelope_id,
        )
    return "read"


def current_folder_key(
    db, dek_mgr, dek_id: str, user_id: str, granted_at: int
) -> tuple[Optional[str], bool]:
    """The current key of the folder a retired ``dek_id`` was replaced
    for (None if there is none), and whether a re-key on the way withdrew
    ``user_id`` (granted at ``granted_at`` ms)."""
    from ulid import ULID

    from .dek import archive_removed

    seen = {dek_id}
    withdrawn = False
    while True:
        link = dek_mgr.successor_link(dek_id)
        if link is None or link[0] in seen:
            return None, withdrawn
        dek_id, archive_id = link
        removed = archive_removed(archive_id, dek_id, dek_mgr.unlock_dek(dek_id), user_id)
        if removed is None:
            removed = granted_at <= ULID.from_str(dek_id).milliseconds
        withdrawn = withdrawn or removed
        row = db.fetchone("SELECT node_id, scope FROM deks WHERE id = ?", (dek_id,))
        if row is not None and row["node_id"] and row["scope"] in ("folder", "root"):
            return dek_id, withdrawn
        seen.add(dek_id)


REKEY_TOO_LARGE_MESSAGE = (
    "The pending folder re-key holds an item over the server's 1 MiB limit per "
    "item (saved before that limit was checked); the server never takes it. Run "
    "'sezam abandon-rekey', shorten or split the item, then 'sezam push' re-keys "
    "the folder again."
)


# Stable server error codes (review d615826 R6-H); must match server/app/errors.py.
HISTORY_CHANGED = "history_changed"
STALE_KEY_EPOCH = "stale_key_epoch"
KEY_CHANGE_MISSES_DEKS = "key_change_misses_deks"
WRONG_CURRENT_PASSWORD = "wrong_current_password"
KEY_CHANGE_NEEDS_PROOF = "key_change_needs_proof"
IDENTITY_ROTATION_NEEDS_NEW_KEYS = "identity_rotation_needs_new_keys"
ATOMIC_BATCH_CONFLICT = "atomic_batch_conflict"
IDENTITY_KEY_ROTATED = "identity_key_rotated"
IDENTITY_KEY_RETIRED = "identity_key_retired"
TOKEN_INVALID = "token_invalid"
TOKEN_REVOKED = "token_revoked"
TEAM_LOG_HEAD_MOVED = "team_log_head_moved"
TEAM_LOG_REFUSED = "team_log_refused"
TEAM_LOG_REQUIRED = "team_log_required"
TEAM_LOG_UNREADABLE = "team_log_unreadable"
# Per-object code of a refused push object.
REVOKED_ENVELOPE = "revoked_envelope"
TEAM_LOG_ENVELOPE = "team_log_envelope"
COLLECTED_OBJECT = "collected_object"
FOLDER_KEY_MOVED = "folder_key_moved"
FOLDER_MOVE_CYCLE = "folder_move_cycle"
ACCOUNT_EXISTS = "account_exists"
USERNAME_TAKEN = "username_taken"
ORG_RECOVERY_SUPERSEDED = "org_recovery_superseded"
INVALID_KEY_VOUCHERS = "invalid_key_vouchers"
KEY_VOUCHERS_INCOMPLETE = "key_vouchers_incomplete"
KEY_VOUCHERS_FULL = "key_vouchers_full"
# SHA-256 of the server's encrypted keypair at the key epoch this device holds:
# what its key-change push sent, or what it took over (stateful test SM30).
SERVER_KEY_MATERIAL_META = "server_key_material_hash"
# The unsigned account name a 409 'Identity key rotated' carried: the takeover
# tries it and keeps it only once /auth/recover under it opens this account.
ROTATED_USERNAME_META = "rotated_username"
# Items shown below the root because their folder was gone: id -> [kind, folder, version].
REATTACHED_META = "reattached_parents"
# Folder DEKs unbound because their folder was gone: dek id -> folder id (SM59).
DETACHED_DEKS_META = "detached_dek_folders"
# DEKs the server refused for their folder (a member's key names none), never
# held by it: a password change does not carry them (review d615826 E8).
REFUSED_DEKS_META = "refused_folder_deks"
INVALID_PERSONAL_DEK = "invalid personal DEK metadata"


def unsent_envelope_count(db) -> int:
    return db.fetchone(
        "SELECT COUNT(*) AS n FROM access_envelopes ae WHERE "
        + outbox.pending(outbox.ENVELOPE, "ae.id")
    )["n"]


def _payload_len(obj: dict) -> int:
    """Decoded length of a sync object's base64 payload."""
    b64 = obj["payload"]
    return len(b64) * 3 // 4 - b64[-2:].count("=")


def sign_auth_challenge(signing_key, challenge_hex: str) -> str:
    """Answer a server login challenge; returns the signature hex.

    The identity key signs only context || challenge, and only a challenge of
    the server's fixed layout, so a server cannot have it sign bytes of its
    choosing (a sync object or a policy) under the guise of a login.
    """
    return signing_key.sign(auth_challenge_message(challenge_hex)).signature.hex()


def auth_challenge_message(challenge_hex: str, current_key: bool = False) -> bytes:
    """The bytes a login signs (the core's, docs/CORE_UNIFICATION.md U6c)."""
    try:
        return bytes.fromhex(sync_core.call(
            "auth_challenge_message", challenge=challenge_hex, current_key=current_key))
    except ValueError as exc:
        raise RuntimeError(f"Server sent a malformed login challenge: {exc}") from exc


def auth_verify_body(username: str, challenge_hex: str, signing_key, current_signing_key=None) -> dict:
    """/api/auth/verify request answering ``challenge_hex`` with ``signing_key``.

    Capability run 300: a restored server knows only the key a rotation of
    this device retired; ``current_signing_key`` (the new one, the team log's)
    signs the challenge too, or the session reads nothing but log and keys.
    """
    body = {
        "username": username,
        "challenge": challenge_hex,
        "signature": sign_auth_challenge(signing_key, challenge_hex),
    }
    if current_signing_key is not None:
        body["current_key_signature"] = current_signing_key.sign(
            auth_challenge_message(challenge_hex, current_key=True)
        ).signature.hex()
    return body


class ServerError(RuntimeError):
    """An error answer of the server.

    Review d615826 R6-H: decisions use ``status`` and ``code`` (the server's
    stable error code, server/app/errors.py), not the wording of the text;
    str() stays "Server error <status>: <body>" for what the user is shown
    (with ``show_detail``, "Server error <status>: <detail>" as the CLI and
    the connect dialog showed it).
    """

    def __init__(self, status: int, body: str, show_detail: bool = False):
        try:
            answer = json.loads(body)
        except ValueError:
            answer = None
        answer = answer if isinstance(answer, dict) else {}
        self.detail = answer.get("detail")
        code = answer.get("code")
        self.code = code if isinstance(code, str) else None
        self.status = status
        self.body = body
        shown = self.detail if show_detail and "detail" in answer else body
        super().__init__(f"Server error {status}: {shown}")


class AccountLostOnServer(RuntimeError):
    """The server refuses the login of an account the team log names as a
    current member with this device's keys (review 8595ec1 #1)."""

    def __init__(self):
        super().__init__(
            "The server does not know this account although the team log names it "
            "with this device's keys. If the server was restored from a backup older "
            "than the account, run 'sezam server rejoin' to bring it back under its id."
        )


def server_error(exc: BaseException, status: int, code: Optional[str] = None) -> bool:
    """Whether ``exc``, or an error it was raised from, is the server's answer
    ``status`` (with ``code``, if given)."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, ServerError):
            return exc.status == status and (code is None or exc.code == code)
        exc = exc.__cause__
    return False


def _rotated_account_name(exc: Exception) -> Optional[str]:
    """The current account name a 409 'Identity key rotated' carries for a
    renamed account (review 526419e N8); None otherwise."""
    detail = getattr(exc, "detail", None)
    name = detail.get("username") if isinstance(detail, dict) else None
    return name if isinstance(name, str) and name else None


def key_rotation_message(
    user_id: str,
    old_signing_pk: bytes,
    old_encryption_pk: bytes,
    new_signing_pk: bytes,
    new_encryption_pk: bytes,
) -> bytes:
    """Bytes the successor signing key signs to certify an archived key (the
    core's, docs/CORE_UNIFICATION.md U6c)."""
    return bytes.fromhex(sync_core.call(
        "key_rotation_message", user_id=user_id,
        old_signing_pk=bytes(old_signing_pk).hex(), old_encryption_pk=bytes(old_encryption_pk).hex(),
        new_signing_pk=bytes(new_signing_pk).hex(), new_encryption_pk=bytes(new_encryption_pk).hex(),
    ))


# A checkpoint's "state_v": the formula its state_hash was made with.
STATE_HASH_VERSION = 2


def _state_hash(objects, legacy: bool) -> str:
    return sync_core.call("state_hash", legacy=legacy, objects=[
        {"id": object_id, "version": version, "payload_hash": hashlib.sha256(payload).hexdigest(),
         "parent_ref": signed[0] if signed else None, "is_deleted": bool(signed[1]) if signed else False}
        for object_id, version, payload, *signed in objects
    ])


def compute_state_hash(objects) -> str:
    """Spec 8.3 state_hash over (object_id, version, payload, parent_ref,
    is_deleted) of every sync object: the core's formula
    (core/src/formats.rs state_hash, docs/CORE_UNIFICATION.md U6g).
    R17-N1: the parent and the deleted flag are signed and count."""
    return _state_hash(objects, False)


def legacy_state_hash(objects) -> str:
    """The state_hash of a checkpoint without "state_v" (before R17-N1)."""
    return _state_hash(objects, True)


def pull_warnings(result: dict) -> list[str]:
    """Security warnings of a pull/full-resync result that the user must see."""
    warnings = []
    if result.get("rollback_warning"):
        warnings.append(
            "ROLLBACK WARNING: the server returned an older vault state; it was "
            f"rejected and the local data kept. {result['rollback_warning']}"
        )
    for warning in result.get("tofu_warnings", []):
        warnings.append(
            "TOFU WARNING: public keys changed for user "
            f"{warning['user_id']} (old {warning['old_fingerprint']}, "
            f"new {warning['new_fingerprint']}). Verify the new fingerprint."
        )
    if result.get("conflicts"):
        warnings.append(
            f"SYNC CONFLICT: {len(result['conflicts'])} item(s) were changed both here "
            "and on another device. Neither copy was discarded; run 'sezam conflicts' "
            "to choose which one to keep."
        )
    return warnings


class SyncRollbackWarning(Exception):
    """Raised when rollback detection identifies inconsistency."""


class TofuKeyChangeError(RuntimeError):
    """Raised when a pinned user's public keys change on the server."""

    def __init__(
        self,
        user_id: str,
        old_fingerprint: str,
        new_fingerprint: str,
        signing_pk: bytes,
        encryption_pk: bytes,
        signing_key_ring: tuple[bytes, ...] = (),
    ):
        super().__init__(
            f"Public keys changed for user {user_id}; explicit fingerprint "
            "verification is required"
        )
        self.user_id = user_id
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        self.signing_pk = signing_pk
        self.encryption_pk = encryption_pk
        # The new key plus the archived keys its rotation certificates vouch
        # for, so a confirmed change still verifies records signed before it.
        self.signing_key_ring = signing_key_ring or (signing_pk,)


KEY_CHANGE_REFUSED = (
    "If the server no longer has the password this pending change starts from (was it "
    "restored from a backup?), run 'sezam abandon-pending-change' with the password the "
    "server has now, then change the password again"
)


class KeyEpochStale(RuntimeError):
    """The account's key material was rotated on another device.

    The device must take the rotation over with the current account password
    (SyncClient.adopt_rotated_key_material) before it can sync again.
    """

    def __init__(self, server_key_epoch: Optional[int] = None):
        super().__init__(
            "Local key epoch is stale; recover with the current password before sync."
        )
        self.server_key_epoch = server_key_epoch


class _RekeyBatchConflict(RuntimeError):
    """The server refused a pending member re-key: another device got there first."""


class _AuditLostByRestore(RuntimeError):
    """A push that cannot wait for a full resync met a server restored from a backup."""


class _KeyChangeMissesDeks(RuntimeError):
    """A pending key change lacks folder keys made elsewhere; a pull re-wraps them in."""


class _RevokedEnvelopesRefused(RuntimeError):
    """An atomic batch was refused only for envelopes sealed for a removed member."""


class _RekeyRecipientsMoved(RuntimeError):
    """The team log moved under a pending re-key and its envelopes were sealed again."""


class _RekeyRebasedOnCollected(RuntimeError):
    """A re-key batch item was rebased on a tombstone the server collected."""


def _batch_conflicts(exc: Exception) -> list[dict]:
    """The per-object conflicts of a refused atomic batch."""
    detail = getattr(exc, "detail", None)
    conflicts = detail.get("conflicts") if isinstance(detail, dict) else None
    return [c for c in conflicts if isinstance(c, dict)] if isinstance(conflicts, list) else []


def key_ring(
    user_id: str,
    current_signing_pk: bytes,
    current_encryption_pk: bytes,
    response: dict,
) -> tuple[bytes, ...]:
    """Current signing key plus the archived ones reachable by rotation
    certificates, in chain order; ValueError on a malformed response.

    The rule is the core's (core/src/keyring.rs, capability review 716, the
    copy the web and the phone use); this only verifies the signatures it
    names. Which objects an archived key may still vouch for is named by the
    current key's voucher lists (sync_vouchers, goal #443).
    """
    args = {
        "user_id": user_id,
        "current_signing_pk": bytes(current_signing_pk).hex(),
        "current_encryption_pk": bytes(current_encryption_pk).hex(),
        "archived_keys": response.get("archived_keys"),
    }
    verified = []
    for check in sync_core.call("key_ring_checks", **args):
        try:
            VerifyKey(bytes.fromhex(check["public_key"])).verify(
                bytes.fromhex(check["message"]), bytes.fromhex(check["signature"])
            )
            verified.append(True)
        except Exception:
            verified.append(False)
    trusted = sync_core.call("key_ring", verified=verified, **args)
    return tuple(bytes.fromhex(pair["signing_pk"]) for pair in trusted)


def withdraw_from_removed_members(db, team, user_id: str) -> None:
    """Queue the withdrawal of this account's envelopes the log's removed
    members still hold on a key no folder here uses any more.

    Review e443cbc R15 (TeamLogMachine, goal #429): A granted a folder and
    the push reply was lost; B of the same account, not pulled since,
    removed the member and re-keyed. B's re-key withdrew only the
    envelopes B held, and A, which took the re-key over in this pull,
    queued nothing (the log had replaced the key): the removed member kept
    a live envelope on the server. The queued re-key finds no folder on
    the key and sends just the tombstone."""
    if team is None:
        return
    queue = pending_states.revocation_queue(db)
    pending = pending_states.rekey_batch(db).get("revoked_user_id")
    removed = []
    for row in db.fetchall(
        "SELECT DISTINCT user_id, dek_id FROM access_envelopes WHERE created_by = ? AND user_id != ?",
        (user_id, user_id),
    ):
        member = team.members.get(row["user_id"])
        if (
            member is not None and not member.active and row["dek_id"] in team.dek_index
            and row["user_id"] not in queue + removed and row["user_id"] != pending
            and not db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ?", (row["dek_id"],))
        ):
            removed.append(row["user_id"])
    if removed:
        logger.warning("Envelopes of removed members %s on replaced keys; queued for withdrawal",
                       removed)
        pending_states.set_revocation_queue(db, queue + removed)


def serialize_audit_row(row) -> bytes:
    """Serialize every signed audit field into a deterministic sync payload."""
    parent_ids = json.loads(row["parent_ids"])
    if not isinstance(parent_ids, list) or not all(
        isinstance(parent_id, str) for parent_id in parent_ids
    ):
        raise ValueError(f"Invalid audit parent list for {row['id']}")
    return sync_core.call(
        "audit_payload",
        id=row["id"],
        actor_id=row["actor_id"],
        parent_ids=parent_ids,
        action=row["action"],
        timestamp=row["timestamp"],
        encrypted_details=bytes(row["encrypted_details"] or b"").hex(),
        signature=bytes(row["signature"]).hex(),
    ).encode("ascii")
