"""Everything the server answers, and what a client may make of it
(docs/ROOT_CAUSE_PLAN.md S4, INV-3: the server may withhold, not forge).

One entry per field of every response: each response model's fields
("Model.field") and the keys of the routes that return a plain dict
("METHOD /path .key"). ``tests/test_unsigned_fields.py`` fails on a field
without an entry and on an entry whose field is gone.

``trust``:
  SIGNED   a signature or AEAD tag the client checks covers it; ``checks``
           names the function (``module:qualname`` under ``sezam``).
  HINT     unsigned; a lie in it can only make the client refuse, ask, or
           show something wrong; ``why`` says why it cannot do more.
  UNREAD   no client decision reads it (shown, or used by the server only).
  DECIDES  unsigned, and a client decision rests on it: an open INV-3
           finding, to be signed or made a hint.
  OPEN     not traced through the clients yet.

``lies`` names the state-machine rules (tests/test_sync_state_machine.py)
that make the server lie in the field, as ``rule`` or ``rule:label``.

The classification so far follows the desktop client (sezam), the one the
state machine drives; web and mobile reads of each field are not traced yet.
"""

from __future__ import annotations

from dataclasses import dataclass

SIGNED, HINT, UNREAD, DECIDES, OPEN = "signed", "hint", "unread", "decides", "open"


@dataclass(frozen=True)
class Field:
    trust: str
    why: str = ""
    checks: tuple[str, ...] = ()
    lies: tuple[str, ...] = ()


_OBJECT_SIG = ("vault.sync_client:SyncClient._verify_object_signature",)
_TOFU = ("vault.sync_client:SyncClient._get_signing_pk",)
_KDF = ("vault.crud:server_account_kdf",)
_LOG = ("teamlog:_verify", "teamlog:apply_record")
_TOKEN = "a bearer token for the server itself; a lie only fails the next request"
_ID = "the server's own row id; the client acts on it only towards the server"
_SHOWN = "shown to the user only"
_USER_LIST_FP = ("the desktop user table and the web user list show the pinned key's fingerprint, not the "
                 "server's (tests/test_inv3_team_table_fingerprint.py, tests/test_inv3_web_user_list_fingerprint.py)")


def _signed(*checks: str, lies: tuple[str, ...] = ()) -> Field:
    return Field(SIGNED, checks=checks, lies=lies)


FIELDS: dict[str, Field] = {
    # ── Bootstrap, login, provisioning ──────────────────────────────────────
    "BootstrapStatusResponse.needs_setup": Field(HINT, "only offers the setup form; the server decides setup"),
    "BootstrapStatusResponse.unfinished_setup": Field(HINT, "only explains why the setup form is offered"),
    "BootstrapResponse.user_id": Field(HINT, "the id the server gives the new account; objects signed under it verify only against the keys the log and pins hold for that id, so a wrong one only gets them refused"),
    "BootstrapResponse.token": Field(HINT, _TOKEN),
    "ChallengeResponse.challenge": Field(HINT, "the client signs it back; a lie fails the login"),
    "ChallengeResponse.timestamp": Field(HINT, "signed back with the challenge; a lie fails the login"),
    "VerifyResponse.token": Field(HINT, _TOKEN),
    "VerifyResponse.user_id": Field(UNREAD, "not read by the desktop"),
    "VerifyResponse.username": Field(HINT, "only names the account the next login and recover ask about; the challenge is answered by this device's keys and the keypair opens only under its password"),
    "VerifyResponse.is_admin": Field(UNREAD, "not read by the desktop"),
    "VerifyResponse.key_material_hash": Field(UNREAD, "not read by the desktop"),
    "ProvisioningTokenResponse.token": Field(UNREAD, "handed to the new device out of band"),
    "ProvisioningTokenResponse.username": Field(UNREAD, _SHOWN),
    "ProvisioningTokenResponse.expires_at": Field(UNREAD, _SHOWN),
    "ProvisionResponse.encrypted_keypair": Field(UNREAD, "not read by the desktop"),
    "ProvisionResponse.argon2_salt": Field(UNREAD, "not read by the desktop"),
    "ProvisionResponse.user_id": Field(UNREAD, "not read by the desktop"),
    "ProvisionResponse.argon2_params": Field(UNREAD, "not read by the desktop"),
    "RecoverResponse.encrypted_keypair": _signed("vault.crud:open_server_keypair"),
    "RecoverResponse.argon2_salt": Field(HINT, "the KEK comes from /api/meta's salt; another one here is refused (SyncClient.adopt_rotated_key_material) or unread, and the keypair opens only under that KEK"),
    "RecoverResponse.user_id": _signed("vault.crud:open_server_keypair"),
    "RecoverResponse.argon2_params": Field(UNREAD, "not read by the desktop"),
    "RecoverResponse.key_epoch": Field(HINT, "taken over with key material that opened under the password; a wrong number only makes a later pull ask for the password or the server refuse the next change"),
    "InviteResponse.invitation_token": Field(UNREAD, "handed to the invitee out of band"),
    "InviteResponse.expires_at": Field(UNREAD, _SHOWN),
    "RegisterResponse.user_id": Field(HINT, "the id the server gives the new account; objects signed under it verify only against the keys the log and pins hold for that id, so a wrong one only gets them refused"),
    "RegisterResponse.token": Field(HINT, _TOKEN),
    "POST /api/auth/registration-resume .key_material_hash": Field(UNREAD, "not read by the desktop"),
    "POST /api/auth/registration-resume .token": Field(HINT, _TOKEN),
    "POST /api/auth/registration-resume .user_id": Field(UNREAD, "not read by the desktop"),
    "POST /api/auth/refresh .token": Field(HINT, _TOKEN),
    "POST /api/auth/logout .status": Field(UNREAD),
    "PUT /api/me/keypair .status": Field(UNREAD),
    "PUT /api/me/keypair .token": Field(HINT, _TOKEN),
    "PUT /api/me/kdf-params .argon2_params": Field(UNREAD, "the client reports its own params; the answer is not read"),
    "PUT /api/me/kdf-params .status": Field(UNREAD),
    "POST /api/me/key-material-archive .generations": Field(UNREAD, "not read by the desktop"),
    "POST /api/me/key-material-archive/purge .purged": Field(UNREAD, "not read by the desktop"),
    "POST /api/me/key-material-archive/purge .status": Field(UNREAD),
    "MetaResponse.version": Field(UNREAD, _SHOWN),
    "MetaResponse.argon2_salt": Field(
        HINT, "only with params at or above the floor; a new salt means a password change the client asks about",
        _KDF, ("server_lies:weak_kdf",)),
    "MetaResponse.argon2_params": Field(
        HINT, "refused below the web floor (or the vault's own params)", _KDF, ("server_lies:weak_kdf",)),
    "MetaResponse.auth_salt": Field(UNREAD, "not read by the desktop"),
    "MetaResponse.argon2_web_params": Field(UNREAD, "the web client's; not read by the desktop"),
    # ── Users and member keys ───────────────────────────────────────────────
    "UserInfo.id": Field(HINT, "only picks which accounts are offered (founding the log, adding a member, the user table); their keys come pinned from /keys and are fingerprint-confirmed"),
    "UserInfo.username": Field(UNREAD, _SHOWN),
    "UserInfo.status": Field(
        HINT, "who is revoked comes from the team log", (), ("server_lies_about_users:revoked_active",)),
    "UserInfo.is_admin": Field(
        HINT, "shown in the team dialog; the admin is the team log's", (), ("server_lies_about_users:member_admin",)),
    "UserInfo.key_fingerprint": Field(UNREAD, _USER_LIST_FP),
    "UserInfo.signing_pk": Field(UNREAD, "member keys come from /api/users/{id}/keys, pinned; " + _USER_LIST_FP),
    "UserInfo.encryption_pk": Field(UNREAD, "member keys come from /api/users/{id}/keys, pinned; " + _USER_LIST_FP),
    "UserInfo.created_at": Field(UNREAD, _SHOWN),
    "GET /api/users/{user_id}/keys .signing_pk": Field(
        HINT, "pinned on first use; a changed key needs the user's fingerprint check", _TOFU,
        ("server_swaps_a_member_key",)),
    "GET /api/users/{user_id}/keys .encryption_pk": Field(
        HINT, "pinned with the signing key", _TOFU, ("server_swaps_a_member_key",)),
    "GET /api/users/{user_id}/keys .archived_keys": Field(
        DECIDES,
        "the keys are certified by their successor (key_ring_from_response), but retired_seq, the last "
        "commit_seq a retired key vouches for, is unsigned and pinned on first sight only: a server holding "
        "a leaked retired key serves a high bound to a device that has not seen one",
        ("vault.sync_common:key_ring_from_response", "vault.sync_client:SyncClient._remember_archive_bounds")),
    "POST /api/users/{user_id}/unlock-recovery .expires_at": Field(UNREAD, _SHOWN),
    "POST /api/users/{user_id}/unlock-recovery .status": Field(UNREAD),
    "POST /api/users/{user_id}/unlock-recovery .unlock_code": Field(UNREAD, "handed to the member out of band"),
    "POST /api/users/{user_id}/allow-key-reset .expires_at": Field(UNREAD, _SHOWN),
    "POST /api/users/{user_id}/allow-key-reset .status": Field(UNREAD),
    "PATCH /api/users/{user_id}/approve .status": Field(UNREAD),
    "DELETE /api/users/{user_id} .note": Field(UNREAD, _SHOWN),
    "DELETE /api/users/{user_id} .status": Field(UNREAD),
    "PATCH /api/users/{user_id}/reactivate .note": Field(UNREAD, _SHOWN),
    "PATCH /api/users/{user_id}/reactivate .status": Field(UNREAD),
    # ── Sync ────────────────────────────────────────────────────────────────
    "StageResponse.staged": Field(UNREAD, "the client counts what it staged itself"),
    "PushResponse.accepted": Field(HINT, "marks a sent write done; a lie only keeps it from the server, which the server could drop the write anyway (withholding)"),
    "PushResponse.conflicts": Field(HINT, "a refused write stays queued, is rebased on this device's own or the collected version, or stops; the server could drop the write anyway (withholding)"),
    "PushResponse.token": Field(HINT, _TOKEN),
    "PushResponse.commit_token": Field(HINT, "rollback anchor: a made-up one only makes a later pull see a rollback and ask for a full resync", (), ("server_lies_into_full_resync:check_token",)),
    "PushObjectResult.id": Field(HINT, "names the sent write a result is about; see .accepted, .conflicts"),
    "PushObjectResult.commit_seq": Field(HINT, "the held copy's seq; against_held lets it pick only between copies of one version (core/src/pull.rs), and a full resync between a conflict and a push of the newer copy"),
    "PushObjectResult.error": Field(HINT, "why a write was refused; see PushResponse.conflicts"),
    "PushObjectResult.code": Field(HINT, "why a write was refused; see PushResponse.conflicts"),
    "PushObjectResult.server_version": Field(HINT, "the copy a refused write is rebased on; the next pull brings that copy checked"),
    "PushObjectResult.server_payload_hash": Field(HINT, "the copy a refused write is rebased on; the next pull brings that copy checked"),
    "PullResponse.objects": Field(
        HINT, "each object is checked on its own; which ones come and in what order is the server's",
        (), ("server_withholds", "server_lies:replay", "server_lies:dek_order")),
    "PullResponse.max_commit_seq": Field(HINT, "the cursor: a lower one repeats, a higher one skips commits (withholding); a same seq with another state is refused", (), ("server_withholds",)),
    "PullResponse.key_epoch": Field(
        HINT, "a higher epoch makes the client ask for the account password; its keys stay",
        (), ("server_lies:epoch_up", "server_lies:epoch_down")),
    "PullResponse.key_material_hash": Field(HINT, "another hash only asks for the account password, and the key material fetched then opens only under it (AEAD); at bootstrap it skips an upload the server could drop anyway"),
    "PullResponse.has_more": Field(HINT, "paging: a lie ends or repeats the pull, which withholding may do anyway"),
    "PullResponse.next_cursor": Field(HINT, "paging: a lie ends or repeats the pull, which withholding may do anyway"),
    "PullResponse.head_commit_seq": Field(HINT, "a lower head reports a rollback and asks for a full resync; a higher one hides one, which is withholding", (), ("server_lies_into_full_resync:check_token",)),
    "PullResponse.gc_floor_seq": Field(HINT, "a higher floor lets in only another copy of a collected tombstone's version, never an older version (core/src/pull.rs against_held, tests/test_inv3_replay_over_tombstone.py); it moves a first cursor up to the head at most and explains a lower seq only with every live object unchanged", (), ("server_lies:gc_floor",)),
    "PullResponse.check_token": Field(
        HINT, "a made-up one forces a full resync, which may only refuse or keep every key",
        (), ("server_lies_into_full_resync:check_token",)),
    "PullResponse.max_token": Field(HINT, "rollback anchor: a made-up one only makes a later pull see a rollback and ask for a full resync", (), ("server_lies_into_full_resync:check_token",)),
    "PullResponse.team_log_head": Field(
        HINT, "the log is fetched and checked record by record; an older head is refused",
        _LOG, ("server_lies_about_the_log:old head",)),
    "PullObject.id": _signed(*_OBJECT_SIG),
    "PullObject.object_type": _signed(*_OBJECT_SIG),
    "PullObject.payload": _signed(*_OBJECT_SIG),
    "PullObject.payload_hash": _signed(*_OBJECT_SIG),
    "PullObject.parent_ref": _signed(*_OBJECT_SIG),
    "PullObject.target_user_id": _signed(*_OBJECT_SIG),
    "PullObject.version": _signed(*_OBJECT_SIG, lies=("server_lies:replay",)),
    "PullObject.is_deleted": _signed(*_OBJECT_SIG),
    "PullObject.client_signature": _signed(*_OBJECT_SIG),
    "PullObject.signature_user_id": Field(
        HINT, "only picks whose pinned keys verify the signature; a wrong one fails the check", _OBJECT_SIG),
    "PullObject.owner_id": Field(
        HINT, "only names the signer when signature_user_id is missing, and a wrong one fails the signature "
        "check; whose DEK it is comes from the verified signer (tests/test_inv3_resync_owner_id.py)",
        _OBJECT_SIG),
    "PullObject.write_policy": Field(UNREAD, "not read by the desktop"),
    "PullObject.access_level": Field(
        HINT, "an envelope's write access comes from the team log", (), ("server_lies:access_up",)),
    "PullObject.scope": Field(
        HINT, "a DEK's role is derived by the device; the label only names a key it did not hold",
        (), ("server_lies:scope", "server_lies:dek_order")),
    "PullObject.commit_seq": Field(
        DECIDES,
        "a retired key's signature counts only for commit_seq at or below its bound, and the server sets "
        "both the object's commit_seq and the bound (see .archived_keys); held as the copy's seq it picks "
        "only between copies of one version (core/src/pull.rs against_held)",
        _OBJECT_SIG),
    "PullObject.modified_at": Field(HINT, "a full resync records a conflict for the user or sends this device's newer copy over the server's, which the server could drop that copy anyway (withholding)"),
    "HeldResponse.objects": Field(HINT, "only whether a pending re-key landed: a lie stops resending it (withholding) or resends it, which the server refuses"),
    "HeldObject.id": Field(HINT, "see HeldResponse.objects"),
    "HeldObject.object_type": Field(HINT, "see HeldResponse.objects"),
    "HeldObject.version": Field(UNREAD),
    "HeldObject.is_deleted": Field(HINT, "see HeldResponse.objects"),
    # ── Team log ────────────────────────────────────────────────────────────
    "TeamLogResponse.records": Field(
        HINT, "every record is verified; withholding, truncating, reordering is refused or waited out",
        _LOG, ("server_lies_about_the_log:truncate", "server_lies_about_the_log:drop a record",
               "server_lies_about_the_log:reorder")),
    "TeamLogResponse.head": Field(
        HINT, "compared with the head of the records it names", _LOG, ("server_lies_about_the_log:old head",)),
    "TeamLogRecord.body": _signed(*_LOG, lies=("server_lies_about_the_log:forged record",)),
    "TeamLogRecord.sig": _signed(*_LOG, lies=("server_lies_about_the_log:forged record",)),
    "TeamLogHead.seq": Field(HINT, "compared with the verified records", _LOG, ("server_lies_about_the_log:old head",)),
    "TeamLogHead.hash": Field(HINT, "compared with the verified records", _LOG, ("server_lies_about_the_log:old head",)),
    "TeamLogHead.genesis_hash": Field(
        HINT, "compared with the pinned genesis", _LOG, ("server_lies_about_the_log:other genesis",)),
    # ── Shares ──────────────────────────────────────────────────────────────
    "ShareResponse.encrypted_blob": Field(OPEN),
    "ShareResponse.view_count": Field(UNREAD, _SHOWN),
    "ShareResponse.max_views": Field(UNREAD, _SHOWN),
    "ShareNotification.id": Field(UNREAD, _ID),
    "ShareNotification.share_id": Field(UNREAD, _SHOWN),
    "ShareNotification.viewed_at": Field(UNREAD, _SHOWN),
    "ShareInfo.id": Field(UNREAD, _ID),
    "ShareInfo.created_by": Field(UNREAD, _SHOWN),
    "ShareInfo.created_at": Field(UNREAD, _SHOWN),
    "ShareInfo.expires_at": Field(UNREAD, _SHOWN),
    "ShareInfo.max_views": Field(UNREAD, _SHOWN),
    "ShareInfo.view_count": Field(UNREAD, _SHOWN),
    "ShareInfo.is_locked": Field(UNREAD, _SHOWN),
    "ShareInfo.notify_on_view": Field(UNREAD, _SHOWN),
    "POST /api/share .id": Field(OPEN),
    "POST /api/share .status": Field(UNREAD),
    "PATCH /api/share/{share_id} .status": Field(UNREAD),
    "DELETE /api/share/{share_id} .status": Field(UNREAD),
    # ── Audit ───────────────────────────────────────────────────────────────
    "AuditResponse.entries": Field(OPEN),
    "AuditResponse.total": Field(UNREAD, _SHOWN),
    "AuditResponse.limit": Field(UNREAD, _SHOWN),
    "AuditResponse.offset": Field(UNREAD, _SHOWN),
    "AuditEntry.id": Field(OPEN),
    "AuditEntry.user_id": Field(OPEN),
    "AuditEntry.username": Field(OPEN),
    "AuditEntry.action": Field(OPEN),
    "AuditEntry.timestamp": Field(OPEN),
    "AuditEntry.request_hash": Field(OPEN),
    "AuditEntry.commit_seq_range": Field(OPEN),
    "AuditEntry.client_signature": Field(OPEN),
    "AuditEntry.client_ip": Field(UNREAD, _SHOWN),
    "POST /api/audit/log .ok": Field(UNREAD),
    # ── Org recovery ────────────────────────────────────────────────────────
    "OrgRecoveryStatusResponse.configured": Field(OPEN),
    "OrgRecoveryStatusResponse.threshold": Field(OPEN),
    "OrgRecoveryStatusResponse.total_shares": Field(OPEN),
    "OrgRecoveryStatusResponse.created_at": Field(UNREAD, _SHOWN),
    "OrgRecoveryStatusResponse.created_by": Field(OPEN),
    "OrgRecoveryStatusResponse.stale": Field(OPEN),
    "OrgRecoveryStatusResponse.recovery_signing_pk": Field(OPEN),
    "OrgRecoveryBlobResponse.wrapped_kek": Field(OPEN),
    "OrgRecoveryBlobResponse.stale": Field(OPEN),
    "OrgRecoveryKeypairResponse.encrypted_keypair": Field(OPEN),
    "OrgRecoveryKeypairResponse.argon2_salt": Field(OPEN),
    "OrgRecoveryKeypairResponse.user_id": Field(OPEN),
    "OrgRecoveryKeypairResponse.username": Field(OPEN),
    "OrgRecoveryKeypairResponse.signing_pk": Field(OPEN),
    "POST /api/org-recovery/store .status": Field(UNREAD),
    # ── AI policy and anchor ────────────────────────────────────────────────
    "AIPolicyResponse.policy": Field(OPEN),
    "AIPolicy.user_id": Field(OPEN),
    "AIPolicy.enabled": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.epoch": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.signature": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.updated_at": Field(UNREAD, _SHOWN),
    "AIAnchorResponse.anchor": Field(OPEN),
    "AIAnchor.anchor": Field(OPEN),
    "AIAnchor.epoch": Field(OPEN),
    "AIAnchor.mac": Field(OPEN),
    # ── Other ───────────────────────────────────────────────────────────────
    "GET /health .status": Field(UNREAD),
    "GET /health .version": Field(UNREAD, _SHOWN),
}
