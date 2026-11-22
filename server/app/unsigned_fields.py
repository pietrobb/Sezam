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

``lies`` names the state-machine rules (tests/test_sync_state_machine.py)
that make the server lie in the field, as ``rule`` or ``rule:label``.

``FIELDS`` classifies what the desktop client (sezam), the one the state
machine drives, makes of each field. ``CLIENT_FIELDS`` does the same for the
web and the mobile client, whose ``checks`` name a function in their own
sources (``web/static/js``, ``mobile/lib``). The test asks for an entry per
client wherever that client's sources read the field's name (capability run
458), so a new read of a server field needs its classification first.
"""

from __future__ import annotations

from dataclasses import dataclass

SIGNED, HINT, UNREAD, DECIDES = "signed", "hint", "unread", "decides"


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
_NO_LOG_GRANT = ("with a team log the level is checked against it; a vault without one (several users "
                 "before the log) takes an envelope's 'write' as a write grant: ROOT_CAUSE_PLAN S6, phase 3")
_FORGET_FROM_HEAD = ("a cause that offers to forget the pin (log_gone, other_genesis, confirmed_genesis) is "
                     "named only as far as the records served from seq 0 bear it out: a first record that is "
                     "this device's genesis makes the head a lie (head_genesis, no offer), and the forget asks "
                     "the same check again (goal #440, tests/vectors/team_log_mismatch.json). What is left, no "
                     "record at all, is the server withholding its whole log, and the offer it gets carries "
                     "RISK: and needs the pinned genesis typed (INV-8)")
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
    "VerifyResponse.username": Field(HINT, "only names the account the next login and recover ask about; the challenge is answered by this device's keys and the keypair opens only under its password; the desktop stores a new name only after its key logs in under it (sync_client._logs_in_as)"),
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
        HINT, "the log is fetched and checked record by record and an older head is refused; "
        + _FORGET_FROM_HEAD, _LOG + ("vault.team_log_local:TeamLogMixin._refuse_as_served",),
        ("server_lies_about_the_log:old head",)),
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
        DECIDES, _NO_LOG_GRANT + " (SyncClient write_grant in sync_writers.py)", (), ("server_lies:access_up",)),
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
        HINT, "compared with the head of the records it names, where the forget is checked again "
        "(TeamLogMixin team_log_refusal); " + _FORGET_FROM_HEAD,
        _LOG + ("vault.team_log_local:TeamLogMixin._refuse_as_served",), ("server_lies_about_the_log:old head",)),
    "TeamLogRecord.body": _signed(*_LOG, lies=("server_lies_about_the_log:forged record",)),
    "TeamLogRecord.sig": _signed(*_LOG, lies=("server_lies_about_the_log:forged record",)),
    "TeamLogHead.seq": Field(HINT, "compared with the verified records", _LOG, ("server_lies_about_the_log:old head",)),
    "TeamLogHead.hash": Field(HINT, "compared with the verified records", _LOG, ("server_lies_about_the_log:old head",)),
    "TeamLogHead.genesis_hash": Field(
        HINT, "compared with the pinned genesis; " + _FORGET_FROM_HEAD,
        _LOG + ("vault.team_log_local:TeamLogMixin._refuse_as_served",),
        ("server_lies_about_the_log:other genesis",)),
    # ── Shares ──────────────────────────────────────────────────────────────
    "ShareResponse.encrypted_blob": Field(UNREAD, "not read by the desktop"),
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
    "POST /api/share .id": Field(HINT, "names the share in the link handed out; a wrong id only gives the recipient nothing, the key in the link opens no other blob (AEAD)"),
    "POST /api/share .status": Field(UNREAD),
    "PATCH /api/share/{share_id} .status": Field(UNREAD),
    "DELETE /api/share/{share_id} .status": Field(UNREAD),
    # ── Audit ───────────────────────────────────────────────────────────────
    "AuditResponse.entries": Field(UNREAD, "not read by the desktop; see AuditEntry"),
    "AuditResponse.total": Field(UNREAD, _SHOWN),
    "AuditResponse.limit": Field(UNREAD, _SHOWN),
    "AuditResponse.offset": Field(UNREAD, _SHOWN),
    "AuditEntry.id": Field(UNREAD, "not read by the desktop; the web shows it with a badge from client_signature, checked against the pinned key (buildServerAuditCanonical)"),
    "AuditEntry.user_id": Field(UNREAD, "not read by the desktop; the web shows it with a badge from client_signature, checked against the pinned key (buildServerAuditCanonical)"),
    "AuditEntry.username": Field(UNREAD, "not read by the desktop; the web shows it, outside the signature"),
    "AuditEntry.action": Field(UNREAD, "not read by the desktop; the web shows it with a badge from client_signature, checked against the pinned key (buildServerAuditCanonical)"),
    "AuditEntry.timestamp": Field(UNREAD, "not read by the desktop; the web shows it with a badge from client_signature, checked against the pinned key (buildServerAuditCanonical)"),
    "AuditEntry.request_hash": Field(UNREAD, "not read by the desktop; the web shows it with a badge from client_signature, checked against the pinned key (buildServerAuditCanonical)"),
    "AuditEntry.commit_seq_range": Field(UNREAD, "not read by the desktop; the web shows it, outside the signature"),
    "AuditEntry.client_signature": Field(UNREAD, "not read by the desktop; the web shows it with a badge from client_signature, checked against the pinned key (buildServerAuditCanonical)"),
    "AuditEntry.client_ip": Field(UNREAD, _SHOWN),
    "POST /api/audit/log .ok": Field(UNREAD),
    # ── Org recovery ────────────────────────────────────────────────────────
    "OrgRecoveryStatusResponse.configured": Field(
        HINT,
        "superseded_by only withholds this device's waiting org recovery setup (its registration and "
        "queued org.recovery record); its local recovery key stays until the team log names a newer one "
        "(tests/test_inv3_org_recovery_status_withholds.py)",
        ("vault.org_recovery_server:superseded_by", "vault.org_recovery_server:withhold_superseded_setup"),
        ("server_lies_about_org_recovery",)),
    "OrgRecoveryStatusResponse.threshold": Field(HINT, "a label kept with an adopted recovery; the shares' threshold was fixed when they were split"),
    "OrgRecoveryStatusResponse.total_shares": Field(HINT, "a label kept with an adopted recovery; the shares' threshold was fixed when they were split"),
    "OrgRecoveryStatusResponse.created_at": Field(UNREAD, _SHOWN),
    "OrgRecoveryStatusResponse.created_by": Field(
        HINT,
        "superseded_by only withholds this device's waiting org recovery setup (its registration and "
        "queued org.recovery record); its local recovery key stays until the team log names a newer one "
        "(tests/test_inv3_org_recovery_status_withholds.py)",
        ("vault.org_recovery_server:superseded_by", "vault.org_recovery_server:withhold_superseded_setup"),
        ("server_lies_about_org_recovery",)),
    "OrgRecoveryStatusResponse.stale": Field(HINT, "only tells the user to set up again, or skips adopting the key the log names (withholding)"),
    "OrgRecoveryStatusResponse.recovery_signing_pk": Field(
        HINT,
        "superseded_by only withholds this device's waiting org recovery setup (its registration and "
        "queued org.recovery record); its local recovery key stays until the team log names a newer one "
        "(tests/test_inv3_org_recovery_status_withholds.py)",
        ("vault.org_recovery_server:superseded_by", "vault.org_recovery_server:withhold_superseded_setup"),
        ("server_lies_about_org_recovery",)),
    "OrgRecoveryBlobResponse.wrapped_kek": Field(HINT, "only whether a registration whose answer was lost landed: a lie registers again or "
        "stops resending it, which the server could do anyway"),
    "OrgRecoveryBlobResponse.stale": Field(UNREAD, "not read by the desktop"),
    "OrgRecoveryKeypairResponse.encrypted_keypair": Field(UNREAD, "not read by the desktop"),
    "OrgRecoveryKeypairResponse.argon2_salt": Field(UNREAD, "not read by the desktop"),
    "OrgRecoveryKeypairResponse.user_id": Field(UNREAD, "not read by the desktop"),
    "OrgRecoveryKeypairResponse.username": Field(UNREAD, "not read by the desktop"),
    "OrgRecoveryKeypairResponse.signing_pk": Field(UNREAD, "not read by the desktop"),
    "POST /api/org-recovery/store .status": Field(UNREAD),
    # ── AI policy and anchor ────────────────────────────────────────────────
    "AIPolicyResponse.policy": Field(HINT, "none is withholding; one present is checked (AIPolicy)"),
    "AIPolicy.user_id": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.enabled": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.epoch": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.signature": _signed("mcp.remote_policy:verify_policy"),
    "AIPolicy.updated_at": Field(UNREAD, _SHOWN),
    "AIAnchorResponse.anchor": Field(HINT, "missing or malformed counts as no anchor, which the server may lose anyway"),
    "AIAnchor.anchor": Field(UNREAD, "the id this vault asked for; only epoch and mac are read"),
    "AIAnchor.epoch": _signed("mcp.remote_policy:ServerAnchor._held"),
    "AIAnchor.mac": _signed("mcp.remote_policy:ServerAnchor._held"),
    # ── Other ───────────────────────────────────────────────────────────────
    "GET /health .status": Field(UNREAD),
    "GET /health .version": Field(UNREAD, _SHOWN),
}

_SIGNED_FIELDS = ("id", "object_type", "payload", "payload_hash", "parent_ref", "target_user_id", "version",
                  "is_deleted", "client_signature")
_RETIRED_BOUND = ("a retired key's signature counts only for commit_seq at or below its bound, and the server "
                  "sets both (see .archived_keys): goal #443, as on the desktop")
_SIGNER = "only picks whose pinned keys verify the signature; a wrong one fails the check"
_PAGING = "paging: a lie ends or repeats the pull, which withholding may do anyway"
_CURSOR = ("the cursor: a lower one repeats, a higher one skips commits (withholding), as on the desktop "
           "through the shared core")
_ANCHOR = "rollback anchor: a made-up one only makes a later pull see a rollback and ask for a full resync"
_FULL_RESYNC = "into the shared core's gate: a made-up one forces a full resync, as on the desktop"
_EACH_CHECKED = "each object is checked on its own; which ones come and in what order is the server's"
_KEY_HASH = ("another hash ends the session or asks for the password, and the key material fetched then "
             "opens only under it (AEAD)")


def _pull_fields(sig_checks: tuple[str, ...], pull: str, log: str) -> dict[str, Field]:
    return {
        **{f"PullObject.{name}": _signed(*sig_checks) for name in _SIGNED_FIELDS},
        "PullObject.signature_user_id": Field(HINT, _SIGNER, sig_checks),
        "PullObject.commit_seq": Field(DECIDES, _RETIRED_BOUND, sig_checks),
        "PullObject.write_policy": Field(HINT, "only the edit UI ('shared' with a write envelope); every "
                                               "receiver checks the write against the team log"),
        "PullResponse.objects": Field(HINT, _EACH_CHECKED, (pull,)),
        "PullResponse.has_more": Field(HINT, _PAGING, (pull,)),
        "PullResponse.next_cursor": Field(HINT, _PAGING, (pull,)),
        "PullResponse.max_commit_seq": Field(HINT, _CURSOR, (pull,)),
        "PullResponse.max_token": Field(HINT, _ANCHOR, (pull,)),
        "PullResponse.check_token": Field(HINT, _FULL_RESYNC, (pull,)),
        "PullResponse.key_material_hash": Field(HINT, _KEY_HASH, (pull,)),
        "PullResponse.team_log_head": Field(
            HINT, "the log is fetched and checked record by record against this device's pins and an "
            "older head is refused; " + _FORGET_FROM_HEAD, (log,)),
    }


def _log_fields(sync: str, refusal: str, replay: str) -> dict[str, Field]:
    return {
        "TeamLogResponse.records": Field(
            HINT, "every record is replayed and verified onto this device's head; a short or reordered page "
            "is refused (short_of_head, does_not_replay)", (sync, replay)),
        "TeamLogResponse.head": Field(
            HINT, "compared with the replayed records, where the forget is checked again; "
            + _FORGET_FROM_HEAD, (refusal, sync)),
        "TeamLogRecord.body": _signed(replay),
        "TeamLogRecord.sig": _signed(replay),
        "TeamLogHead.seq": Field(
            HINT, "compared with the replayed records and the pin: a lie is went_back, differs or "
            "short_of_head, none of which offers forget", (sync,)),
        "TeamLogHead.hash": Field(HINT, "as .seq: differs or short_of_head, never forget", (sync,)),
        "TeamLogHead.genesis_hash": Field(
            HINT, "compared with the pin; " + _FORGET_FROM_HEAD, (sync,)),
    }


_NO_JSON_STATUS = ("the web reads no status in a reply body: Error.status is the HTTP code, user.status "
                   "is UserInfo's")

_CHALLENGE = ("signed behind a context prefix and at a fixed length, so it is never another signed message; "
              "a lie fails the login")
_SETUP = {
    "BootstrapStatusResponse.needs_setup": Field(HINT, "only offers the setup form; the server decides setup"),
    "BootstrapStatusResponse.unfinished_setup": Field(HINT, "only explains why the setup form is offered"),
}
_RECOVER_REST = {key: Field(UNREAD, "only encrypted_keypair and user_id of the recover reply are read") for key in (
    "RecoverResponse.argon2_params", "RecoverResponse.argon2_salt")}


def _not_called(path: str, *keys: str) -> dict[str, Field]:
    return {key: Field(UNREAD, f"this client never calls {path}") for key in keys}


def _auth_fields(signin: str, challenge: str, recover: str) -> dict[str, Field]:
    return {
        **{key: Field(HINT, _TOKEN) for key in (
            "VerifyResponse.token", "BootstrapResponse.token", "RegisterResponse.token")},
        **{key: Field(
            HINT, "the id the server gives the new account: the keys are wrapped for it (KEYPAIR_WRAP AAD) "
            "and every later sign-in must name it; objects signed under it verify only against the keys the "
            "log and pins hold for it", (signin,)) for key in ("BootstrapResponse.user_id", "RegisterResponse.user_id")},
        "ChallengeResponse.challenge": Field(HINT, _CHALLENGE, (challenge,)),
        "ChallengeResponse.timestamp": Field(HINT, "signed back with the challenge; a lie fails the login"),
        "RecoverResponse.encrypted_keypair": _signed(recover),
        "RecoverResponse.user_id": _signed(recover),
        **_RECOVER_REST,
        **_SETUP,
        **_not_called("GET /health", "GET /health .version"),
        **_not_called("PUT /api/me/kdf-params", "PUT /api/me/kdf-params .argon2_params"),
        **_not_called("/api/auth/provisioning-token (the desktop makes the QR)",
                      "ProvisioningTokenResponse.token", "ProvisioningTokenResponse.username"),
    }


_HELD_NOT_ASKED = {key: Field(UNREAD, "this client never calls /api/objects/held (only the desktop's re-key "
                                       "does); the names are its own objects'") for key in (
    "HeldResponse.objects", "HeldObject.id", "HeldObject.object_type", "HeldObject.version",
    "HeldObject.is_deleted")}

CLIENT_FIELDS: dict[str, dict[str, Field]] = {
    "web": {
        "VerifyResponse.is_admin": Field(
            HINT, "with a team log known, admin is who the verified log says (webIsAdmin: canEditObject, "
            "buildWebRekeyBatch, Shamir setup); a refused or pinned-not-held log makes nobody admin. It "
            "stands only for a vault with no log at all, whose admin calls the server authorizes (S6), and "
            "asks for the server's own admin list (performTOFUChecks), which only adds pin checks",
            ("webIsAdmin",)),
        "VerifyResponse.key_material_hash": Field(
            HINT, "equal to the hash of the cached wrap keeps the keypair this browser opened under its "
            "password (what withholding a rotation does anyway); any other value only fetches the server's, "
            "which opens under the password alone"),
        "MetaResponse.argon2_web_params": Field(
            HINT, "clamped to the hard floor and refused above the account maximum", ("normalizeKdfParams",)),
        "PullObject.access_level": Field(
            DECIDES, _NO_LOG_GRANT + " (unauthorizedWrites); with a log keyEnvelopesForUser checks it "
            "(envelopeValid), a re-key carries 'write' only from an envelope this browser made",
            ("unauthorizedWrites", "keyEnvelopesForUser")),
        "PullObject.owner_id": Field(
            HINT, "who wrote a copy is its verified signer (pullAndBuildTreeLocked's verifiedSigner: the "
            "signature checked at pull, "
            "or this account for a queued change), which resolveInheritedPersonalDekId and "
            "migrateLegacyPersonalDescendants ask (a personal object is signed by its author only, TL7); "
            "owner_id is left to canEditObject's edit UI, every receiver checks the write by signature "
            "(unauthorizedWrites). As the signer fallback it is checked like signature_user_id",
            ("pullAndBuildTreeLocked", "resolveInheritedPersonalDekId", "migrateLegacyPersonalDescendants")),
        "PullObject.scope": Field(
            HINT, "a label: it picks which items below this account's personal root move to its personal "
            "key (migrateLegacyPersonalDescendants), the root key among the ones this KEK opened, and an "
            "order; every choice is a key this account holds",
            ("migrateLegacyPersonalDescendants",)),
        "PullResponse.gc_floor_seq": Field(
            HINT, "into the shared core as on the desktop (against_held, next_cursor); a lower floor sends "
            "this browser's own signed copies again, a higher one does not (withholding)",
            ("webPulledIsStale", "syncPositionAfter", "requeueWritesTheServerLost")),
        "PullResponse.head_commit_seq": Field(
            HINT, "into the shared core as on the desktop (gate, next_cursor): a lower head asks for a full "
            "resync, a higher one hides a rollback (withholding)", ("syncPositionAfter",)),
        "PullResponse.key_epoch": Field(
            HINT, "a lower one is refused; a higher one (or another key_material_hash) ends the session, and "
            "the next login's key material opens only under the password; a journal from before epochs "
            "takes it +1, which the server refuses if wrong", ("applyKekRotationJournal",)),
        "PushResponse.commit_token": Field(UNREAD, "the name is the browser's own checkpoint field; the "
                                           "token comes from the pull's max_token"),
        "RecoverResponse.key_epoch": Field(UNREAD, "the recover reply gives only encrypted_keypair and user_id"),
        "UserInfo.status": Field(
            HINT, "the admin list's buttons; a revocation re-key stops while another holder is not active, "
            "and otherwise drops only the revoked member, as with the status unread (withholding)",
            ("buildWebRekeyBatch",)),
        **{key: Field(UNREAD, _NO_JSON_STATUS) for key in (
            "DELETE /api/share/{share_id} .status", "DELETE /api/users/{user_id} .status", "GET /health .status",
            "PATCH /api/share/{share_id} .status", "PATCH /api/users/{user_id}/approve .status",
            "PATCH /api/users/{user_id}/reactivate .status", "POST /api/auth/logout .status",
            "POST /api/me/key-material-archive/purge .status", "POST /api/org-recovery/store .status",
            "POST /api/share .status", "POST /api/users/{user_id}/allow-key-reset .status",
            "POST /api/users/{user_id}/unlock-recovery .status", "PUT /api/me/kdf-params .status",
            "PUT /api/me/keypair .status")},
        **_pull_fields(("verifyObjectSignature", "pullAndBuildTreeLocked"), "pullAndBuildTreeLocked",
                       "syncWebTeamLog"),
        "PullObject.modified_at": Field(UNREAD, "the name is a field of a decrypted entry, not the server's"),
        **_log_fields("syncWebTeamLog", "webTeamLogRefusal", "replay"),
        **_HELD_NOT_ASKED,
        "PushResponse.accepted": Field(
            HINT, "marks a sent write, a re-key or a member's envelopes landed: the queued copy leaves and "
            "its own version is the next base; a lie keeps it from the server, which could drop it anyway "
            "(withholding), and the next pull brings the server's copy checked",
            ("pushEncryptedVaultObjectLocked", "pushWebRekeyBatch", "sealToRotatedMembers")),
        "PushResponse.conflicts": Field(
            HINT, "a refused write stays queued and is shown; a re-key or envelope batch with one is "
            "refused and tried again", ("pushEncryptedVaultObjectLocked", "pushWebRekeyBatch")),
        "PushResponse.token": Field(HINT, _TOKEN, ("applyKekRotationJournal",)),
        "PushObjectResult.id": Field(HINT, "names the sent write a result is about; see .accepted, .conflicts"),
        "PushObjectResult.server_version": Field(
            HINT, "shown in the conflict; none lets the next accepted copy settle the refusal, which only "
            "clears a conflict whose write has landed", ("pushEncryptedVaultObjectLocked",)),
        "PushObjectResult.server_payload_hash": Field(
            HINT, "equal to the sent hash counts a password change's DEK as landed by an earlier attempt; a "
            "lie leaves a wrap the server did not keep, as dropping it would (withholding), and the old "
            "wrap opens only under the old password", ("applyKekRotationJournal",)),
        **{key: Field(UNREAD, "the browser reads no seq, error or code of a push result: its "
                              "commit_seq is the pulled object's") for key in (
            "PushObjectResult.commit_seq", "PushObjectResult.error", "PushObjectResult.code")},
        "MetaResponse.argon2_params": Field(
            HINT, "for the KDF clamped to the hard floor and refused above the account maximum, and the "
            "keypair wrap opens under them (AEAD); org recovery records the forgotten password with the "
            "state this browser saw it open (webKdfStateOf, bound to the recovered KEK), never these",
            ("accountKdfParams", "webKdfStateOf")),
        "MetaResponse.argon2_salt": Field(
            HINT, "the salt the keypair wrap opens under (AEAD); none is no such user, another one than a "
            "password-change journal's stops its resume", ("deriveLoginKey",)),
        "MetaResponse.version": Field(UNREAD, "the name is an object's version; the server's is not read"),
        **_auth_fields("signedInUserId", "signAuthChallenge", "decryptLoginKeypair"),
        "VerifyResponse.user_id": Field(
            HINT, "this browser's identity only when it is the account its keys were wrapped for (KEYPAIR_WRAP "
            "AAD); another refuses the sign-in, as on the phone (tests/test_inv3_web_verify_user_id.py). A "
            ".sezam-key wraps for a random id, so its keys are bound at their first sign-in (firstSignInUserId), "
            "as the desktop's rebind_server_identity; getUserSigningPks then refuses another account's keys",
            ("signedInUserId", "firstSignInUserId", "getUserSigningPks")),
        "VerifyResponse.username": Field(
            HINT, "kept for this session only; the next sign-in asks under it and only this browser's keys "
            "answer, for the account signedInUserId checks", ("signedInUserId",)),
        "POST /api/auth/refresh .token": Field(HINT, _TOKEN),
        "PUT /api/me/keypair .token": Field(UNREAD, "the upload's reply is not read"),
        "InviteResponse.invitation_token": Field(UNREAD, "handed to the invitee out of band"),
        **_not_called("/api/auth/registration-resume", "POST /api/auth/registration-resume .key_material_hash",
                      "POST /api/auth/registration-resume .token", "POST /api/auth/registration-resume .user_id"),
        **_not_called("/api/auth/provision", "ProvisionResponse.argon2_params", "ProvisionResponse.argon2_salt",
                      "ProvisionResponse.encrypted_keypair", "ProvisionResponse.user_id"),
        # ── Users and member keys ──
        "UserInfo.id": Field(
            HINT, "picks whose keys the admin list pins on first use (performTOFUChecks); a member's keys are "
            "sealed to only from /keys, checked against the same pin", ("performTOFUChecks", "checkKnownKey")),
        "UserInfo.username": Field(UNREAD, _SHOWN),
        "UserInfo.is_admin": Field(
            HINT, "the list's badge, and which row offers the revoke button; the revocation is checked by the "
            "server and the team log, not by this flag"),
        "UserInfo.signing_pk": Field(
            HINT, "pinned on first use (checkKnownKey); a changed one shows the key-change warning, and sealing "
            "takes the keys from /keys against that pin", ("performTOFUChecks", "checkKnownKey")),
        "UserInfo.encryption_pk": Field(
            HINT, "pinned with the signing key (checkKnownKey)", ("performTOFUChecks", "checkKnownKey")),
        "UserInfo.key_fingerprint": Field(
            UNREAD, "the fingerprint read is an archived key's, compared with its own keys; " + _USER_LIST_FP),
        "GET /api/users/{user_id}/keys .signing_pk": Field(
            HINT, "pinned on first use; a changed key is a key-change error (TofuKeyChangeError), and this "
            "account's own must be the keys its password opened",
            ("getUserSigningPks", "getVerifiedEncryptionPkForRekey", "checkKnownKey")),
        "GET /api/users/{user_id}/keys .encryption_pk": Field(
            HINT, "pinned with the signing key", ("getUserSigningPks", "getVerifiedEncryptionPkForRekey")),
        "GET /api/users/{user_id}/keys .archived_keys": Field(
            DECIDES, "certified by their successor as on the desktop, but retired_seq is unsigned and kept only "
            "for the session (state.archivedKeyBounds, cleared at sign-out): each new session takes the "
            "server's bound for a leaked retired key; goal #443", ("getUserSigningPks",)),
        # ── Shares, audit, AI ──
        "ShareResponse.encrypted_blob": _signed("decryptShareBlob"),
        **_not_called("/api/shares or POST /api/share (the browser only opens a share link)",
                      "ShareInfo.id", "ShareInfo.created_by", "ShareNotification.id", "POST /api/share .id"),
        "AuditResponse.entries": Field(HINT, "the rows shown; a server can leave rows out (withholding)"),
        "AuditResponse.total": Field(UNREAD, _SHOWN),
        **{key: Field(
            HINT, "shown with a badge: client_signature over id, user_id, action, timestamp and request_hash is "
            "checked against the author's trusted keys; without one the row shows as unverified",
            ("loadAuditEntries", "buildServerAuditCanonical")) for key in (
            "AuditEntry.id", "AuditEntry.user_id", "AuditEntry.action", "AuditEntry.timestamp",
            "AuditEntry.request_hash", "AuditEntry.client_signature")},
        **{key: Field(UNREAD, _SHOWN + ", outside the signature") for key in (
            "AuditEntry.username", "AuditEntry.client_ip", "AuditEntry.commit_seq_range")},
        "POST /api/audit/log .ok": Field(UNREAD, "the ok read is the fetch Response's"),
        **_not_called("/api/ai-policy", "AIPolicy.signature", "AIPolicy.user_id"),
        # ── Org recovery ──
        **{key: Field(
            HINT, "only refuses a password change of the account that set org recovery up "
            "(publishWebTeamAnchorLocked), picks the setup's warning text (handleShamirGenerate), or ends a "
            "recovery early (openOrgRecoveryModal); a lie the other way leaves the recovery wrapping the old "
            "KEK, which the server could make useless by dropping its blob anyway (withholding)",
            ("publishWebTeamAnchorLocked", "handleShamirGenerate", "openOrgRecoveryModal")) for key in (
            "OrgRecoveryStatusResponse.configured", "OrgRecoveryStatusResponse.created_by",
            "OrgRecoveryStatusResponse.stale")},
        **{key: Field(
            HINT, "how many share fields the recovery shows, re-stored as a label with the re-wrapped blob; "
            "the shares' threshold was fixed when they were split, too few do not open the blob (AEAD)",
            ("openOrgRecoveryModal", "handleOrgRecovery")) for key in (
            "OrgRecoveryStatusResponse.threshold", "OrgRecoveryStatusResponse.total_shares")},
        "OrgRecoveryStatusResponse.recovery_signing_pk": Field(
            UNREAD, "the one read is this browser's own journal's (resumed.recovery_signing_pk)"),
        "OrgRecoveryBlobResponse.wrapped_kek": _signed("handleOrgRecovery"),
        "OrgRecoveryBlobResponse.stale": Field(HINT, "only ends the recovery (withholding)", ("handleOrgRecovery",)),
        "OrgRecoveryKeypairResponse.encrypted_keypair": _signed("decryptLoginKeypair"),
        "OrgRecoveryKeypairResponse.user_id": _signed("decryptLoginKeypair"),
        "OrgRecoveryKeypairResponse.username": Field(
            HINT, "the recovered keys sign in under it, and only they answer, for the account signedInUserId "
            "checks", ("signedInUserId",)),
        "OrgRecoveryKeypairResponse.argon2_salt": Field(
            UNREAD, "a recovered bundle without the anchor is recorded under the state this browser saw the "
            "forgotten password open (webKdfStateOf, bound to the recovered KEK); with none known no anchor "
            "is published"),
        "OrgRecoveryKeypairResponse.signing_pk": Field(UNREAD, "the signing key read is the recovered keys' own"),
    },
    "mobile": {
        "VerifyResponse.is_admin": Field(
            HINT, "stored as sezam_is_admin (also for offline unlock); with a team log known, admin is who "
            "the verified log says (VaultService.isAdmin, which VaultEntry.canEdit asks), a refused log makes "
            "nobody admin; it stands only for a vault with no log at all (S6)",
            ("isAdmin",)),
        "MetaResponse.argon2_web_params": Field(
            HINT, "refused outside the server policy's bounds, never guessed", ("accountKdfParams",)),
        "PullObject.access_level": Field(
            DECIDES, _NO_LOG_GRANT + " (unauthorizedWrites); with a log TeamLog.envelopeValid checks it, "
            "VaultEntry.canEdit only gates the edit UI", ("unauthorizedWrites", "envelopeValid")),
        "PullObject.owner_id": Field(
            HINT, "a DEK's owner is the verified signer (verifiedOwnerId), the signer fallback is checked "
            "like signature_user_id; otherwise VaultEntry.canEdit's edit UI, and every receiver checks the "
            "write against the team log", ("verifiedOwnerId",)),
        "PullResponse.gc_floor_seq": Field(
            HINT, "into the shared core as on the desktop (next_cursor); a lower floor sends this phone's own "
            "signed rows again, a higher one does not (withholding)", ("rowsTheServerLost",)),
        "PullResponse.head_commit_seq": Field(
            HINT, "into the shared core as on the desktop (gate, next_cursor): a lower head asks for a full "
            "resync, a higher one hides a rollback (withholding)"),
        "PullResponse.key_epoch": Field(
            HINT, "a lower one is taken only while this phone holds exactly the server's key material "
            "(as the desktop, SM12); a higher one asks for the password", ("_holdsServerKeyMaterial",)),
        "PushResponse.commit_token": Field(UNREAD, "the name is the phone's own checkpoint field; the token "
                                           "comes from the pull's max_token"),
        "RecoverResponse.key_epoch": Field(UNREAD, "the recover reply's epoch is not read; the pull's is"),
        **_pull_fields(("buildSyncSignatureData", "keyMayVouch"), "_pull", "syncTeamLog"),
        "PullObject.modified_at": Field(
            HINT, "kept as the row's time; the queue orders only this phone's own edits, stamped here"),
        **_log_fields("syncTeamLog", "_teamLogRefusal", "replay"),
        **_HELD_NOT_ASKED,
        "PushResponse.accepted": Field(
            HINT, "marks the sent version clean (markClean); a lie keeps it from the server, which could drop "
            "it anyway (withholding), and the next pull brings the server's copy checked",
            ("_push", "markClean", "advanceKeyEpoch")),
        "PushResponse.conflicts": Field(
            HINT, "counted and shown; the write stays queued, a key-epoch advance with one is refused",
            ("_push", "advanceKeyEpoch")),
        "PushResponse.token": Field(HINT, _TOKEN, ("advanceKeyEpoch",)),
        "PushObjectResult.id": Field(HINT, "names the sent write a result is about; see .accepted, .conflicts"),
        "PushObjectResult.commit_seq": Field(
            HINT, "the accepted copy's seq (markClean): it drops held-aside copies below it, which the server "
            "could have withheld; one at or below the GC floor lets a full resync drop this phone's copy the "
            "server then lacks instead of sending it again (rowsTheServerLost): that guards against a server "
            "restored from a backup (review d615826 H6), not one that drops writes, which it may (withholding)",
            ("markClean", "rowsTheServerLost")),
        "PushObjectResult.server_payload_hash": Field(
            HINT, "equal to the sent hash counts a key-epoch advance's DEK as landed by an earlier attempt; a "
            "lie leaves a wrap the server did not keep, as dropping it would (withholding)",
            ("advanceKeyEpoch",)),
        "PushObjectResult.server_version": Field(
            UNREAD, "the name is the phone's own sync_conflicts column, filled from the pulled copy"),
        "PushObjectResult.error": Field(UNREAD, _SHOWN),
        "PushObjectResult.code": Field(UNREAD, "the code read is an HTTP error body's (_errorCode)"),
        "MetaResponse.argon2_params": Field(
            HINT, "refused outside the server policy's bounds, never guessed", ("accountKdfParams",)),
        "MetaResponse.argon2_salt": Field(
            HINT, "the salt the keypair wrap opens under (AEAD); this phone's own params while it is the "
            "local salt", ("_accountKdfFor",)),
        "MetaResponse.version": Field(UNREAD, "the name is an object's version; the server's is not read"),
        **_auth_fields("requireCanonicalUserObjectId", "signAuthChallenge", "_openAnchoredAccountKeypair"),
        "VerifyResponse.user_id": Field(
            HINT, "compared with the id the keypair is wrapped for (review 8595ec1 R10-F): another fails the "
            "sign-in; the other sign-ins take the id from the keys and read only is_admin"),
        "VerifyResponse.username": Field(
            HINT, "a new name is stored only after this phone's key logs in under it", ("_logsInAs",)),
        "VerifyResponse.key_material_hash": Field(UNREAD, "the name is the pull's and the registration resume's"),
        "POST /api/auth/registration-resume .token": Field(HINT, _TOKEN),
        "POST /api/auth/registration-resume .user_id": Field(
            HINT, "must equal the first registration reply's; the id the keys are wrapped for"),
        "POST /api/auth/registration-resume .key_material_hash": Field(
            HINT, "equal to the hash of this phone's wrap skips the upload, which the server could drop anyway "
            "(withholding); another one refuses the registration"),
        "PUT /api/me/keypair .token": Field(HINT, _TOKEN, ("uploadKeypair",)),
        **_not_called("/api/auth/refresh", "POST /api/auth/refresh .token"),
        "ProvisionResponse.encrypted_keypair": _signed("_opensKeypair"),
        "ProvisionResponse.user_id": _signed("_opensKeypair"),
        "ProvisionResponse.argon2_params": Field(
            HINT, "refused outside the server policy's bounds, never guessed", ("accountKdfParams",)),
        "ProvisionResponse.argon2_salt": Field(HINT, "the salt the keypair wrap opens under (AEAD)", ("_opensKeypair",)),
        # ── Users and member keys ──
        **_not_called("/api/users (the admin user list)", "UserInfo.id", "UserInfo.username", "UserInfo.is_admin",
                      "UserInfo.signing_pk", "UserInfo.encryption_pk", "UserInfo.key_fingerprint"),
        "GET /api/users/{user_id}/keys .signing_pk": Field(
            HINT, "pinned on first use; a changed key is a key-change error (TofuKeyChangeException), and this "
            "account's own must be this phone's", ("resolveAuthorSigningKeys",)),
        "GET /api/users/{user_id}/keys .encryption_pk": Field(
            HINT, "pinned with the signing key", ("resolveAuthorSigningKeys",)),
        "GET /api/users/{user_id}/keys .archived_keys": Field(
            DECIDES, "certified by their successor as on the desktop, but retired_seq is unsigned and pinned "
            "on first sight only (archived_key_bound:*): goal #443", ("resolveAuthorSigningKeys",)),
        # ── Shares, audit, AI ──
        "ShareResponse.encrypted_blob": _signed("consumeShareLink"),
        "POST /api/share .id": Field(
            HINT, "must be the id this phone chose; another refuses the share", ("createShareLink",)),
        "ShareInfo.id": Field(UNREAD, "listShares, the only call of /api/shares, has no caller"),
        "ShareInfo.created_by": Field(UNREAD, "listShares, the only call of /api/shares, has no caller"),
        **_not_called("for share notifications", "ShareNotification.id"),
        **_not_called("/api/audit", "AuditResponse.entries", "AuditEntry.id", "AuditEntry.user_id",
                      "AuditEntry.username", "AuditEntry.action", "AuditEntry.timestamp",
                      "AuditEntry.client_signature", "POST /api/audit/log .ok"),
        "AIPolicyResponse.policy": Field(
            HINT, "none is epoch 0; the brake is published above the stored epoch", ("pullBrake",)),
        "AIPolicy.epoch": Field(
            HINT, "the brake takes an epoch above it and at least the current time; a lower one can only get "
            "the brake refused or ignored, as dropping it would (withholding)", ("pullBrake",)),
        **{key: Field(UNREAD, "the brake reads only the stored policy's epoch") for key in (
            "AIPolicy.signature", "AIPolicy.user_id")},
        **_not_called("/api/ai-anchor", "AIAnchor.epoch"),
        # ── Org recovery ──
        **{key: Field(
            HINT, "only refuses a password change of the account that set org recovery up (publishTeamAnchor); "
            "a lie the other way leaves the recovery wrapping the old KEK, which the server could make useless "
            "by dropping its blob anyway (withholding)", ("publishTeamAnchor",)) for key in (
            "OrgRecoveryStatusResponse.configured", "OrgRecoveryStatusResponse.created_by",
            "OrgRecoveryStatusResponse.stale")},
        **{key: Field(UNREAD, "the names read are a signed team log record's") for key in (
            "OrgRecoveryStatusResponse.threshold", "OrgRecoveryStatusResponse.total_shares")},
        **_not_called("/api/org-recovery/blob or /keypair (recovery is the desktop's and the web's)",
                      "OrgRecoveryBlobResponse.stale", "OrgRecoveryBlobResponse.wrapped_kek",
                      "OrgRecoveryKeypairResponse.argon2_salt", "OrgRecoveryKeypairResponse.encrypted_keypair",
                      "OrgRecoveryKeypairResponse.signing_pk", "OrgRecoveryKeypairResponse.user_id",
                      "OrgRecoveryKeypairResponse.username"),
    },
}
