"""The server's authority map (docs/ROOT_CAUSE_PLAN.md S1, INV-2).

One entry per route of the app: what it changes, who may call it, which
functions enforce that and which tests cover it. ``tests/test_authority_map.py``
fails on a route without an entry, on an entry whose route is gone, on a
route that writes while its entry says it only reads, and on checks that do
not match the route's dependencies. ``docs/AUTHORITY_MAP.md`` is generated
from this file and from ``sezam.authority`` (``python scripts/authority_map.py``).

``checks`` name functions as ``module:function`` under ``server.app``; an auth
dependency (``dependencies:...``) listed here must be one the route uses, and
every auth dependency the route uses must be listed.
"""

from __future__ import annotations

from dataclasses import dataclass

# Who may: the account kinds the entries name.
PUBLIC = "anyone"
PROOF = "anyone holding the proof the checks verify (no session)"
SESSION = "a signed-in account (full session)"
ONBOARDING = "a signed-in account, or the onboarding session of a new one"
ROTATION = "a signed-in account, or a retired key's session that proved the log's current key"
READER = "a signed-in account, or any retired key's session"
ADMIN = "the admin: users.is_admin, which the team log sets once it has a genesis"
LOG = "decided record by record by the signed team log (signer's role in the log)"


@dataclass(frozen=True)
class Route:
    changes: str  # "" = reads only
    who: str
    checks: tuple[str, ...]
    tests: tuple[str, ...]
    note: str = ""


ROUTES: dict[str, Route] = {
    # ── Bootstrap and accounts ──────────────────────────────────────────────
    "GET /api/bootstrap-status": Route(
        "", PUBLIC, (), ("tests/test_unfinished_bootstrap_explained.py",),
    ),
    "POST /api/bootstrap": Route(
        "creates the first admin account (users)",
        PUBLIC + ", only while no usable admin exists; a reseed proves the identity key",
        ("routers.auth:_abandoned_bootstrap_id", "auth:verify_reseed_signature"),
        ("tests/test_unfinished_bootstrap_explained.py", "tests/test_ai_r3_reseed.py"),
        "before the team log's genesis this account is the only authority (is_admin=1)",
    ),
    "POST /api/auth/rejoin": Route(
        "brings back an account a restored backup lost (users)",
        PROOF + ": the keys the team log names for that id, over a fresh challenge",
        ("routers.auth:_rejoin_keys_logged", "auth:verify_reseed_signature", "team_log:load_state"),
        ("tests/test_review10_restore_before_member.py", "tests/test_review11_rejoin_name_taken.py"),
    ),
    "POST /api/auth/challenge": Route(
        "", PUBLIC, ("auth:generate_bound_challenge",), ("tests/test_server_spec.py",),
        "stateless: a challenge is consumed (written) only by the request that signs it",
    ),
    "POST /api/auth/registration-resume": Route(
        "consumes the signed challenge; re-issues an onboarding session",
        PROOF + ": the pending account's signing key over a fresh challenge",
        ("routers.auth:consume_signed_challenge",), ("tests/test_server_spec.py",),
    ),
    "POST /api/auth/verify": Route(
        "consumes the signed challenge; issues a session",
        PROOF + ": the account's signing key over a fresh challenge",
        ("routers.auth:consume_signed_challenge", "auth:verify_current_key_proof"),
        ("tests/test_server_spec.py", "tests/test_review9_retired_key_after_restore.py"),
    ),
    "POST /api/auth/refresh": Route(
        "consumes the signed challenge; issues a new session",
        SESSION + ", with a fresh challenge signed by its key",
        ("dependencies:get_current_user", "routers.auth:consume_signed_challenge"),
        ("tests/test_server_spec.py", "tests/test_review7_web_lost_refresh_response.py"),
    ),
    "POST /api/auth/logout": Route(
        "revokes the session's token (revoked_tokens)", SESSION + " (its own token only)",
        ("dependencies:get_current_user",), ("tests/test_server_spec.py",),
    ),
    "POST /api/auth/provisioning-token": Route(
        "mints a one-time device token for the caller's own account",
        SESSION, ("dependencies:require_full_jwt",), ("tests/test_team_log_desktop.py",),
    ),
    "POST /api/auth/provision": Route(
        "consumes the device token", PROOF + ": the one-time device token (10 min)",
        ("routers.auth:auth_provision",), ("tests/test_server_spec.py", "tests/test_review_server_medium.py"),
        "returns key material still wrapped by the master password",
    ),
    "POST /api/auth/recover": Route(
        "replaces the account's key material; failure counters and lockouts",
        PROOF + ": the account password's auth proof, within the lockout rations",
        ("auth:compute_auth_proof_hash", "routers.auth:record_wrong_account_proof"),
        ("tests/test_server_spec.py", "tests/test_recover_lockout_dos.py"),
    ),
    "PUT /api/me/keypair": Route(
        "stores the account's first key material",
        ONBOARDING + "; a full session only while the account has no key material, with a fresh challenge",
        ("dependencies:get_keypair_upload_user", "routers.auth:consume_signed_challenge"),
        ("tests/test_server_spec.py",),
    ),
    "PUT /api/me/kdf-params": Route(
        "stores the KDF params of an account kept without them (once)",
        SESSION + ", with a challenge signed by the account keypair",
        ("dependencies:require_full_jwt", "routers.auth:consume_signed_challenge"),
        ("tests/test_legacy_account_kdf_review_n2.py",),
    ),
    "POST /api/me/key-material-archive": Route(
        "takes a probe slot (rate limit)", SESSION + ", with the current password's auth proof",
        ("dependencies:require_full_jwt", "routers.auth:_key_material_archive_op"),
        ("tests/test_key_material_archive_access.py",),
    ),
    "POST /api/me/key-material-archive/purge": Route(
        "deletes the account's archived key material",
        SESSION + ", with the current password's auth proof",
        ("dependencies:require_full_jwt", "routers.auth:_key_material_archive_op"),
        ("tests/test_key_material_archive_access.py",),
    ),
    # ── Users (admin endpoints) ─────────────────────────────────────────────
    "POST /api/users/invite": Route(
        "creates an invitation token", ADMIN, ("dependencies:require_admin",),
        ("tests/test_team_log_desktop.py",),
    ),
    "POST /api/users/register": Route(
        "creates a pending account", PROOF + ": a one-time invitation token (72 h)",
        ("routers.users:register_user",), ("tests/test_server_spec.py", "tests/test_integration.py"),
        "the account gets no team access until an admin's signed member.add",
    ),
    "GET /api/users": Route("", ADMIN, ("dependencies:require_admin",), ("tests/test_server_spec.py",)),
    "POST /api/users/{user_id}/unlock-recovery": Route(
        "clears a recovery lockout; a one-time unlock code", ADMIN,
        ("dependencies:require_admin",), ("tests/test_recovery_unlock_code.py",),
    ),
    "POST /api/users/{user_id}/allow-key-reset": Route(
        "lets the account replace its key material once without the password",
        ADMIN + ", never for itself", ("dependencies:require_admin",),
        ("tests/test_key_material_needs_password.py",),
    ),
    "GET /api/users/{user_id}/keys": Route(
        "", READER, ("dependencies:get_team_log_reader",), ("tests/test_server_spec.py",),
    ),
    "PATCH /api/users/{user_id}/approve": Route(
        "activates a pending account (status)", ADMIN, ("dependencies:require_admin",),
        ("tests/test_server_spec.py",),
    ),
    "PATCH /api/users/{user_id}/rotate-keys": Route(
        "", SESSION, ("dependencies:require_full_jwt",), ("tests/test_identity_rotation.py",),
        "disabled: always refuses",
    ),
    "DELETE /api/users/{user_id}": Route(
        "revokes an account: status, write_acl, re-key", ADMIN + ", never the last admin",
        ("dependencies:require_admin",),
        ("tests/test_revoke_admins_review12.py", "tests/test_team_log_server.py"),
    ),
    "PATCH /api/users/{user_id}/reactivate": Route(
        "undoes a revocation (status only)", ADMIN, ("dependencies:require_admin",),
        ("tests/test_revoke_admins_review12.py", "tests/test_review9_server_reactivate.py"),
    ),
    # ── Sync ────────────────────────────────────────────────────────────────
    "POST /api/sync/stage": Route(
        "stages objects of the caller's next all-or-nothing push", ROTATION,
        ("dependencies:get_rotation_user", "routers.sync:_check_objects"),
        ("tests/test_review7_staged_push_memory_h7.py",),
    ),
    "POST /api/sync": Route(
        "objects, write_acl, key material (rotation, password change), team log records",
        ROTATION + "; each object by its signer's write access (team folders: the log), "
        "team records by the log, key material by the account's current key or a reset grant",
        (
            "dependencies:get_rotation_user", "routers.sync:_verify_sync_signature",
            "routers.sync:_has_write_authority", "routers.sync:_team_log_refusal",
            "routers.sync:_authorize_key_material_change", "team_log:append",
        ),
        ("tests/test_server_spec.py", "tests/test_sync_state_machine.py"),
    ),
    "GET /api/sync": Route("", ROTATION, ("dependencies:get_rotation_user",), ("tests/test_server_spec.py",)),
    "GET /api/meta": Route("", PUBLIC, (), ("tests/test_legacy_account_kdf_review_n2.py",),
                           "unknown names get a fake salt"),
    "POST /api/objects/held": Route(
        "", ROTATION, ("dependencies:get_rotation_user",), ("tests/test_r15_rekey_landed_on_server.py",),
    ),
    # ── Team log ────────────────────────────────────────────────────────────
    "GET /api/team-log": Route("", READER, ("dependencies:get_team_log_reader",),
                               ("tests/test_inv8_forget_acts_only_on_lost.py",)),
    "POST /api/team-log": Route(
        "team log records; users (role, status, keys) and write_acl follow them", SESSION + "; " + LOG,
        ("dependencies:require_full_jwt", "team_log:prepare_append", "team_log:append"),
        ("tests/test_team_log_server.py", "tests/test_inv2_restore_within_append.py"),
    ),
    "POST /api/team-log/restore": Route(
        "team log records the server lost", SESSION + "; " + LOG
        + ", never more than an append (INV-2) and key rotations only by the team admin",
        ("dependencies:require_full_jwt", "team_log:prepare_restore", "team_log:restore"),
        ("tests/test_inv2_restore_within_append.py", "tests/test_review9_team_log_restore.py"),
    ),
    # ── Secure Share ────────────────────────────────────────────────────────
    "POST /api/share": Route("creates a share link", SESSION, ("dependencies:get_current_user",),
                             ("tests/test_server_spec.py",)),
    "POST /api/share/{share_id}": Route(
        "consumes a view; PIN attempt counters", PROOF + ": the link's id (and PIN)",
        ("routers.share:_reserve_pin_attempt", "routers.share:_verify_pin_off_loop"),
        ("tests/test_server_spec.py",),
    ),
    "GET /api/share-notifications": Route(
        "claims the caller's pending view notifications", SESSION + " (own links only)",
        ("dependencies:get_current_user",), ("tests/test_server_spec.py",),
    ),
    "PATCH /api/share/{share_id}": Route(
        "unlocks or deactivates a share link", ADMIN, ("dependencies:require_admin",),
        ("tests/test_server_spec.py",),
    ),
    "DELETE /api/share/{share_id}": Route(
        "deletes a share link", SESSION + ": its creator, or " + ADMIN,
        ("dependencies:get_current_user",), ("tests/test_server_spec.py",),
    ),
    "GET /api/shares": Route("", ADMIN, ("dependencies:require_admin",), ("tests/test_server_spec.py",)),
    # ── Audit ───────────────────────────────────────────────────────────────
    "POST /api/audit/log": Route(
        "stores a client event", SESSION + ", signed by the account key",
        ("dependencies:require_full_jwt",), ("tests/test_server_spec.py",),
    ),
    "GET /api/audit": Route("", ADMIN, ("dependencies:require_admin",), ("tests/test_server_spec.py",)),
    "GET /api/audit/csv": Route("", ADMIN, ("dependencies:require_admin",), ("tests/test_review_server_medium.py",)),
    # ── Org recovery ────────────────────────────────────────────────────────
    "POST /api/org-recovery/store": Route(
        "stores the wrapped KEK of the organisation's recovery",
        ADMIN + ", with the current password (or, re-storing the same recovery key, its signature); "
        "replacing another admin's setup only when asked to",
        ("dependencies:get_current_user", "routers.recovery:store_recovery_blob",
         "routers.recovery:_require_current_password", "routers.recovery:_rewrap_signature_ok"),
        ("tests/test_org_recovery_epoch.py", "tests/test_lone_admin_org_recovery.py"),
        "the admin check is inline in the handler (user['is_admin']), not a dependency",
    ),
    "GET /api/org-recovery/status": Route("", PUBLIC, (), ("tests/test_review13_server_perf.py",)),
    "GET /api/org-recovery/blob": Route("", PUBLIC, (), ("tests/test_org_recovery_epoch.py",),
                                        "the blob is encrypted with the recovery key"),
    "POST /api/org-recovery/challenge": Route(
        "stores a one-time challenge", PUBLIC + ", within the recovery budget",
        ("routers.recovery:_consume_recovery_budget",), ("tests/test_review_server_medium.py",),
    ),
    "POST /api/org-recovery/keypair": Route(
        "consumes the challenge and an attempt", PROOF + ": the reconstructed recovery key over the challenge",
        ("routers.recovery:_consume_keypair_attempt", "routers.recovery:_recovery_keys"),
        ("tests/test_server_spec.py", "tests/test_review11_org_recovery_current.py"),
    ),
    # ── AI ──────────────────────────────────────────────────────────────────
    "PUT /api/ai-policy": Route(
        "the caller's AI kill switch (higher epoch only)", SESSION + ", signed by the account key",
        ("dependencies:require_full_jwt",), ("tests/test_ai_s1e_remote_policy.py",),
    ),
    "GET /api/ai-policy": Route("", SESSION, ("dependencies:require_full_jwt",), ("tests/test_ai_s1e_remote_policy.py",)),
    "PUT /api/ai-anchor": Route(
        "raises one of the caller's vault anchors (never lowers, never another account's)",
        SESSION, ("dependencies:require_full_jwt",), ("tests/test_review13_ai_switch_anchor.py",),
    ),
    "GET /api/ai-anchor/{anchor}": Route("", SESSION, ("dependencies:require_full_jwt",),
                                         ("tests/test_review13_ai_switch_anchor.py",)),
    # ── Pages ───────────────────────────────────────────────────────────────
    "GET /health": Route("", PUBLIC, (), ("tests/test_server_spec.py",)),
    "GET /": Route("", PUBLIC, (), ("tests/test_server_spec.py",)),
    "GET /s/{share_id}": Route("", PUBLIC, (), ("tests/test_review2_server_medium.py",)),
}
