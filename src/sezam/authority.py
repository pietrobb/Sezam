"""The clients' authority map (docs/ROOT_CAUSE_PLAN.md S1, INV-2).

What each CLI command, MCP tool and client operation (the Vault and SyncClient
API, and the ``sezam.vault`` functions the CLI, GUI and MCP call) changes, who
may do it and where that is decided. A client never decides authority alone:
team changes are decided by the signed team log and by the server route named
in ``decided_by`` (``server/app/authority.py`` says who may call it there);
local changes by whoever unlocked the vault. ``tests/test_authority_map.py``
fails on an operation without an entry, and ``docs/AUTHORITY_MAP.md`` is
generated from both maps (``python scripts/authority_map.py``).

Fields: ``changes`` ("" = reads only), ``who``, ``decided_by`` (server routes;
``LOCAL`` for the local vault only), ``calls`` (routes the operation sends to
itself, checked against its code), ``tests`` (each names the operation),
``part_of`` (operations whose code runs this one: tested through them),
``via`` (for CLI commands and MCP tools: the operations they run).
"""

from __future__ import annotations

from dataclasses import dataclass

LOCAL = "local"

OWNER = "whoever unlocked the vault (master password, or the broker's session key)"
ACCOUNT = "the signed-in account, for itself"
MEMBER = "a team member; each object by the signer's write access, team folders by the log"
LOG_ADMIN = "the team admin in the local team log; the server takes only records the log allows"
SERVER_ADMIN = "an admin on the server (users.is_admin)"
NOBODY = "nothing is changed"

PUSH = "POST /api/sync"
APPEND = "POST /api/team-log"
RESTORE = "POST /api/team-log/restore"


@dataclass(frozen=True)
class Op:
    changes: str
    who: str
    decided_by: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()
    part_of: tuple[str, ...] = ()
    via: tuple[str, ...] = ()
    note: str = ""


def read(*tests: str, calls: tuple[str, ...] = (), part_of: tuple[str, ...] = (), note: str = "") -> Op:
    return Op("", NOBODY, (), calls, tests, part_of, (), note)


def local(changes: str, *tests: str, part_of: tuple[str, ...] = (), note: str = "") -> Op:
    return Op(changes, OWNER, (LOCAL,), (), tests, part_of, (), note)


def pushed(changes: str, *tests: str, who: str = MEMBER, part_of: tuple[str, ...] = (), note: str = "") -> Op:
    """A local change the next push sends; the server decides there."""
    return Op(changes, who, (PUSH,), (), tests, part_of, (), note)


# ── Vault (sezam.vault.crud.Vault) ──────────────────────────────────────────
VAULT: dict[str, Op] = {
    "adopt_account_kek": local("this device's KEK wrap: the account KEK after a password recovery",
                               "tests/test_review7_stale_kek_pull.py"),
    "change_password": pushed("the KEK wrap and, queued for the push, the account's key material",
                              "tests/test_sync_state_machine.py", who=ACCOUNT),
    "create_entry": pushed("a new entry", "tests/test_e2e_scenarios.py"),
    "create_node": pushed("a new folder", "tests/test_e2e_scenarios.py"),
    "create_personal_folder": pushed("a personal folder with a key of its own (no admin envelope)",
                                     "tests/test_team_log_personal_root_desktop.py", who=ACCOUNT),
    "current_auth_proof": read("tests/test_review10_single_admin.py"),
    "deep_search": read("tests/test_gui_e2e_flow.py"),
    "delete_entry": pushed("deletes an entry (trash)", "tests/test_sync_state_machine.py"),
    "delete_node": pushed("deletes a folder (trash)", "tests/test_trash_history_review_m2.py"),
    "find_entry_by_path": read("tests/test_trash_history_review_m2.py"),
    "get_field_value": read("tests/test_review9_team_identity.py"),
    "get_tree": read("tests/test_vault.py"),
    "grant_folder_access": Op(
        "an access envelope with the folder key, and the log's access.set", LOG_ADMIN, (PUSH, APPEND),
        tests=("tests/test_grant_folder_access.py", "tests/test_review9_desktop_tree_authority.py"),
    ),
    "key_change_unpushed": read("tests/test_inv7_unlock_never_blocked.py"),
    "list_entries": read("tests/test_gui_e2e_flow.py"),
    "list_nodes": read("tests/test_gui_e2e_flow.py"),
    "lock": local("forgets the unlocked keys", "tests/test_e2e_scenarios.py"),
    "move_entry": pushed("moves an entry (re-sealed to the target folder's key)", "tests/test_sync_state_machine.py"),
    "move_node": pushed("moves a folder (re-sealed to the target's key)", "tests/test_review9_move_node_reseal.py"),
    "org_recovery": Op(
        "the KEK from the recovery shares; a new password and key material, pushed",
        "whoever holds the threshold of recovery shares", (PUSH, "POST /api/org-recovery/keypair"),
        tests=("tests/test_review8_org_recovery_lost_answer_h9.py",),
    ),
    "org_recovery_configured": read("tests/test_org_recovery_resetup_review_n4.py"),
    "password_form": read("tests/test_password_nfc_review_m8.py"),
    "read_entry": read("tests/test_e2e_scenarios.py"),
    "read_entry_policy": read(part_of=("sezam.mcp.broker:MCPBroker._live_session_entry_id",)),
    "read_node": read("tests/test_review2_desktop_medium.py"),
    "rebind_server_identity": local("the local identity's server user id (after registration)",
                                    "tests/test_review_data_loss.py"),
    "rekey_after_handover": pushed("new keys for the team folders a former admin held as admin", "tests/test_review14_oplock_coverage.py",
                                   who=LOG_ADMIN),
    "rekey_after_revocation": pushed("new keys for every folder a removed member held", "tests/test_rekey_rebase_review8.py",
                                     who=LOG_ADMIN),
    "rename_node": pushed("a folder's name", "tests/test_sync_s3_outbox.py"),
    "resolve_path": read("tests/test_e2e_scenarios.py"),
    "search": read("tests/test_spec_compliance.py"),
    "setup_org_recovery": local("the recovery shares and a recovery wrap of the KEK (sent by setup_and_register)",
                                "tests/test_org_recovery_resetup_review_n4.py"),
    "unlock": local("opens the vault with the master password", "tests/test_e2e_scenarios.py"),
    "unlock_with_kek": local("opens the vault with a KEK (broker session)", "tests/test_ai_s1b_control.py"),
    "update_entry": pushed("an entry's fields", "tests/test_sync_state_machine.py"),
    "verify_password": read("tests/test_review2_desktop_crit.py"),
    "withdraw_unsent_grant": local("drops an envelope the server refused (never shared)",
                                   part_of=("sezam.vault.revocation:grant_member",)),
}

# ── SyncClient (sezam.vault.sync_client.SyncClient and its mixins) ───────────
SYNC: dict[str, Op] = {
    "abandon_pending_change": local("drops this device's unsent password or key change",
                                    "tests/test_stuck_key_change_escape.py"),
    "accept_own_team_log": local("stores records the server accepted", part_of=("SyncClient.push",)),
    "add_identity_team_record": Op("the log's member.keys for an identity rotation", ACCOUNT, (PUSH,),
                                   part_of=("SyncClient.push",)),
    "adopt_logged_org_recovery": local("a local KEK wrap of a recovery the log names (set up elsewhere)",
                                       part_of=("SyncClient.push",)),
    "adopt_rotated_key_material": Op("this device's key material: a password change made on another device",
                                     ACCOUNT, ("POST /api/auth/recover",), ("/api/auth/recover",),
                                     ("tests/test_rival_key_change_same_epoch_sm30.py",)),
    "allow_key_reset": Op("lets a member replace its key material once", SERVER_ADMIN,
                          ("POST /api/users/{user_id}/allow-key-reset",), ("/allow-key-reset",),
                          ("tests/test_key_material_needs_password.py",)),
    "anchor_org_recovery": Op("queues the log's org.recovery naming this vault's recovery key", LOG_ADMIN, (APPEND,),
                              part_of=("sezam.vault.org_recovery_server:setup_and_register",)),
    "append_team_log": Op("team log records, sent now (queued if that fails)", LOG_ADMIN, (APPEND,),
                          tests=("tests/test_team_log_desktop_pull.py",)),
    "approve_user": Op("activates a pending account", SERVER_ADMIN, ("PATCH /api/users/{user_id}/approve",),
                       ("/approve",), ("tests/test_grant_folder_access.py",)),
    "authenticate": Op("a session (consumes a challenge)", ACCOUNT, ("POST /api/auth/verify",),
                       ("/api/auth/challenge", "/api/auth/verify"), ("tests/test_review9_retired_key_after_restore.py",)),
    "close_rekey_if_landed": local("closes a pending re-key the server already took", part_of=("SyncClient.push",)),
    "confirm_tofu_key_change": local("a member's changed pinned key, after its fingerprint was verified",
                                     "tests/test_sync_conformance.py"),
    "continue_identity_in_log": Op("links the account's current keys to the ones the log names", ACCOUNT, (APPEND, RESTORE),
                                   part_of=("SyncClient.push", "SyncClient.pull")),
    "create_invitation": Op("an invitation token", SERVER_ADMIN + ", anchored by this device's trusted log",
                            ("POST /api/users/invite",), ("/api/users/invite",), ("tests/test_team_log_desktop.py",)),
    "create_provisioning_token": Op("a one-time device token for this account", ACCOUNT,
                                    ("POST /api/auth/provisioning-token",), ("/api/auth/provisioning-token",),
                                    ("tests/test_team_log_desktop.py",)),
    "dirty_object_count": read("tests/test_sync_state_machine.py"),
    "discard_set_aside_team_changes": local("drops team changes set aside (refused by the log)",
                                            "tests/test_review10_team_queue.py"),
    "drop_superseded_org_recovery": local("withholds a local recovery setup the server reports replaced",
                                          "tests/test_review13_org_recovery_queued_record.py"),
    "drop_team_grant": local("drops a queued grant the log refuses", part_of=("SyncClient.push",)),
    "finish_pending_change": local("adds the server password's proof to an older queued change",
                                   "tests/test_review11_pre_proof_change.py"),
    "flush_team_log": Op("sends queued team records", LOG_ADMIN, (APPEND, RESTORE), ("/api/team-log",),
                         ("tests/test_review13_team_queue_race.py",)),
    "fold_unlogged_folder_keys": pushed("re-seals folders below a team folder to the keys the log knows",
                                        part_of=("SyncClient.push",)),
    "found_team_log": Op("the log's genesis, by this account", LOG_ADMIN + " (the server's admin before a genesis)",
                         (APPEND,), tests=("tests/test_review9_team_log_restore.py",)),
    "full_resync": Op("replaces the local sync snapshot with the server's", OWNER + ", after explicit confirmation",
                      (LOCAL,), ("/api/sync",), ("tests/test_sync_state_machine.py",)),
    "full_resync_blocker": read("tests/test_sync_state_machine.py"),
    "get_ai_policy": read("tests/test_ai_s1e_server_mariadb.py", calls=("/api/ai-policy",)),
    "get_pull_conflicts": read("tests/test_sync_state_machine.py"),
    "has_pending_key_change": read("tests/test_sync_state_machine.py"),
    "list_shares": read("tests/test_crypto.py", calls=("/api/shares",)),
    "list_users": read("tests/test_crypto.py", calls=("/api/users",)),
    "pending_team_changes": read("tests/test_review10_team_queue.py"),
    "pending_team_grants": read("tests/test_review9_team_log_durability.py"),
    "pin_envelope_holder_keys": local("pins the keys of the members this account sealed folders for",
                                      part_of=("SyncClient.prepare_key_change",)),
    "poll_share_notifications": Op("claims this account's share view notifications", ACCOUNT,
                                   ("GET /api/share-notifications",), ("/api/share-notifications",),
                                   ("tests/test_gui_full.py",)),
    "prepare_key_change": read("tests/test_review9_team_identity.py", note="logs in and pulls"),
    "pull": Op("applies the server's objects and team log, each checked against the log and signatures",
               OWNER, (LOCAL,), ("/api/sync", "/api/team-log"), ("tests/test_sync_state_machine.py",),
               note="the server's data is checked, not trusted (INV-3)"),
    "push": Op("sends dirty objects, key changes and queued team records", MEMBER, (PUSH,),
               ("/api/sync",), ("tests/test_sync_state_machine.py",)),
    "put_ai_policy": Op("this account's signed AI kill switch", ACCOUNT, ("PUT /api/ai-policy",),
                        ("/api/ai-policy",), ("tests/test_ai_s1e_server_mariadb.py",)),
    "queue_team_changes": local("queues team records for the next push; refused now if the log's rules would",
                                "tests/test_review13_team_queue_race.py"),
    "queue_team_grant": local("queues a grant's records with its envelope; refused now if the rules would",
                              part_of=("sezam.vault.revocation:grant_member",)),
    "rekey_batch_on_server": read("tests/test_r15_rekey_held_many_deks.py", calls=("/api/objects/held",)),
    "require_trusted_team_log": read("tests/test_inv7_personal_push_while_refused.py"),
    "resolve_conflict": local("settles a pull conflict (keep local or server)", "tests/test_sync_state_machine.py"),
    "retry_org_recovery_rewrap": Op("re-stores the recovery blob (signed by the recovery key)", LOG_ADMIN,
                                    ("POST /api/org-recovery/store",), ("/api/org-recovery/store",),
                                    part_of=("SyncClient.push",)),
    "retry_set_aside_team_changes": local("queues set-aside team changes again", "tests/test_review10_team_queue.py"),
    "revoke_share": Op("deletes a share link", "its creator, or " + SERVER_ADMIN, ("DELETE /api/share/{share_id}",),
                       ("/api/share/",), ("tests/test_crypto.py",)),
    "revoke_user": Op("revokes an account on the server", SERVER_ADMIN, ("DELETE /api/users/{user_id}",),
                      ("/api/users/",), ("tests/test_revoke_second_member_8b.py",)),
    "server_org_recovery_stale": read(part_of=("sezam.cli:change_password",), calls=("/api/org-recovery/status",)),
    "set_aside_refused_team_changes": local("sets aside a queued change the log no longer takes",
                                            part_of=("SyncClient.queue_team_grant",)),
    "set_aside_team_changes": local("sets queued team changes aside", "tests/test_review10_team_queue.py"),
    "set_dek_manager": local("the key manager the checkpoint is encrypted with", "tests/test_crypto.py"),
    "store_org_recovery": Op("registers this vault's recovery key on the server", SERVER_ADMIN + ", with the password",
                             ("POST /api/org-recovery/store",), ("/api/org-recovery/store",),
                             ("tests/test_lone_admin_org_recovery.py",)),
    "team_log_records": read("tests/test_team_log_desktop.py", note="signs records onto the local head; stores nothing"),
    "team_log_refusal": read("tests/test_inv7_unlock_never_blocked.py"),
    "team_log_trusted": read("tests/test_team_log_desktop.py"),
    "team_state": read("tests/test_team_log_desktop.py"),
    "unlock_recovery": Op("clears a member's recovery lockout; a one-time code", SERVER_ADMIN,
                          ("POST /api/users/{user_id}/unlock-recovery",), ("/unlock-recovery",),
                          part_of=("sezam.cli:unlock_recovery",)),
    "unpin_member_key": local("forgets a member's pinned keys (pinned anew on next contact)",
                              part_of=("sezam.vault.revocation:grant_member",)),
    "verified_encryption_pk": local("pins a member's keys on first use (TOFU)", "tests/test_rotation_medium_270.py"),
}

# ── Functions of sezam.vault the CLI, GUI and MCP call ("module:function") ──
FUNCTIONS: dict[str, Op] = {
    "ai_access:anchor_id": read("tests/test_review13_ai_switch_anchor.py"),
    "ai_access:anchor_mac": read(part_of=("sezam.mcp.remote_policy:ServerAnchor.sync",)),
    "ai_access:disable": local("turns AI access off (signed local switch)", "tests/test_review7_two_brokers_disable.py"),
    "ai_access:enable": local("turns AI access on (signed local switch)", "tests/test_review10_ai_enable_race.py"),
    "ai_access:raise_floor": local("raises the AI switch's epoch floor", part_of=("sezam.mcp.broker:MCPBroker.raise_floor",)),
    "ai_access:read_state": read("tests/test_review6_ai_switch_mac.py"),
    "ai_access:record_remote_applied": local("notes the remote kill switch's epoch applied",
                                             part_of=("sezam.mcp.remote_policy:apply_policy",)),
    "ai_access:remote_applied_epoch": read(part_of=("sezam.mcp.remote_policy:apply_policy",)),
    "ai_access:seal_new_vault": local("the AI switch of a vault imported under a new KEK", part_of=("sezam.cli:import_key",)),
    "ai_access:verified_on_epoch": read("tests/test_review9_ai_snapshot_switch.py"),
    "crud:open_server_keypair": read("tests/test_account_anchor_bundle.py"),
    "crud:recover_refusal": read("tests/test_recover_refusal_v2.py"),
    "crud:recover_with_password": Op("replaces this device's keys with the account's (password recovery)",
                                     "whoever knows the account password", ("POST /api/auth/recover",),
                                     tests=("tests/test_legacy_account_kdf_review_n2.py",)),
    "crud:require_usable_password": read(part_of=("sezam.cli:change_password",)),
    "crud:server_account_kdf": read("tests/test_review6_kdf_floor.py"),
    "onboarding:bootstrap_upload_pending": read("tests/test_pending_states_blocks.py"),
    "onboarding:finish_bootstrap_upload": Op("the new account's key material, uploaded once", ACCOUNT,
                                             ("PUT /api/me/keypair",), part_of=("sezam.cli:connect",)),
    "onboarding:keypair_upload_body": read("tests/test_password_nfc_review_m8.py"),
    "oplock:exclusive": read("tests/test_review6_vault_oplock.py", note="the vault's operation lock"),
    "org_recovery_server:register_while_password_known": Op(
        "the recovery blob on the server", SERVER_ADMIN + ", with the password", ("POST /api/org-recovery/store",),
        tests=("tests/test_org_recovery_server_replace.py",)),
    "org_recovery_server:registration_issue": read("tests/test_org_recovery_stale_told.py"),
    "org_recovery_server:setup_and_register": Op(
        "the recovery shares, the blob on the server and the log's org.recovery",
        LOG_ADMIN + "; " + SERVER_ADMIN + " for the blob", ("POST /api/org-recovery/store", APPEND),
        tests=("tests/test_review10_single_admin.py",)),
    "outbox:queue_write": local("queues a local object for the next push", "tests/test_pending_states_status.py"),
    "pending_states:blocker": read("tests/test_pending_states_blocks.py"),
    "pending_states:change_lacks_server_proof": read("tests/test_review11_pre_proof_change.py"),
    "pending_states:closed_shared_before_team_log": read(part_of=("sezam.cli:list_tree",)),
    "pending_states:key_change_journal": read("tests/test_review9_team_identity.py"),
    "pending_states:key_reset_way_out": read("tests/test_review10_single_admin.py"),
    "pending_states:mark_bootstrap_upload_pending": local("notes an unfinished key upload", "tests/test_pending_states_blocks.py"),
    "pending_states:pending_states": read("tests/test_sync_state_machine.py"),
    "pending_states:rekey_batch": read("tests/test_sync_state_machine.py"),
    "pending_states:revocation_queue": read("tests/test_sync_s3_outbox.py"),
    "pending_states:set_revocation_queue": local("the queue of members to remove and re-key for",
                                                 "tests/test_sync_s3_outbox.py"),
    "rekey_abandon:abandon_pending_rekey": local("drops a pending re-key (the folders keep their keys)",
                                                 "tests/test_review8_abandon_foreign_grant.py"),
    "reseed:rejoin_server": Op("brings this account back on a server a backup lost", ACCOUNT,
                               ("POST /api/auth/rejoin",), tests=("tests/test_review11_rejoin_name_taken.py",)),
    "reseed:reseed_server": Op("the first admin of an empty server, with this vault's identity",
                               "whoever unlocked the vault, while the server has no admin", ("POST /api/bootstrap",),
                               tests=("tests/test_ai_r3_reseed.py",)),
    "revocation:blocked_message": read(part_of=("sezam.cli:push",)),
    "revocation:finish_handover_rekeys": pushed("the re-keys a hand-over left", who=LOG_ADMIN, part_of=("sezam.cli:push",)),
    "revocation:finish_queued_into": pushed("the queued removals' re-keys", who=LOG_ADMIN, part_of=("sezam.cli:push",)),
    "revocation:grant_member": Op("a member's access to a folder: envelope and access.set", LOG_ADMIN, (PUSH, APPEND),
                                  tests=("tests/test_grant_folder_access.py",)),
    "revocation:push_with_queued_revocations": pushed("pushes with the queued removals",
                                                      "tests/test_review13_handover_rekey.py", who=LOG_ADMIN),
    "revocation:revoke_member": Op("removes a member: member.remove, revocation on the server, re-keys", LOG_ADMIN,
                                   (APPEND, "DELETE /api/users/{user_id}", PUSH),
                                   tests=("tests/test_grant_under_rekeyed_key_sm62.py",)),
    "snapshots:discard_staged": local("drops a staged restore", "tests/test_review10_snapshots.py"),
    "snapshots:drop_snapshots_of_other_passwords": local("deletes snapshots under older passwords",
                                                         part_of=("sezam.cli:snapshot_drop_old_passwords",)),
    "snapshots:install_staged": local("replaces the vault file with a staged one", "tests/test_review10_snapshots.py"),
    "snapshots:list_snapshots": read("tests/test_ai_r1_snapshots.py"),
    "snapshots:snapshot_dir": read("tests/test_ai_r1_snapshots.py"),
    "snapshots:snapshots_of_other_passwords": read(part_of=("sezam.cli:status",)),
    "snapshots:stage_file": local("stages a backup file for restore", part_of=("sezam.cli:restore_backup",)),
    "snapshots:stage_snapshot": local("stages a snapshot for restore", "tests/test_review10_snapshots.py"),
    "snapshots:take_snapshot": local("a snapshot of the vault file", "tests/test_review10_snapshots.py"),
    "snapshots:vault_salt": read(part_of=("sezam.cli:snapshot_list",)),
    "sync_common:pull_warnings": read("tests/test_sync_conflicts_review_m1.py"),
    "sync_common:server_error": read("tests/test_review6_server_error_codes.py"),
    "team_log_forget:forget_team_log_pin": local("forgets the pinned team log (only one the server lost, INV-8)",
                                                 "tests/test_inv8_forget_acts_only_on_lost.py"),
    "team_log_forget:pinned_genesis": read("tests/test_review13_forget_pin.py"),
    "team_log_state:discard_set_aside": local("drops set-aside team changes", part_of=("sezam.cli_team_log:team_log_discard",)),
    "team_log_state:forgotten_genesis": read("tests/test_inv7_unlock_never_blocked.py"),
    "team_log_state:founder_key_lineage": read("tests/test_sync_state_machine.py"),
    "team_log_state:local_team_state": read("tests/test_sync_state_machine.py"),
    "team_log_state:publishable_anchor": read(part_of=("sezam.cli_team_log:team_log_publish_anchor",)),
    "team_log_state:queued_changes": read("tests/test_sync_s3_outbox.py"),
    "team_log_state:readable_forgotten_genesis": read(part_of=("sezam.cli_team_log:team_log_confirm_genesis",)),
    "team_log_state:retry_set_aside": local("queues set-aside team changes again", "tests/test_sync_s3_outbox.py"),
    "team_log_state:set_aside_changes": read("tests/test_sync_state_machine.py"),
    "team_migration:add_member": Op("the log's member.add", LOG_ADMIN, (APPEND,), tests=("tests/test_team_log_migration.py",)),
    "team_migration:found_team_log": Op("the log's genesis and the team folders' access", LOG_ADMIN
                                        + " (the server's admin before a genesis)", (APPEND, PUSH),
                                        tests=("tests/test_team_log_migration.py",)),
    "team_migration:hand_over_admin": Op("the log's member.role: the admin role to another member", LOG_ADMIN, (APPEND,),
                                         tests=("tests/test_review10_single_admin.py",)),
    "team_migration:readmit_member": Op("the log's member.remove + member.add with new keys", LOG_ADMIN, (APPEND,),
                                        tests=("tests/test_review10_readmit.py",)),
    "trash:list_history": read("tests/test_trash_history_review_m2.py"),
    "trash:list_trash": read("tests/test_trash_history_review_m2.py"),
    "trash:read_history": read("tests/test_trash_history_review_m2.py"),
    "trash:restore_entry": pushed("an entry back from the trash", "tests/test_trash_history_review_m2.py"),
    "trash:restore_history": pushed("an older version of an entry", "tests/test_trash_history_review_m2.py"),
    "trash:restore_node": pushed("a folder back from the trash", "tests/test_trash_history_review_m2.py"),
}

# Classes of sezam.vault the CLI, GUI and MCP use besides Vault and SyncClient.
CLASSES: dict[str, Op] = {
    "audit:AuditLog": local("the local audit log (append only)", "tests/test_spec_compliance.py"),
    "dek:DEKManager": local("the keys of an unlocked vault", "tests/test_crypto.py"),
}

# ── CLI commands (sezam.cli) ────────────────────────────────────────────────


def cli(changes: str, who: str, *via: str, decided_by: tuple[str, ...] = (), calls: tuple[str, ...] = (),
        tests: tuple[str, ...] = (), note: str = "") -> Op:
    return Op(changes, who, decided_by, calls, tests, (), via, note)


CLI: dict[str, Op] = {
    "init": cli("a new vault; with a server, registers and connects it", OWNER, "Vault.lock",
                "onboarding:finish_bootstrap_upload", "SyncClient.authenticate"),
    "connect": cli("connects a vault to a server account", OWNER, "SyncClient.authenticate",
                   "Vault.rebind_server_identity", "onboarding:finish_bootstrap_upload"),
    "server reseed": cli("the first admin of an empty server", OWNER, "reseed:reseed_server"),
    "server rejoin": cli("this account on a server a backup lost", OWNER, "reseed:rejoin_server"),
    "unlock": cli("", NOBODY, "Vault.unlock", note="checks the master password"),
    "lock": cli("", NOBODY),
    "search": cli("", NOBODY, "Vault.search"),
    "get": cli("", NOBODY, "Vault.find_entry_by_path"),
    "set": cli("an entry", MEMBER, "Vault.create_entry", "Vault.update_entry", decided_by=(PUSH,)),
    "list": cli("", NOBODY, "Vault.get_tree"),
    "create-personal": cli("a personal folder", ACCOUNT, "Vault.create_personal_folder", decided_by=(PUSH,)),
    "generate": cli("", NOBODY),
    "change-password": cli("the master password and the account's key material", ACCOUNT,
                           "Vault.change_password", "SyncClient.push"),
    "rotate-identity": cli("the account's identity keys", ACCOUNT, "Vault.change_password", "SyncClient.push"),
    "export-key": cli("", NOBODY, note="writes the wrapped key to a file the user names"),
    "import-key": cli("a vault from an exported key", OWNER, "ai_access:seal_new_vault", "outbox:queue_write"),
    "org-recovery-setup": cli("the organisation's recovery", LOG_ADMIN, "org_recovery_server:setup_and_register"),
    "org-recovery": cli("the KEK from recovery shares", "whoever holds the threshold of shares", "Vault.org_recovery"),
    "fingerprint": cli("", NOBODY),
    "grant-access": cli("a member's access to a folder", LOG_ADMIN, "revocation:grant_member"),
    "revoke-user": cli("removes a member", LOG_ADMIN, "revocation:revoke_member"),
    "allow-key-reset": cli("a member's one-time key reset", SERVER_ADMIN, "SyncClient.allow_key_reset"),
    "unlock-recovery": cli("a member's recovery lockout", SERVER_ADMIN, "SyncClient.unlock_recovery"),
    "export": cli("", NOBODY, "Vault.read_entry", note="writes a plaintext export to a file"),
    "snapshot list": cli("", NOBODY, "snapshots:list_snapshots"),
    "snapshot drop-old-passwords": cli("deletes snapshots under older passwords", OWNER,
                                       "snapshots:drop_snapshots_of_other_passwords"),
    "snapshot restore": cli("replaces the vault with a snapshot", OWNER, "snapshots:stage_snapshot",
                            "snapshots:install_staged"),
    "restore": cli("replaces the vault with a backup file", OWNER, "snapshots:stage_file", "snapshots:install_staged"),
    "import": cli("entries from another password manager", MEMBER, "Vault.create_entry", decided_by=(PUSH,)),
    "abandon-pending-change": cli("drops an unsent password or key change", OWNER, "SyncClient.abandon_pending_change"),
    "finish-pending-change": cli("completes an older queued key change", ACCOUNT, "SyncClient.finish_pending_change",
                                 "SyncClient.push"),
    "abandon-rekey": cli("drops a pending re-key", OWNER, "rekey_abandon:abandon_pending_rekey",
                         "pending_states:set_revocation_queue"),
    "status": cli("", NOBODY, "pending_states:pending_states"),
    "push": cli("sends local changes", MEMBER, "SyncClient.push", "revocation:finish_queued_into"),
    "conflicts resolve": cli("settles a pull conflict", OWNER, "SyncClient.resolve_conflict"),
    "trash restore": cli("an item back from the trash", MEMBER, "trash:restore_entry", "trash:restore_node"),
    "history": cli("an older version of an entry (with --restore)", MEMBER, "trash:restore_history"),
    "pull": cli("applies the server's changes", OWNER, "SyncClient.pull"),
    "share": cli("a share link", ACCOUNT, "SyncClient.authenticate", calls=("/api/share",)),
    "share-list": cli("", NOBODY, "SyncClient.authenticate", calls=("/api/shares",)),
    "provision-device": cli("a one-time device token", ACCOUNT, "SyncClient.create_provisioning_token"),
    "share-revoke": cli("deletes a share link", "its creator, or " + SERVER_ADMIN, "SyncClient.authenticate",
                        calls=("/api/share/",)),
    "mcp-policy": cli("an entry's AI policy", OWNER, "Vault.update_entry", decided_by=(PUSH,)),
    "mcp-serve": cli("", NOBODY, note="serves the MCP tools below"),
    "ssh-agent": cli("", NOBODY, "Vault.unlock_with_kek", note="serves keys of entries the policy allows"),
    "ai-host-setup": cli("the AI host's local configuration files", OWNER, decided_by=(LOCAL,)),
    "broker install-service": cli("installs the broker service", "the operating system user", decided_by=(LOCAL,)),
    "ai off": cli("turns AI access off", OWNER, "ai_access:disable"),
    "ai on": cli("turns AI access on", OWNER, "ai_access:enable"),
    "ai status": cli("", NOBODY, "ai_access:read_state"),
    "ai log": cli("", NOBODY),
    "team-log status": cli("", NOBODY, "SyncClient.team_state"),
    "team-log confirm-founder": cli("confirms the founder's key (pins it)", OWNER, "team_log_state:founder_key_lineage"),
    "team-log confirm-genesis": cli("confirms the pinned genesis", OWNER, "team_log_state:local_team_state"),
    "team-log forget-pin": cli("forgets the pinned log (only one the server lost)", OWNER,
                               "team_log_forget:forget_team_log_pin"),
    "team-log publish-anchor": cli("", NOBODY, "team_log_state:publishable_anchor"),
    "team-log init": cli("the log's genesis", LOG_ADMIN, "team_migration:found_team_log"),
    "team-log queue": cli("", NOBODY, "team_log_state:queued_changes"),
    "team-log retry": cli("queues set-aside team changes again", OWNER, "team_log_state:retry_set_aside"),
    "team-log discard": cli("drops set-aside team changes", OWNER, "team_log_state:discard_set_aside"),
    "team-log add-member": cli("the log's member.add", LOG_ADMIN, "team_migration:add_member"),
    "team-log readmit": cli("a member back with new keys", LOG_ADMIN, "team_migration:readmit_member"),
    "team-log hand-over": cli("the admin role to another member", LOG_ADMIN, "team_migration:hand_over_admin"),
}

# ── UI code that calls the server itself ("module:qualname" under sezam) ───
# Every function of the CLI, GUI or MCP with an /api/ path in it is here.
DIRECT: dict[str, Op] = {
    "gui.server_connect_dialog:ServerConnectWorker._do_connect": read(
        "tests/test_integration_client_server.py", calls=("/api/bootstrap-status",)),
    "gui.server_connect_dialog:ServerConnectWorker._handle_bootstrap": Op(
        "the first admin of an empty server", "whoever unlocked the vault, while the server has no admin",
        ("POST /api/bootstrap",), ("/api/bootstrap",), part_of=("sezam.gui.server_connect_dialog:ServerConnectWorker._do_connect",)),
    "gui.server_connect_dialog:ServerConnectWorker._handle_existing_server": Op(
        "registers with an invitation, or recovers the account's keys with its password",
        "the invitation's holder; whoever knows the account password",
        ("POST /api/users/register", "POST /api/auth/recover"), ("/api/users/register", "/api/auth/recover", "/api/meta"),
        part_of=("sezam.gui.server_connect_dialog:ServerConnectWorker._do_connect",)),
    "gui.server_connect_dialog:ServerConnectWorker._upload_keypair": Op(
        "the new account's key material", ACCOUNT, ("PUT /api/me/keypair",), ("/api/me/keypair",),
        part_of=("sezam.gui.server_connect_dialog:ServerConnectWorker._handle_existing_server",)),
    "cli:_server_register_and_upload": Op(
        "the first admin, or an account from an invitation, and its key material",
        "whoever unlocked the vault: while the server has no admin, or with an invitation",
        ("POST /api/bootstrap", "POST /api/users/register", "PUT /api/me/keypair"),
        ("/api/bootstrap", "/api/users/register", "/api/me/keypair"), part_of=("sezam.cli:init",)),
    "cli:_server_connect_flow": Op(
        "recovers the account's keys with its password", "whoever knows the account password",
        ("POST /api/auth/recover",), ("/api/auth/recover", "/api/bootstrap-status", "/api/meta"),
        part_of=("sezam.cli:connect",)),
    "cli:share": Op("a share link", ACCOUNT, ("POST /api/share",), ("/api/share",)),
    "cli:share_list": read(calls=("/api/shares",)),
    "cli:share_revoke": Op("deletes a share link", "its creator, or " + SERVER_ADMIN, ("DELETE /api/share/{share_id}",),
                           ("/api/share/",)),
    "mcp.remote_policy:ServerAnchor._held": read(calls=("/api/ai-anchor/",),
                                                 part_of=("sezam.mcp.remote_policy:ServerAnchor.sync",)),
    "mcp.remote_policy:ServerAnchor.sync": Op(
        "raises this vault's AI anchor on the server", ACCOUNT, ("PUT /api/ai-anchor",), ("/api/ai-anchor",),
        tests=("tests/test_review13_ai_switch_anchor.py",)),
}

# Operations that change something and have no test yet. The map test fails
# on a writing operation without tests (or ``part_of``) unless it is here, and
# on an entry here that has tests: the list only shrinks.
UNTESTED: frozenset[str] = frozenset({
    "DIRECT cli:share",
    "DIRECT cli:share_revoke",
})

# ── MCP tools (sezam.mcp.server) ────────────────────────────────────────────
_AI = "an AI agent, for entries whose policy allows it, while AI access is on (with approval where asked)"
MCP: dict[str, Op] = {
    "vault_list": Op("", _AI, tests=("tests/test_ai_p4_mcp_serve_lock.py",)),
    "vault_read": Op("", _AI, tests=("tests/test_mcp_watchtower.py",), note="never secret fields"),
    "vault_search": Op("", _AI, tests=("tests/test_mcp_watchtower.py",)),
    "vault_use": Op("", _AI, tests=("tests/test_mcp_watchtower.py",), note="uses a secret without showing it"),
    **{name: Op("", _AI, tests=("tests/test_mcp_ssh.py",), note="acts on the remote host, not on the vault")
       for name in ("ssh_execute", "ssh_session_open", "ssh_session_write", "ssh_session_read",
                    "ssh_session_resize", "ssh_session_close", "ssh_upload", "ssh_download")},
    "ftp": Op("", _AI, tests=("tests/test_ai_f3_ftp_tool.py",), note="acts on the remote host, not on the vault"),
    "http_request": Op("", _AI, tests=("tests/test_ai_h2_http_tool.py",), note="acts on the remote host, not on the vault"),
}
