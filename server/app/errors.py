"""Stable machine-readable error codes (review d615826 R6-H).

A client decides on ``code``, never on the wording of ``detail``: the error
answer is ``{"detail": ..., "code": ...}`` and ``detail`` stays as it was for
the web and mobile clients. The desktop client mirrors these values in
src/sezam/vault/sync_common.py (tests/test_review6_server_error_codes.py
checks both lists match).
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException

HISTORY_CHANGED = "history_changed"
STALE_KEY_EPOCH = "stale_key_epoch"
KEY_CHANGE_MISSES_DEKS = "key_change_misses_deks"
WRONG_CURRENT_PASSWORD = "wrong_current_password"
KEY_CHANGE_NEEDS_PROOF = "key_change_needs_proof"
IDENTITY_ROTATION_NEEDS_NEW_KEYS = "identity_rotation_needs_new_keys"
ATOMIC_BATCH_CONFLICT = "atomic_batch_conflict"
IDENTITY_KEY_ROTATED = "identity_key_rotated"
# The team log retired the key the account still signs in with (a restore).
IDENTITY_KEY_RETIRED = "identity_key_retired"
TOKEN_INVALID = "token_invalid"
TOKEN_REVOKED = "token_revoked"
# Team log (docs/DESIGN_TEAM_LOG.md): the head moved on, a record was refused,
# or the change needs a team log record the request did not carry.
TEAM_LOG_HEAD_MOVED = "team_log_head_moved"
TEAM_LOG_REFUSED = "team_log_refused"
TEAM_LOG_REQUIRED = "team_log_required"
# The stored team log does not replay (a damaged database): the server decides
# nothing from it and says so instead of a bare 500 (review 8595ec1, R10-B).
TEAM_LOG_UNREADABLE = "team_log_unreadable"
# Per-object code of a refused push object (PushObjectResult.code).
REVOKED_ENVELOPE = "revoked_envelope"
# R15 #441 (capability finding 494): an envelope the team log does not give to
# its account (team_log.envelope_refusal). Sent again as is, it is refused again.
TEAM_LOG_ENVELOPE = "team_log_envelope"
# The write's base is older than a deleted copy tombstone GC collected: the
# server keeps only that copy's (version, hash), no payload to show.
COLLECTED_OBJECT = "collected_object"
# R16-Z SM16: a re-key batch's new folder key, and the folder got another key
# after the device's checked commit (the code the team log refuses it with).
FOLDER_KEY_MOVED = "folder_key_moved"
# Rejoin (review 4acfdde R11, low): the account's id is back already, or
# another account took the name after the backup (rejoin under another name).
ACCOUNT_EXISTS = "account_exists"
USERNAME_TAKEN = "username_taken"
# Review c78fd19 R13-10: a registration saved earlier names the org recovery it
# replaces; a newer one set up meanwhile (on the web) is kept.
ORG_RECOVERY_SUPERSEDED = "org_recovery_superseded"
# Goal #443: a key voucher list not signed by the key it names.
INVALID_KEY_VOUCHERS = "invalid_key_vouchers"
# Goal #443: an identity rotation whose lists leave out an object the old key signed.
KEY_VOUCHERS_INCOMPLETE = "key_vouchers_incomplete"
# R17-N10: the account's key holds as many voucher lists or bytes as it may.
KEY_VOUCHERS_FULL = "key_vouchers_full"
# R16-Z SM22: a folder move whose new parent is below the folder (crossed moves
# of two devices). The result names where the server keeps the folder.
FOLDER_MOVE_CYCLE = "folder_move_cycle"

ERROR_CODES = frozenset({
    HISTORY_CHANGED, STALE_KEY_EPOCH, KEY_CHANGE_MISSES_DEKS, WRONG_CURRENT_PASSWORD,
    KEY_CHANGE_NEEDS_PROOF,
    IDENTITY_ROTATION_NEEDS_NEW_KEYS, ATOMIC_BATCH_CONFLICT, IDENTITY_KEY_ROTATED,
    IDENTITY_KEY_RETIRED, TOKEN_INVALID, TOKEN_REVOKED, REVOKED_ENVELOPE,
    COLLECTED_OBJECT, TEAM_LOG_HEAD_MOVED, TEAM_LOG_REFUSED, TEAM_LOG_REQUIRED, TEAM_LOG_UNREADABLE,
    ACCOUNT_EXISTS, USERNAME_TAKEN, ORG_RECOVERY_SUPERSEDED, INVALID_KEY_VOUCHERS,
    KEY_VOUCHERS_INCOMPLETE, KEY_VOUCHERS_FULL, TEAM_LOG_ENVELOPE, FOLDER_KEY_MOVED, FOLDER_MOVE_CYCLE,
})


class ApiError(HTTPException):
    """An HTTPException that also carries one of the codes above."""

    def __init__(
        self, status_code: int, code: str, detail: Any = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code
