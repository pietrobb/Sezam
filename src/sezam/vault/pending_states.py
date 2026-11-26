"""Every state this vault keeps waiting for the server (review 526419e SYS).

Each round of review found another pending state - a password change, a
member re-key, the revocation queue, edits held by a re-key, a recovery key
the server lacks - that blocked sync with no visible way out. They are all
listed here, each with the way it resolves and a way to drop it that needs no
forgotten secret; 'sezam status' prints them.

Their outbox rows (docs/SYNC_SINGLE_SOURCE.md point 3) are read and written
only through this module (stabilization ST4) and team_log_local.py, so what
a state is and when it ends is in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from .crud import Vault

from . import oplock, outbox

# The server's key_epoch as of the last key-change push it took; the local
# key_epoch above it is a password/identity change the server lacks.
LAST_PUSHED_KEY_EPOCH = "last_pushed_key_epoch"


# Review e443cbc R15 (goal #429): this device joined an account the server
# already holds (connect, Path B) and no pull has taken that account's tree
# yet. A push pulls first; it ends with the first pull or full resync taken.
JOINED_UNPULLED = "joined_account_unpulled"


def last_pushed_key_epoch(db) -> int:
    return int(db.get_meta(LAST_PUSHED_KEY_EPOCH) or "0")


def set_last_pushed_key_epoch(db, epoch: int | str) -> None:
    oplock.require(db)
    db.set_meta(LAST_PUSHED_KEY_EPOCH, str(epoch))


def key_epoch_unpushed(db) -> bool:
    """The local key_epoch is above the last one the server took."""
    return int(db.get_meta("key_epoch") or "0") > last_pushed_key_epoch(db)


def key_change_journal(db) -> dict:
    """The journal (key_rotation.make_journal) of the unsent password/identity
    change, {} when none."""
    return outbox.body(db, outbox.KEY_CHANGE) or {}


def set_key_change_journal(db, journal: dict) -> None:
    outbox.put(db, outbox.KEY_CHANGE, journal)


def clear_key_change_journal(db) -> None:
    outbox.sent(db, outbox.KEY_CHANGE, outbox.ONE)


PRE_PROOF_CHANGE = (
    "This device's password change was made by an older Sezam version, which kept no "
    "proof of the password the server has; the server refuses it without that proof."
)


def change_lacks_server_proof(db) -> bool:
    """The unsent change carries neither the proof of the password the server
    has nor an org recovery secret: a journal of a version from before the
    server asked for one (688edcb K1). The server refuses it until
    'sezam finish-pending-change' adds the proof (review 4acfdde R11)."""
    journal = key_change_journal(db)
    return bool(journal) and not ({"current_auth_proof", "recovery_secret"} & journal.keys())


def key_change_pending(db) -> bool:
    return key_epoch_unpushed(db) or outbox.has(db, outbox.KEY_CHANGE)


def rekey_batch(db) -> dict:
    """The unsent member re-key (or envelopes re-sealed by an identity
    rotation), sent as one atomic batch; {} when none. Its held_edits come
    back as conflicts once it landed."""
    return outbox.body(db, outbox.REKEY) or {}


def set_rekey_batch(db, batch: dict) -> None:
    if batch:
        outbox.put(db, outbox.REKEY, batch)
    else:
        clear_rekey_batch(db)


def clear_rekey_batch(db) -> None:
    outbox.sent(db, outbox.REKEY, outbox.ONE)


def revocation_queue(db) -> list:
    """Members revoked on the server while an earlier member's re-key was
    still pending, in re-key order (review 688edcb #8b)."""
    return [user_id for user_id, _ in outbox.items(db, outbox.REVOKE)]


def set_revocation_queue(db, queue: list) -> None:
    outbox.replace_items(db, outbox.REVOKE, [(user_id, None) for user_id in queue])


# Stateful test SM24a (R16-Z): keys of this account a member held through an
# envelope withdrawn here without a re-key, {dek_id: [user_id, ...]}.
WITHDRAWN_HOLDERS_META = "withdrawn_holder_keys"


def note_withdrawn_holder(db, dek_id: str, user_id: str) -> None:
    """Remember that ``user_id`` knew ``dek_id``: their envelope went while a
    folder here is still sealed under that key (another device of the account
    had no folder to re-key, or the folder comes back from this device)."""
    held = {
        key: users for key, users in (db.get_meta_json(WITHDRAWN_HOLDERS_META) or {}).items()
        if db.fetchone("SELECT 1 FROM deks WHERE id = ?", (key,))
    }
    held[dek_id] = sorted(set(held.get(dek_id, [])) | {user_id})
    db.set_meta_json(WITHDRAWN_HOLDERS_META, held)


def withdrawn_holder_keys(db, user_id: Optional[str] = None) -> dict[str, list[str]]:
    """The noted keys (of ``user_id``, or all) some live folder here is still
    sealed under: the re-key of a revoked holder must replace them too."""
    return {
        key: [u for u in users if user_id in (None, u)]
        for key, users in (db.get_meta_json(WITHDRAWN_HOLDERS_META) or {}).items()
        if (user_id is None or user_id in users)
        and db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ? AND is_deleted = 0", (key,))
    }


# Capability review run 638 (R16-N19): keys of this account a member got through
# a share a server without its log took alone and the log then would not take
# (log_pre_log_grants, _push_team_grants), {dek_id: [user_id, ...]}. The member
# may hold the key; the admin's handover re-key replaces it (crud._handover_rekey_rows).
LEAKED_GRANTS_META = "leaked_grant_keys"


def note_leaked_grant(db, dek_id: str, user_id: str) -> None:
    held = leaked_grant_keys(db)
    held[dek_id] = sorted(set(held.get(dek_id, [])) | {user_id})
    db.set_meta_json(LEAKED_GRANTS_META, held)


def leaked_grant_keys(db, user_id: Optional[str] = None) -> dict[str, list[str]]:
    """The noted keys (of ``user_id``, or all) some live folder here still uses."""
    return {
        key: [u for u in users if user_id in (None, u)]
        for key, users in (db.get_meta_json(LEAKED_GRANTS_META) or {}).items()
        if (user_id is None or user_id in users)
        and db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ? AND is_deleted = 0", (key,))
    }


def org_recovery_registration(db) -> Optional[Any]:
    """The public /store body the server has not registered, or None
    (capability review run 91): wrapped_kek is sealed under the recovery
    secret, the rest is public. Dropped when the KEK it wraps changes."""
    return outbox.body(db, outbox.ORG_RECOVERY, "registration")


def set_org_recovery_registration(db, body) -> None:
    outbox.put(db, outbox.ORG_RECOVERY, body, "registration")


def clear_org_recovery_registration(db) -> None:
    outbox.sent(db, outbox.ORG_RECOVERY, "registration")


def org_recovery_rewrap(db) -> Optional[Any]:
    """The server blob re-wrapped after an org recovery that the server has
    not taken, or None (review 526419e N5): the /store body, nothing secret."""
    return outbox.body(db, outbox.ORG_RECOVERY, "rewrap")


def set_org_recovery_rewrap(db, body) -> None:
    outbox.put(db, outbox.ORG_RECOVERY, body, "rewrap")


def clear_org_recovery_rewrap(db) -> None:
    outbox.sent(db, outbox.ORG_RECOVERY, "rewrap")


def reseed_state(db) -> Optional[str]:
    """'sezam server reseed': "bootstrap URL" = bootstrap sent, objects not yet
    queued; "push URL" = everything queued, push/pull not finished."""
    return outbox.body(db, outbox.RESEED)


def set_reseed_state(db, state: str) -> None:
    outbox.put(db, outbox.RESEED, state)


def clear_reseed_state(db) -> None:
    outbox.sent(db, outbox.RESEED, outbox.ONE)


def bootstrap_upload_flag(db) -> bool:
    """A bootstrap admin account exists on the server without key material
    (the keypair upload after POST /api/bootstrap has not succeeded)."""
    return outbox.has(db, outbox.BOOTSTRAP)


def mark_bootstrap_upload_pending(db, pending: bool) -> None:
    if pending:
        outbox.put(db, outbox.BOOTSTRAP)
    else:
        outbox.sent(db, outbox.BOOTSTRAP, outbox.ONE)


class RekeyWaitsForKeyChange(RuntimeError):
    """A member re-key would be pushed together with an unsent password change
    and refused for good (review 526419e V4); it waits until that change landed."""


KEY_CHANGE_BLOCKS_RESYNC = (
    "This device has a password change the server has not received yet; "
    "a full resync would make every entry unreadable. "
    "Run 'sezam push' first."
)

# Operations a pending state can refuse (blocker()).
FULL_RESYNC = "full_resync"
KEY_CHANGE = "key_change"  # change_password, rotate_identity; ctx: rotate_identity
GRANT_AGAIN = "grant_again"  # a new envelope for a member whose old one is stale
REKEY = "rekey"  # rekey_after_revocation
RESOLVE_CONFLICT = "resolve_conflict"  # ctx: object_id
ABANDON_REKEY = "abandon_rekey"
ABANDON_QUEUED = "abandon_queued"  # sezam abandon-rekey --queued
ABANDON_KEY_CHANGE = "abandon_key_change"
OPERATIONS = (
    FULL_RESYNC, KEY_CHANGE, GRANT_AGAIN, REKEY, RESOLVE_CONFLICT,
    ABANDON_REKEY, ABANDON_QUEUED, ABANDON_KEY_CHANGE,
)


def _connected(db) -> bool:
    return bool(db.get_meta("server_url"))


def _journal_rewraps(db) -> bool:
    """SM40/SM54: the journal keeps the old KEK, so the change re-wraps every
    server wrap as it is applied and survives a full resync."""
    return "old_kek" in key_change_journal(db)


def _key_change_blocks_resync(db, ctx: dict) -> bool:
    return (key_epoch_unpushed(db) or bool(key_change_journal(db))) and not _journal_rewraps(db)


def _rekey_blocks_resync(db, ctx: dict) -> bool:
    batch = rekey_batch(db)
    # SM57: an identity rotation's batch only re-seals this account's
    # envelopes; full_resync seals the server's again.
    return bool(batch) and not (
        batch.get("identity_rotation") and _journal_rewraps(db)
        and "identity" in key_change_journal(db)
    )


@dataclass(frozen=True)
class _Rule:
    operation: str
    state: str
    applies: Callable[[Any, dict], bool]
    message: str
    error: type[Exception] = RuntimeError


# What each pending state refuses, highest priority first within an operation;
# the message names the way out.
BLOCKS: tuple[_Rule, ...] = (
    _Rule(FULL_RESYNC, "key_change", _key_change_blocks_resync, KEY_CHANGE_BLOCKS_RESYNC),
    _Rule(
        FULL_RESYNC, "rekey", _rekey_blocks_resync,
        "This device has a folder re-key the server has not received yet; "
        "a full resync would make the re-keyed entries unreadable. "
        "Run 'sezam push' first (or drop the re-key: 'sezam abandon-rekey').",
    ),
    # Review 688edcb K2: a second change would overwrite the journal of the
    # first, which holds what the server still knows.
    _Rule(
        KEY_CHANGE, "key_change",
        lambda db, ctx: _connected(db) and bool(key_change_journal(db)),
        "The previous password or key change has not reached the server yet; "
        "run 'sezam push' first (if the server refuses it, "
        "'sezam abandon-pending-change' drops it).",
        ValueError,
    ),
    # Review 526419e V4: pushed together with the re-key, the change was
    # refused with 409 on every sync and the re-key rebase was skipped.
    _Rule(
        KEY_CHANGE, "rekey",
        lambda db, ctx: bool(rekey_batch(db)) and (
            bool(ctx.get("rotate_identity")) or _connected(db)
        ),
        "A member re-key has not reached the server yet; run 'sezam push' "
        "first (if the server keeps refusing it, 'sezam abandon-rekey' drops it).",
        ValueError,
    ),
    _Rule(
        GRANT_AGAIN, "rekey", lambda db, ctx: bool(rekey_batch(db)),
        "A folder re-key is still pending; push it before granting access again",
        ValueError,
    ),
    _Rule(
        REKEY, "rekey", lambda db, ctx: bool(rekey_batch(db)),
        "A previous re-key must be synchronized before starting another "
        "(or dropped with 'sezam abandon-rekey')",
    ),
    _Rule(
        REKEY, "key_change", lambda db, ctx: _connected(db) and key_change_pending(db),
        "This device's password change has not reached the server yet; "
        "the re-key follows the push that sends it",
        RekeyWaitsForKeyChange,
    ),
    _Rule(
        RESOLVE_CONFLICT, "rekey",
        lambda db, ctx: ctx.get("object_id") in (rekey_batch(db).get("object_ids") or []),
        "This item is part of a pending re-key; push it first, or drop the "
        "re-key with 'sezam abandon-rekey'",
    ),
    _Rule(
        ABANDON_REKEY, "rekey", lambda db, ctx: not rekey_batch(db),
        "This device has no member re-key waiting for the server",
    ),
    _Rule(
        ABANDON_REKEY, "key_change", lambda db, ctx: bool(rekey_batch(db).get("identity_rotation")),
        "The pending change is an identity rotation; use 'sezam abandon-pending-change'",
    ),
    _Rule(
        ABANDON_QUEUED, "queued_revocations", lambda db, ctx: not revocation_queue(db),
        "No removed member waits for a re-key",
    ),
    _Rule(
        ABANDON_KEY_CHANGE, "key_change", lambda db, ctx: not key_change_pending(db),
        "This device has no password or key change waiting for the server",
    ),
)


@dataclass(frozen=True)
class Blocker:
    state: str
    message: str
    error: type[Exception]


def blocker(db, operation: str, **ctx) -> Optional[Blocker]:
    """The pending state that refuses ``operation`` now (first rule of BLOCKS), or None."""
    if operation not in OPERATIONS:
        raise ValueError(f"Unknown operation {operation!r}")
    for rule in BLOCKS:
        if rule.operation == operation and rule.applies(db, ctx):
            return Blocker(rule.state, rule.message, rule.error)
    return None


def refuse_if_blocked(db, operation: str, **ctx) -> None:
    """Raise the blocking state's error with its message (see blocker())."""
    found = blocker(db, operation, **ctx)
    if found is not None:
        raise found.error(found.message)


def read_team(db) -> tuple[Any, Any]:
    """(team state or None, TeamLogMismatch or None): the one read of the log
    for 'status' and the way-out messages (capability runs 406/407, INV-7)."""
    from .team_log_local import TeamLogMismatch, local_team_state

    try:
        return local_team_state(db), None
    except TeamLogMismatch as refusal:
        return None, refusal


def refusal_way_out(refusal) -> str:
    """The way out of a team log this device refuses, from its cause."""
    from .team_log_local import LOST_LOG_HINT

    if refusal.offers_forget:
        return LOST_LOG_HINT.strip()
    if getattr(refusal, "way_out", None):
        return refusal.way_out
    return ("'sezam pull' fetches the log again, held to the genesis and the head this "
            "device saw; a server that went back or forked is still refused.")


def key_reset_way_out(db, user_id: str, read: Optional[tuple[Any, Any]] = None) -> str:
    """How a password change the server refuses (no old password) gets through.

    Review 8595ec1 #3/#4: the admin of a team log is its only admin, so no
    'allow-key-reset' can come from another admin; the way out is the
    recovery key the log names (or there is none). ``read`` is read_team()'s
    result when the caller has it; a refused log is named first, since who may
    allow a reset is decided from the log (capability run 407).
    """
    from .. import teamlog

    state, refusal = read if read is not None else read_team(db)
    if refusal is not None:
        return (
            f"first the team log this device refuses ({refusal.cause}): "
            f"{refusal_way_out(refusal).rstrip('.')}; then 'sezam status' names who can "
            "let the reset through"
        )
    if state is None:
        # Review 4acfdde R11 (medium): without a team log the only admin was
        # sent to another admin's allow-key-reset, which cannot exist.
        if db.get_meta("org_recovery_signing_pk"):
            lone = (
                "found the team log ('sezam team-log init'), then 'sezam push' names this vault's "
                "org recovery key and the server takes a reset signed by it"
            )
        else:
            lone = "only the password the server has works ('sezam abandon-pending-change')"
        return (
            f"another admin's 'sezam allow-key-reset {user_id}', then 'sezam push'. If this account "
            f"is the organisation's only admin, there is no other admin: {lone}"
        )
    if not teamlog.is_admin(state, user_id):
        return f"another admin's 'sezam allow-key-reset {user_id}', then 'sezam push'"
    if teamlog.recovery_key(state, user_id) is not None:
        return (
            "this account is the team log's only admin, so nobody can allow a key reset; "
            "the server takes a reset signed by the org recovery key the team log names "
            "('sezam push' also puts back a team log a restored server lost)"
        )
    return (
        "this account is the team log's only admin, so nobody can allow a key reset, and "
        "the team log names no org recovery key of it: only the password the server has "
        "works ('sezam abandon-pending-change'). While a password is known, set up org "
        "recovery ('sezam org-recovery-setup') and consider 'sezam team-log hand-over USER_ID'"
    )


@dataclass(frozen=True)
class PendingState:
    key: str
    summary: str
    resolve: str
    drop: Optional[str]


def closed_shared_before_team_log(vault: "Vault") -> set[str]:
    """Keys shared with this account before the organisation had a team log
    that do not open here. Only those: a no-log member whose own KEK wraps the
    DEK (it has the key already) is not waiting on anything."""
    from .dek import shared_before_team_log

    db = vault.db
    dek_mgr = getattr(vault, "_dek_mgr", None)
    if not db.get_meta("server_url") or dek_mgr is None:
        return set()
    shared = set()
    for dek_id in shared_before_team_log(db, db.get_meta("user_id") or ""):
        row = db.fetchone("SELECT encrypted_dek, version FROM deks WHERE id = ?", (dek_id,))
        if row is None or not dek_mgr.can_unwrap(dek_id, bytes(row["encrypted_dek"]), row["version"]):
            shared.add(dek_id)
    return shared


def _sent_pre_log_grants(db) -> int:
    """Shares a server without its log took alone; with the log here the next
    push puts them in it (log_pre_log_grants, R16-N16)."""
    from . import outbox
    from .team_log_local import PRE_LOG_GRANTS_META

    marked = db.get_meta_json(PRE_LOG_GRANTS_META) or []
    if not marked or db.fetchone("SELECT 1 FROM team_log LIMIT 1") is None:
        return 0
    return sum(
        1 for envelope_id in marked
        if not outbox.is_pending(db, outbox.ENVELOPE, envelope_id)
        and db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (envelope_id,))
    )


def pending_states(vault: "Vault") -> list[PendingState]:
    """What waits, in the order the ways out have to be taken. Local only."""
    from .sync_client import unsent_envelope_count

    db = vault.db
    connected = bool(db.get_meta("server_url"))
    user_id = db.get_meta("user_id") or "USER_ID"
    states: list[PendingState] = []
    # Capability runs 406/407 (INV-7): the log is read once, guarded, and every
    # state below (the key-reset way out too) is decided from this read.
    read = read_team(db)

    from .sync_common import SERVER_ROLLBACK_META, STALE_OWN_WRAPS_META

    if connected and db.get_meta_json(STALE_OWN_WRAPS_META):
        states.append(PendingState(
            "stale_own_wraps",
            "The server sent keys of this account in a copy from before a password "
            "change; the folders they lock do not open here and pulls stop until a "
            "full resync.",
            "'sezam pull --full-resync' takes the server's current copies over.",
            None,
        ))

    if connected and db.get_meta(SERVER_ROLLBACK_META) is not None:
        # Review 7c10379 Y6: pulls and pushes stop until the full resync, and
        # 'status' said nothing was waiting.
        states.append(PendingState(
            "server_rollback",
            "The server went back to an older state (restored from a backup?): this "
            "device neither pulls nor pushes until a full resync.",
            "'sezam pull --full-resync' takes the server's state over; items this "
            "device has and the server lost are kept and sent again.",
            None,
        ))

    if vault.key_change_unpushed():
        journal = key_change_journal(db)
        if "recovery_secret" in journal:
            states.append(PendingState(
                "key_change",
                "A password reset by org recovery has not reached the server.",
                "'sezam push' sends it, signed with the recovery key the server registered.",
                f"If the server refuses it: {key_reset_way_out(db, user_id, read)}.",
            ))
        elif change_lacks_server_proof(db):
            states.append(PendingState(
                "key_change",
                PRE_PROOF_CHANGE,
                "'sezam finish-pending-change' (asks for the password the server has now; "
                "the new password stays).",
                "'sezam abandon-pending-change' (drops the new password for the server's).",
            ))
        else:
            states.append(PendingState(
                "key_change",
                "This device's password or key change has not reached the server.",
                "'sezam push' sends it.",
                "'sezam abandon-pending-change' (asks for the password the server has now).",
            ))

    batch = rekey_batch(db)
    if batch and not batch.get("identity_rotation"):
        held = len(batch.get("held_edits") or {})
        states.append(PendingState(
            "rekey",
            f"The re-key after removing member {batch.get('revoked_user_id')} has not "
            "reached the server" + (f" ({held} own edit(s) held by it)." if held else "."),
            "'sezam push' sends it (held edits come back as conflicts).",
            "'sezam abandon-rekey' (the member is queued for a fresh re-key).",
        ))

    queue = revocation_queue(db)
    if queue:
        states.append(PendingState(
            "queued_revocations",
            f"{len(queue)} removed member(s) wait for their folders to be re-keyed: "
            + ", ".join(queue) + ".",
            "'sezam push' re-keys them one after another.",
            "'sezam abandon-rekey --queued' (they keep the keys of folders they had).",
        ))

    # Review 8595ec1 #2: the team change queue was invisible here.
    from .team_log_local import queued_changes, set_aside_changes

    aside = set_aside_changes(db)
    if aside:
        lines = "; ".join(
            f"{n}. {item['change'][0]} {item['change'][1].get('user_id') or item['change'][1].get('folder', '')}"
            f" ({item['reason']})" for n, item in enumerate(aside, 1)
        )
        removed = sorted({item["change"][1]["user_id"] for item in aside if item["change"][0] == "member.remove"})
        states.append(PendingState(
            "team_changes_set_aside",
            f"{len(aside)} team change(s) the team log or the server refused, set aside: {lines}."
            + (f" This device keeps {', '.join(removed)} from new keys meanwhile." if removed else ""),
            "'sezam team-log retry' queues them again for the next push.",
            "'sezam team-log discard N' (or --all) drops them.",
        ))
    queued = queued_changes(db)
    if connected and queued:
        states.append(PendingState(
            "team_changes_queued",
            f"{len(queued)} team change(s) not in the team log yet: "
            + ", ".join(kind for kind, _ in queued) + ".",
            "'sezam push' sends them.",
            None,
        ))

    # Review 8595ec1 #3: losing the lone admin froze the organisation unnoticed.
    from .. import teamlog

    # Capability run 406 (INV-7): a refused log ended 'status' with the
    # refusal; it is a state of its own, its way out from its cause, and no
    # team state is decided from it.
    team, refusal = read
    if refusal is not None:
        states.append(PendingState(
            "team_log_refused",
            f"This device refuses its team log ({refusal.cause}): team folders and team "
            "changes wait; personal entries go on.",
            refusal_way_out(refusal),
            None,
        ))
    if not connected:
        team = None
    if (
        team is not None and teamlog.is_admin(team, user_id)
        and teamlog.recovery_key(team, user_id) is None
        and not any(kind == "org.recovery" for kind, _ in queued)
    ):
        states.append(PendingState(
            "lone_admin_without_recovery",
            "This account is the team log's only admin and the log names no org recovery "
            "key of it: losing its devices and password freezes the organisation (no "
            "member, access or key change, nobody to allow a key reset).",
            "'sezam push' names this vault's org recovery key in the team log."
            if db.get_meta("org_recovery_signing_pk") else
            "'sezam org-recovery-setup' (the next 'sezam push' names the key in the team "
            "log), or 'sezam team-log hand-over USER_ID' to a member you trust.",
            None,
        ))

    shared = closed_shared_before_team_log(vault)
    if shared:
        states.append(PendingState(
            "shared_before_team_log",
            f"{len(shared)} folder(s) shared with this account before the organisation had a "
            "team log do not open here: this device takes another account's key only "
            "through the log.",
            "An admin runs 'sezam team-log init'; then 'sezam team-log confirm-founder "
            "FINGERPRINT' (the admin's device shows it) and 'sezam pull'.",
            None,
        ))

    from .personal_root import PERSONAL_ROOTS_WAITING_META

    waiting_roots = db.get_meta_json(PERSONAL_ROOTS_WAITING_META) or []
    if waiting_roots:
        states.append(PendingState(
            "personal_root_waits_for_server",
            f"{len(waiting_roots)} personal folder(s) stay on this device: the server is older "
            "than this app and takes no personal folder of a member yet. Their entries wait with "
            "them; nothing else waits on it.",
            "The server's operator updates the server; the next 'sezam push' sends them.",
            None,
        ))

    conflicts = db.fetchall("SELECT object_id FROM sync_conflicts")
    if conflicts:
        states.append(PendingState(
            "conflicts",
            f"{len(conflicts)} conflict(s) with the server's copies.",
            "'sezam conflicts' lists them; 'sezam conflicts resolve ID --keep local' "
            "sends this copy.",
            "'sezam conflicts resolve ID --keep server' takes the server's copy.",
        ))

    if connected and org_recovery_registration(db) is not None:
        states.append(PendingState(
            "org_recovery_registration",
            "The server has not registered this vault's org recovery key yet.",
            "'sezam push' in a terminal registers it (asks for the password).",
            "'sezam org-recovery-setup --replace' sets up a new one instead.",
        ))

    if connected and org_recovery_rewrap(db) is not None:
        states.append(PendingState(
            "org_recovery_rewrap",
            "After the org recovery, the server still holds the recovery blob of the "
            "old password: the shares do not work there yet.",
            "'sezam push' sends the new one.",
            "'sezam org-recovery-setup --replace' sets up a new recovery instead.",
        ))

    reseed = reseed_state(db)
    if reseed:
        url = reseed.split(" ", 1)[-1]
        states.append(PendingState(
            "server_reseed",
            f"The reseed of {url} has not finished.",
            f"'sezam server reseed {url}' resumes it.",
            None,
        ))
    elif connected and bootstrap_upload_flag(db):
        url = db.get_meta("server_url")
        states.append(PendingState(
            "bootstrap_upload",
            "The admin account this vault set up on the server has no key material yet.",
            f"'sezam connect {url}' finishes the upload (asks for the password).",
            None,
        ))

    if connected:
        dirty = db.fetchone(
            "SELECT COUNT(*) AS n FROM outbox WHERE kind = 'write'"
        )["n"] + unsent_envelope_count(db) + _sent_pre_log_grants(db)
        if dirty:
            states.append(PendingState(
                "unpushed",
                f"{dirty} local change(s) not on the server yet.",
                "'sezam push' sends them.",
                None,
            ))
    return states
