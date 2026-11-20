"""Granting and revoking a team member's access, shared by the CLI and the desktop GUI."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, Optional

from . import oplock, outbox, pending_states, sync_core
from .crud import RekeyBlockedByConflicts
from .sync_client import CONFIRMED_MEMBER_KEYS_META
from .sync_limits import SyncUnitTooLarge
from .sync_common import queued_for_removal
from .team_log_local import local_team_state, projected_team_state

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .crud import Vault
    from .sync_client import SyncClient


class RekeyPending(RuntimeError):
    """The member is revoked on the server; the folder re-key is not there yet."""


class QueuedRekeysBlocked(RekeyBlockedByConflicts):
    """Queued members whose folders hold open conflicts; the others were
    re-keyed (``done``) - review 526419e S4."""

    def __init__(
        self, done: dict[str, int], blocked: dict[str, list[str]],
        too_large: Optional[dict[str, str]] = None,
    ):
        super().__init__(sorted({oid for ids in blocked.values() for oid in ids}))
        self.done = done
        self.blocked = blocked
        # Review d150605 S1: members whose re-key the server can never take
        # (member -> the reason and the way out).
        self.too_large = too_large or {}


class MemberKeyUnconfirmed(RuntimeError):
    """The member's key fingerprint was never confirmed by this admin."""

    def __init__(self, user_id: str, fingerprint: str):
        super().__init__(
            f"The key fingerprint of member {user_id} has not been confirmed: "
            f"{fingerprint}. Compare it with the one the member sees "
            "('sezam fingerprint' on their device) before sharing a folder."
        )
        self.user_id = user_id
        self.fingerprint = fingerprint


@oplock.held  # review 8bc70f7 #3: the re-grant's batch and the check before it
def grant_member(
    vault: Vault,
    client: SyncClient,
    user_id: str,
    node_id: str,
    access_level: str = "read",
    confirm_fingerprint: Optional[Callable[[str], bool]] = None,
) -> str:
    """Share a folder's DEK with an approved member and push the envelope.

    The member must be active on the server (a pending invitee gets
    nothing) and the envelope is sealed for the encryption key pinned with
    the member's signing key. The first time, that pinned key is only what
    the server said, so its fingerprint must be confirmed out of band:
    ``confirm_fingerprint(fp)`` is asked, and without a yes nothing is sealed
    (MemberKeyUnconfirmed; review 688edcb, low). An envelope the server
    refuses is withdrawn locally, so the folder is never shown as shared
    when it is not. Returns the envelope id.
    """
    team = local_team_state(vault.db)
    if team is not None:
        return _grant_in_team_log(vault, client, team, user_id, node_id, access_level)
    member = next((u for u in client.list_users() if u.get("id") == user_id), None)
    if member is None or member.get("status") != "active":
        raise ValueError("Only an approved member can be given access to a folder")
    pinned_before = vault.db.fetchone(
        "SELECT 1 FROM known_keys WHERE user_id = ?", (user_id,)
    ) is not None
    encryption_pk = client.verified_encryption_pk(user_id)
    fingerprint = vault.db.fetchone(
        "SELECT fingerprint FROM known_keys WHERE user_id = ?", (user_id,)
    )["fingerprint"]
    confirmed = dict(vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
    if confirmed.get(user_id) != fingerprint:
        if confirm_fingerprint is None or not confirm_fingerprint(fingerprint):
            if not pinned_before:
                # Review 7c10379: the key this grant pinned was not confirmed
                # as the member's. Kept, a key the server swapped in stayed
                # pinned, and the member's real one then failed every pull of
                # this device as a key change.
                client.unpin_member_key(user_id)
            raise MemberKeyUnconfirmed(user_id, fingerprint)
        confirmed[user_id] = fingerprint
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
    envelope_id = vault.grant_folder_access(node_id, user_id, encryption_pk, access_level)
    return _push_grant(vault, client, envelope_id)


def _push_grant(vault: Vault, client: SyncClient, envelope_id: str) -> str:
    try:
        result = client.push()
    except (RuntimeError, OSError) as exc:
        raise RuntimeError(
            f"The access envelope was not sent ({exc}); it goes with the next push"
        ) from exc
    refused = [c for c in result.get("conflicts", []) if c.get("id") == envelope_id]
    if refused:
        vault.withdraw_unsent_grant(envelope_id)
        raise RuntimeError(f"The server refused the access envelope: {refused[0].get('error')}")
    return envelope_id


def _grant_in_team_log(
    vault: Vault, client: SyncClient, team, user_id: str, node_id: str, access_level: str,
) -> str:
    """A grant once the organisation has a team log (docs/DESIGN_TEAM_LOG.md §4.3.1).

    The member and their key come from the log (an admin added them with a
    confirmed fingerprint), never from /api/users; the access is an
    ``access.set`` record that lands before the envelope, the first grant of a
    folder also records its key (``folder.key`` gen 0).
    """
    from .. import teamlog

    if not client.team_log_trusted(team):
        raise RuntimeError(
            "This device has not confirmed the fingerprint of the admin who founded the "
            "team log; nothing is shared until it has ('sezam team-log status')."
        )
    # docs/SYNC_SINGLE_SOURCE.md 3.5: decided on the log after this device's
    # queued changes land. On the server's log alone, a grant made while a
    # member's removal waited was sealed under the key that removal retires;
    # reported as "goes with the next push", it then never reached the member.
    projected = projected_team_state(vault.db, vault.db.get_meta("user_id"))
    member = projected.members.get(user_id)
    if member is None or not member.active:
        if user_id in queued_for_removal(vault.db):
            raise ValueError("This member is queued for removal and gets no new key")
        raise ValueError(
            "Only a member of the team log can be given access to a folder "
            "('sezam team-log add-member')"
        )
    row = vault.db.fetchone(
        "SELECT d.id FROM nodes n JOIN deks d ON d.id = n.dek_id "
        "WHERE n.id = ? AND n.is_deleted = 0 AND d.node_id = n.id",
        (node_id,),
    )
    if row is None:
        raise ValueError("This folder has no key of its own to share")
    changes = []
    if not teamlog.is_team_folder(team, node_id):
        changes.append(("folder.key", {"folder": node_id, "dek_id": row["id"], "prev_dek_id": None}))
    elif teamlog.current_key(projected, node_id) != row["id"]:
        raise RuntimeError(
            "This folder's key here is not its current key in the team log; pull first."
        )
    elif not teamlog.may_seal(projected, node_id):
        raise RuntimeError(
            "This folder waits for the re-key of a member's removal; nothing is sealed "
            "under its old key. Sync first ('sezam push'), then share it."
        )
    changes.append(("access.set", {"folder": node_id, "user_id": user_id, "level": access_level}))
    client.set_aside_refused_team_changes()  # a stale queued change does not refuse this one
    held = vault.db.fetchone(
        "SELECT id FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (row["id"], user_id)
    )
    if held is not None and team.access.get(node_id, {}).get(user_id) not in (None, access_level):
        # Only the level changes (review 8595ec1, R10-C: the way to show items a
        # founding hid): the log decides it, the member keeps the current key.
        client.append_team_log(changes)
        return held["id"]
    client.team_log_records(client.pending_team_changes() + changes)  # refused by the rules: nothing is made
    envelope_id = vault.grant_folder_access(
        node_id, user_id, bytes.fromhex(member.encryption_pk), access_level
    )
    # Review 1141a20 H4: the access.set (and a first folder.key) go only in
    # the atomic request of the envelope. Sent before it on their own, a
    # refused envelope left the member in the log, a recipient of every later
    # key, while the grant was reported refused.
    try:
        batch = pending_states.rekey_batch(vault.db)
        if envelope_id in batch.get("object_ids", []):
            # A re-grant replacing a dead envelope is already an atomic unit.
            pending_states.set_rekey_batch(vault.db, {
                **batch, "team_changes": [[kind, data] for kind, data in changes],
            })
        else:
            client.queue_team_grant(envelope_id, changes)
    except Exception:
        vault.withdraw_unsent_grant(envelope_id)
        raise
    return _push_grant(vault, client, envelope_id)


def queued_revocations(vault: Vault) -> list[str]:
    """Members revoked on the server whose folders still wait for their re-key."""
    return pending_states.revocation_queue(vault.db)


def queue_revoked_holders(vault: Vault, client: SyncClient) -> None:
    """Queue the re-key of members revoked elsewhere whose envelopes this device holds.

    Stateful test SM23: the re-key finds a member's folders through the
    envelopes the device holds. Revoked from a device that had not seen the
    grant, nothing was re-keyed there, and the device that made the grant
    never learned it had to: the member's envelope stayed live and new items
    kept going under the key they had.
    """
    me = vault.db.get_meta("user_id")
    lost = dict(outbox.items(vault.db, outbox.WITHDRAWAL, outbox.HELD))
    # Only envelopes this account sealed: re-keying (and listing users) is the
    # granting admin's job, never a member's.
    holders = {
        row["user_id"] for row in vault.db.fetchall(
            "SELECT DISTINCT user_id FROM access_envelopes WHERE created_by = ? AND user_id != ?",
            (me, me),
        )
    }
    if not holders and not lost:
        return
    revoked = {u.get("id") for u in client.list_users() if u.get("status") == "revoked"}
    # Review 7c10379 R7-G (state machine: a revoked member keeps a live
    # envelope): one this account withdrew and a restored server holds live
    # again goes back in for the re-key, which withdraws it once more. Only
    # for a revoked member: an active one's stays ignored (review d615826 H2).
    revive = {
        envelope_id: row for envelope_id, row in sorted(lost.items())
        if row["user_id"] in revoked
        and vault.db.fetchone("SELECT 1 FROM deks WHERE id = ?", (row["dek_id"],))
    }
    if revive:
        with vault.db.transaction():
            for envelope_id, row in revive.items():
                vault.db.execute(
                    "INSERT OR REPLACE INTO access_envelopes (id, dek_id, user_id, created_by, "
                    "access_level, encrypted_dek) VALUES (?, ?, ?, ?, ?, ?)",
                    (envelope_id, row["dek_id"], row["user_id"], me, row["access_level"],
                     bytes.fromhex(row["encrypted_dek"])),
                )
                outbox.sent(vault.db, outbox.ENVELOPE, envelope_id)
                outbox.sent(vault.db, outbox.WITHDRAWAL, envelope_id)
                vault.db.execute("DELETE FROM withdrawn_envelopes WHERE envelope_id = ?", (envelope_id,))
                holders.add(row["user_id"])
    queue = queued_revocations(vault)
    pending = (pending_states.rekey_batch(vault.db)).get("revoked_user_id")
    new = sorted((holders & revoked) - set(queue) - {pending})
    revived = {row["user_id"] for row in revive.values()}
    if [u for u in new if u not in revived] and local_team_state(vault.db) is not None:
        client._refresh_team_log()
        team = local_team_state(vault.db)
        new = [u for u in new if u in revived or _rekey_due(vault, team, me, u)]
    if new:
        pending_states.set_revocation_queue(vault.db, queue + new)


def _rekey_due(vault: Vault, team, me: str, user_id: str) -> bool:
    """Whether a member revoked elsewhere still holds a key of this account's
    that is some folder's current one (by the server's team log, ``team``).

    Conformance scenario client_revokes_member: another device of the account
    revoked the member and re-keyed. This device, not pulled yet, still held
    the member's envelope on the old key, queued the re-key again before its
    pull, and the team log refused it (folder_key_moved): the sync failed on
    every try and told the user to 'sezam abandon-rekey'. The pull withdraws
    the envelope; a key the log does not know is re-keyed as before."""
    keys = [row["dek_id"] for row in vault.db.fetchall(
        "SELECT DISTINCT dek_id FROM access_envelopes WHERE created_by = ? AND user_id = ?", (me, user_id)
    )]
    return sync_core.call("rekey_due", team=sync_core.team_input(team, me), keys=keys)


def finish_queued_revocations(vault: Vault, client: SyncClient) -> dict[str, int]:
    """Re-key and send the folders of every queued member, one batch at a time.

    Only one re-key batch can be pending, so it must land before the next one
    starts. A member leaves the queue only once their batch is accepted; the
    first push that fails raises and leaves the rest queued (a re-key already
    made stays pending). Returns folders re-keyed per member.

    A member whose folders hold open conflicts stays queued while the members
    after them are re-keyed; QueuedRekeysBlocked then names the waiting ones
    and carries the rest (review 526419e S4: the first one blocked them all).
    """
    client.flush_team_log()
    done: dict[str, int] = {}
    blocked: dict[str, list[str]] = {}
    too_large: dict[str, str] = {}
    redone: set[str] = set()
    pulled: set[str] = set()
    while True:
        queue = queued_revocations(vault)
        pending = pending_states.rekey_batch(vault.db)
        if not pending and vault.key_change_unpushed():
            break  # review 526419e V4: re-keyed after the password change landed
        waiting = [u for u in queue if u not in blocked and u not in too_large]
        user_id = pending.get("revoked_user_id") if pending else (waiting[0] if waiting else None)
        if user_id is None or user_id not in queue or user_id in too_large:
            break  # nothing queued, or an unrelated (or refused) batch waits
        if pending:
            client.requeued_rekey = None
            result = client.push()
            if pending_states.rekey_batch(vault.db):
                if result.get("rollback_warning"):
                    break  # stateful test SM85: it waits for the full resync named
                if result.get("rekey_too_large"):
                    # Only one batch can be pending: the rest waits for it.
                    too_large[user_id] = result["rekey_too_large"]
                    continue
                raise RuntimeError("The re-key batch was not accepted")
            if client.requeued_rekey == user_id and user_id not in redone:
                # Review 8595ec1 (#377, reviewer's seed): the push dropped a
                # batch another device of this account superseded, and the
                # member still holds an envelope. Counted as landed, they left
                # the queue and kept a live key: re-key again on the current
                # folder keys.
                redone.add(user_id)
                continue
            count = pending.get("folders_rekeyed", 0)
        else:
            try:
                client.pin_envelope_holder_keys(exclude=(user_id,))  # stateful test SM46
                count = vault.rekey_after_revocation(user_id)
            except RekeyBlockedByConflicts as exc:
                blocked[user_id] = exc.object_ids  # nothing re-keyed; stays queued
                continue
            except SyncUnitTooLarge as exc:
                # Review d150605 S1: refused before a batch exists (it was made
                # and failed on every sync); the member stays queued and the
                # members after them go on.
                too_large[user_id] = str(exc)
                continue
            if (pending_states.rekey_batch(vault.db).get("dek_map") or None) and user_id not in pulled:
                # Review 4acfdde R11 #3 (state machine, second admin): another
                # device of this account had already re-keyed the member's
                # folders. Built on this device's unpulled copy, a second
                # re-key of the same keys landed too (nothing in it clashed):
                # devices split between the two new keys and a member granted
                # meanwhile lost the folder. Before its first send the batch
                # meets what the server holds: one another re-key superseded
                # is dropped (the next round re-keys what the member still
                # holds on the current keys). Pulled after the batch is made,
                # so a conflict the pull brings does not hold the re-key up
                # (SM37); the envelopes the batch withdraws stay withdrawn.
                from .rekey_abandon import abandon_pending_rekey, superseded_rekey

                pulled.add(user_id)
                client.pull()
                if superseded_rekey(client):
                    abandon_pending_rekey(client)
                else:
                    with vault.db.transaction():
                        for item in pending_states.rekey_batch(vault.db).get("envelope_tombstones") or []:
                            vault.db.execute("DELETE FROM access_envelopes WHERE id = ?", (item["id"],))
                continue
            if count > 0 or pending_states.rekey_batch(vault.db):
                continue  # the batch is now pending: the next round sends it
        done[user_id] = count
        pending_states.set_revocation_queue(vault.db, [u for u in queued_revocations(vault) if u != user_id]
        )
    if blocked or too_large:
        raise QueuedRekeysBlocked(done, blocked, too_large)
    return done


def finish_queued_into(
    vault: Vault, client: SyncClient, rekeyed: dict[str, int], blocked: dict[str, list[str]],
    too_large: Optional[dict[str, str]] = None,
) -> None:
    """finish_queued_revocations, collecting the re-keyed and the members that
    wait for conflicts (``blocked`` is replaced) or whose re-key the server
    can never take (``too_large``, replaced) instead of raising for them."""
    if too_large is None:
        too_large = {}

    def add(done: dict[str, int]) -> None:
        # A member re-keyed, then queued again for a re-sealed grant the
        # pre-send pull brought (R11 #3), reports both rounds, not the last.
        for user_id, count in done.items():
            rekeyed[user_id] = rekeyed.get(user_id, 0) + count

    queue_revoked_holders(vault, client)
    try:
        add(finish_queued_revocations(vault, client))
        blocked.clear()
        too_large.clear()
    except QueuedRekeysBlocked as exc:
        add(exc.done)
        blocked.clear()
        blocked.update(exc.blocked)
        too_large.clear()
        too_large.update(exc.too_large)


def finish_handover_rekeys(vault: Vault, client: SyncClient) -> dict[str, int]:
    """Admin: re-key the folders a former admin still holds only as admin.

    Review c78fd19 (R13-8): handing the role over left the former admin with
    every folder key they made and the log's write exception for them
    (``former_admins``) until a re-key nobody made. The new admin's push makes
    it, one former admin at a time, after the queued removals; folders with
    open conflicts or too large to send wait for a later push. Returns folders
    re-keyed per former admin.
    """
    from .. import teamlog

    done: dict[str, int] = {}
    team = local_team_state(vault.db)
    me = vault.db.get_meta("user_id")
    if team is None or not teamlog.is_admin(team, me) or not client.team_log_trusted(team):
        return done
    for former in sorted({u for users in team.former_admins.values() for u in users} - {me}):
        if pending_states.rekey_batch(vault.db) or vault.key_change_unpushed():
            break  # one batch at a time; after a password change lands
        try:
            count = vault.rekey_after_handover(former)
        except (RekeyBlockedByConflicts, SyncUnitTooLarge) as exc:
            logger.warning("Re-key after the handover of %s waits: %s", former, exc)
            continue
        if count:
            client.push()
            if pending_states.rekey_batch(vault.db):
                break  # not landed: the next push sends it again
            done[former] = count
    return done


def push_with_queued_revocations(vault: Vault, client: SyncClient) -> dict:
    """A push that also finishes the revocation queue, as 'sezam push' does
    (review 526419e S4: the GUI never did), and the re-key after an admin
    handover. Returns the push result plus ``rekeyed`` (member -> folders),
    ``blocked`` (member -> conflict ids) and ``handover_rekeyed`` (former
    admin -> folders)."""
    rekeyed: dict[str, int] = {}
    blocked: dict[str, list[str]] = {}
    too_large: dict[str, str] = {}
    finish_queued_into(vault, client, rekeyed, blocked, too_large)
    result = dict(client.push())
    finish_queued_into(vault, client, rekeyed, blocked, too_large)
    result["handover_rekeyed"] = finish_handover_rekeys(vault, client)
    result["rekeyed"] = rekeyed
    result["blocked"] = blocked
    result["too_large"] = too_large
    return result


def blocked_message(user_id: str, object_ids: list[str]) -> str:
    return (
        f"The re-key of revoked user {user_id} waits for unresolved sync conflicts "
        f"({', '.join(object_ids)}); settle them and push again."
    )


def revoke_member(vault: Vault, client: Optional[SyncClient], user_id: str) -> int:
    """Revoke ``user_id`` on the server, then re-key the folders they could open.

    The server revocation comes first and does not wait for the re-key: it
    stops the member at once (lockout review #8), while the re-key can be
    refused by a concurrent edit or a network error. A re-key that could not
    be sent stays pending, goes with the next push and raises RekeyPending.
    While an earlier member's re-key is pending, this member is queued and
    re-keyed right after it lands - here or by the next ``sezam push``
    (review 688edcb #8b: before, the member was revoked on the server but
    their folders were never re-keyed, while the message said they would be).
    Without a server only the local re-key runs. Returns the folders re-keyed.
    """
    if client is not None:
        team = local_team_state(vault.db)
        member = team.members.get(user_id) if team is not None else None
        if member is not None and member.active:
            # A signed member.remove (the server revokes the account with
            # it); kept for the next push if it cannot be sent now.
            client.queue_team_changes([("member.remove", {"user_id": user_id})])
            try:
                client.flush_team_log()
            except (RuntimeError, OSError) as exc:
                queue = queued_revocations(vault)
                if user_id not in queue:
                    pending_states.set_revocation_queue(vault.db, queue + [user_id])
                raise RekeyPending(
                    f"The server has NOT confirmed removal of {user_id} ({exc}). "
                    "Removal stays queued and locally blocked; retry 'sezam push'."
                ) from exc
        else:
            client.revoke_user(user_id)
    pending = pending_states.rekey_batch(vault.db)
    queue = queued_revocations(vault)
    if not pending and vault.key_change_unpushed():
        # Review 526419e V4: pushed with the password change, the re-key was
        # refused for good. It is queued and follows the push that sends it.
        if user_id not in queue:
            pending_states.set_revocation_queue(vault.db, queue + [user_id])
        raise RekeyPending(
            "The user is revoked on the server, but their folders are not re-keyed "
            "yet: this device's password change has to reach the server first. "
            "'sezam push' sends it and then re-keys the folders."
        )
    if (pending and pending.get("revoked_user_id") != user_id) or queue:
        if client is None:
            raise RuntimeError(
                "An earlier re-key is still pending; connect to the server and push it first"
            )
        if user_id not in queue:
            queue.append(user_id)
            pending_states.set_revocation_queue(vault.db, queue)
        try:
            if pending and pending.get("revoked_user_id") not in queue:
                client.push()  # the earlier member's batch has to land first
            return finish_queued_revocations(vault, client).get(user_id, 0)
        except QueuedRekeysBlocked as exc:
            if user_id in exc.done:
                return exc.done[user_id]  # an earlier member waits for conflicts
            reason = exc.too_large.get(user_id) or next(iter(exc.too_large.values()), None)
            raise RekeyPending(
                "The user is revoked on the server, but their folders are not re-keyed: "
                f"{reason or exc}"
            ) from exc
        except Exception as exc:
            raise RekeyPending(
                "The user is revoked on the server, but their folders are not re-keyed "
                f"on the server yet ({exc}): an earlier member's re-key has to land "
                "first. Both stay queued and are sent with the next push."
            ) from exc
    try:
        if pending:
            rekey_count = pending.get("folders_rekeyed", 0)
        else:
            if client is not None:
                client.pin_envelope_holder_keys(exclude=(user_id,))  # stateful test SM46
            rekey_count = vault.rekey_after_revocation(user_id)
        if client is not None and (pending or rekey_count > 0):
            client.push()
    except (RekeyBlockedByConflicts, SyncUnitTooLarge) as exc:
        if client is None:
            raise
        # Review e4cd15a #3 (and d150605 S1 for an item too large to send):
        # queued, so the next push re-keys once the
        # conflicts are settled (nothing was re-keyed yet).
        if user_id not in queue:
            pending_states.set_revocation_queue(vault.db, queue + [user_id])
        raise RekeyPending(
            f"The user is revoked on the server, but their folders are not re-keyed: {exc}"
        ) from exc
    except Exception as exc:
        if client is None:
            raise
        raise _rekey_not_sent(vault, user_id, exc) from exc
    return rekey_count


def _rekey_not_sent(vault: Vault, user_id: str, exc: Exception) -> RekeyPending:
    """Say what really happened to a re-key that did not land (review 526419e S7).

    "It stays pending" was said also when the re-key itself failed and nothing
    was pending - e.g. the vault locked under the background revocation.
    """
    try:
        pending = pending_states.rekey_batch(vault.db)
        if pending.get("revoked_user_id") == user_id:
            return RekeyPending(
                "The user is revoked on the server, but the folder re-key was not "
                f"synchronized ({exc}). It stays pending and is sent with the next push."
            )
        queue = queued_revocations(vault)
        if user_id not in queue:
            pending_states.set_revocation_queue(vault.db, queue + [user_id])
    except Exception:  # noqa: BLE001 - the vault is locked: nothing could be kept
        return RekeyPending(
            f"The user is revoked on the server, but their folders were NOT re-keyed ({exc}) "
            "and nothing is pending. Unlock the vault and revoke the user again."
        )
    return RekeyPending(
        f"The user is revoked on the server, but their folders are not re-keyed yet ({exc}). "
        "They are queued; the next push re-keys them."
    )
