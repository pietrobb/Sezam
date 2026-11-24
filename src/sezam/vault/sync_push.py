"""Push: collect, sign and send local changes (spec 8.2).

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Optional

from ..crypto.aead import BlobKind, encrypt, parse_envelope
from ..models import EntryData, bytes_to_ulid, new_ulid, ulid_to_bytes
from . import oplock, outbox, pending_states
from .audit import AuditLog
from .personal_root import in_personal_tree, personal_root_ids, personal_roots_refused
from .rekey_abandon import UNPULLED, meet_server
from .sealed import open_sealed
from .sync_limits import (
    SyncUnitTooLarge,
    object_json_bytes,
    payload_too_large,
    require_fits_atomic_unit,
    split_for_push,
)
from .team_log_local import TeamLogMismatch, local_team_state, rekey_changes

from .sync_common import (
    _AuditLostByRestore,
    _batch_conflicts,
    DETACHED_DEKS_META,
    FULL_RESYNC_HINT,
    INVALID_PERSONAL_DEK,
    KEY_CHANGE_REFUSED,
    REFUSED_DEKS_META,
    _KeyChangeMissesDeks,
    KeyEpochStale,
    logger,
    _payload_len,
    REKEY_TOO_LARGE_MESSAGE,
    _RekeyBatchConflict,
    RESEED_ARCHIVES_META,
    ATOMIC_BATCH_CONFLICT,
    COLLECTED_OBJECT,
    HISTORY_CHANGED,
    IDENTITY_ROTATION_NEEDS_NEW_KEYS,
    KEY_CHANGE_MISSES_DEKS,
    REVOKED_ENVELOPE,
    TEAM_LOG_ENVELOPE,
    serialize_audit_row,
    server_error,
    STALE_KEY_EPOCH,
    WRONG_CURRENT_PASSWORD,
    _RekeyRebasedOnCollected,
    _RekeyRecipientsMoved,
    _RevokedEnvelopesRefused,
    SERVER_KEY_MATERIAL_META,
    SERVER_ROLLBACK_META,
)

_MAX_REVOKED_ENVELOPE_RETRIES = 100


class PushMixin:
    """SyncClient methods: push: collect, sign and send local changes (spec 8.2)."""

    @oplock.held
    def push(self) -> dict:
        """Push dirty objects to server.

        Returns: {accepted: [{id, commit_seq}], conflicts: [{id, error}]}

        A member re-key the server refused because another device changed
        one of its objects meanwhile is pulled, carried over those changes
        and sent once more; otherwise it would be refused on every sync.

        Grants waiting in the team log go after it, each in its own atomic
        request; a refused one is a conflict of its envelope.
        """
        self._require_current_kek()
        if self._db.get_meta(pending_states.JOINED_UNPULLED):
            # Review e443cbc R15 (goal #429): a device joining an account whose
            # connect pull was refused (a pinned log the server had lost) pushed
            # its own pristine root; the pull after it kept that second root and
            # showed the account's root as a folder. Nothing goes out before the
            # first pull took the account's tree. A device whose own tree the
            # account is (it registered it) pushes as before.
            self.pull()
        if pending_states.rekey_batch(self._db).get(UNPULLED):
            rollback = meet_server(self)
            if rollback:
                return {"accepted": [], "conflicts": [], "rollback_warning": rollback}
        withdrawn = self.log_pre_log_grants()
        resp = self._push_checked()
        refused = withdrawn + self._push_team_grants()
        if refused:
            resp = {**resp, "conflicts": list(resp.get("conflicts") or []) + refused}
        return resp

    def _envelope_object(self, row) -> dict:
        obj = self._push_cache.get(row["id"])
        if obj is None:
            # R15 (goal #441): the level is not signed and the log decides it;
            # a level change leaves the envelope as it was, so a resend (after
            # a restore took it from the server) goes at the log's level.
            level = row["access_level"]
            team = self.team_state()
            if team is not None:
                folder = team.dek_index.get(row["dek_id"], (None, None))[0]
                level = team.access.get(folder, {}).get(row["user_id"]) or level
            obj = self._make_sync_object(
                id=row["id"],
                object_type="envelope",
                payload=row["encrypted_dek"],
                parent_ref=row["dek_id"],
                target_user_id=row["user_id"],
                access_level=level,
                version=1,
            )
            self._push_cache[row["id"]] = obj
        return obj

    def _push_checked(self) -> dict:
        try:
            return self._push()
        except _AuditLostByRestore:
            lost_seq = self._commit_anchor()[0]
            self._resend_audit_lost_by_restore()
            self._push_unchecked = True
            try:
                resp = self._push()
            finally:
                self._push_unchecked = False
        if self.has_pending_key_change() or pending_states.rekey_batch(self._db):
            return resp
        # Stateful test SM66: the unchecked push moved the commit anchor onto
        # the restored server's history, so the pull after it no longer saw
        # the restore, and what the server lost of this device's (a rename
        # pushed before it) never went out again. The full resync that keeps
        # and resends it is allowed now that the change has landed.
        message = (
            f"Sync rollback detected: the server no longer holds commit_seq "
            f"{lost_seq} as this device saw it (restored from a backup). "
            f"{FULL_RESYNC_HINT}"
        )
        logger.error(message)
        self._db.set_meta(SERVER_ROLLBACK_META, str(lost_seq))
        return {**resp, "rollback_warning": message}

    def _resend_audit_lost_by_restore(self) -> None:
        """Mark this account's sent audit records the server no longer holds unsent.

        As the full resync does (SM6, SM14): one signed with an identity key
        the restored server lost is signed again with the current one.
        """
        snapshot = self._fetch_pull_pages(0, full_resync=True) or {}
        # Stateful test (second admin, bg238): the restore may have lost this
        # device's key change too. The resend goes out unchecked, at the epoch
        # the server no longer has, and was refused on every push; the device
        # takes over the server's key material first, as every pull does (SM12).
        # A pending change rewraps every DEK anyway; its refusal names the way
        # out (SM9).
        if not self.has_pending_key_change():
            self._check_key_epoch(snapshot)
        # Stateful test SM87: the DEKs it lost go out again too. A re-key the
        # restored server lost left items sealed with its new DEK; this push
        # sent them again without it, and no other device could open them.
        held_deks = {
            obj["id"] for obj in snapshot.get("objects") or []
            if obj.get("object_type") == "dek"
        }
        pushed = self._db.get_meta_json("pushed_dek_versions") or {}
        if any(dek_id not in held_deks for dek_id in pushed):
            self._db.set_meta_json(
                "pushed_dek_versions",
                {dek_id: v for dek_id, v in pushed.items() if dek_id in held_deks},
            )
            for dek_id in [k for k in pushed if k not in held_deks]:
                self._push_cache.pop(dek_id, None)
        held = {
            obj["id"] for obj in snapshot.get("objects") or []
            if obj.get("object_type") == "audit"
        }
        lost = [
            row
            for row in self._db.fetchall(
                "SELECT a.id, a.actor_id FROM audit_log a WHERE NOT EXISTS "
                "(SELECT 1 FROM outbox o WHERE o.kind = 'audit' AND o.object_id = a.id)"
            )
            if row["id"] not in held
        ]
        if not lost:
            return
        with self._db.transaction():
            for row in lost:
                # Another admin's record goes again too, as the full resync does.
                outbox.queue(self._db, outbox.AUDIT, row["id"])
            if self._keypair is not None:
                AuditLog(self._db).reattribute_unpushed(
                    self._user_id, self._user_id, self._keypair.to_nacl_signing_key()
                )
        for obj_id in [k for k, obj in self._push_cache.items() if obj["object_type"] == "audit"]:
            del self._push_cache[obj_id]

    def _push(self) -> dict:
        try:
            return self._push_rebased()
        except _KeyChangeMissesDeks:
            pulled = self.pull()
            if pulled.get("rollback_warning"):
                # Stateful test SM65: the server was restored from a backup, so
                # the pull applied nothing and the change still missed the
                # folder keys; the way out then named was abandoning it, which
                # an org recovery cannot do. A full resync brings those keys
                # and keeps the change (its journal re-wraps them, SM40).
                raise RuntimeError(
                    "The password change misses folder keys the server holds. "
                    + pulled["rollback_warning"]
                )
            self._pulled_for_key_change = True
            try:
                return self._push_rebased()
            finally:
                self._pulled_for_key_change = False

    def _push_rebased(self) -> dict:
        self._rebased_on_own_write = False
        try:
            # Without the refused envelopes. Review a159e97 H7: the server stops
            # an atomic batch at its first conflict, so it names one per push.
            for _ in range(_MAX_REVOKED_ENVELOPE_RETRIES):
                try:
                    result = self._push_once()
                    break
                except (_RevokedEnvelopesRefused, _RekeyRecipientsMoved, _RekeyRebasedOnCollected):
                    continue
            else:
                result = self._push_once()
            if self._rebased_on_own_write:
                # An earlier push landed but its reply was lost; what was
                # refused as a conflict with it goes out again on top of it.
                self._rebased_on_own_write = False
                again = self._push_once()
                result = {
                    **again,
                    "accepted": list(result.get("accepted") or []) + list(again.get("accepted") or []),
                }
        except _RekeyBatchConflict:
            # Stateful test SM85: refused by a server restored from a backup,
            # the batch has nothing to rebase on until the full resync; the
            # push reports the rollback instead of a conflict for good.
            if self._db.get_meta(SERVER_ROLLBACK_META) is not None:
                pulled = {"rollback_warning": (
                    f"Sync rollback detected: the server went back (restored from a backup). "
                    f"{FULL_RESYNC_HINT}"
                )}
            else:
                pulled = self.pull()
            if pulled.get("rollback_warning"):
                return {"accepted": [], "conflicts": [], "rollback_warning": pulled["rollback_warning"]}
            self._rebase_pending_rekey()
            try:
                result = self._push_once()
            except _RekeyBatchConflict as exc:
                raise RuntimeError(
                    "Atomic re-key batch conflict; it stays pending for the next sync "
                    "(if it keeps failing: 'sezam abandon-rekey')"
                ) from exc
        if not self.retry_org_recovery_rewrap():
            result = {**result, "org_recovery_rewrap_pending": True}
        if getattr(self, "_org_recovery_superseded", False):
            self._org_recovery_superseded = False
            result = {**result, "org_recovery_superseded": True}
        return result

    def _push_once(self) -> dict:
        # Review e443cbc #436 (precedence rule 1): whatever fails in the team
        # log check (a refused copy, a founder not confirmed yet, a pinned log
        # the server does not answer for, an error in the check) holds back
        # the team's changes only.
        try:
            local_team_state(self._db)
            self.require_trusted_team_log()
        except Exception as refusal:  # noqa: BLE001 - every failed check is a refusal here
            return self._push_personal_while_refused(refusal)
        if not self._token:
            self.authenticate()

        # Collect dirty objects (uses push cache for idempotent retry)
        # Review 7c10379 H8: the batch landed with its reply lost and a pull
        # brought its copies back clean (956656b), so they were no longer
        # collected and every push stopped as 'missing'. A batch key the server
        # holds proves the atomic batch is there: it is closed as sent first.
        if pending_states.rekey_batch(self._db):
            self.close_rekey_if_landed()
        # Team changes first (docs/DESIGN_TEAM_LOG.md §5): an access the
        # objects below rely on is in the log before they land.
        if self.drop_superseded_org_recovery():
            self._org_recovery_superseded = True
        self.adopt_logged_org_recovery()
        self.anchor_org_recovery()
        if pending_states.key_change_journal(self._db).get("identity") and self.team_state() is not None:
            # Review e443cbc R15 (goal #442): a server restored from before
            # this rotation's member.keys lacks it; this copy holds it, so the
            # push sent the rotation alone and was refused for good ('requires
            # matching member.keys'). The log is put back first.
            self._refresh_team_log()
        self.continue_identity_in_log()
        self.fold_unlogged_folder_keys()
        self.flush_team_log()
        # A re-key's new key goes to the log's recipients as the log is now.
        self._reseal_team_rekey(self.team_state())
        pending_rekey = pending_states.rekey_batch(self._db)
        key_epoch = int(self._db.get_meta("key_epoch") or "0")
        last_pushed_key_epoch = pending_states.last_pushed_key_epoch(self._db)
        password_rewrap_pending = key_epoch > last_pushed_key_epoch
        self._reseal_under_successors()
        # Stateful test SM34: a change made after the last pull to an item below
        # a folder deleted elsewhere was refused ('parent folder is deleted');
        # in an atomic re-key batch that failed the whole push. The pull revives
        # such folders, so the push now does it too before collecting.
        with self._db.transaction():
            self._revive_folders_of_unsent()
        objects = self._collect_dirty_objects()
        atomic_batch = bool(pending_rekey) or password_rewrap_pending
        required_ids = set(pending_rekey.get("object_ids", []))
        if password_rewrap_pending:
            required_ids.update(self._key_change_dek_ids())
        missing_ids = required_ids - {obj["id"] for obj in objects}
        if missing_ids:
            # Stateful test SM36: the batch landed, its reply was lost, and a
            # pull brought its envelopes back - the server holds them, so they
            # are not collected again and are not missing either.
            marks = ",".join("?" * len(missing_ids))
            held = {
                row["id"] for row in self._db.fetchall(
                    f"SELECT ae.id FROM access_envelopes ae WHERE ae.id IN ({marks}) "
                    f"AND NOT {outbox.pending(outbox.ENVELOPE, 'ae.id')}",
                    tuple(missing_ids),
                )
            }
            missing_ids -= held
            required_ids -= held
        if missing_ids:
            raise RuntimeError(
                f"Atomic re-key batch is missing {len(missing_ids)} local object(s)"
            )
        if not objects:
            return {"accepted": [], "conflicts": [], "message": "Nothing to push"}
        # An atomic unit is just its own objects: other dirty objects ride in
        # a normal push afterwards. A member's unpushable top-level root
        # (review 2052248) or any unrelated conflicting edit would otherwise
        # sink the atomic batch on every sync.
        rekey_too_large = None
        if (
            pending_rekey
            and not password_rewrap_pending
            and any(
                payload_too_large(_payload_len(obj))
                for obj in objects
                if obj["id"] in required_ids
            )
        ):
            # Review d150605 S1: a re-key batch (made before the per-object
            # check) with an object the server never takes was refused on
            # every sync and held back every other change. It waits for
            # 'sezam abandon-rekey'; the rest goes out.
            rekey_too_large = REKEY_TOO_LARGE_MESSAGE
            logger.error(rekey_too_large)
            objects = [obj for obj in objects if obj["id"] not in required_ids]
            atomic_batch = False
            if not objects:
                return {"accepted": [], "conflicts": [], "rekey_too_large": rekey_too_large}
        # Stateful test SM27: the unit's audit record names this device's
        # earlier records as parents. Left for the normal push after it, they
        # never came when that push failed: the server held a record whose
        # parents it did not have and every full resync refused the audit DAG.
        # Unsent audit records are append-only and go with a member re-key.
        # A password / identity change batch stays as it was: with them a
        # member's rotation no longer retired the old envelope (#270 test).
        # Stateful test SM73: a folder of the re-key deleted elsewhere is taken
        # back for the unsent item in it, and so is its parent deleted there
        # too. Left for the normal push after the unit, that parent was gone on
        # the server when the unit came, which was refused on every sync.
        revived = self._revived_ancestors(required_ids) if atomic_batch else set()
        # Another account's record goes in a normal push: refused there
        # ('admin only'), it does not sink the unit.
        foreign_audit = {
            row["id"] for row in self._db.fetchall(
                "SELECT a.id FROM audit_log a WHERE a.actor_id <> ? AND "
                + outbox.pending(outbox.AUDIT, "a.id"),
                (self._user_id,),
            )
        }

        def in_unit(obj: dict) -> bool:
            return obj["id"] in required_ids or obj["id"] in revived or (
                bool(pending_rekey) and not password_rewrap_pending
                and obj["object_type"] == "audit" and obj["id"] not in foreign_audit
            )

        deferred = atomic_batch and any(not in_unit(obj) for obj in objects)
        if deferred:
            objects = [obj for obj in objects if in_unit(obj)]
        if atomic_batch:
            objects.sort(key=lambda obj: (
                0 if obj["object_type"] == "dek" else
                1 if obj["object_type"] == "envelope" and obj["is_deleted"] else
                3 if obj["object_type"] == "envelope" else
                2
            ))
            # Review 526419e #1: over the server's limits it was a 422 on every
            # sync, so it is refused with the reason. Over one request's
            # limits it goes staged (review d150605 #3).
            if any(payload_too_large(_payload_len(obj)) for obj in objects):
                raise SyncUnitTooLarge(
                    "An object of the pending re-key / password change exceeds "
                    "the server's 1 MiB limit per object."
                )
            require_fits_atomic_unit(
                len(objects), sum(object_json_bytes(obj) for obj in objects),
                "The pending re-key / password change",
            )
            resp = self._send_push(
                objects, True, key_epoch, pending_rekey, password_rewrap_pending,
                required_ids,
            )
        else:
            # Review 526419e #1: the server takes at most 1000 objects / 16 MiB
            # per request and 1 MiB per object. One push of everything was
            # refused as a whole on every sync (an import, a long offline
            # stretch of audit records, one big note blocked all of it).
            too_large = [obj for obj in objects if payload_too_large(_payload_len(obj))]
            if too_large:
                logger.error(
                    "%d object(s) exceed the server's 1 MiB limit and stay local",
                    len(too_large),
                )
                too_large_ids = {obj["id"] for obj in too_large}
                objects = [obj for obj in objects if obj["id"] not in too_large_ids]
            resp = {"accepted": [], "conflicts": [
                {"id": obj["id"], "error": "exceeds the server's 1 MiB limit per object"}
                for obj in too_large
            ]}
            for chunk in split_for_push(objects):
                part = self._send_push(chunk, False, key_epoch, {}, False, set())
                resp = {
                    **part,
                    "accepted": resp["accepted"] + list(part.get("accepted", [])),
                    "conflicts": resp["conflicts"] + list(part.get("conflicts", [])),
                }

        if deferred:
            rest = self.push()
            resp = {
                **resp,
                "accepted": list(resp.get("accepted", [])) + list(rest.get("accepted", [])),
                "conflicts": list(rest.get("conflicts", [])),
            }
        if rekey_too_large:
            resp = {**resp, "rekey_too_large": rekey_too_large}
        return resp

    def _push_personal_while_refused(self, refusal: Exception) -> dict:
        """INV-7: a refused team log holds back only the team's changes. The
        personal tree's go out; the rest stays queued and the refusal names its
        way out. A re-key or key change is one unit with the team's keys and waits whole.
        A failure that is no TeamLogMismatch is raised after the push in any case,
        so its caller still sees it (a founder to confirm, a server to retry)."""
        if pending_states.rekey_batch(self._db) or self.has_pending_key_change():
            raise refusal
        if not self._token:
            self.authenticate()
        roots = set(personal_root_ids(self._db, self._dek_mgr))
        key_nodes = {row["id"]: row["node_id"] for row in self._db.fetchall("SELECT id, node_id FROM deks")}

        def personal(obj: dict) -> bool:
            if obj["object_type"] == "node":
                return in_personal_tree(self._db, obj["id"], roots)
            if obj["object_type"] == "entry":
                return in_personal_tree(self._db, obj["parent_ref"], roots)
            if obj["object_type"] == "dek":
                return bool(key_nodes.get(obj["id"])) and in_personal_tree(self._db, key_nodes[obj["id"]], roots)
            return False

        collected = self._collect_dirty_objects()
        objects = [obj for obj in collected if personal(obj)]
        too_large = {obj["id"] for obj in objects if payload_too_large(_payload_len(obj))}
        resp = {"accepted": [], "conflicts": [
            {"id": obj_id, "error": "exceeds the server's 1 MiB limit per object"} for obj_id in too_large
        ]}
        key_epoch = int(self._db.get_meta("key_epoch") or "0")
        for chunk in split_for_push([obj for obj in objects if obj["id"] not in too_large]):
            part = self._send_push(chunk, False, key_epoch, {}, False, set())
            resp = {**part, "accepted": resp["accepted"] + list(part.get("accepted", [])),
                    "conflicts": resp["conflicts"] + list(part.get("conflicts", []))}
        waiting = len(collected) - len(objects)
        if waiting or not isinstance(refusal, TeamLogMismatch):
            # Callers must learn the team's changes did not go (a grant reads "no error" as sent).
            refusal.args = (f"{len(resp['accepted'])} personal change(s) went out; {waiting} wait "
                            f"for the team log. {refusal}",)
            refusal.pushed = resp
            raise refusal
        return {**resp, "team_log_refused": str(refusal)}

    def _send_with_team_records(self, body: dict, team_extra: list) -> dict:
        from .. import teamlog

        sends = []

        def send(records):
            if sends and self._reseal_team_rekey(self.team_state()):
                # The head moved (another device changed the log): the batch
                # is collected again with the envelopes of the new head.
                raise _RekeyRecipientsMoved()
            sends.append(1)
            if self.add_identity_team_record(records):
                body["team_log"] = records
            else:
                body.pop("team_log", None)
            return self._request("POST", "/api/sync", body, auth=True)

        try:
            return self._send_team_records(send, team_extra)
        except teamlog.TeamLogError as exc:
            raise RuntimeError(
                f"The re-key cannot go in the team log ({exc}): another device re-keyed "
                "the folder first. Pull, then 'sezam abandon-rekey' and re-key again."
            ) from exc

    def _send_push(
        self,
        objects: list[dict],
        atomic_batch: bool,
        key_epoch: int,
        pending_rekey: dict,
        password_rewrap_pending: bool,
        required_ids: set,
        team_changes: tuple = (),
    ) -> dict:
        """One POST /api/sync; marks what the server accepted as pushed."""
        pushed_dek_candidates = {
            obj["id"]: obj["version"] for obj in objects if obj["object_type"] == "dek"
        }
        self._stamp_base_versions(objects)
        # Review d150605 #3: an atomic batch over one request's limits (a
        # password change re-wraps every DEK) is staged in parts and the last
        # part applies all of it at once.
        chunks = split_for_push(objects) if atomic_batch else [objects]
        body = {
            "objects": chunks[-1],
            "atomic_batch": atomic_batch,
            "key_epoch": key_epoch,
        }
        anchor_seq, anchor_token = self._commit_anchor()
        # With a password change or re-key the server lacks, a full resync is
        # refused (it would make the entries unreadable): that push has to go
        # out first, so it is not held back by the check; the pull after it
        # reports the rollback.
        blocked = self.has_pending_key_change() or bool(
            pending_states.rekey_batch(self._db)
        )
        if anchor_token and not getattr(self, "_push_unchecked", False):
            body["check_seq"] = anchor_seq
            body["check_token"] = anchor_token
        if len(chunks) > 1:
            batch_id, staged = new_ulid(), 0
            for chunk in chunks[:-1]:
                self._request(
                    "POST", "/api/sync/stage",
                    {"batch_id": batch_id, "start": staged, "objects": chunk}, auth=True,
                )
                staged += len(chunk)
            body["staged_batch_id"] = batch_id
            body["staged_count"] = staged
        landed_journal = None
        if password_rewrap_pending:
            body["key_rotation"] = self._key_rotation_payload(key_epoch)
            landed_journal = pending_states.key_change_journal(self._db)
        # A re-key of a folder in the team log lands with its folder.key
        # records in this same request, or not at all.
        if pending_rekey:
            team_extra = rekey_changes(self.team_state(), pending_rekey) + [
                list(change) for change in pending_rekey.get("team_changes") or []
            ]
        else:
            team_extra = [list(change) for change in team_changes]
        try:
            if team_extra or (landed_journal or {}).get("identity"):
                resp = self._send_with_team_records(body, team_extra)
            else:
                resp = self._request("POST", "/api/sync", body, auth=True)
        except RuntimeError as exc:
            if (
                pending_rekey and not password_rewrap_pending
                and getattr(exc.__cause__, "code", None) == "folder_key_moved"
            ):
                # Stateful test (review e443cbc R15, #429): another device of
                # this account re-keyed the folder after this batch was made
                # (it finished the revocation this device's push had not sent).
                # The log refuses the batch's folder.key before the server sees
                # it; as for the server's batch conflict, the pull and rebase
                # drop the superseded batch (superseded_rekey). Raised as is,
                # every sync failed and named 'sezam abandon-rekey'.
                raise _RekeyBatchConflict() from exc
            if server_error(exc, 409, HISTORY_CHANGED) and blocked:
                # Stateful test SM39: sent unchecked, its new audit records
                # landed on parents the restore lost, and every other device's
                # pull refused the audit DAG until this one ran a full resync.
                # Every sent record goes out again with it (an identical resend
                # is accepted as is).
                raise _AuditLostByRestore() from exc
            if server_error(exc, 409, HISTORY_CHANGED):
                # Stateful test SM7: the server lost a commit this device saw
                # (its own push included). Nothing was applied; the next pull
                # asks for the full resync that keeps and resends what was lost.
                message = (
                    f"Sync rollback detected: the server no longer holds commit_seq "
                    f"{anchor_seq} as this device saw it (restored from a backup). "
                    f"{FULL_RESYNC_HINT}"
                )
                logger.error(message)
                self._db.set_meta(SERVER_ROLLBACK_META, str(anchor_seq))
                return {"accepted": [], "conflicts": [], "rollback_warning": message}
            if server_error(exc, 409, STALE_KEY_EPOCH):
                raise KeyEpochStale() from exc
            if password_rewrap_pending and server_error(exc, 409, KEY_CHANGE_MISSES_DEKS):
                journal = pending_states.key_change_journal(self._db)
                if "old_kek" in journal and not getattr(self, "_pulled_for_key_change", False):
                    # Stateful test SM40: DEKs made elsewhere since the last
                    # pull (an org recovery pulls nothing first). The pull
                    # re-wraps them into the change (SM31); the way out named
                    # below needs the old password, forgotten after a recovery.
                    raise _KeyChangeMissesDeks() from exc
                # A rival rotation brought DEKs this device never saw (#2c).
                self._check_key_epoch(self._request(
                    "GET",
                    "/api/sync?since_commit_seq="
                    f"{int(self._db.get_meta('last_known_commit_seq') or '0')}",
                    auth=True,
                ) or {})
                raise RuntimeError(
                    f"{exc}. If this device cannot send its password change, run "
                    "'sezam abandon-pending-change' to take over the server's."
                ) from exc
            if password_rewrap_pending and server_error(exc, 403, WRONG_CURRENT_PASSWORD):
                # Stateful test SM9: the change proves the password this device
                # last sent, but the server no longer has it (restored from a
                # backup that predates it). Resent as it is, it can never land;
                # the refusal named no way out.
                raise RuntimeError(f"{exc}. {KEY_CHANGE_REFUSED}") from exc
            if (
                password_rewrap_pending
                and server_error(exc, 400, IDENTITY_ROTATION_NEEDS_NEW_KEYS)
                and "identity" in (landed_journal or {})
                and not getattr(self, "_identity_landed", False)
            ):
                # Stateful test SM43: the rotation's push landed and its reply
                # was lost; an org recovery then made a new change on top of it
                # that still carried the rotation. The server already has these
                # keys, so the change goes out again without the rotation part.
                self._identity_landed = True
                try:
                    return self._push_once()
                finally:
                    self._identity_landed = False
            if server_error(exc, 409, ATOMIC_BATCH_CONFLICT):
                refused = _batch_conflicts(exc)
                envelope_ids = {obj["id"] for obj in objects if obj["object_type"] == "envelope"}
                if refused and all(
                    c.get("code") == REVOKED_ENVELOPE and c.get("id") in envelope_ids
                    for c in refused
                ):
                    # Stateful test SM29: an identity rotation (or re-key) re-sealed
                    # a grant for a member another device removed meanwhile. The
                    # server refuses that envelope, and with it the whole unit on
                    # every sync. Like a refused envelope outside a unit (review
                    # d150605 S5) it stays local and is not sent again.
                    dropped = {c["id"] for c in refused}
                    for obj_id in dropped:
                        outbox.refuse(self._db, outbox.ENVELOPE, obj_id)
                        self._push_cache.pop(obj_id, None)
                    if pending_rekey:
                        pending_states.set_rekey_batch(self._db, {
                            **pending_rekey,
                            "object_ids": [
                                i for i in pending_rekey.get("object_ids", []) if i not in dropped
                            ],
                        })
                    raise _RevokedEnvelopesRefused(str(exc)) from exc
                dek_ids = {obj["id"] for obj in objects if obj["object_type"] == "dek"}
                if (
                    password_rewrap_pending
                    and refused
                    and all(c.get("id") in dek_ids for c in refused)
                    and "old_kek" in (landed_journal or {})
                    and not getattr(self, "_pulled_for_key_change", False)
                ):
                    # Stateful test SM44: an org recovery (it pulls nothing
                    # first) re-wrapped DEKs another device's rotation had moved
                    # on since this device's last pull. The pull re-wraps the
                    # newer copies into the change (SM31), which goes out again.
                    raise _KeyChangeMissesDeks() from exc
                versions = {obj["id"]: int(obj.get("version") or 0) for obj in objects if obj["id"] in dek_ids}
                if (
                    password_rewrap_pending
                    and refused
                    and getattr(self, "_pulled_for_key_change", False)
                    and all(int(c.get("server_version") or 0) >= versions.get(c.get("id"), 1 << 62)
                            for c in refused)
                ):
                    # Stateful test (review 7c10379 R7-G): the server holds newer
                    # copies of these DEKs than this device, and the pull just
                    # made brought none - a full resync answered with older ones
                    # and the checkpoint has passed the current copies. Only a
                    # full resync brings them (the change re-wraps them, SM40);
                    # the raw 409 named no way out.
                    raise RuntimeError(
                        f"The password change re-wraps {len(refused)} key(s) the server "
                        "holds in newer copies that no delta pull brings. "
                        f"{FULL_RESYNC_HINT}"
                    ) from exc
                items = {
                    obj["id"]: obj for obj in objects if obj["object_type"] in ("node", "entry")
                }
                if pending_rekey and not password_rewrap_pending and refused and all(
                    c.get("code") == COLLECTED_OBJECT and c.get("id") in items for c in refused
                ):
                    # Review seed 171717 after S1: another device deleted an item
                    # of the re-keyed folder and GC collected the tombstone before
                    # this device pulled it. As outside a batch, the item builds on
                    # the collected (version, hash) and comes back; resent as it
                    # was, the whole batch was refused on every push.
                    rekeyed = dict(pending_rekey.get("rekeyed_versions") or {})
                    with self._db.transaction():
                        for c in refused:
                            obj = items[c["id"]]
                            self._rebase_local(
                                obj["id"], obj["object_type"],
                                c["server_version"], c["server_payload_hash"],
                            )
                            if rekeyed.get(obj["id"]) == obj["version"]:
                                table = "nodes" if obj["object_type"] == "node" else "entries"
                                rekeyed[obj["id"]] = self._db.fetchone(
                                    f"SELECT version FROM {table} WHERE id = ?", (obj["id"],)
                                )["version"]
                            self._push_cache.pop(obj["id"], None)
                        pending_states.set_rekey_batch(
                            self._db, {**pending_rekey, "rekeyed_versions": rekeyed}
                        )
                    raise _RekeyRebasedOnCollected() from exc
                if pending_rekey and not password_rewrap_pending:
                    raise _RekeyBatchConflict() from exc
            raise
        finally:
            if "key_rotation" in body:
                body["key_rotation"]["auth_proof"] = ""
                body["key_rotation"].pop("current_auth_proof", None)
        # The rotation bumped token_epoch: every older token, ours included, is dead.
        if resp.get("token"):
            self._token = resp["token"]
        accepted_seqs = [acc.get("commit_seq") or 0 for acc in resp.get("accepted", [])]
        self._advance_commit_anchor(max(accepted_seqs, default=0), resp.get("commit_token"))
        accepted_ids = {acc["id"] for acc in resp.get("accepted", [])}
        if atomic_batch and (
            resp.get("conflicts") or not required_ids.issubset(accepted_ids)
        ):
            raise RuntimeError("Atomic re-key batch was not fully accepted")

        # Mark accepted objects clean and remove their conflict shadows atomically.
        # Review 526419e #2: only the version that was sent. An edit made while
        # the request was out (GUI during 'sezam push' or a background sync)
        # was marked pushed too and never reached the server.
        sent = {obj["id"]: obj for obj in objects}
        accepted_seqs = {acc["id"]: acc.get("commit_seq") for acc in resp.get("accepted", [])}
        self._db.begin()
        try:
            for obj_id in accepted_ids:
                obj = sent.get(obj_id)
                if obj is None:
                    continue
                if obj["object_type"] in ("node", "entry"):
                    self._record_server_seq(obj_id, accepted_seqs.get(obj_id))
                    self._set_base(obj_id, obj["version"], obj["payload_hash"], own=True)
                for table in ("nodes", "entries"):
                    self._db.execute(
                        "DELETE FROM outbox WHERE kind = 'write' AND object_id = ? AND EXISTS "
                        f"(SELECT 1 FROM {table} t WHERE t.id = ? AND t.version = ? "
                        "AND t.is_deleted = ?)",
                        (obj_id, obj_id, obj["version"], obj["is_deleted"]),
                    )
                self._db.execute(
                    "DELETE FROM sync_conflicts WHERE object_id = ?", (obj_id,)
                )
                if obj["object_type"] == "audit":
                    outbox.sent(self._db, outbox.AUDIT, obj_id)
                if obj["object_type"] == "envelope":
                    outbox.sent(self._db, outbox.ENVELOPE, obj_id)
                    if obj.get("is_deleted"):
                        # Review d615826 H2: the server took this withdrawal;
                        # a replay of the live envelope is not taken back.
                        self._db.execute(
                            "INSERT OR IGNORE INTO withdrawn_envelopes (envelope_id) VALUES (?)",
                            (obj_id,),
                        )
            # Review d150605 S5: the server takes no live envelope for a removed
            # member. This device's stale copy of that grant is not resent on
            # every push; it stays local (a re-key finds the member's folders
            # through it).
            for conflict in resp.get("conflicts", []):
                obj = sent.get(conflict.get("id"))
                if (
                    obj and obj["object_type"] in ("node", "entry")
                    and conflict.get("code") == COLLECTED_OBJECT
                    and conflict.get("server_version") == obj["version"]
                    and conflict.get("server_payload_hash") == obj["payload_hash"]
                ):
                    # SM51 after S1: two devices deleted the same object into
                    # one identical tombstone and GC collected it. This write is
                    # the collected one, already done - not rebased and resent.
                    self._set_base(obj["id"], obj["version"], obj["payload_hash"], own=True)
                    for table in ("nodes", "entries"):
                        self._db.execute(
                            "DELETE FROM outbox WHERE kind = 'write' AND object_id = ? AND EXISTS "
                            f"(SELECT 1 FROM {table} t WHERE t.id = ? AND t.version = ? "
                            "AND t.is_deleted = 1)",
                            (obj["id"], obj["id"], obj["version"]),
                        )
                elif obj and obj["object_type"] in ("node", "entry") and self._own_sent_version(
                    obj["id"], conflict.get("server_version"), conflict.get("server_payload_hash")
                ):
                    # The server holds what this device sent earlier (that
                    # reply never arrived): build on it, and send again.
                    self._set_base(
                        obj["id"], conflict["server_version"], conflict["server_payload_hash"],
                        own=True,
                    )
                    self._rebased_on_own_write = True
                elif (
                    obj and obj["object_type"] in ("node", "entry")
                    and conflict.get("code") == COLLECTED_OBJECT
                ):
                    # A delete tombstone GC collected: no server copy is left to
                    # pick, so this change builds on the collected (version,
                    # hash) and brings the object back, as before the delete.
                    self._rebase_local(
                        obj["id"], obj["object_type"],
                        conflict["server_version"], conflict["server_payload_hash"],
                    )
                    self._rebased_on_own_write = True
                elif obj and obj["object_type"] in ("node", "entry"):
                    # Refused: this version is not a write the server has.
                    self._db.execute(
                        "DELETE FROM object_sent_base WHERE object_id = ? AND version = ?",
                        (obj["id"], obj["version"]),
                    )
                if obj and obj["object_type"] == "audit" and conflict.get("error") == "admin only":
                    # Only an admin's device can send it again; this one stops.
                    self._db.execute(
                        "DELETE FROM outbox WHERE kind = 'audit' AND object_id = ? AND EXISTS "
                        "(SELECT 1 FROM audit_log a WHERE a.id = ? AND a.actor_id <> ?)",
                        (obj["id"], obj["id"], self._user_id),
                    )
                if obj and obj["object_type"] == "envelope" and (
                    # R15 #441 (capability finding 494): an envelope sent without
                    # the access.set that gives its key (whatever lost it) is
                    # withdrawn once and reported, not resent on every push. A
                    # queued grant goes with its records (_push_team_grants).
                    conflict.get("code") in (REVOKED_ENVELOPE, TEAM_LOG_ENVELOPE)
                ):
                    outbox.refuse(self._db, outbox.ENVELOPE, obj["id"])
            personal_roots_refused(self._db, self._dek_mgr, resp.get("conflicts", []), list(accepted_ids))

            # A DEK conflict means the server already holds that version or
            # newer (e.g. archived DEK whose owner pointer changed locally).
            settled_dek_ids = set(accepted_ids) | {
                c["id"] for c in resp.get("conflicts", [])
                if c.get("id") in pushed_dek_candidates
                and int(c.get("server_version") or 0) >= pushed_dek_candidates[c["id"]]
            }
            if settled_dek_ids & pushed_dek_candidates.keys():
                pushed_dek_versions = self._db.get_meta_json("pushed_dek_versions") or {}
                for dek_id in settled_dek_ids & pushed_dek_candidates.keys():
                    pushed_dek_versions[dek_id] = pushed_dek_candidates[dek_id]
                self._db.set_meta_json("pushed_dek_versions", pushed_dek_versions)
            # TL7: a member's own top-level folder now goes up (the server takes
            # it as a personal root), so a folder below it is in step while its
            # key, naming the folder, is refused: E8's "folder in step" no longer
            # proves the server holds the key.
            refused = set(self._db.get_meta_json(REFUSED_DEKS_META) or [])
            now_refused = refused - settled_dek_ids | {
                c["id"] for c in resp.get("conflicts", [])
                if c.get("id") in pushed_dek_candidates and c.get("error") == INVALID_PERSONAL_DEK
            }
            if now_refused != refused:
                self._db.set_meta_json(REFUSED_DEKS_META, sorted(now_refused))

            if pending_rekey:
                self._restore_held_edits(pending_rekey.get("held_edits") or {}, resp)
                pending_states.clear_rekey_batch(self._db)
            reseed_archives = self._db.get_meta_json(RESEED_ARCHIVES_META)
            if reseed_archives:
                self._db.set_meta_json(RESEED_ARCHIVES_META, [
                    archive_id for archive_id in reseed_archives
                    if archive_id not in accepted_ids
                ])
            if password_rewrap_pending:
                pending_states.set_last_pushed_key_epoch(self._db, key_epoch)
                # Which key material that epoch is on the server (SM30).
                self._db.set_meta(SERVER_KEY_MATERIAL_META, hashlib.sha256(
                    bytes.fromhex(self._db.get_meta("encrypted_keypair") or "")
                ).hexdigest())
                pending_states.clear_key_change_journal(self._db)
                # A rotated identity: the server now also lists the old key
                # (certified) for this account.
                self._signing_key_rings.pop(self._user_id, None)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

        for obj_id in accepted_ids:
            self._push_cache.pop(obj_id, None)
        if landed_journal:
            self._restore_org_recovery_blob(landed_journal, key_epoch)
        return resp

    def _emptied_tombstone_data(self, entry_id: str, meta_blob: bytes, version: int) -> bytes:
        """No fields, sealed like the tombstone's meta (review d150605 N5).

        A tombstone carried the entry's whole content, so deleting an entry
        over the server's 1 MiB limit was refused like the entry itself and
        stayed unsent for good. Its content never reached the server; the
        local row keeps it, so a restore on this device still has it.
        """
        dek_id = parse_envelope(meta_blob).dek_id
        dek = self._dek_mgr.unlock_dek(bytes_to_ulid(dek_id))
        sealed_at = open_sealed(
            meta_blob, dek, entry_id, version, BlobKind.ENTRY_META, deleted=True
        )[1]
        return encrypt(
            plaintext=EntryData(fields=[]).to_json(), dek=dek, dek_id=dek_id,
            object_id=ulid_to_bytes(entry_id), version=sealed_at,
            blob_kind=BlobKind.ENTRY_DATA,
        )

    def _collect_dirty_objects(self) -> list[dict]:
        """Collect the vault objects with a queued write (outbox order) for push."""
        objects = []

        rows = self._db.fetchall(
            "SELECT n.id, n.parent_id, n.encrypted_meta, n.dek_id, n.version, n.is_deleted "
            "FROM nodes n JOIN outbox o ON o.kind = 'write' AND o.object_id = n.id "
            "ORDER BY o.seq"
        )
        for row in rows:
            obj_id = row["id"]
            cached = self._push_cache.get(obj_id)
            if (
                cached is not None
                and cached["version"] == row["version"]
                and cached["is_deleted"] == row["is_deleted"]
            ):
                objects.append(cached)
                continue
            payload = row["encrypted_meta"]
            obj = self._make_sync_object(
                id=obj_id,
                object_type="node",
                payload=payload,
                parent_ref=row["parent_id"],
                version=row["version"],
                is_deleted=row["is_deleted"],
            )
            self._push_cache[obj_id] = obj
            objects.append(obj)
        # Parent before child: the server refuses a live node below a folder it
        # does not hold yet (review d150605 #1), e.g. a folder moved into a new one.
        objects = self._order_pulled_objects(objects)

        # Entries (length-prefixed binary format)
        rows = self._db.fetchall(
            "SELECT e.id, e.node_id, e.encrypted_meta, e.encrypted_data, e.version, e.is_deleted "
            "FROM entries e JOIN outbox o ON o.kind = 'write' AND o.object_id = e.id "
            "ORDER BY o.seq"
        )
        for row in rows:
            obj_id = row["id"]
            cached = self._push_cache.get(obj_id)
            if (
                cached is not None
                and cached["version"] == row["version"]
                and cached["is_deleted"] == row["is_deleted"]
            ):
                objects.append(cached)
                continue
            # Encode: u32be(len(encrypted_meta)) + encrypted_meta + encrypted_data
            meta_bytes = bytes(row["encrypted_meta"])
            data_bytes = bytes(row["encrypted_data"])
            payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + data_bytes
            if row["is_deleted"] and payload_too_large(len(payload)):
                data_bytes = self._emptied_tombstone_data(obj_id, meta_bytes, row["version"])
                payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + data_bytes
            obj = self._make_sync_object(
                id=obj_id,
                object_type="entry",
                payload=payload,
                parent_ref=row["node_id"],
                version=row["version"],
                is_deleted=row["is_deleted"],
            )
            self._push_cache[obj_id] = obj
            objects.append(obj)

        # Password rotation re-wraps every active DEK, including root/audit DEKs
        # that have no dirty node. Until that epoch is accepted, send all of them.
        key_epoch = int(self._db.get_meta("key_epoch") or "0")
        last_pushed_key_epoch = pending_states.last_pushed_key_epoch(self._db)
        # Root, audit and tier-2 DEKs have no dirty owner node, so track which
        # DEK versions the server already holds instead of relying on nodes.
        pushed_dek_versions = self._db.get_meta_json("pushed_dek_versions") or {}
        rows = self._db.fetchall(
            "SELECT d.id, d.node_id, d.scope, d.encrypted_dek, d.version, "
            f"{outbox.queued('n')} AS node_dirty "
            "FROM deks d LEFT JOIN nodes n ON d.node_id = n.id"
        )
        rewrap_all = key_epoch > last_pushed_key_epoch
        foreign_dek_ids = set(self._db.get_meta_json("foreign_dek_ids") or [])
        detached = self._db.get_meta_json(DETACHED_DEKS_META) or {}
        personal_tops = None
        for row in rows:
            obj_id = row["id"]
            if obj_id in foreign_dek_ids:
                continue
            if not (
                rewrap_all
                or row["node_dirty"] == 1
                or pushed_dek_versions.get(obj_id) != row["version"]
            ):
                continue
            cached = self._push_cache.get(obj_id)
            if cached is not None and cached["version"] == row["version"]:
                objects.append(cached)
                continue
            # TL7: a key in a personal root's tree (the root's own, a tier-2
            # item's) names no folder, as the web's does; the server takes a
            # member's key only so.
            folderless = False
            if row["scope"] in ("personal", "tier2") and row["node_id"]:
                if personal_tops is None:
                    personal_tops = set(personal_root_ids(self._db, self._dek_mgr))
                folderless = in_personal_tree(self._db, row["node_id"], personal_tops)
            obj = self._make_sync_object(
                id=obj_id,
                object_type="dek",
                payload=row["encrypted_dek"],
                # Stateful test SM64: a DEK detached from its GC-collected
                # folder still names it on the server. Sent without it, the
                # resend of a landed key change was no identical retry and
                # refused for good; a re-wrap erased the folder's binding.
                parent_ref=None if folderless else row["node_id"] or detached.get(obj_id),
                version=row["version"],
            )
            # Unsigned label so a full resync can tell root/audit/tier-2 DEKs
            # apart (the server only stores and returns it).
            obj["scope"] = row["scope"]
            self._push_cache[obj_id] = obj
            objects.append(obj)

        # Access envelopes the server does not hold yet. Capability review of
        # #284: they went only while their folder node was dirty, and a split
        # push (or a grant during a push) marked the folder clean before the
        # envelope landed - the grant stayed on this device for good.
        rows = self._db.fetchall(
            "SELECT ae.id, ae.dek_id, ae.user_id, ae.created_by, "
            "ae.access_level, ae.encrypted_dek "
            "FROM access_envelopes ae JOIN outbox o ON o.kind = 'envelope' "
            "AND o.object_id = ae.id AND o.state = 'queued' ORDER BY o.seq"
        )
        grants = self.pending_team_grants()
        for row in rows:
            if row["id"] not in grants:  # a queued grant goes in its own atomic request
                objects.append(self._envelope_object(row))

        # Audit records are append-only; queued ones go in queue order, parents first.
        rows = outbox.parents_first(self._db.fetchall(
            "SELECT a.id, a.parent_ids, a.actor_id, a.action, "
            "a.encrypted_details, a.timestamp, a.signature "
            "FROM audit_log a JOIN outbox o ON o.kind = 'audit' AND o.object_id = a.id "
            "AND o.state = 'queued' ORDER BY o.seq"
        ))
        for row in rows:
            obj_id = row["id"]
            if (
                row["action"] == "sync_pull"
                and bytes(row["signature"]) == b"\x00" * 64
            ):
                logger.error(
                    "Quarantining unverifiable legacy audit record %s", obj_id
                )
                outbox.refuse(self._db, outbox.AUDIT, obj_id)
                continue
            if obj_id in self._push_cache:
                objects.append(self._push_cache[obj_id])
                continue
            payload = self._serialize_audit_row(row)
            try:
                self._verify_audit_payload(obj_id, payload)
            except ValueError as exc:
                if row["actor_id"] == self._user_id:
                    raise
                # Review a159e97 H11 (regression of 3d59ab3): another account's
                # record a restored server lost, signed with a key the server
                # no longer has for them (an identity rotation it lost too).
                # Sent again it failed every push of this device for good,
                # full resync included. Not this device's to vouch for: it is
                # left out, as the server would refuse it anyway.
                logger.warning(
                    "Not sending again audit record %s of %s: %s", obj_id, row["actor_id"], exc
                )
                outbox.sent(self._db, outbox.AUDIT, obj_id)
                continue
            obj = self._make_sync_object(
                id=obj_id,
                object_type="audit",
                payload=payload,
                version=2,
            )
            self._push_cache[obj_id] = obj
            objects.append(obj)

        # A re-key is persisted as one exact sync unit so retries remain
        # all-or-nothing across process restarts.
        pending_rekey = pending_states.rekey_batch(self._db)
        collected_ids = {obj["id"] for obj in objects}

        # A reseed re-sends archived DEKs too: normally only a re-key does.
        archive_ids = list(pending_rekey.get("archive_ids", [])) + list(
            self._db.get_meta_json(RESEED_ARCHIVES_META) or []
        )
        for archive_id in archive_ids:
            if archive_id in collected_ids:
                continue
            row = self._db.fetchone(
                "SELECT id, replaced_by, encrypted_dek, version "
                "FROM dek_archive WHERE id = ?",
                (archive_id,),
            )
            if row:
                obj = self._make_sync_object(
                    id=row["id"],
                    object_type="dek_archive",
                    payload=row["encrypted_dek"],
                    parent_ref=row["replaced_by"],
                    version=row["version"],
                )
                self._push_cache[archive_id] = obj
                objects.append(obj)
                collected_ids.add(archive_id)

        for audit_id in pending_rekey.get("audit_ids", []):
            if audit_id in collected_ids:
                continue
            row = self._db.fetchone(
                "SELECT id, parent_ids, actor_id, action, encrypted_details, "
                "timestamp, signature FROM audit_log WHERE id = ?",
                (audit_id,),
            )
            if row:
                payload = self._serialize_audit_row(row)
                self._verify_audit_payload(audit_id, payload)
                obj = self._make_sync_object(
                    id=row["id"],
                    object_type="audit",
                    payload=payload,
                    version=2,
                )
                self._push_cache[audit_id] = obj
                objects.append(obj)
                collected_ids.add(audit_id)

        for tombstone in pending_rekey.get("envelope_tombstones", []):
            obj_id = tombstone["id"]
            if obj_id in collected_ids:
                continue
            obj = self._make_sync_object(
                id=obj_id,
                object_type="envelope",
                payload=bytes.fromhex(tombstone["encrypted_dek"]),
                parent_ref=tombstone["dek_id"],
                target_user_id=tombstone["user_id"],
                access_level=tombstone["access_level"],
                version=2,
                is_deleted=1,
            )
            self._push_cache[obj_id] = obj
            objects.append(obj)
            collected_ids.add(obj_id)

        return objects

    def dirty_object_count(self) -> int:
        """Return how many unsynchronized objects a full resync would overwrite."""
        return len(self._collect_dirty_objects())

    _serialize_audit_row = staticmethod(serialize_audit_row)

    def _make_sync_object(
        self,
        id: str,
        object_type: str,
        payload: bytes,
        parent_ref: Optional[str] = None,
        target_user_id: Optional[str] = None,
        access_level: Optional[str] = None,
        version: int = 1,
        is_deleted: int = 0,
    ) -> dict:
        """Create a sync object dict with signature."""
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Build canonical signed data (spec 8.2)
        canonical = self._build_signature_payload(
            id, object_type, parent_ref, target_user_id, is_deleted, version, payload_hash
        )
        signing_key = self._keypair.to_nacl_signing_key()
        signature = signing_key.sign(canonical).signature.hex()

        return {
            "id": id,
            "object_type": object_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "parent_ref": parent_ref,
            "target_user_id": target_user_id,
            "access_level": access_level,
            "version": version,
            "is_deleted": is_deleted,
            "payload_hash": payload_hash,
            "signature": signature,
        }

    @staticmethod
    def _id_to_bytes(id_str: str) -> bytes:
        """Encode ID as 26-byte NUL-padded string; ValueError on a longer one."""
        return ulid_to_bytes(id_str)

    @staticmethod
    def _build_signature_payload(
        id: str,
        object_type: str,
        parent_ref: Optional[str],
        target_user_id: Optional[str],
        is_deleted: int,
        version: int,
        payload_hash: str,
    ) -> bytes:
        """Build canonical signed data for Ed25519 signature (spec 8.2).

        Uses UTF-8 string encoding for IDs (matching server's _verify_sync_signature).

        R15 #428 (INV-3): a value the u8/u32 fields cannot hold exactly is a
        ValueError, so a pulled object carrying one is unverified, not a crash.
        """
        if type(is_deleted) not in (int, bool) or is_deleted not in (0, 1):
            raise ValueError(f"is_deleted must be 0 or 1, not {is_deleted!r}")
        if type(version) is not int or not 0 <= version <= 0xFFFFFFFF:
            raise ValueError(f"version must fit a u32, not {version!r}")
        id_bytes = PushMixin._id_to_bytes(id)
        ot = object_type.encode("utf-8")
        pr = PushMixin._id_to_bytes(parent_ref) if parent_ref else b"\x00" * 26
        tu = PushMixin._id_to_bytes(target_user_id) if target_user_id else b"\x00" * 26
        ph = bytes.fromhex(payload_hash)

        return (
            id_bytes
            + struct.pack("B", len(ot)) + ot
            + pr
            + tu
            + struct.pack("B", is_deleted)
            + struct.pack(">I", version)
            + ph
        )
