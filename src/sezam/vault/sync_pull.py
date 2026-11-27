"""Pull: fetch, verify, order and bind what the server sent.

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError, CryptoError

from .. import teamlog
from ..crypto.aead import BlobKind, encrypt, parse_envelope
from ..models import bytes_to_ulid, ulid_to_bytes
from .personal_root import is_personal_root
from . import oplock, outbox, pending_states, sync_core
from .audit import AuditLog
from .sealed import open_sealed
from .sync_writers import WRITES_AUDITED_META

from .sync_common import (
    server_error,
    _AUDIT_PAYLOAD_FORMAT,
    DETACHED_DEKS_META,
    FULL_RESYNC_HINT,
    logger,
    REATTACHED_META,
    REFUSED_DEKS_META,
    SERVER_ROLLBACK_META,
    STALE_OWN_WRAPS_META,
    SyncRollbackWarning,
    withdraw_from_removed_members,
)


class PullMixin:
    """SyncClient methods: pull: fetch, verify, order and bind what the server sent."""

    @staticmethod
    def _parse_audit_payload(obj_id: str, payload: bytes) -> dict:
        """Parse and validate the canonical, complete audit sync payload."""
        try:
            record = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid audit payload for {obj_id}") from exc

        expected_fields = {
            "action",
            "actor_id",
            "encrypted_details",
            "format",
            "id",
            "parent_ids",
            "signature",
            "timestamp",
        }
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise ValueError(f"Incomplete audit payload for {obj_id}")
        canonical_payload = json.dumps(
            record, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if payload != canonical_payload:
            raise ValueError(f"Non-canonical audit payload for {obj_id}")
        if record["format"] != _AUDIT_PAYLOAD_FORMAT or record["id"] != obj_id:
            raise ValueError(f"Mismatched audit identity for {obj_id}")

        actor_id = record["actor_id"]
        action = record["action"]
        parent_ids = record["parent_ids"]
        timestamp = record["timestamp"]
        if (
            not isinstance(actor_id, str)
            or len(actor_id) != 26
            or not isinstance(action, str)
            or not action
            or len(action.encode("utf-8")) > 65535
            or type(timestamp) is not int
            or timestamp < 0
            or not isinstance(parent_ids, list)
            or not all(
                isinstance(parent_id, str) and len(parent_id) == 26
                for parent_id in parent_ids
            )
            or parent_ids != sorted(set(parent_ids))
        ):
            raise ValueError(f"Invalid audit fields for {obj_id}")

        try:
            actor_id.encode("ascii")
            for parent_id in parent_ids:
                parent_id.encode("ascii")
            encrypted_details = base64.b64decode(
                record["encrypted_details"], validate=True
            )
            signature = bytes.fromhex(record["signature"])
        except (UnicodeEncodeError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid audit encoding for {obj_id}") from exc
        if len(signature) != 64 or record["signature"] != signature.hex():
            raise ValueError(f"Invalid audit signature encoding for {obj_id}")

        record["encrypted_details"] = encrypted_details
        record["signature"] = signature
        record["parent_ids_json"] = json.dumps(
            parent_ids, separators=(",", ":")
        )
        return record

    def _verify_audit_payload(self, obj_id: str, payload: bytes) -> dict:
        """Return a parsed audit record only when its original signature verifies.

        Any key of the actor's ring counts here (goal #443): the sync object
        around the record carries its payload_hash, and a retired key's
        signature of that counts only for a vouched version
        (_verify_object_signature); another pusher sends again only records
        it took that way."""
        record = self._parse_audit_payload(obj_id, payload)
        if obj_id in record["parent_ids"]:
            raise ValueError(f"Invalid self-referencing audit record {obj_id}")

        details_hash = (
            hashlib.sha256(record["encrypted_details"]).digest()
            if record["encrypted_details"]
            else b"\x00" * 32
        )
        canonical = AuditLog._build_canonical(
            obj_id,
            record["actor_id"],
            record["parent_ids_json"],
            record["action"],
            record["timestamp"],
            details_hash,
        )
        signing_pks = self._get_signing_pks(record["actor_id"])
        for signing_pk in signing_pks:
            try:
                VerifyKey(signing_pk).verify(canonical, record["signature"])
                return record
            except (BadSignatureError, ValueError):
                continue
        raise ValueError(f"Invalid audit signature for {obj_id}")

    def _validate_audit_dag(self) -> None:
        """Reject missing parents and cycles in the complete local audit graph."""
        rows = self._db.fetchall("SELECT id, parent_ids FROM audit_log")
        parents_by_id: dict[str, list[str]] = {}
        for row in rows:
            try:
                parent_ids = json.loads(row["parent_ids"])
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid audit DAG parents for {row['id']}") from exc
            if not isinstance(parent_ids, list) or not all(
                isinstance(parent_id, str) for parent_id in parent_ids
            ):
                raise ValueError(f"Invalid audit DAG parents for {row['id']}")
            parents_by_id[row["id"]] = parent_ids

        known_ids = set(parents_by_id)
        children: dict[str, list[str]] = {audit_id: [] for audit_id in known_ids}
        indegree: dict[str, int] = {}
        for audit_id, parent_ids in parents_by_id.items():
            missing = set(parent_ids) - known_ids
            if missing:
                raise ValueError(
                    f"Audit DAG record {audit_id} references missing parent(s)"
                )
            indegree[audit_id] = len(set(parent_ids))
            for parent_id in set(parent_ids):
                children[parent_id].append(audit_id)

        ready = [audit_id for audit_id, degree in indegree.items() if degree == 0]
        visited = 0
        while ready:
            parent_id = ready.pop()
            visited += 1
            for child_id in children[parent_id]:
                indegree[child_id] -= 1
                if indegree[child_id] == 0:
                    ready.append(child_id)
        if visited != len(known_ids):
            raise ValueError("Audit DAG contains a cycle")

    # ── Pull ──

    def _fetch_pull_pages(
        self,
        since_seq: int,
        *,
        full_resync: bool = False,
        check: tuple[int, Optional[str]] = (0, None),
    ) -> dict:
        """Fetch every bounded server page before any local state mutation."""
        objects: list[dict] = []
        cursor: Optional[int] = None
        previous_cursor = since_seq
        first_check_token = None
        while True:
            path = f"/api/sync?since_commit_seq={since_seq}"
            if full_resync:
                path += "&full_resync=true"
            if cursor is not None:
                path += f"&cursor={cursor}"
            elif check[1]:
                path += f"&check_seq={check[0]}&check_token={check[1]}"
            page = self._request("GET", path, auth=True)
            if not isinstance(page, dict):
                raise RuntimeError("Sync returned an invalid page")
            if cursor is None:
                first_check_token = page.get("check_token")
            page_objects = page.get("objects")
            page_max = page.get("max_commit_seq")
            if not isinstance(page_objects, list) or not isinstance(page_max, int):
                raise RuntimeError("Sync returned an invalid page")
            objects.extend(page_objects)
            if not page.get("has_more", False):
                result = dict(page)
                result["objects"] = objects
                result["check_token"] = first_check_token
                return result
            next_cursor = page.get("next_cursor")
            if (
                not isinstance(next_cursor, int)
                or next_cursor <= previous_cursor
                or next_cursor != page_max
            ):
                raise RuntimeError("Sync returned an invalid continuation cursor")
            previous_cursor = next_cursor
            cursor = next_cursor

    @oplock.held
    def pull(self, *, _raced: bool = False) -> dict:
        """Pull delta from server since last known commit_seq.

        After applying pulled objects, computes state_hash and stores
        an encrypted sync checkpoint for rollback detection (spec 8.3).

        If the server returns 410 Gone (delta baseline compacted), the caller
        must start a separately confirmed full resync.
        """
        self._require_current_kek()
        if not self._token:
            self.authenticate()

        last_seq = int(self._db.get_meta("last_known_commit_seq") or "0")
        anchor = self._commit_anchor()

        try:
            resp = self._fetch_pull_pages(last_seq, check=anchor)
        except RuntimeError as e:
            if server_error(e, 410):
                raise RuntimeError(
                    "Server compacted past the local checkpoint; explicit full resync "
                    "with dirty-data warning and confirmation is required"
                ) from e
            raise

        rollback_head = self._db.get_meta(SERVER_ROLLBACK_META)
        head = resp.get("head_commit_seq")
        verdict = sync_core.call(
            "gate",
            checkpoint={"seq": last_seq, "anchor_token": anchor[1]},
            reply={
                "gone": False,  # a 410 ended above
                "head_commit_seq": head if isinstance(head, int) else None,
                "check_token": resp.get("check_token"),
            },
            rollback_pending=bool(rollback_head),
        )["gate"]
        if verdict == "rollback_pending":
            self._put_back_lost_team_log(resp.get("team_log_head"))
            # The server went back and has since moved on: what it committed
            # again reuses sequence numbers this device has already passed,
            # so a delta pull would skip it.
            raise RuntimeError(
                f"The server went back (seen at commit_seq {rollback_head}; this "
                f"device's checkpoint is {last_seq}); a delta pull would skip what "
                f"it committed since. {FULL_RESYNC_HINT}"
            )
        stale_own = self._stale_own_wraps()
        if stale_own:
            raise RuntimeError(
                f"The server sent {len(stale_own)} key(s) of this account in a copy "
                "from before a password change, which the current password does not "
                f"open; a delta pull never brings the current copy. {FULL_RESYNC_HINT}"
            )

        # max_commit_seq never goes below our baseline, so only the server
        # head (or, once a push moved it past this checkpoint, the commit
        # token: stateful test SM7) reveals a server restored from a backup.
        if verdict in ("head_behind", "reissued"):
            message = (
                f"Sync rollback detected: server head commit_seq {head} "
                f"< local checkpoint {last_seq}. {FULL_RESYNC_HINT}"
                if verdict == "head_behind" else
                f"Sync rollback detected: the server no longer holds commit_seq "
                f"{anchor[0]} as this device saw it (restored from a backup). "
                f"{FULL_RESYNC_HINT}"
            )
            logger.error(message)
            self._db.set_meta(SERVER_ROLLBACK_META, str(head))
            self._put_back_lost_team_log(resp.get("team_log_head"))
            return {
                "pulled": 0,
                "skipped": 0,
                "max_commit_seq": last_seq,
                "rollback_warning": message,
            }

        self._check_key_epoch(resp)
        # The team log first: the objects below are judged by it (TL4).
        # A rolled back, forked or missing log raises TeamLogMismatch.
        self._sync_team_log(resp.get("team_log_head"))
        self.require_trusted_team_log()
        self.continue_identity_in_log()

        # Clear per-pull security trackers before applying objects
        self._equivocations = []
        gc_floor = resp.get("gc_floor_seq")
        self._gc_floor = gc_floor if isinstance(gc_floor, int) else 0
        self._tofu_checked_user_ids.clear()
        self._tofu_warnings = []
        self._signing_key_rings.clear()
        self._reset_vouchers()
        self._post_legacy_vouchers()

        pulled = 0
        skipped = 0
        objects = resp.get("objects", [])
        for obj in objects:
            if not self._verify_object_signature(obj):
                raise RuntimeError(f"Pull rejected object {obj.get('id', '?')}: {self._rejected(obj)}")

        max_seq = resp.get("max_commit_seq", last_seq)
        rollback_warning = None
        state_hash = None
        # Write lock first: another process's pull must not commit between
        # the check below and this batch (review d150605 N8).
        self._db.execute("BEGIN IMMEDIATE")
        if int(self._db.get_meta("last_known_commit_seq") or "0") != last_seq:
            # Another process (desktop app, CLI, MCP server) pulled since this
            # batch was fetched. Checked against its newer checkpoint, the
            # batch read as a server rollback.
            self._db.rollback()
            if _raced:
                raise RuntimeError("Another pull of this vault keeps running; try again.")
            return self.pull(_raced=True)
        try:
            # A delta page may carry a DEK before its folder or a subfolder
            # before its parent; FK checks run once the batch is complete.
            self._db.execute("PRAGMA defer_foreign_keys = ON")
            self._pulled_dek_ids = []
            self._pulled_archive_successors = set()
            self._new_unbound_dek_ids: set[str] = set()
            objects = self._with_held_back_writes(objects)
            unauthorized = self._unauthorized_writes(objects)
            served = 0  # applied from what the server sent now, not re-judged here
            for obj in self._order_pulled_objects(objects):
                if obj["id"] in unauthorized and obj.get("object_type") in ("node", "entry"):
                    skipped += 1
                    continue
                self._apply_pulled_object(obj)
                if obj.get("object_type") in ("node", "entry"):
                    self._record_server_seq(obj["id"], obj.get("commit_seq"), obj.get("modified_at"))
                pulled += 1
                served += obj["id"] not in self._revived_write_ids
            self._hold_verified()
            self._refuse_archives_without_their_key()
            self._bind_pulled_deks()
            self._resolve_entry_deks()
            self._adopt_server_root()
            self._detach_orphan_deks()
            self._reattach_orphans()
            self._revive_folders_of_unsent()
            withdraw_from_removed_members(self._db, self.team_state(), self._user_id)

            if any(obj.get("object_type") == "audit" for obj in objects):
                try:
                    self._validate_audit_dag()
                except ValueError as exc:
                    # The usual cause: the server lost records this device
                    # already had and reused their sequence numbers.
                    raise RuntimeError(f"{exc}. {FULL_RESYNC_HINT}") from exc

            if pulled > 0 or max_seq > last_seq:
                state_hash = self._compute_state_hash()
                # Applying only writes the log now allows (served before)
                # changes the state at this seq here, not on the server.
                self._check_rollback(max_seq, state_hash, served=bool(served))
                self._save_sync_checkpoint(max_seq, state_hash)
                logger.debug(
                    "Sync checkpoint saved: seq=%d hash=%s",
                    max_seq, state_hash[:16],
                )

            # Review a159e97: a first pull ending below the GC floor (the
            # newest commits were collected tombstones) as for a full resync.
            known = sync_core.call(
                "next_cursor", last_seq=last_seq, max_commit_seq=max_seq,
                gc_floor_seq=self._gc_floor,
            )
            if known > last_seq:
                self._db.set_meta("last_known_commit_seq", str(known))
            if not last_seq:
                self._db.set_meta(WRITES_AUDITED_META, "1")  # checked as it came
            self._db.execute("DELETE FROM vault_meta WHERE key = ?", (pending_states.JOINED_UNPULLED,))
            self._advance_commit_anchor(max_seq, resp.get("max_token"))
            self._db.commit()
        except SyncRollbackWarning as warning:
            self._db.rollback()
            rollback_warning = str(warning)
            pulled = 0
            logger.error(
                "Rollback detected — rejected pull batch and preserved trusted "
                "checkpoint: %s",
                warning,
            )
        except Exception:
            self._db.rollback()
            raise
        if pulled and rollback_warning is None:
            # A pulled subfolder of a team folder can name a key of its own the
            # log does not know; it is folded before items go onto it (R16-N21).
            self.fold_unlogged_folder_keys()
            self._reseal_under_successors()
            self._grant_again_on_successors()
        if rollback_warning is None:
            self._seal_to_rotated_members()

        result: dict = {
            "pulled": pulled,
            "skipped": skipped,
            "max_commit_seq": max_seq,
        }
        if state_hash is not None:
            result["state_hash"] = state_hash
        if rollback_warning is not None:
            result["rollback_warning"] = rollback_warning
        if self._equivocations:
            result["equivocations"] = list(self._equivocations)
        if self._tofu_warnings:
            result["tofu_warnings"] = list(self._tofu_warnings)
        if rollback_warning is None:
            self._audit_once(last_seq, result)
        conflicts = self.get_pull_conflicts()
        if conflicts:
            result["conflicts"] = conflicts
        return result

    def _audit_once(self, last_seq: int, result: dict) -> dict:
        """Capability run 174: once, for a vault an older client synced."""
        if last_seq and self._db.get_meta(WRITES_AUDITED_META) is None:
            try:
                result["removed_unauthorized"] = self._audit_applied_writes()
            except RuntimeError as exc:
                logger.warning("Checking folders applied before H4 failed (next pull retries): %s", exc)
        return result

    def _stale_own_wraps(self) -> list[str]:
        """Own DEKs still held only in a copy this device's KEK does not open."""
        if self._dek_mgr is None or self._db.get_meta(STALE_OWN_WRAPS_META) is None:
            return []
        marked = self._db.get_meta_json(STALE_OWN_WRAPS_META) or []
        stale = []
        for dek_id in marked:
            row = self._db.fetchone("SELECT encrypted_dek, version FROM deks WHERE id = ?", (dek_id,))
            if row is not None and not self._dek_mgr.can_unwrap(
                dek_id, bytes(row["encrypted_dek"]), row["version"]
            ):
                stale.append(dek_id)
        if stale != marked:
            self._db.set_meta_json(STALE_OWN_WRAPS_META, stale)
        return stale

    def get_pull_conflicts(self) -> list[dict]:
        """Return all unresolved pull conflicts, including persisted shadows."""
        rows = self._db.fetchall(
            "SELECT object_id, object_type, local_version, server_version, "
            "server_payload, server_parent_ref, server_is_deleted, "
            "server_payload_hash, server_commit_seq, detected_at "
            "FROM sync_conflicts ORDER BY detected_at, object_id"
        )
        return [
            {
                "id": row["object_id"],
                "object_type": row["object_type"],
                "local_version": row["local_version"],
                "server_version": row["server_version"],
                "server_payload": bytes(row["server_payload"]),
                "server_parent_ref": row["server_parent_ref"],
                "server_is_deleted": row["server_is_deleted"],
                "server_payload_hash": row["server_payload_hash"],
                "server_commit_seq": row["server_commit_seq"],
                "detected_at": row["detected_at"],
            }
            for row in rows
        ]

    def resolve_conflict(self, object_id: str, keep: str) -> None:
        """Settle a pull conflict by keeping the local or the server copy.

        ``"local"`` re-seals the local copy one version above the server's,
        so the next push supersedes the server copy instead of conflicting
        on every sync. ``"server"`` replaces the local copy with the verified
        server copy kept in the conflict shadow.
        """
        if keep not in ("local", "server"):
            raise ValueError("keep must be 'local' or 'server'")
        shadow = self._db.fetchone(
            "SELECT object_type, server_version, server_payload, server_parent_ref, "
            "server_is_deleted, server_payload_hash FROM sync_conflicts WHERE object_id = ?",
            (object_id,),
        )
        if shadow is None:
            raise KeyError(f"No sync conflict for {object_id}")
        object_type = shadow["object_type"]
        if object_type not in ("node", "entry"):
            raise RuntimeError(f"Cannot resolve a {object_type} conflict")
        pending_states.refuse_if_blocked(
            self._db, pending_states.RESOLVE_CONFLICT, object_id=object_id
        )
        if self._dek_mgr is None:
            raise RuntimeError("Unlock the vault to resolve conflicts")
        server_version = shadow["server_version"]
        payload = bytes(shadow["server_payload"])
        self._db.begin()
        try:
            # The server copy can sit below a folder this vault no longer has
            # (its tombstone collected, a full resync since): checked once the
            # orphan hangs below the root, as a pull does (nightly c78fd19).
            self._db.execute("PRAGMA defer_foreign_keys = ON")
            if keep == "server":
                table = "nodes" if object_type == "node" else "entries"
                outbox.drop_write(self._db, object_id)
                self._db.execute(f"UPDATE {table} SET version = 0 WHERE id = ?", (object_id,))
                apply = self._apply_node if object_type == "node" else self._apply_entry
                apply(
                    object_id, shadow["server_parent_ref"], payload, server_version,
                    shadow["server_is_deleted"],
                )
                self._resolve_entry_deks()
                self._detach_orphan_deks()
                self._reattach_orphans()
            else:
                self._rebase_local(
                    object_id, object_type, server_version, shadow["server_payload_hash"],
                    server_parent=shadow["server_parent_ref"] or "",
                )
            # Keeping the server's delete of a folder that holds unsent work
            # here left that work refused on every push (stateful test SM3).
            self._revive_folders_of_unsent()
            self._db.execute("DELETE FROM sync_conflicts WHERE object_id = ?", (object_id,))
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        self._push_cache.pop(object_id, None)

    def _rebase_local(
        self, object_id: str, object_type: str, server_version: int, server_hash: Optional[str],
        server_parent: Optional[str] = None,
    ) -> None:
        """Re-seal this device's copy one version above the server's and build
        on the server's (version, hash), so the next push supersedes it. The
        caller holds the transaction."""
        if self._dek_mgr is None:
            raise RuntimeError("Unlock the vault to resolve conflicts")
        # Stateful test SM22: above every version this device already sent,
        # too. After a server restore one of them can come back (another device
        # sends it again); kept at server_version + 1 below it, the change was
        # rebased on that own write and refused on every push.
        sent = self._db.fetchone(
            "SELECT MAX(version) AS v FROM object_sent_version WHERE object_id = ?", (object_id,)
        )
        new_version = max(server_version, (sent["v"] or 0) if sent else 0) + 1

        def reseal(
            blob: bytes, version: int, kind: BlobKind, deleted: bool, folder_id: Optional[str]
        ) -> bytes:
            # A delete only bumps the row version: a tombstone's blobs stay
            # sealed below it (one version, or more after other clients'
            # bumps). Opening it at the row version raised CryptoError with a
            # traceback (review 688edcb M1); it is resealed one version below
            # the new row version, where trash restore looks first.
            try:
                dek_id = parse_envelope(blob).dek_id
                if deleted and self._successor_targets([(dek_id, folder_id)]).get((dek_id, folder_id)) is None:
                    # R16-Z SM18 (TeamLogMachine): a tombstone moves only off a
                    # retired key. Under any other key it stays as sealed, as a
                    # delete leaves it: a folder's name is sealed with its
                    # parent's key, which a new admin need not hold, and the
                    # re-key of the collected folder failed on every push.
                    return blob
                dek = self._dek_mgr.unlock_dek(bytes_to_ulid(dek_id))
                plain = open_sealed(blob, dek, object_id, version, kind, deleted=deleted)[0]
            except (KeyError, ValueError, CryptoError) as exc:
                raise RuntimeError(f"{object_id} cannot be opened on this device") from exc
            dek_id, dek = self._successor_dek(dek_id, dek, folder_id)
            return encrypt(
                plaintext=plain, dek=dek, dek_id=dek_id, object_id=ulid_to_bytes(object_id),
                version=new_version - 1 if deleted else new_version, blob_kind=kind,
            )

        if object_type == "node":
            row = self._db.fetchone(
                "SELECT parent_id, encrypted_meta, version, is_deleted FROM nodes WHERE id = ?",
                (object_id,),
            )
            deleted = bool(row["is_deleted"])
            outbox.queue_write(self._db, object_id)
            self._db.execute(
                "UPDATE nodes SET encrypted_meta = ?, version = ? WHERE id = ?",
                (
                    reseal(
                        bytes(row["encrypted_meta"]), row["version"], BlobKind.NODE_META,
                        deleted, row["parent_id"] or object_id,
                    ),
                    new_version, object_id,
                ),
            )
        else:
            row = self._db.fetchone(
                "SELECT node_id, encrypted_meta, encrypted_data, version, is_deleted "
                "FROM entries WHERE id = ?",
                (object_id,),
            )
            deleted = bool(row["is_deleted"])
            outbox.queue_write(self._db, object_id)
            self._db.execute(
                "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, version = ? "
                "WHERE id = ?",
                (
                    reseal(
                        bytes(row["encrypted_meta"]), row["version"], BlobKind.ENTRY_META,
                        deleted, row["node_id"],
                    ),
                    reseal(
                        bytes(row["encrypted_data"]), row["version"], BlobKind.ENTRY_DATA,
                        deleted, row["node_id"],
                    ),
                    new_version, object_id,
                ),
            )
        self._set_base(object_id, server_version, server_hash, parent=server_parent)
        self._push_cache.pop(object_id, None)

    def _record_pull_conflict(
        self, obj: dict, payload: bytes, local_version: int
    ) -> None:
        """Preserve a verified server object while its local copy stays dirty."""
        conflict = {
            "id": obj["id"],
            "object_type": obj["object_type"],
            "local_version": local_version,
            "server_version": obj.get("version", 1),
            "server_payload_hash": obj.get("payload_hash"),
            "server_commit_seq": obj.get("commit_seq"),
        }
        self._db.execute(
            "INSERT OR REPLACE INTO sync_conflicts "
            "(object_id, object_type, local_version, server_version, server_payload, "
            "server_parent_ref, server_is_deleted, server_payload_hash, "
            "server_commit_seq, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                conflict["id"],
                conflict["object_type"],
                conflict["local_version"],
                conflict["server_version"],
                payload,
                obj.get("parent_ref"),
                obj.get("is_deleted", 0),
                conflict["server_payload_hash"],
                conflict["server_commit_seq"],
                int(time.time() * 1000),
            ),
        )

    def _refuse_archives_without_their_key(self) -> None:
        """Stateful run on S4a: a server that left the re-key's new folder key
        out of a pull (review 7c10379) and sent its archive, folder and items.
        The archive names a key this device does not hold, and the commit
        failed on its foreign key (sqlite3.IntegrityError, a crash); the items
        sealed under that key could not be read. The pull is refused instead
        (nothing applied); the next complete pull brings the key with them.
        Call inside the pull's transaction, after every object is applied."""
        missing = sync_core.call(
            "missing_successor",
            archives=[
                {"id": row["id"], "replaced_by": row["replaced_by"]}
                for row in self._db.fetchall("SELECT id, replaced_by FROM dek_archive")
            ],
            keys=[row["id"] for row in self._db.fetchall("SELECT id FROM deks")],
        )
        if missing:
            raise RuntimeError(
                f"The server sent key archive {missing['id']} without the key "
                f"{missing['replaced_by']} that replaces it (an incomplete pull); "
                "nothing was applied. Pull again."
            )

    @staticmethod
    def _order_pulled_objects(objects: list[dict]) -> list[dict]:
        """Apply DEKs first, then nodes parent-before-child, then the rest."""
        refs = [
            {
                "id": o["id"],
                "object_type": o.get("object_type") or "",
                "parent_ref": o.get("parent_ref"),
            }
            for o in objects
        ]
        return [objects[i] for i in sync_core.call("order_pulled", objects=refs)]

    def _bind_pulled_deks(self) -> None:
        """Bind pulled DEKs to their folders without clobbering existing ones.

        The first DEK seen for a folder becomes its own DEK. A later DEK for a
        folder that already owns one is either the re-key replacement (named by
        a dek_archive.replaced_by) — then every node sharing the old DEK moves —
        or a tier-2 DEK, which must never replace the folder DEK.
        """
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])
        team = self.team_state()
        for dek_id in self._pulled_dek_ids:
            dek_row = self._db.fetchone(
                "SELECT node_id, scope FROM deks WHERE id = ?", (dek_id,)
            )
            if dek_row is None:
                continue
            if not dek_row["node_id"]:
                if dek_id in self._new_unbound_dek_ids and dek_id not in foreign:
                    self._derive_unbound_scope(dek_id)
                continue
            node_id = dek_row["node_id"]
            node_row = self._db.fetchone(
                "SELECT dek_id, parent_id, encrypted_meta FROM nodes WHERE id = ?", (node_id,)
            )
            if node_row is None:
                continue
            if dek_row["scope"] == "folder" and (
                node_row["parent_id"] is not None or is_personal_root(self._db, self._dek_mgr, node_id)
            ):
                # A personal root is the one folder whose signed meta is
                # sealed under its own key (crud._node_meta_dek); the scope
                # label saying so is the server's word (run 151).
                try:
                    header = bytes_to_ulid(parse_envelope(bytes(node_row["encrypted_meta"])).dek_id)
                except ValueError:
                    header = None
                if header == dek_id:
                    self._db.execute("UPDATE deks SET scope = 'personal' WHERE id = ?", (dek_id,))
            current = node_row["dek_id"]
            if current == dek_id:
                continue
            if team is not None and teamlog.is_team_folder(team, node_id):
                self._bind_team_folder_dek(team, node_id, dek_id, current)
                continue
            owned = current and self._db.fetchone(
                "SELECT 1 FROM deks WHERE id = ? AND node_id = ? AND scope != 'tier2'",
                (current, node_id),
            )
            if not owned:
                self._db.execute(
                    "UPDATE nodes SET dek_id = ? WHERE id = ?", (dek_id, node_id)
                )
                continue
            if self._db.fetchone(
                "SELECT 1 FROM dek_archive WHERE replaced_by = ?", (dek_id,)
            ):
                if self._losing_sibling_rekey(node_id, dek_id, current):
                    self._db.execute("UPDATE deks SET node_id = NULL WHERE id = ?", (dek_id,))
                    continue
                self._db.execute(
                    "UPDATE nodes SET dek_id = ? WHERE dek_id = ?", (dek_id, current)
                )
                self._db.execute(
                    "UPDATE deks SET node_id = NULL WHERE id = ?", (current,)
                )
                continue
            if self._dek_mgr is not None and self._dek_mgr.successor_of(dek_id):
                # Stateful test SM62: another device's re-wrap of the key a
                # re-key here replaced (a password change it made before
                # pulling the re-key) is that retired key, not a tier-2 one:
                # taken for tier 2, it stayed bound to the folder.
                self._db.execute("UPDATE deks SET node_id = NULL WHERE id = ?", (dek_id,))
                continue
            if dek_row["scope"] == "folder":
                tier2 = dek_id
                if self._is_folders_own_key(node_id, dek_id, current):
                    tier2 = current
                    # Subfolders without a key of their own took the folder's
                    # key when they were applied; they follow it, as they do
                    # when an archive names the successor.
                    self._db.execute(
                        "UPDATE nodes SET dek_id = ? WHERE id = ? OR dek_id = ?",
                        (dek_id, node_id, current),
                    )
                self._db.execute(
                    "UPDATE deks SET scope = 'tier2' WHERE id = ?", (tier2,)
                )
        self._retire_keys_taken_for_tier2()

    def _retire_keys_taken_for_tier2(self) -> None:
        """A folder's old key, taken for a tier-2 key, is retired once its archive arrives.

        Stateful test seed 626262 (review 1141a20 R9-E): the server withheld
        a re-key's archive from a pull that brought the folder's new key, so
        the old one, still naming the folder, was labelled tier 2. The next
        pull brought the archive, but the label stayed: the old key was never
        seen as retired, and a member this device had just granted under it
        never got the folder's current key (_grant_again_on_successors looks
        only at retired folder keys). The archive is sealed under the new key
        and opens to the old one, so it proves the link; a key that seals a
        tier-2 entry's signed meta stays tier 2.
        """
        if self._dek_mgr is None or not self._pulled_archive_successors:
            return
        marks = ",".join("?" * len(self._pulled_archive_successors))
        team = self.team_state()
        for row in self._db.fetchall(
            "SELECT d.id, d.node_id FROM deks d JOIN nodes n ON n.id = d.node_id "
            f"WHERE d.scope = 'tier2' AND n.dek_id IN ({marks})",
            tuple(sorted(self._pulled_archive_successors)),
        ):
            if team is not None and teamlog.is_team_folder(team, row["node_id"]):
                continue  # the log names its keys (_bind_team_folder_dek)
            current = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (row["node_id"],))["dek_id"]
            if self._dek_mgr.successor_of(row["id"]) != current or self._seals_tier2_entry(row["id"]):
                continue
            self._db.execute(
                "UPDATE deks SET scope = 'folder', node_id = NULL WHERE id = ?", (row["id"],)
            )

    def _seals_tier2_entry(self, dek_id: str) -> bool:
        for row in self._db.fetchall(
            "SELECT id, encrypted_meta, version, is_deleted FROM entries "
            "WHERE substr(encrypted_meta, 4, 26) = ?",
            (ulid_to_bytes(dek_id),),
        ):
            try:
                meta, _ = open_sealed(
                    bytes(row["encrypted_meta"]), self._dek_mgr.unlock_dek(dek_id),
                    row["id"], row["version"], BlobKind.ENTRY_META, deleted=bool(row["is_deleted"]),
                )
            except (KeyError, CryptoError, ValueError):
                continue
            if json.loads(meta).get("tier") == 2:
                return True
        return False

    def _bind_team_folder_dek(self, team, node_id: str, dek_id: str, current: Optional[str]) -> None:
        """A pulled key naming a folder of the team log (docs/DESIGN_TEAM_LOG.md §4.3.2).

        The folder's key is the log's current generation, nothing else: not
        the first or the latest id seen, not what an archive or the children
        suggest. An older generation is retired; a key the log does not know
        is never the folder's key (at most a tier-2 key of one entry).
        """
        self.require_trusted_team_log()
        if teamlog.current_key(team, node_id) == dek_id:
            if not teamlog.may_hold_key(team, self._user_id, dek_id):
                return
            # Subfolders without a key of their own follow the folder.
            if current:
                self._db.execute("UPDATE nodes SET dek_id = ? WHERE dek_id = ?", (dek_id, current))
                self._db.execute(
                    "UPDATE deks SET node_id = NULL WHERE id = ? AND scope != 'tier2'", (current,)
                )
            self._db.execute("UPDATE nodes SET dek_id = ? WHERE id = ?", (dek_id, node_id))
            self._db.execute("UPDATE deks SET scope = 'folder' WHERE id = ?", (dek_id,))
        elif teamlog.key_generation(team, node_id, dek_id)[0] == "old":
            self._db.execute("UPDATE deks SET node_id = NULL WHERE id = ?", (dek_id,))
        else:
            logger.warning(
                "Pulled key %s names team folder %s but is not in the team log; "
                "never used as the folder's key", dek_id, node_id,
            )
            self._db.execute("UPDATE deks SET scope = 'tier2' WHERE id = ?", (dek_id,))

    def _losing_sibling_rekey(self, node_id: str, newcomer: str, current: str) -> bool:
        """Whether ``newcomer``, a re-key's successor, loses the folder to ``current``.

        Review a159e97 (state machine, seed 171717): two devices re-keyed the
        folder's key and both batches landed, so two archives retire it.
        Whichever successor arrived last took the folder: devices split
        between the two keys, and a device (or a new one) on the key the
        folder's items are not sealed under lost them. Only a successor of
        ``current`` itself replaces it outright. Between siblings the one that
        seals the folder's live children wins, else the later id (as in
        _is_folders_own_key), the same on every device whatever the order.
        """
        if self._dek_mgr is None or not self._db.fetchone(
            "SELECT 1 FROM dek_archive WHERE replaced_by = ?", (current,)
        ):
            return False
        if current in (pending_states.rekey_batch(self._db).get("object_ids") or []):
            return False  # this device's re-key has not landed: the landed one supersedes it
        if any(successor == newcomer for successor, _ in self._dek_mgr._successor_links(current)):
            return False
        new_seals, current_seals = (
            self._seals_live_children(node_id, newcomer),
            self._seals_live_children(node_id, current),
        )
        if new_seals != current_seals:
            return current_seals
        return current > newcomer

    def _seals_live_children(self, node_id: str, dek_id: str) -> bool:
        header = ulid_to_bytes(dek_id)
        return bool(self._db.fetchone(
            "SELECT 1 FROM nodes WHERE parent_id = ? AND is_deleted = 0 "
            "AND substr(encrypted_meta, 4, 26) = ?",
            (node_id, header),
        ) or self._db.fetchone(
            "SELECT 1 FROM entries WHERE node_id = ? AND is_deleted = 0 "
            "AND substr(encrypted_meta, 4, 26) = ?",
            (node_id, header),
        ))

    def _is_folders_own_key(self, node_id: str, newcomer: str, current: str) -> bool:
        """Whether ``newcomer``, not ``current``, is the folder's own key.

        Capability run 155: both a folder's key and its tier-2 keys name the
        folder, and whichever the server listed first became the folder key.
        The order is unsigned; what each key seals is signed. A subfolder's
        meta and its tier-0/1 entries' meta are sealed under its own key, a
        re-key successor is a folder key, a tier-2 entry (tier 2 in its signed
        meta) is under its own tier-2 key. Without any of these facts the
        later key id wins (run 157): a re-key successor is always later than
        the key it retires, and a tier-2 key no entry uses has fewer holders
        than the folder.
        """
        def role(dek_id: str) -> Optional[str]:
            """'tier2', 'folder' (seals live children or is a re-key's
            successor) or None. A re-key reseals only live children, so a
            retired key may still seal deleted ones: those say nothing about
            which key is current."""
            header = ulid_to_bytes(dek_id)
            if self._db.fetchone(
                "SELECT 1 FROM nodes WHERE parent_id = ? AND is_deleted = 0 "
                "AND substr(encrypted_meta, 4, 26) = ?",
                (node_id, header),
            ) or self._db.fetchone("SELECT 1 FROM dek_archive WHERE replaced_by = ?", (dek_id,)):
                return "folder"
            if self._dek_mgr is None:
                return None
            # A tier-2 entry moved to another folder keeps its own key; the
            # tier in a deleted entry's signed meta still names a tier-2 key.
            found = None
            for row in self._db.fetchall(
                "SELECT id, node_id, encrypted_meta, version, is_deleted FROM entries "
                "WHERE substr(encrypted_meta, 4, 26) = ?",
                (header,),
            ):
                try:
                    meta, _ = open_sealed(
                        bytes(row["encrypted_meta"]), self._dek_mgr.unlock_dek(dek_id),
                        row["id"], row["version"], BlobKind.ENTRY_META,
                        deleted=bool(row["is_deleted"]),
                    )
                    if json.loads(meta).get("tier") == 2:
                        return "tier2"
                    if row["node_id"] == node_id and not row["is_deleted"]:
                        found = "folder"
                except (KeyError, CryptoError, ValueError):
                    continue
            return found

        new_role, current_role = role(newcomer), role(current)
        if new_role != current_role:
            return new_role == "folder" or current_role == "tier2"
        # Capability run 157: a re-key's successor is made after the key it
        # retires, and only the withholdable archive ties the two; the earlier
        # id would hand the folder back to the key a removed member holds.
        return newcomer > current

    def _derive_unbound_scope(self, dek_id: str) -> None:
        """The role of a new key of ours that names no folder, from signed meta.

        Stateful test SM82: the unsigned label was taken for such a key, so
        the server could make another device's audit key a root key (or the
        root key an audit key, which then sealed audit details). The account
        root's meta is sealed under the root key, a personal root's under its
        personal key (a member's names no folder); a key that seals no
        folder's meta is an audit key. TL7: a tier-2 item's key in a personal
        root's tree names no folder either; it seals that item, no folder.
        """
        sealed = self._db.fetchall(
            "SELECT id, parent_id FROM nodes WHERE substr(encrypted_meta, 4, 26) = ?",
            (ulid_to_bytes(dek_id),),
        )
        if any(
            row["parent_id"] is None and not is_personal_root(self._db, self._dek_mgr, row["id"])
            for row in sealed
        ):
            scope = "root"
        elif sealed:
            scope = "personal"
        elif self._db.fetchone(
            "SELECT 1 FROM entries WHERE substr(encrypted_meta, 4, 26) = ?", (ulid_to_bytes(dek_id),)
        ):
            scope = "tier2"
        else:
            scope = "audit"
        self._db.execute("UPDATE deks SET scope = ? WHERE id = ?", (scope, dek_id))

    def _detach_orphan_deks(self) -> None:
        """Unbind DEKs whose folder no longer exists locally.

        After tombstone GC the server drops a deleted folder's node but keeps
        its DEK, whose parent_ref still names the folder; binding it would
        break the deks.node_id foreign key and abort the whole sync. The DEK
        remembers its folder: another device may bring the folder back, and
        the server does not send the DEK again then (stateful test SM59).
        """
        orphans = self._db.fetchall(
            "SELECT id, node_id FROM deks WHERE node_id IS NOT NULL "
            "AND scope != 'tier2' AND node_id NOT IN (SELECT id FROM nodes)"
        )
        if orphans:
            detached = dict(self._db.get_meta_json(DETACHED_DEKS_META) or {})
            detached.update({row["id"]: row["node_id"] for row in orphans})
            self._db.set_meta_json(DETACHED_DEKS_META, detached)
        self._db.execute(
            "UPDATE deks SET node_id = NULL WHERE node_id IS NOT NULL "
            "AND node_id NOT IN (SELECT id FROM nodes)"
        )

    def _key_change_dek_ids(self) -> set[str]:
        """The DEKs a password / identity change must carry atomically.

        Review d615826 (E8): a team member's folder under their own top-level
        root never reaches the server (its key has a parent_ref, which the
        server refuses from a non-admin). As part of the atomic change it sank
        the change on every sync, so the new epoch never arrived. A folder key
        the server has never held (neither the key nor its folder was ever in
        step) is not required: the server asks only for the keys it holds, and
        this one rides re-wrapped in the normal push after the change.
        """
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])
        pushed = self._db.get_meta_json("pushed_dek_versions") or {}
        # TL7: below a member's own top-level folder (now on the server) the
        # folder is in step while the server refused its key.
        refused = set(self._db.get_meta_json(REFUSED_DEKS_META) or [])
        return {
            row["id"]
            for row in self._db.fetchall(
                "SELECT d.id, d.node_id, EXISTS (SELECT 1 FROM nodes n WHERE n.id = d.node_id "
                f"AND ({outbox.not_queued('n')} OR n.base_version IS NOT NULL)) AS node_synced "
                "FROM deks d"
            )
            if row["id"] not in foreign
            and (row["node_id"] is None or row["id"] in pushed
                 or (row["node_synced"] and row["id"] not in refused))
        }

    def _reattach_orphans(self) -> None:
        """Hang what lost its folder below the root (review d150605 #1).

        A server before that fix let a live item stay below a deleted folder
        and then collected the folder's tombstone. The orphan broke the parent
        foreign key of every new device and full resync, and nobody could see
        it to delete it. It now shows below the root; an entry keeps the DEK
        its header names, so it still opens.

        Stateful test SM51: the move is local and keeps the version. A copy
        kept by a full resync after a restore went out at that version with
        the root as parent - another write than the one it copies, which the
        server refused from its writer on every push (the blob hash, all the
        writer compares, is the same). Once the folder is back, the item
        moves back to it while the version is still the one it had.
        """
        moved = self._db.get_meta_json(REATTACHED_META) or {}
        for obj_id, (kind, parent, version) in list(moved.items()):
            table, column = ("nodes", "parent_id") if kind == "node" else ("entries", "node_id")
            row = self._db.fetchone(
                f"SELECT version, is_deleted FROM {table} WHERE id = ?", (obj_id,)
            )
            folder = self._db.fetchone("SELECT is_deleted FROM nodes WHERE id = ?", (parent,))
            if row is None or row["version"] != version:
                del moved[obj_id]
            elif folder is not None and (row["is_deleted"] or not folder["is_deleted"]):
                self._db.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (parent, obj_id))
                self._push_cache.pop(obj_id, None)
                del moved[obj_id]
        orphan_nodes = self._db.fetchall(
            "SELECT id, parent_id, version FROM nodes WHERE parent_id IS NOT NULL "
            "AND parent_id NOT IN (SELECT id FROM nodes)"
        )
        orphan_entries = self._db.fetchall(
            "SELECT id, node_id, version, encrypted_meta FROM entries "
            "WHERE node_id NOT IN (SELECT id FROM nodes)"
        )
        for row in orphan_nodes:
            moved.setdefault(row["id"], ["node", row["parent_id"], row["version"]])
        for row in orphan_entries:
            moved.setdefault(row["id"], ["entry", row["node_id"], row["version"]])
        self._db.set_meta_json(REATTACHED_META, moved)
        if not orphan_nodes and not orphan_entries:
            return
        root = self._db.get_meta("root_node_id")
        if not root or not self._db.fetchone(
            "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (root,)
        ):
            row = self._db.fetchone(
                "SELECT id FROM nodes WHERE parent_id IS NULL AND is_deleted = 0 "
                "ORDER BY id LIMIT 1"
            )
            if row is None:
                raise RuntimeError(
                    "The server holds items whose folder is gone and this vault "
                    "has no root folder to show them in"
                )
            root = row["id"]
        for row in orphan_nodes:
            self._db.execute("UPDATE nodes SET parent_id = ? WHERE id = ?", (root, row["id"]))
        for row in orphan_entries:
            try:
                dek_id = bytes_to_ulid(parse_envelope(bytes(row["encrypted_meta"])).dek_id)
            except (ValueError, TypeError):
                dek_id = None
            if dek_id and not self._db.fetchone("SELECT 1 FROM deks WHERE id = ?", (dek_id,)):
                dek_id = None
            self._db.execute(
                "UPDATE entries SET node_id = ?, dek_id = COALESCE(?, dek_id) WHERE id = ?",
                (root, dek_id, row["id"]),
            )
        logger.warning(
            "Server held %d folder(s) and %d entr(ies) whose parent folder is gone; "
            "they are shown below the root folder",
            len(orphan_nodes), len(orphan_entries),
        )

    def _opens_node(self, node_id: str) -> bool:
        row = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))
        if row is None or self._dek_mgr is None:
            return False
        try:
            self._dek_mgr.unlock_dek(row["dek_id"])
        except (CryptoError, KeyError, ValueError):
            return False
        return True

    def _adopt_server_root(self) -> None:
        """Make the account's root this vault's root on a newly joined device.

        ``Vault.create`` gives every device its own root. When a device joins
        an existing account, that root is still pristine (never pushed, no
        children); keeping it would hide the whole account tree and push a
        second root to the server. A local root with content is left alone.
        """
        local_root = self._db.get_meta("root_node_id")
        if self._dek_mgr is None:
            return
        candidates = self._db.fetchall(
            "SELECT id, dek_id FROM nodes WHERE parent_id IS NULL AND is_deleted = 0 "
            f"AND {outbox.not_queued('nodes')} AND id != ? ORDER BY id",
            (local_root or "",),
        )
        if not candidates:
            return
        # With several admins the server holds several roots, and an admin
        # envelope opens the others' too. The account's own root is the one
        # under its KEK; a root reachable only by envelope (a member's
        # adopted org root) is the fallback.
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])
        candidates = sorted(candidates, key=lambda row: row["dek_id"] in foreign)
        server_root = None
        for row in candidates:
            if is_personal_root(self._db, self._dek_mgr, row["id"]):
                continue  # TL7: the account's personal root is never its root.
            try:
                self._dek_mgr.unlock_dek(row["dek_id"])
            except (CryptoError, KeyError, ValueError):
                continue  # Not our tree (e.g. a member without an envelope yet).
            server_root = row
            break
        if server_root is None:
            return
        if local_root:
            pristine = self._db.fetchone(
                f"SELECT dek_id FROM nodes WHERE id = ? AND {outbox.queued('nodes')} AND version = 1 "
                "AND NOT EXISTS (SELECT 1 FROM nodes WHERE parent_id = ?) "
                "AND NOT EXISTS (SELECT 1 FROM entries WHERE node_id = ?)",
                (local_root, local_root, local_root),
            )
            if pristine is None:
                logger.warning(
                    "Server root %s differs from local root %s, which has content; "
                    "keeping the local root", server_root["id"], local_root,
                )
                return
            self._db.execute("DELETE FROM nodes WHERE id = ?", (local_root,))
            pushed = self._db.get_meta_json("pushed_dek_versions") or {}
            if pristine["dek_id"] not in pushed and not self._db.fetchone(
                "SELECT 1 FROM nodes WHERE dek_id = ?", (pristine["dek_id"],)
            ):
                self._db.execute("DELETE FROM deks WHERE id = ?", (pristine["dek_id"],))
        self._db.execute(
            # A new key's role came from the meta pulled with it: the root
            # node may come only with a later page (SM82).
            "UPDATE deks SET scope = 'root' WHERE id = ? AND scope IN ('folder', 'audit', 'personal')",
            (server_root["dek_id"],),
        )
        self._db.set_meta("root_node_id", server_root["id"])

    def _resolve_entry_deks(self) -> None:
        """Select each synced entry's DEK from its authenticated envelope header."""
        rows = self._db.fetchall(
            "SELECT e.id, e.encrypted_meta, e.dek_id, n.dek_id AS node_dek_id "
            "FROM entries e JOIN nodes n ON n.id = e.node_id "
            f"WHERE {outbox.not_queued('e')} AND e.is_deleted = 0"
        )
        for row in rows:
            try:
                header_dek_id = bytes_to_ulid(
                    parse_envelope(bytes(row["encrypted_meta"])).dek_id
                )
            except ValueError:
                continue
            wanted = None if header_dek_id == row["node_dek_id"] else header_dek_id
            if wanted is not None and not self._db.fetchone(
                "SELECT 1 FROM deks WHERE id = ?", (wanted,)
            ):
                wanted = None
            if wanted != row["dek_id"]:
                self._db.execute(
                    "UPDATE entries SET dek_id = ? WHERE id = ?", (wanted, row["id"])
                )
