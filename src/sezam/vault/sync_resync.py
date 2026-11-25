"""Full resync: rebuild from the server, keep what a restored server lost.

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional

from . import oplock, outbox, pending_states, sync_core
from .audit import AuditLog
from .personal_root import is_personal_root

from .sync_common import (
    logger,
    NO_SERVER_COPY_HASH,
    RESEED_ARCHIVES_META,
    SERVER_ROLLBACK_META,
)


class ResyncMixin:
    """SyncClient methods: full resync: rebuild from the server, keep what a restored server lost."""

    def full_resync_blocker(self) -> Optional[str]:
        """Why a full resync would destroy local key material, or None.

        A full resync overwrites every local DEK wrap with the server's. While
        this device holds an unpushed password change or member re-key, the
        server's wraps are under the old KEK / old DEKs: every DEK would end up
        unreadable here and the pending push would have nothing left to send.
        """
        # Stateful test SM40: a password change whose journal keeps the old KEK
        # survives it - every server wrap is re-wrapped into the change as it
        # is applied (SM31). Refused, a change that had to pull a DEK made
        # elsewhere past the server's GC floor (410) could never go out.
        # SM54: the same with an identity rotation; the journal keeps the old
        # keypair, and re-sealed envelopes wait in the outbox's rekey row.
        found = pending_states.blocker(self._db, pending_states.FULL_RESYNC)
        return found.message if found else None

    def _local_objects_ahead_of(
        self, objects: list[dict], max_seq: int, gc_floor: int = 0, *, rolled_back: bool = False
    ) -> dict[str, dict[str, int]]:
        """What this device holds newer than a server that is behind it.

        A full resync normally follows tombstone GC: the server is ahead, and
        a local object it no longer has was deleted elsewhere. After
        ``sezam server reseed`` from a device that missed later changes the
        new server is BEHIND this one: its commit_seq is below this device's,
        or it has an older version of an object this device synced. Then a
        local object the server lacks or has older is kept (lockout review M6).

        Returns ``{"node": {id: version}, "entry": {...}, "dek": {...}}`` with
        the DEKs of kept folders the server lacks; all empty when the server
        is not behind. Folders of other users (foreign DEKs) follow the server,
        as reseed leaves them to their owner.
        """
        empty: dict[str, dict[str, int]] = {"node": {}, "entry": {}, "dek": {}}
        server_versions = {
            obj["id"]: int(obj.get("version") or 0)
            for obj in objects
            if obj["object_type"] in ("node", "entry")
        }
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])
        rows = {
            "node": self._db.fetchall(
                f"SELECT id, parent_id, version, {outbox.queued('nodes')} AS queued, is_deleted, "
                "dek_id FROM nodes"
            ),
            "entry": self._db.fetchall(
                "SELECT e.id, e.node_id, e.dek_id AS own_dek_id, e.version, "
                f"{outbox.queued('e')} AS queued, "
                "e.is_deleted, n.dek_id FROM entries e JOIN nodes n ON e.node_id = n.id"
            ),
        }
        local = {
            kind: {
                row["id"]: row["version"]
                for row in kind_rows
                if row["dek_id"] not in foreign and row["version"] > 0
            }
            for kind, kind_rows in rows.items()
        }
        # Only versions the old server confirmed tell that the new one is
        # behind; an unsent edit is ahead of any server.
        local_seq = int(self._db.get_meta("last_known_commit_seq") or "0")
        behind = max_seq < local_seq or any(
            row["version"] > server_versions[row["id"]]
            for kind_rows in rows.values()
            for row in kind_rows
            if not row["queued"] and row["id"] in server_versions
        )
        # Review d150605 #5: a server restored from a backup that other
        # devices have since pushed past is not behind by commit_seq, yet it
        # lost what this device had confirmed. Tombstone GC removes only rows
        # up to gc_floor, and a delete of an object confirmed above the floor
        # leaves a tombstone above it too: such an object missing from the
        # server was lost, not deleted.
        confirmed_seq = {
            row["object_id"]: row["commit_seq"]
            for row in self._db.fetchall("SELECT object_id, commit_seq FROM object_server_seq")
        }
        lost = {
            kind: {
                obj_id: version
                for obj_id, version in versions.items()
                if obj_id not in server_versions
                and confirmed_seq.get(obj_id, 0) > gc_floor
            }
            for kind, versions in local.items()
        }
        if behind:
            keep = {
                kind: {
                    obj_id: version
                    for obj_id, version in versions.items()
                    if version > server_versions.get(obj_id, 0)
                }
                for kind, versions in local.items()
            }
        else:
            keep = lost
        # Stateful test SM13: a write of this device the server confirmed and
        # then lost (restored from a backup) while another device wrote the
        # same version on top of the backup. The server takes one write per
        # version, so the same version with other content proves it; the
        # server's copy was made without knowing this one.
        sent = {
            row["object_id"]: (row["version"], row["payload_hash"])
            for row in self._db.fetchall(
                "SELECT object_id, version, payload_hash FROM object_sent_version"
            )
        }
        server_hashes = {obj["id"]: obj.get("payload_hash") for obj in objects}
        for kind, kind_rows in rows.items():
            for row in kind_rows:
                mine = sent.get(row["id"])
                if (
                    mine is not None
                    and not row["queued"]
                    and row["dek_id"] not in foreign
                    and mine[0] == row["version"] == server_versions.get(row["id"])
                    and server_hashes.get(row["id"]) != mine[1]
                ):
                    keep[kind][row["id"]] = row["version"]
        # Stateful test SM45: the same after a restore, but the other device
        # wrote a higher version on top of the backup (a rename and a delete
        # there). Its copy was made on the base of this device's write, so it
        # replaced the write unseen; kept, the write comes back as a conflict.
        if rolled_back:
            copies = {obj["id"]: obj for obj in objects}
            for kind, kind_rows in rows.items():
                for row in kind_rows:
                    mine = sent.get(row["id"])
                    server_copy = copies.get(row["id"])
                    if (
                        mine is not None
                        and server_copy is not None
                        and not row["queued"]
                        and row["dek_id"] not in foreign
                        and mine[0] == row["version"] != server_versions[row["id"]]
                        and self._written_without_my_write(row["id"], row["version"], server_copy)
                    ):
                        keep[kind][row["id"]] = row["version"]
        # Review d150605 #6: what this device never sent (created or changed
        # offline) is kept and sent with the next push, whatever the server
        # holds; a newer server copy then comes back as a conflict. Only a
        # delete of something the server had and no longer has is moot; an
        # item created and deleted offline is in the trash and goes out as a
        # tombstone like any other delete (stateful test SM5).
        # Stateful test SM53: a delete over an unsent edit (more than one
        # version above the server copy it was made on) holds that edit; it
        # went with the moot delete and was gone everywhere. It is kept and
        # comes back as a conflict with a restore made elsewhere.
        base_versions = {
            object_id: base[0] for object_id, base in self._all_bases().items()
        }
        known_to_server = set(confirmed_seq) | set(base_versions)
        nodes_by_id = {row["id"]: row for row in rows["node"]}
        for kind, kind_rows in rows.items():
            for row in kind_rows:
                if (
                    row["queued"]
                    and row["version"] > 0
                    and row["dek_id"] not in foreign
                    and (
                        row["id"] in server_versions
                        or not row["is_deleted"]
                        or row["id"] not in known_to_server
                        or row["version"] > base_versions.get(row["id"], 0) + 1
                    )
                ):
                    keep[kind][row["id"]] = row["version"]
        # A kept item needs its folders: those the server lost (or GC'd after
        # a delete elsewhere) come back with it.
        for kind, parent_key in (("entry", "node_id"), ("node", "parent_id")):
            for row in rows[kind]:
                if row["id"] not in keep[kind]:
                    continue
                parent = nodes_by_id.get(row[parent_key])
                while parent is not None and parent["id"] not in server_versions:
                    keep["node"].setdefault(parent["id"], max(parent["version"], 1))
                    parent = nodes_by_id.get(parent["parent_id"])
        if not keep["node"] and not keep["entry"]:
            return empty
        server_dek_ids = {obj["id"] for obj in objects if obj["object_type"] == "dek"}
        keep["dek"] = {
            row["id"]: row["version"]
            for node_id in keep["node"]
            for row in self._db.fetchall(
                "SELECT id, version FROM deks WHERE node_id = ?", (node_id,)
            )
            if row["id"] not in server_dek_ids
        }
        # The key of a kept item itself (a root DEK names no node).
        own_deks = [(row["id"], "node", row["dek_id"]) for row in rows["node"]]
        # Stateful test SM50: an entry without its own key is sealed with its
        # folder's. A member re-key gives the folder a new DEK and re-seals
        # the entries without changing the folder, so after a restore the
        # entries are ahead and kept while the folder follows the server; its
        # new DEK must stay with them.
        own_deks += [
            (row["id"], "entry", row["own_dek_id"] or row["dek_id"]) for row in rows["entry"]
        ]
        for obj_id, kind, own in own_deks:
            if obj_id in keep[kind] and own and own not in server_dek_ids:
                dek = self._db.fetchone("SELECT version FROM deks WHERE id = ?", (own,))
                if dek is not None:
                    keep["dek"][own] = max(dek["version"], 1)
        logger.warning(
            "Keeping %d local object(s) the server does not have yet",
            len(keep["node"]) + len(keep["entry"]),
        )
        return keep

    def _rebind_nodes_of_pruned_deks(self) -> None:
        """Bind a folder whose DEK the full resync dropped to one it kept.

        Review 7c10379 R7-G (state machine: the server restored from a backup
        taken before a member re-key): a folder another account owns keeps
        its local DEK binding when its server copy is applied, so on a
        member's desktop it stayed on the re-key's DEK the server lost. That
        DEK was pruned, the deferred foreign key failed the commit, and every
        'sezam pull --full-resync' there raised IntegrityError. The folder
        takes its own kept DEK (a re-key's replacement, else the newest), else
        its parent's.
        """
        for _ in range(64):  # one level of folders per round
            rows = self._db.fetchall(
                "SELECT id, parent_id FROM nodes WHERE dek_id NOT IN (SELECT id FROM deks)"
            )
            moved = False
            for row in rows:
                own = self._db.fetchone(
                    "SELECT id FROM deks WHERE node_id = ? AND scope != 'tier2' ORDER BY "
                    "id IN (SELECT replaced_by FROM dek_archive) DESC, id DESC LIMIT 1",
                    (row["id"],),
                )
                parent = None if own or not row["parent_id"] else self._db.fetchone(
                    "SELECT dek_id AS id FROM nodes WHERE id = ? AND dek_id IN (SELECT id FROM deks)",
                    (row["parent_id"],),
                )
                if own or parent:
                    self._db.execute(
                        "UPDATE nodes SET dek_id = ? WHERE id = ?", ((own or parent)["id"], row["id"])
                    )
                    moved = True
            if not moved:
                return

    def _own_dek_wraps(self) -> dict[str, tuple[bytes, int]]:
        """The DEK wraps this device's KEK opens, before a full resync resets them.

        Review 7c10379 H1: with every DEK at version 0 any server copy replaced
        the local wrap, and a server that kept the wraps from before a password
        change (old KEK, old version, validly signed back then) locked the
        vault for good. A pending key change re-wraps the server's copies
        itself and stops the resync when it cannot (SM40).
        """
        if self._dek_mgr is None or self.has_pending_key_change():
            return {}
        return {
            row["id"]: (bytes(row["encrypted_dek"]), row["version"])
            for row in self._db.fetchall("SELECT id, encrypted_dek, version FROM deks")
            if row["version"] > 0
            and self._dek_mgr.can_unwrap(row["id"], bytes(row["encrypted_dek"]), row["version"])
        }

    def _own_deks_still_in_use(
        self, own_wraps: dict[str, tuple[bytes, int]], kept_dek_ids: list[str]
    ) -> list[str]:
        """Own DEKs the snapshot left out while what it kept is sealed with them."""
        missing = [dek_id for dek_id in own_wraps if dek_id not in set(kept_dek_ids)]
        in_use = []
        for dek_id in missing:
            if self._db.fetchone(
                "SELECT 1 FROM nodes WHERE dek_id = ? UNION ALL "
                "SELECT 1 FROM entries WHERE dek_id = ? LIMIT 1",
                (dek_id, dek_id),
            ):
                in_use.append(dek_id)
        if in_use:
            logger.warning(
                "Full resync: the server left out %d key(s) still in use; kept", len(in_use)
            )
        return in_use

    def _restore_own_dek_wraps(
        self, own_wraps: dict[str, tuple[bytes, int]], objects: list[dict]
    ) -> None:
        """Never lower a DEK version, never swap a wrap the KEK opens for one it does not."""
        server_versions = {
            obj["id"]: int(obj.get("version") or 0)
            for obj in objects
            if obj["object_type"] == "dek" and not obj.get("is_deleted")
        }
        pushed = self._db.get_meta_json("pushed_dek_versions") or {}
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])
        for dek_id, (wrap, version) in own_wraps.items():
            row = self._db.fetchone(
                "SELECT encrypted_dek, version FROM deks WHERE id = ?", (dek_id,)
            )
            if row is None:
                continue
            if row["version"] >= version and self._dek_mgr.can_unwrap(
                dek_id, bytes(row["encrypted_dek"]), row["version"]
            ):
                continue
            self._db.execute(
                "UPDATE deks SET encrypted_dek = ?, version = ? WHERE id = ?",
                (wrap, version, dek_id),
            )
            foreign.discard(dek_id)
            if server_versions.get(dek_id, 0) < version:
                pushed.pop(dek_id, None)  # the server gets this copy back
            else:
                logger.warning(
                    "Full resync: the server's wrap of DEK %s at version %d does not "
                    "open with this account's key; the local wrap stays",
                    dek_id, server_versions[dek_id],
                )
        self._db.set_meta_json("pushed_dek_versions", pushed)
        self._db.set_meta_json("foreign_dek_ids", sorted(foreign))

    @oplock.held
    def full_resync(
        self,
        *,
        confirmed: bool = False,
        dirty_export_path: Optional[str | Path] = None,
    ) -> dict:
        """Replace the local sync snapshot after explicit user confirmation.

        The caller is responsible for showing the warning. Unsent folders and
        entries are kept and go out with the next push; an encrypted copy of
        the vault can be saved before any local state is changed.
        """
        self._require_current_kek()
        blocker = self.full_resync_blocker()
        if blocker:
            raise RuntimeError(blocker)
        dirty_objects = self._collect_dirty_objects()
        if not confirmed:
            raise RuntimeError(
                "Full resync requires explicit confirmation; it replaces the local "
                f"snapshot ({len(dirty_objects)} unsynchronized object(s) are kept)"
            )

        from .snapshots import take_snapshot

        take_snapshot(self._db, "full-resync")

        if dirty_export_path is not None:
            # Review d150605 #6: bare ciphertext objects without their keys
            # could not be read or loaded back. An encrypted copy of the vault
            # opens with the current password and 'sezam restore' loads it.
            self._db.backup(dirty_export_path)

        logger.warning("Starting explicitly confirmed full resync")
        self._tofu_checked_user_ids.clear()
        self._tofu_warnings = []
        self._signing_key_rings.clear()
        self._reset_vouchers()
        if not self._token:
            self.authenticate()

        anchor = self._commit_anchor()
        resp = self._fetch_pull_pages(0, full_resync=True, check=anchor)

        objects = resp.get("objects")
        max_seq = resp.get("max_commit_seq")
        if (
            not isinstance(objects, list)
            or not isinstance(max_seq, int)
            or max_seq < 0
            or (objects and max_seq == 0)
        ):
            raise RuntimeError("Full resync returned an invalid snapshot")
        self._check_key_epoch(resp)
        # The team log is signed and only grows: a full resync never takes a
        # shorter or other one over (TeamLogMismatch).
        self._sync_team_log(resp.get("team_log_head"))
        self.require_trusted_team_log()
        self._post_legacy_vouchers()

        allowed_types = {"node", "entry", "dek", "envelope", "dek_archive", "audit"}
        for obj in objects:
            if obj.get("object_type") not in allowed_types:
                raise RuntimeError(
                    f"Full resync contains unknown object type for {obj.get('id', '?')}"
                )
            if not self._verify_object_signature(obj):
                raise RuntimeError(
                    f"Full resync rejected object {obj.get('id', '?')}: {self._rejected(obj, 'invalid signature')}"
                )

        ids_by_type = {
            object_type: [obj["id"] for obj in objects if obj["object_type"] == object_type]
            for object_type in allowed_types
        }
        server_copies = {
            obj["id"]: obj for obj in objects if obj["object_type"] in ("node", "entry")
        }
        # What the unsent changes were made on, before the reset below.
        # Public CI run 44260509986: after tombstone GC another device's write
        # can sit at the very version a change here was made on; the hash
        # tells the two apart.
        prior_bases = self._all_bases()
        prior_base = {object_id: base[0] for object_id, base in prior_bases.items()}
        prior_base_hash = {object_id: base[1] for object_id, base in prior_bases.items()}
        unsent = outbox.queued_ids(self._db, "nodes") | outbox.queued_ids(self._db, "entries")
        revived_before = outbox.revived_folders(self._db)
        confirmed_at = {
            row["object_id"]: (row["commit_seq"], row["modified_at"])
            for row in self._db.fetchall(
                "SELECT s.object_id, s.commit_seq, t.modified_at FROM object_server_seq s "
                "LEFT JOIN object_server_time t ON t.object_id = s.object_id"
            )
        }
        gc_floor = resp.get("gc_floor_seq")
        # Stateful test SM38: a full resync run before any pull or push saw the
        # restore (only a key takeover since) is told by the snapshot itself.
        head = resp.get("head_commit_seq")
        rolled_back = sync_core.call(
            "gate",
            checkpoint={"seq": anchor[0], "anchor_token": anchor[1]},
            reply={
                "gone": False,  # a full pull starts at 0
                "head_commit_seq": head if isinstance(head, int) else None,
                "check_token": resp.get("check_token"),
            },
            rollback_pending=self._db.get_meta(SERVER_ROLLBACK_META) is not None,
        )["gate"] != "apply"
        keep_local = self._local_objects_ahead_of(
            objects, max_seq, gc_floor if isinstance(gc_floor, int) else 0,
            rolled_back=rolled_back,
        )
        kept_envelope_ids = [
            row["id"]
            for dek_id in keep_local["dek"]
            for row in self._db.fetchall(
                "SELECT id FROM access_envelopes WHERE dek_id = ?", (dek_id,)
            )
        ]
        # Stateful test SM24: a grant of this account the server does not hold
        # - never sent, or lost when the server was restored from a backup -
        # was dropped, and the member lost the folder for good. It stays and
        # goes out again while its DEK does (the server refuses one for a
        # revoked member).
        server_envelope_ids = set(ids_by_type["envelope"])
        surviving_deks = set(ids_by_type["dek"]) | set(keep_local["dek"])
        # SM57: the envelopes an unsent identity rotation re-sealed go; the
        # rotation re-seals the server's below (another device's included).
        rotation = pending_states.rekey_batch(self._db)
        if not rotation.get("identity_rotation"):
            rotation = {}
        resealed = set(rotation.get("object_ids") or []) - {
            item["id"] for item in rotation.get("envelope_tombstones") or []
        }
        resent_envelope_ids = [
            row["id"]
            for row in self._db.fetchall(
                "SELECT ae.id, ae.dek_id, "
                f"{outbox.pending(outbox.ENVELOPE, 'ae.id')} AS unsent "
                "FROM access_envelopes ae WHERE ae.created_by = ?",
                (self._user_id,),
            )
            if row["id"] not in server_envelope_ids
            and row["id"] not in resealed
            and row["dek_id"] in surviving_deks
            and (row["unsent"] or rolled_back)
        ]
        kept_envelope_ids += resent_envelope_ids
        # Audit records are append-only: one the server does not hold (lost
        # when it was restored from a backup, or never sent) stays. Dropped,
        # the records the server kept or got since that name it as a parent
        # failed the DAG check on every full resync (stateful test SM6).
        server_audit_ids = set(ids_by_type["audit"])
        kept_audit = [
            row
            for row in self._db.fetchall(
                "SELECT a.id, a.parent_ids, a.actor_id, o.state FROM audit_log a "
                "LEFT JOIN outbox o ON o.kind = 'audit' AND o.object_id = a.id"
            )
            if row["id"] not in server_audit_ids
        ]
        own_wraps = self._own_dek_wraps()
        audit_versions = {
            row["id"]: row["version"] or 1
            for row in self._db.fetchall("SELECT id, version FROM deks WHERE scope = 'audit'")
        }

        self._db.begin()
        try:
            # The local schema has intentional node↔DEK references. Defer their
            # FK checks until the complete verified snapshot has been applied.
            self._db.execute("PRAGMA defer_foreign_keys = ON")
            outbox.drop_all_writes(self._db)
            self._db.execute("UPDATE nodes SET version = 0")
            self._db.execute("UPDATE entries SET version = 0")
            self._db.execute("UPDATE deks SET version = 0")
            self._db.set_meta_json("foreign_dek_ids", [])
            self._db.execute("UPDATE dek_archive SET version = 0")
            self._db.execute("DELETE FROM audit_dag_edges")

            self._pulled_dek_ids = []
            self._pulled_archive_successors = set()
            self._new_unbound_dek_ids: set[str] = set()
            unauthorized = self._unauthorized_writes(objects, full=True)
            # Capability run 174: a copy applied before this check (an older
            # client) goes as well, not only the server's.
            for obj_id in unauthorized:
                keep_local["node"].pop(obj_id, None)
                keep_local["entry"].pop(obj_id, None)
            for obj in self._order_pulled_objects(objects):
                if obj["id"] in keep_local.get(obj["object_type"], {}):
                    continue  # The server's copy is older than this device's.
                if obj["id"] in unauthorized and obj["object_type"] in ("node", "entry"):
                    continue  # Review 7c10379 H4: its author could not write it there.
                self._apply_pulled_object(obj)
                if obj["object_type"] in ("node", "entry"):
                    self._record_server_seq(obj["id"], obj.get("commit_seq"), obj.get("modified_at"))
            self._bind_pulled_deks()
            self._resolve_entry_deks()

            self._db.execute("DELETE FROM sync_conflicts")

            def prune(table: str, object_ids: list[str]) -> None:
                if object_ids:
                    placeholders = ",".join("?" for _ in object_ids)
                    self._db.execute(
                        f"DELETE FROM {table} WHERE id NOT IN ({placeholders})",
                        tuple(object_ids),
                    )
                else:
                    self._db.execute(f"DELETE FROM {table}")

            prune("access_envelopes", ids_by_type["envelope"] + kept_envelope_ids)
            for envelope_id in resent_envelope_ids:
                outbox.requeue(self._db, outbox.ENVELOPE, envelope_id)
            # SM50: a kept re-key DEK comes back with its archive (old key
            # under the new one); without it the other devices took the new
            # DEK for a tier-2 key and left the folder on the old one.
            kept_archive_ids = [
                row["id"]
                for dek_id in keep_local["dek"]
                for row in self._db.fetchall(
                    "SELECT id FROM dek_archive WHERE replaced_by = ?", (dek_id,)
                )
                if row["id"] not in ids_by_type["dek_archive"]
            ]
            prune("dek_archive", ids_by_type["dek_archive"] + kept_archive_ids)
            if kept_archive_ids:
                self._db.execute(
                    "UPDATE dek_archive SET version = 1 WHERE id IN "
                    f"({','.join('?' for _ in kept_archive_ids)})",
                    tuple(kept_archive_ids),
                )
                self._db.set_meta_json(RESEED_ARCHIVES_META, sorted(
                    set(self._db.get_meta_json(RESEED_ARCHIVES_META) or []) | set(kept_archive_ids)
                ))
            prune("entries", [i for i in ids_by_type["entry"] if i not in unauthorized] + list(keep_local["entry"]))
            prune("audit_log", ids_by_type["audit"] + [row["id"] for row in kept_audit])
            for row in kept_audit:
                for parent_id in json.loads(row["parent_ids"] or "[]"):
                    self._db.execute(
                        "INSERT OR IGNORE INTO audit_dag_edges (child_id, parent_id) "
                        "VALUES (?, ?)",
                        (row["id"], parent_id),
                    )
                if row["state"] is None:
                    # Sent once and lost by the server: it goes out again.
                    # Review 7c10379 (new device after a server restore):
                    # another admin's record too, whose author may no longer
                    # be an admin on the restored server. This device's
                    # records name it as a parent; it goes out again from here
                    # (its author's signature is checked on every pull).
                    outbox.queue(self._db, outbox.AUDIT, row["id"])
            if kept_audit and self._keypair is not None:
                # Stateful test SM14: one may be signed with an identity key
                # the restored server lost; the server knows only this one.
                AuditLog(self._db).reattribute_unpushed(
                    self._user_id, self._user_id, self._keypair.to_nacl_signing_key()
                )
            prune("nodes", [i for i in ids_by_type["node"] if i not in unauthorized] + list(keep_local["node"]))
            self._db.execute(
                "DELETE FROM object_server_seq WHERE object_id NOT IN "
                "(SELECT id FROM nodes UNION SELECT id FROM entries)"
            )
            self._db.execute(
                "DELETE FROM object_server_time WHERE object_id NOT IN "
                "(SELECT id FROM nodes UNION SELECT id FROM entries)"
            )
            self._db.execute("DELETE FROM vault_meta WHERE key = ?", (SERVER_ROLLBACK_META,))
            self._detach_orphan_deks()
            kept_dek_ids = list(ids_by_type["dek"]) + list(keep_local["dek"])
            local_audit_ids = [
                row["id"] for row in self._db.fetchall("SELECT id FROM deks WHERE scope = 'audit'")
            ]
            kept_dek_ids += self._own_deks_still_in_use(own_wraps, kept_dek_ids)
            if not set(local_audit_ids) & set(kept_dek_ids):
                # The server holds no labelled audit DEK (legacy rows carry no
                # scope): keep this device's own, pushed with the next sync,
                # so the checkpoint can still be sealed.
                kept_dek_ids += local_audit_ids
                # Goal #369: the wrap is bound to its version; version 1 for
                # one re-wrapped since (a key change) opened with no KEK.
                pushed = self._db.get_meta_json("pushed_dek_versions") or {}
                for dek_id in local_audit_ids:
                    self._db.execute(
                        "UPDATE deks SET version = ? WHERE id = ? AND version = 0",
                        (audit_versions.get(dek_id, 1), dek_id),
                    )
                    pushed.pop(dek_id, None)  # the server lost it: it goes out again
                self._db.set_meta_json("pushed_dek_versions", pushed)
            prune("deks", kept_dek_ids)
            self._rebind_nodes_of_pruned_deks()
            # Review d615826: history is local only and every row of it went;
            # only what lost its entry or its key goes now.
            self._db.execute(
                "DELETE FROM entry_history WHERE entry_id NOT IN (SELECT id FROM entries) "
                "OR dek_id NOT IN (SELECT id FROM deks)"
            )
            # What this device has newer goes back to the server with the
            # next push instead of being lost (lockout review M6).
            for table, kind in (("nodes", "node"), ("entries", "entry")):
                for obj_id, version in keep_local[kind].items():
                    outbox.queue_write(self._db, obj_id)
                    self._db.execute(
                        f"UPDATE {table} SET version = ? WHERE id = ?", (version, obj_id)
                    )
                    server_copy = server_copies.get(obj_id)
                    # Nightly run on e443cbc (goal #429 b): a kept folder the
                    # server holds deleted brings it back. Queued without the
                    # mark, a re-key batch with an item below it left it for
                    # the normal push and was refused ('parent folder is
                    # deleted') on every sync.
                    if kind == "node" and (
                        obj_id in revived_before or (server_copy or {}).get("is_deleted")
                    ):
                        outbox.mark_revived(self._db, obj_id)
                    if server_copy is None:
                        # Stateful test SM42: built on no server copy. Without
                        # a base, its push overwrote a copy another device sent
                        # meanwhile (after GC collected the tombstone) unseen.
                        self._set_base(obj_id, 0, NO_SERVER_COPY_HASH)
                    elif not self._lost_same_version(obj_id, server_copy) and (
                        (
                            obj_id not in unsent
                            and server_copy.get("version", 1) < version
                            and not self._written_without_my_write(obj_id, version, server_copy)
                            and not self._committed_after(server_copy, confirmed_at.get(obj_id, (None, None)))
                        )
                        or (
                            (
                                (
                                    prior_base.get(obj_id) == server_copy.get("version", 1)
                                    and prior_base_hash.get(obj_id, server_copy.get("payload_hash"))
                                    == server_copy.get("payload_hash")
                                )
                                or self._own_sent_version(
                                    obj_id, server_copy.get("version", 1),
                                    server_copy.get("payload_hash"),
                                )
                            )
                            and (
                                version > server_copy.get("version", 1)
                                or self._is_server_copy(table, obj_id, server_copy)
                            )
                        )
                    ):
                        # Newer than a server that is behind, or an unsent
                        # change of the very copy the server holds.
                        self._set_base(
                            obj_id, server_copy.get("version", 1), server_copy["payload_hash"]
                        )
                    else:
                        # Changed here and on the server: a conflict to settle.
                        # Sent as it was, the server refused it on every push
                        # and no pull ever brought its copy (stateful test SM4).
                        self._record_pull_conflict(
                            server_copy,
                            base64.b64decode(server_copy["payload"]) if server_copy.get("payload") else b"",
                            version,
                        )
            pushed_dek_versions = self._db.get_meta_json("pushed_dek_versions") or {}
            for dek_id, version in keep_local["dek"].items():
                self._db.execute(
                    "UPDATE deks SET version = ? WHERE id = ?", (version, dek_id)
                )
                # SM50: sent before the restore, the server lost it.
                pushed_dek_versions.pop(dek_id, None)
            self._db.set_meta_json("pushed_dek_versions", pushed_dek_versions)
            self._restore_own_dek_wraps(own_wraps, objects)
            self._validate_audit_dag()
            if self.has_pending_key_change() and self._dek_mgr is not None:
                # SM40: allowed with a change that re-wraps the server's DEKs,
                # but only if they are under the KEK it replaces (not after
                # a restore to an even older one): else nothing opens them.
                for obj in objects:
                    if obj["object_type"] != "dek" or obj.get("is_deleted"):
                        continue
                    # Whose DEK it is: the signer verified above, not the
                    # unsigned owner_id (INV-3).
                    if self._signer_id(obj) != self._user_id:
                        continue
                    row = self._db.fetchone(
                        "SELECT encrypted_dek, version FROM deks WHERE id = ?", (obj["id"],)
                    )
                    if row is not None and not self._dek_mgr.can_unwrap(
                        obj["id"], bytes(row["encrypted_dek"]), row["version"]
                    ):
                        raise RuntimeError(pending_states.KEY_CHANGE_BLOCKS_RESYNC)

            root_nodes = [
                obj["id"]
                for obj in objects
                if obj["object_type"] == "node"
                and not obj.get("parent_ref")
                and not obj.get("is_deleted", 0)
                and not is_personal_root(self._db, self._dek_mgr, obj["id"])  # TL7
            ]
            # Stateful test SM81: a team member's desktop sees no top-level node
            # on the server (its own root never goes up, idea #24). Clearing the
            # mark turned its root into a plain folder (or made the admins'
            # root it cannot open its root). As in _adopt_server_root, the
            # local root stays when it holds something, the server has no
            # root this device opens, or it is one of the server's.
            local_root = self._db.get_meta("root_node_id")
            if local_root and self._db.fetchone(
                "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0 AND parent_id IS NULL", (local_root,)
            ) and (
                local_root in root_nodes or not any(map(self._opens_node, root_nodes)) or self._db.fetchone(
                    "SELECT 1 FROM nodes WHERE parent_id = ? UNION ALL SELECT 1 FROM entries WHERE node_id = ?",
                    (local_root, local_root),
                )
            ):
                root_nodes.insert(0, local_root)
            self._db.set_meta("root_node_id", root_nodes[0] if root_nodes else "")
            self._reattach_orphans()
            self._revive_folders_of_unsent()
            if rotation:
                from .crud import reseal_envelopes_for_rotation

                pending_states.clear_rekey_batch(self._db)
                reseal_envelopes_for_rotation(self._db, self._dek_mgr, self._user_id, self._keypair)

            state_hash = self._compute_state_hash()
            self._save_sync_checkpoint(max_seq, state_hash)
            # Review a159e97 (state machine): a snapshot whose newest commits
            # were collected tombstones ends below the GC floor; from there
            # every delta pull was refused with 410 for good. Nothing exists
            # between the snapshot's newest object and the floor.
            self._db.set_meta(
                "last_known_commit_seq",
                str(sync_core.call(
                    "next_cursor", last_seq=0, max_commit_seq=max_seq,
                    gc_floor_seq=gc_floor if isinstance(gc_floor, int) else 0,
                )),
            )
            self._db.execute("DELETE FROM vault_meta WHERE key = ?", (pending_states.JOINED_UNPULLED,))
            self._advance_commit_anchor(max_seq, resp.get("max_token"), reset=True)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

        self._push_cache.clear()
        # R16-Z SM25b: as after a pull. Kept unsent items sealed with a key the
        # snapshot's re-key replaced (a subfolder's name, restored from the
        # trash here) go onto the folder's current key; until then their
        # folder named the new key and they no longer opened.
        self._reseal_under_successors()
        self._grant_again_on_successors()
        return {
            "pulled": len(objects),
            "skipped": 0,
            "max_commit_seq": max_seq,
            "full_resync": True,
            "dirty_exported": len(dirty_objects) if dirty_export_path is not None else 0,
            "kept_local": len(keep_local["node"]) + len(keep_local["entry"]),
            "state_hash": state_hash,
            "tofu_warnings": list(self._tofu_warnings),
        }
