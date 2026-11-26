"""Apply single pulled objects to the local vault.

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import time
from typing import Optional

from .. import teamlog
from ..crypto.aead import parse_envelope
from ..models import bytes_to_ulid
from . import outbox, pending_states, sync_core
from .schema import row_payload_hash
from .key_rotation import (
    open_old_kek,
)

from .sync_common import (
    DETACHED_DEKS_META,
    STALE_OWN_WRAPS_META,
    logger,
)


class ApplyMixin:
    """SyncClient methods: apply single pulled objects to the local vault."""

    def _apply_pulled_object(self, obj: dict) -> None:
        """Apply a single pulled sync object to the local vault."""
        object_type = obj["object_type"]
        obj_id = obj["id"]
        version = obj.get("version", 1)
        is_deleted = obj.get("is_deleted", 0)
        payload = base64.b64decode(obj["payload"]) if obj.get("payload") else b""
        parent_ref = obj.get("parent_ref")
        payload_hash = obj.get("payload_hash")

        local_row = None
        if object_type in {"node", "entry"}:
            table = "nodes" if object_type == "node" else "entries"
            parent = "parent_id" if table == "nodes" else "node_id"
            data = "NULL" if table == "nodes" else "encrypted_data"
            local_row = self._db.fetchone(
                f"SELECT version, {outbox.queued(table)} AS queued, {parent} AS parent, "
                f"is_deleted, encrypted_meta, {data} AS encrypted_data FROM {table} WHERE id = ?",
                (obj_id,),
            )
            if local_row and local_row["queued"]:
                found = self._base(obj_id)
                # The shared core decides (docs/SYNC_SINGLE_SOURCE.md 4b,
                # sezam-sync-core pull::decide). The cases it was built from:
                # SM56 (tombstone GC reused a version number: same number,
                # other hash is a conflict), SM86 (the row is the server copy:
                # left queued, a re-key sent it at a version the server holds)
                # and the deep run on ed9a3f1 (this device's own earlier push
                # whose reply was lost becomes the base).
                decision = sync_core.call(
                    "decide_pulled",
                    unsent={
                        "version": local_row["version"],
                        "hash": row_payload_hash(
                            local_row["encrypted_meta"], local_row["encrypted_data"]),
                        "parent_ref": local_row["parent"] or None,
                        "is_deleted": bool(local_row["is_deleted"]),
                        "base": None if found is None
                        else {"version": found[0], "hash": found[1] or ""},
                    },
                    pulled={
                        "version": version,
                        "hash": payload_hash or "",
                        "parent_ref": parent_ref or None,
                        "is_deleted": bool(is_deleted),
                        "own_earlier_push": self._own_sent_version(
                            obj_id, version, payload_hash),
                    },
                )
                if decision in ("sent", "adopt_as_base"):
                    self._set_base(obj_id, version, payload_hash, parent=parent_ref or "")
                if decision == "sent":
                    outbox.drop_write(self._db, obj_id)
                if decision == "conflict":
                    self._record_pull_conflict(obj, payload, local_row["version"])
                return

        if object_type == "node":
            self._apply_node(obj_id, parent_ref, payload, version, is_deleted, payload_hash)
        elif object_type == "entry":
            self._apply_entry(obj_id, parent_ref, payload, version, is_deleted, payload_hash)
        elif object_type == "dek":
            self._apply_dek(obj_id, parent_ref, payload, version, obj, payload_hash)
        elif object_type == "envelope":
            self._apply_envelope(obj_id, parent_ref, payload, is_deleted, obj)
        elif object_type == "dek_archive":
            self._apply_dek_archive(obj_id, payload, version, obj)
        elif object_type == "audit":
            self._apply_audit(obj_id, payload, obj)
        else:
            raise ValueError(f"Unknown pulled object type {object_type!r} for id {obj_id}")

    def _keeps_held_copy(
        self, kind: str, obj_id: str, existing, local_hash: str, version: int,
        payload_hash: Optional[str],
    ) -> bool:
        """Whether the copy held here stays: the pulled one is an older
        version, or another copy of the version held (equivocation, logged and
        reported). The shared core decides (sezam-sync-core pull::against_held,
        review c78fd19), as on the web and phone; a copy over a tombstone the
        server collected comes in (SM8, SM21)."""
        seq = self._db.fetchone(
            "SELECT commit_seq FROM object_server_seq WHERE object_id = ?", (obj_id,)
        )
        decision = sync_core.call(
            "against_held",
            gc_floor_seq=self._gc_floor,
            items=[{
                "held": {
                    "version": existing["version"], "hash": local_hash,
                    "is_deleted": bool(existing["is_deleted"]), "queued": bool(existing["queued"]),
                    "commit_seq": seq["commit_seq"] if seq else None,
                },
                "pulled": {"version": version, "hash": payload_hash or ""},
            }],
        )[0]
        if decision == "equivocation":
            logger.warning(
                "EQUIVOCATION DETECTED on %s %s at version %d: local hash %s != server hash %s",
                kind, obj_id, version, local_hash[:16], payload_hash[:16],
            )
            self._equivocations.append({
                "id": obj_id, "type": kind, "version": version,
                "local_hash": local_hash[:16], "server_hash": payload_hash[:16],
            })
        return decision != "apply"

    def _apply_node(
        self, obj_id: str, parent_ref: Optional[str],
        payload: bytes, version: int, is_deleted: int,
        payload_hash: Optional[str] = None,
    ) -> None:
        """UPSERT node — only if server version > local version."""
        existing = self._db.fetchone(
            f"SELECT version, encrypted_meta, is_deleted, {outbox.queued('nodes')} AS queued "
            "FROM nodes WHERE id = ?",
            (obj_id,),
        )
        if existing and self._keeps_held_copy(
            "node", obj_id, existing, hashlib.sha256(bytes(existing["encrypted_meta"])).hexdigest(),
            version, payload_hash,
        ):
            return  # Local version is same or newer

        try:
            header_dek_id = bytes_to_ulid(parse_envelope(payload).dek_id)
        except ValueError:
            header_dek_id = None
        # A personal root's meta is sealed with its own personal DEK. The web
        # (and any member: the server allows a member's DEK no parent) binds
        # that DEK to no node; inheriting the parent's DEK instead left the
        # branch unreadable here and would seal what the desktop adds below
        # it with the root DEK. Subfolders' meta names it too.
        personal_dek_id = header_dek_id if parent_ref and header_dek_id and self._db.fetchone(
            "SELECT 1 FROM deks WHERE id = ? AND scope = 'personal'", (header_dek_id,)
        ) else None

        # Get dek_id from parent or existing record
        dek_id = personal_dek_id
        if not dek_id and existing:
            row = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (obj_id,))
            if row:
                dek_id = row["dek_id"]
        if not dek_id:
            # DEKs are applied before nodes, so a folder's own DEK may already exist.
            row = self._db.fetchone(
                "SELECT id FROM deks WHERE node_id = ? AND scope != 'tier2' "
                "ORDER BY rowid LIMIT 1",
                (obj_id,),
            )
            if row:
                dek_id = row["id"]
        detached_dek_id = None
        if not dek_id:
            detached = self._db.get_meta_json(DETACHED_DEKS_META) or {}
            for candidate, folder in detached.items():
                if folder == obj_id and self._db.fetchone(
                    "SELECT 1 FROM deks WHERE id = ? AND node_id IS NULL", (candidate,)
                ):
                    dek_id = detached_dek_id = candidate
                    break
        if not dek_id and parent_ref:
            row = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (parent_ref,))
            if row:
                dek_id = row["dek_id"]
        if not dek_id and not parent_ref:
            # A root's meta is sealed with the root's own DEK; another device's
            # root must not be bound to this device's local root DEK.
            if header_dek_id and self._db.fetchone(
                "SELECT 1 FROM deks WHERE id = ?", (header_dek_id,)
            ):
                dek_id = header_dek_id
        if not dek_id:
            # Use root DEK as fallback
            row = self._db.fetchone("SELECT id FROM deks WHERE scope = 'root' LIMIT 1")
            dek_id = row["id"] if row else obj_id

        outbox.drop_write(self._db, obj_id)
        if existing:
            self._db.execute(
                "UPDATE nodes SET parent_id = ?, encrypted_meta = ?, dek_id = ?, version = ?, "
                "is_deleted = ? WHERE id = ?",
                (parent_ref, payload, dek_id, version, is_deleted, obj_id),
            )
        else:
            self._db.execute(
                "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (obj_id, parent_ref, payload, dek_id, version, is_deleted),
            )
        if detached_dek_id:
            self._db.execute(
                "UPDATE deks SET node_id = ? WHERE id = ?", (obj_id, detached_dek_id)
            )
            detached = dict(self._db.get_meta_json(DETACHED_DEKS_META) or {})
            detached.pop(detached_dek_id, None)
            self._db.set_meta_json(DETACHED_DEKS_META, detached)

    def _apply_entry(
        self, obj_id: str, node_id: Optional[str],
        payload: bytes, version: int, is_deleted: int,
        payload_hash: Optional[str] = None,
    ) -> None:
        """UPSERT entry — parse length-prefixed payload to get meta + data."""
        existing = self._db.fetchone(
            "SELECT version, encrypted_meta, encrypted_data, is_deleted, "
            f"{outbox.queued('entries')} AS queued FROM entries WHERE id = ?",
            (obj_id,),
        )
        if existing and self._keeps_held_copy(
            "entry", obj_id, existing,
            row_payload_hash(existing["encrypted_meta"], existing["encrypted_data"]), version, payload_hash,
        ):
            return

        # Parse length-prefixed binary format: u32be(meta_len) + meta + data
        if is_deleted and existing and (
            len(payload) < 4 or 4 + struct.unpack(">I", payload[:4])[0] > len(payload)
        ):
            outbox.drop_write(self._db, obj_id)
            self._db.execute(
                "UPDATE entries SET node_id = ?, version = ?, is_deleted = 1 "
                "WHERE id = ?",
                (node_id, version, obj_id),
            )
            return
        if len(payload) < 4:
            raise ValueError(
                f"Entry {obj_id} payload too short ({len(payload)} bytes)"
            )
        meta_len = struct.unpack(">I", payload[:4])[0]
        if 4 + meta_len > len(payload):
            raise ValueError(
                f"Entry {obj_id} meta_len {meta_len} exceeds payload size {len(payload)}"
            )
        encrypted_meta = payload[4:4 + meta_len]
        encrypted_data = payload[4 + meta_len:]

        outbox.drop_write(self._db, obj_id)
        if existing:
            # A tombstone carries what was deleted (stateful test SM2): keeping
            # this device's older copy let a restore here undo the last edit.
            self._db.execute(
                "UPDATE entries SET node_id = ?, encrypted_meta = ?, encrypted_data = ?, "
                "version = ?, is_deleted = ? WHERE id = ?",
                (node_id, encrypted_meta, encrypted_data, version, 1 if is_deleted else 0, obj_id),
            )
        else:
            self._db.execute(
                "INSERT INTO entries (id, node_id, encrypted_meta, encrypted_data, "
                "version, is_deleted) VALUES (?, ?, ?, ?, ?, ?)",
                (obj_id, node_id, encrypted_meta, encrypted_data, version, is_deleted),
            )

    def _apply_dek(
        self, obj_id: str, node_id: Optional[str],
        payload: bytes, version: int, obj: dict,
        payload_hash: Optional[str] = None,
    ) -> None:
        """UPSERT DEK and remember whether its KEK wrap belongs to this user."""
        existing = self._db.fetchone(
            "SELECT version, encrypted_dek FROM deks WHERE id = ?", (obj_id,)
        )
        # A rotation that lost the race (another device pushed its own from
        # the same epoch first) left this DEK unpushed at the version the
        # winner's wrap holds on the server. Once the device adopted the
        # winner's KEK that wrap opens: it is the same DEK, take it and the
        # DEK is settled instead of conflicting on every push.
        superseded_local_wrap = (
            existing is not None
            and existing["version"] == version
            and self._dek_mgr is not None
            and (self._db.get_meta_json("pushed_dek_versions") or {}).get(obj_id) != version
            and self._dek_mgr.can_unwrap(obj_id, payload, version)
        )
        change_rewrap = None
        if (
            existing is not None
            and existing["version"] == version
            and not superseded_local_wrap
            and self._dek_mgr is not None
            and (self._db.get_meta_json("pushed_dek_versions") or {}).get(obj_id) != version
            and not self._dek_mgr.can_unwrap(obj_id, payload, version)
        ):
            # Stateful test SM44: this device's waiting change re-wrapped the
            # DEK at the version another device's rotation took meanwhile
            # (an org recovery pulls nothing first). The change was refused on
            # every push; the server's copy joins it at the next version.
            change_rewrap = self._rewrap_under_pending_change(obj_id, payload, version)
        if (
            existing and not superseded_local_wrap and change_rewrap is None
            and self._keeps_held_copy(
                "dek", obj_id, {"version": existing["version"], "is_deleted": 0, "queued": 0},
                hashlib.sha256(bytes(existing["encrypted_dek"])).hexdigest(), version, payload_hash,
            )
        ):
            # The local wrap stays, so its ownership must not be judged by a
            # stale server wrap (e.g. one under our pre-password-change KEK).
            return

        server_version = version
        if self._dek_mgr is not None and not self._dek_mgr.can_unwrap(obj_id, payload, version):
            # Stateful test SM31: made elsewhere while this device's password
            # change waits, so wrapped under the KEK the server still has.
            # Unreadable here, and the change (it must carry every active DEK)
            # was refused on every push. It joins the change at the next version.
            rewrapped = self._rewrap_under_pending_change(obj_id, payload, version)
            if rewrapped is not None:
                payload, version = rewrapped, version + 1
        foreign_dek_ids = set(self._db.get_meta_json("foreign_dek_ids") or [])
        # owner_id is unsigned server metadata; a server could use it to hide
        # our own DEKs. Ours is exactly what our KEK can unwrap.
        if self._dek_mgr is not None:
            foreign = not self._dek_mgr.can_unwrap(obj_id, payload, version)
        else:
            signer = obj.get("signature_user_id") or obj.get("owner_id")
            foreign = bool(signer) and signer != self._user_id
        if foreign:
            foreign_dek_ids.add(obj_id)
        else:
            foreign_dek_ids.discard(obj_id)
        self._db.set_meta_json("foreign_dek_ids", sorted(foreign_dek_ids))
        # Stateful test (review 7c10379 R7-G): signed by this account (the
        # signature was checked) at the key epoch this device holds, yet its
        # KEK does not open it - the copy from before a password change that a
        # server kept and sent into a full resync. The current copy sits at a
        # commit_seq the checkpoint has passed, so no delta pull brings it and
        # the folder stayed unreadable here for good.
        stale_own = set(self._db.get_meta_json(STALE_OWN_WRAPS_META) or [])
        if foreign and self._dek_mgr is not None and self._signer_id(obj) == self._user_id:
            stale_own.add(obj_id)
        else:
            stale_own.discard(obj_id)
        if stale_own:
            self._db.set_meta_json(STALE_OWN_WRAPS_META, sorted(stale_own))
        else:
            self._db.execute("DELETE FROM vault_meta WHERE key = ?", (STALE_OWN_WRAPS_META,))

        # The scope label is unsigned. A DEK's role never changes after it is
        # made, and this device derives the changes it knows of from its own
        # facts (tier 2 from a second key under a folder, see
        # _bind_pulled_deks; root from the adopted root node), so a key it
        # holds keeps its label. A new key whose signed parent_ref names a
        # folder is a folder key here: labelled tier2 it no longer counted as
        # the folder's own, and the next tier-2 key pulled for the folder
        # replaced it (run 151); labelled root or audit it would be picked to
        # seal top-level folders or audit details, which every member of that
        # folder can open (run 149). root / audit / personal need a key that
        # names no folder and that this user's KEK opens.
        scope = obj.get("scope")
        if node_id is not None or foreign or scope not in ("root", "audit", "personal"):
            scope = None
        if existing:
            self._db.execute(
                "UPDATE deks SET node_id = ?, encrypted_dek = ?, version = ? WHERE id = ?",
                (node_id, payload, version, obj_id),
            )
        else:
            self._db.execute(
                "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
                "VALUES (?, ?, ?, ?, ?)",
                (obj_id, node_id, scope or "folder", payload, version),
            )
            if node_id is None:
                self._new_unbound_dek_ids.add(obj_id)

        pushed_dek_versions = self._db.get_meta_json("pushed_dek_versions") or {}
        pushed_dek_versions[obj_id] = server_version
        self._db.set_meta_json("pushed_dek_versions", pushed_dek_versions)
        # Node binding is resolved after the whole batch is applied, see
        # _bind_pulled_deks: a second DEK under a folder is tier-2 unless an
        # archive marks it as the folder's re-key replacement.
        self._pulled_dek_ids.append(obj_id)

    def _rewrap_under_pending_change(
        self, dek_id: str, payload: bytes, version: int
    ) -> Optional[bytes]:
        """``payload`` re-wrapped under this device's pending KEK, when the
        KEK the pending change replaces opens it."""
        journal = pending_states.key_change_journal(self._db)
        if "old_kek" not in journal:
            return None
        old_kek = open_old_kek(journal, self._dek_mgr._kek, self._user_id)
        try:
            return self._dek_mgr.rewrap_from(dek_id, payload, version, old_kek)
        finally:
            old_kek[:] = b"\x00" * len(old_kek)

    def _apply_envelope(
        self, obj_id: str, dek_id: Optional[str],
        payload: bytes, is_deleted: int, obj: dict,
    ) -> None:
        """Apply an access envelope or its signed tombstone.

        Review d615826 H2: an envelope is version 1 and its tombstone version
        2. The live version was stored again whenever the server sent it, so
        a replayed grant of a removed member came back (and the grant again
        sealed the folder's new key to them). The author is the account whose
        key the signature was verified with, not the unsigned owner_id."""
        lost = dict(outbox.items(self._db, outbox.WITHDRAWAL, outbox.HELD))
        if is_deleted:
            # Stateful test SM24a: another device of this account withdrew a
            # grant with no folder to re-key (tombstone GC took it there); this
            # one brings the folder back on that key. Forgotten with the
            # envelope, the member's re-key found nothing and they could read
            # the folder again.
            held = self._db.fetchone(
                "SELECT dek_id, user_id FROM access_envelopes WHERE id = ? AND created_by = ? AND user_id != ?",
                (obj_id, self._user_id, self._user_id),
            )
            if held is not None and self._db.fetchone(
                "SELECT 1 FROM nodes WHERE dek_id = ? AND is_deleted = 0", (held["dek_id"],)
            ):
                pending_states.note_withdrawn_holder(self._db, held["dek_id"], held["user_id"])
            self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (obj_id,))
            self._db.execute(
                "INSERT OR IGNORE INTO withdrawn_envelopes (envelope_id) VALUES (?)", (obj_id,)
            )
            outbox.sent(self._db, outbox.WITHDRAWAL, obj_id)
            return
        if not dek_id or not self._db.fetchone("SELECT 1 FROM deks WHERE id = ?", (dek_id,)):
            # R16-Z deep run: a server that left the key out of this pull (its
            # checkpoint stops before it) sent the envelope on it; stored, it
            # failed the whole batch on the foreign key. The next pull brings both.
            logger.warning("Envelope %s on key %s this vault does not hold; not stored", obj_id, dek_id)
            return
        user_id = obj.get("target_user_id", "")
        created_by = self._signer_id(obj)
        self.require_trusted_team_log()
        team = self.team_state()
        if team is not None and dek_id in team.dek_index:
            target = team.members.get(user_id)
            if target is None or not teamlog.envelope_valid(
                team, created_by, user_id, dek_id, obj.get("access_level"), target.encryption_pk,
            ):
                logger.warning("Envelope %s refused by the team log", obj_id)
                if (
                    created_by == self._user_id and target is not None and not target.active
                    and obj_id not in lost
                    and not self._db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (obj_id,))
                ):
                    # R16-N8 (manual CI 45709981956 on 8a0548a): this account's
                    # envelope to a member the log removed, which no device here
                    # holds any more (restores, full resyncs). Refused and
                    # forgotten, the dropped re-key was not requeued and the
                    # member kept it live on the server. Held like a withdrawn
                    # one sent again: queue_revoked_holders revives it for the
                    # re-key, which withdraws it.
                    level = obj.get("access_level")
                    outbox.put(self._db, outbox.WITHDRAWAL, {
                        "dek_id": dek_id, "user_id": user_id,
                        "access_level": level if level in ("read", "write") else "read",
                        "encrypted_dek": payload.hex(),
                    }, obj_id, outbox.HELD)
                return
        elif team is not None and created_by != self._user_id:
            # Review 1141a20 H6: with a log, another account's key reaches
            # this one only through the log (§9), not by who signed the tree.
            logger.warning("Envelope %s on a key the team log does not know; ignored", obj_id)
            return
        # Save only a signature verified with the log's current key at receipt,
        # never a key picked from the server's archive after it was retired.
        if team is not None and dek_id in team.dek_index:
            from nacl.exceptions import CryptoError
            from .team_log_local import received_envelope_sender

            receipt = {"seq": team.head_seq, "hash": team.head_hash,
                       "signature": obj.get("signature") or obj.get("client_signature"),
                       "version": obj.get("version", 1)}
            env = {"id": obj_id, "dek_id": dek_id, "user_id": user_id, "created_by": created_by,
                   "access_level": obj.get("access_level"), "encrypted_dek": payload}
            try:
                received_envelope_sender(self._db, env, receipt)
            except CryptoError:
                pass  # An older receipt remains bound to its exact signed ciphertext.
            else:
                self._db.set_meta_json("team_envelope_receipt:" + obj_id, receipt)
        # Review a159e97 H3: the level is not signed. A missing or unknown one
        # is 'read', and an envelope made on this device keeps the level it
        # was made with: before, a server's 'write' replaced it on every pull.
        access_level = obj.get("access_level")
        if access_level not in ("read", "write"):
            access_level = "read"
        made_here = self._db.fetchone(
            "SELECT access_level FROM access_envelopes WHERE id = ? AND id NOT IN "
            "(SELECT envelope_id FROM pulled_envelopes)",
            (obj_id,),
        )
        if made_here is not None:
            access_level = made_here["access_level"]
        if self._db.fetchone(
            "SELECT 1 FROM withdrawn_envelopes WHERE envelope_id = ?", (obj_id,)
        ):
            logger.warning("Withdrawn access envelope %s sent again; ignored", obj_id)
            if created_by == self._user_id and user_id and obj_id not in lost:
                # Stateful test (review 7c10379 R7-G): a server restored from
                # a backup taken before this account's re-key holds a revoked
                # member's envelope live again. Ignored, its tombstone was
                # never sent again and the member kept a live envelope.
                # queue_revoked_holders revives it for the re-key once the
                # member is revoked (stored as live here, a replayed grant
                # came back - review d615826 H2).
                outbox.put(self._db, outbox.WITHDRAWAL, {
                    "dek_id": dek_id, "user_id": user_id,
                    "access_level": access_level, "encrypted_dek": payload.hex(),
                }, obj_id, outbox.HELD)
            return

        # Stateful test (second admin): this device's pending re-key deleted
        # its own envelope here until the batch is sent; the server copy is
        # still that grant, not one pulled from elsewhere (a pulled one was
        # recorded when it first came).
        withdrawn_here = {
            item["id"]: item
            for item in pending_states.rekey_batch(self._db).get("envelope_tombstones") or []
        }
        own_withdrawal = obj_id in withdrawn_here
        if own_withdrawal and not self._db.fetchone(
            "SELECT 1 FROM pulled_envelopes WHERE envelope_id = ?", (obj_id,)
        ):
            access_level = withdrawn_here[obj_id].get("access_level") or "read"
        if not own_withdrawal and not self._db.fetchone(
            "SELECT 1 FROM access_envelopes WHERE id = ?", (obj_id,)
        ):
            self._db.execute(
                "INSERT OR IGNORE INTO pulled_envelopes (envelope_id) VALUES (?)", (obj_id,)
            )

        self._db.execute(
            "INSERT OR REPLACE INTO access_envelopes "
            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (obj_id, dek_id, user_id, created_by, access_level, payload),
        )
        outbox.sent(self._db, outbox.ENVELOPE, obj_id)
        # Review a159e97 (state machine): another device of this account
        # re-sealed a member's grant (an identity rotation) before this one's
        # re-key removed them from the key; the re-key withdrew only the copy it
        # held, and the re-sealed one came in live after it. A key this account
        # re-keyed to remove the member queues their re-key, which withdraws it.
        if (
            created_by == self._user_id and user_id and user_id != self._user_id and dek_id
            and self._dek_mgr is not None
            and user_id not in pending_states.revocation_queue(self._db)
            and pending_states.rekey_batch(self._db).get("revoked_user_id") != user_id
            and not self._db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ?", (dek_id,))
            and self._dek_mgr.removed_from(dek_id, user_id)
        ):
            logger.warning("Envelope %s of removed member %s sent live; queued for withdrawal",
                           obj_id, user_id)
            pending_states.set_revocation_queue(
                self._db, pending_states.revocation_queue(self._db) + [user_id]
            )

    def _apply_dek_archive(
        self, obj_id: str, payload: bytes, version: int, obj: dict,
    ) -> None:
        """UPSERT DEK archive entry."""
        existing = self._db.fetchone(
            "SELECT version FROM dek_archive WHERE id = ?", (obj_id,)
        )
        if existing and existing["version"] >= version:
            return

        replaced_by = obj.get("parent_ref", "")
        archived_at = obj.get("timestamp") or int(time.time() * 1000)
        self._pulled_archive_successors.add(replaced_by)

        if existing:
            self._db.execute(
                "UPDATE dek_archive SET replaced_by = ?, encrypted_dek = ?, "
                "archived_at = ?, version = ? WHERE id = ?",
                (replaced_by, payload, archived_at, version, obj_id),
            )
        else:
            self._db.execute(
                "INSERT INTO dek_archive (id, replaced_by, encrypted_dek, archived_at, version) "
                "VALUES (?, ?, ?, ?, ?)",
                (obj_id, replaced_by, payload, archived_at, version),
            )

    def _apply_audit(self, obj_id: str, payload: bytes, obj: dict) -> None:
        """Verify and insert one complete, append-only audit DAG record."""
        if obj.get("version", 1) != 2:
            raise ValueError(
                f"Legacy audit object {obj_id} is not independently verifiable; "
                "migrate it from an authoritative local vault before pulling"
            )
        record = self._verify_audit_payload(obj_id, payload)

        existing = self._db.fetchone(
            "SELECT id, parent_ids, actor_id, action, encrypted_details, timestamp, "
            "signature FROM audit_log WHERE id = ?",
            (obj_id,),
        )
        if existing:
            if self._serialize_audit_row(existing) != payload:
                is_legacy_synthetic = (
                    existing["action"] == "sync_pull"
                    and bytes(existing["signature"]) == b"\x00" * 64
                )
                # Stateful test SM16: a server restore lost an identity
                # rotation and the records signed with the rotated key. The
                # device that took the old key back re-signed its copy and sent
                # it again; this device still held the copy signed with the
                # lost key, and the full resync stopped at it for good. The
                # same record with a signature that verifies (checked above)
                # is the same record.
                re_signed = (
                    existing["parent_ids"] == record["parent_ids_json"]
                    and existing["actor_id"] == record["actor_id"]
                    and existing["action"] == record["action"]
                    and bytes(existing["encrypted_details"] or b"")
                    == bytes(record["encrypted_details"] or b"")
                    and existing["timestamp"] == record["timestamp"]
                )
                if not (is_legacy_synthetic or re_signed):
                    raise ValueError(f"Conflicting append-only audit record {obj_id}")
                self._db.execute(
                    "DELETE FROM audit_dag_edges WHERE child_id = ?", (obj_id,)
                )
                self._db.execute(
                    "UPDATE audit_log SET parent_ids = ?, actor_id = ?, action = ?, "
                    "encrypted_details = ?, timestamp = ?, signature = ? WHERE id = ?",
                    (
                        record["parent_ids_json"],
                        record["actor_id"],
                        record["action"],
                        record["encrypted_details"],
                        record["timestamp"],
                        record["signature"],
                        obj_id,
                    ),
                )
        else:
            self._db.execute(
                "INSERT INTO audit_log (id, parent_ids, actor_id, action, "
                "encrypted_details, timestamp, signature) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    obj_id,
                    record["parent_ids_json"],
                    record["actor_id"],
                    record["action"],
                    record["encrypted_details"],
                    record["timestamp"],
                    record["signature"],
                ),
            )

        for parent_id in record["parent_ids"]:
            self._db.execute(
                "INSERT OR IGNORE INTO audit_dag_edges (child_id, parent_id) "
                "VALUES (?, ?)",
                (obj_id, parent_id),
            )
        outbox.sent(self._db, outbox.AUDIT, obj_id)
