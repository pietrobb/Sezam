"""Member re-key batches: close, rebase and reseal after removals.

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import hashlib
import struct
import time
from typing import Optional

from nacl.exceptions import CryptoError

from ..crypto.aead import BlobKind, decrypt, encrypt, parse_envelope
from ..models import bytes_to_ulid, new_ulid, ulid_to_bytes
from . import oplock, outbox, pending_states, sync_core
from .rekey_abandon import abandon_pending_rekey, superseded_rekey
from .schema import row_payload_hash

from .sync_common import (
    logger,
    queued_for_removal,
    reseal_key_row,
    vouched_access_level,
)
from .team_log_local import local_team_state, projected_team_state

# Last team-log seq whose member.keys records this device sealed keys for.
ROTATION_SEALED_META = "team_rotation_sealed_seq"


class RekeyMixin:
    """SyncClient methods: member re-key batches: close, rebase and reseal after removals."""

    def _rekey_batch_landed(self, pending: dict) -> bool:
        """Close a pending re-key the server already took (its reply was lost).

        Stateful test SM25: the batch landed, the reply never came, and another
        device changed one of its objects on top of it. Resent, the batch was
        refused; rebased, the server copy was sealed with the batch's own new
        key - 'sealed with another key' - on every sync. The new DEKs are this
        device's own, so a server copy sealed with one proves the atomic batch
        is there: it is closed as landed, held edits come back as conflicts and
        the rest goes out as ordinary changes.
        """
        new_raw = {ulid_to_bytes(new) for new in (pending.get("dek_map") or {}).values()}
        object_ids = set(pending.get("object_ids") or [])
        landed = False
        for row in self._db.fetchall(
            "SELECT object_id, object_type, server_payload FROM sync_conflicts"
        ):
            if row["object_id"] not in object_ids or row["server_payload"] is None:
                continue
            payload = bytes(row["server_payload"])
            if row["object_type"] == "entry":
                payload = payload[4:4 + int.from_bytes(payload[:4], "big")] if len(payload) >= 4 else b""
            try:
                landed = parse_envelope(payload).dek_id in new_raw
            except ValueError:
                continue
            if landed:
                break
        if not landed:
            return False
        self._close_landed_rekey(pending)
        return True

    @oplock.held
    def close_rekey_if_pulled_back(self) -> bool:
        """Close a pending re-key whose new DEK a pull already brought back.

        Stateful test SM77: the batch landed, its reply was lost and a pull
        brought its new folder key. A Shamir recovery then dropped the re-key
        as never sent and deleted that key here; the recovery's password
        change, which must re-wrap every key the server holds, was refused on
        every sync. The batch is atomic, so one of its keys on the server
        proves all of it is there.
        """
        pending = pending_states.rekey_batch(self._db)
        held_by_server = self._db.get_meta_json("pushed_dek_versions") or {}
        new_ids = set((pending.get("dek_map") or {}).values()) if pending else set()
        if not pending or not (
            any(new in held_by_server for new in new_ids)
            or self._rekey_copy_pulled_back(pending, new_ids)
        ):
            return False
        self._close_landed_rekey(pending)
        return True

    def _rekey_copy_pulled_back(self, pending: dict, new_ids: set[str]) -> bool:
        """Nightly state machine run on 782dde8: the batch landed, its reply was
        lost, and the server left the batch's new keys out of the pull that
        brought its copies back. The copies came back clean, so every push
        stopped as 'Atomic re-key batch is missing'. A clean copy sealed with
        one of the batch's new keys - this device's own, never sent outside
        the batch - proves the batch is there just as the key itself would."""
        object_ids = list(pending.get("object_ids") or [])
        if not object_ids or not new_ids:
            return False
        new_raw = {ulid_to_bytes(new) for new in new_ids}
        marks = ",".join("?" * len(object_ids))
        for table in ("nodes", "entries"):
            for row in self._db.fetchall(
                f"SELECT encrypted_meta FROM {table} "
                f"WHERE id IN ({marks}) AND NOT {outbox.queued(table)}",
                tuple(object_ids),
            ):
                try:
                    if parse_envelope(bytes(row["encrypted_meta"])).dek_id in new_raw:
                        return True
                except ValueError:
                    continue
        return False

    def _close_landed_rekey(self, pending: dict) -> None:
        object_ids = set(pending.get("object_ids") or [])
        rekeyed_versions = pending.get("rekeyed_versions") or {}
        self._db.begin()
        try:
            for object_id in object_ids:
                for table, apply in (("nodes", self._apply_node), ("entries", self._apply_entry)):
                    row = self._db.fetchone(
                        f"SELECT version, {outbox.queued(table)} AS queued FROM {table} "
                        "WHERE id = ?",
                        (object_id,),
                    )
                    if row is None or not row["queued"]:
                        continue
                    if rekeyed_versions.get(object_id) != row["version"]:
                        continue  # edited here since: an ordinary unsent change
                    shadow = self._db.fetchone(
                        "SELECT server_version, server_payload, server_parent_ref, "
                        "server_is_deleted FROM sync_conflicts WHERE object_id = ?",
                        (object_id,),
                    )
                    if shadow is None:
                        # The server holds the batch's copy: it is this device's write.
                        outbox.drop_write(self._db, object_id)
                        self._set_base(object_id, *self._base(object_id), own=True)
                        continue
                    # Changed elsewhere on top of the batch: that copy is current.
                    outbox.drop_write(self._db, object_id)
                    self._db.execute(
                        f"UPDATE {table} SET version = 0 WHERE id = ?", (object_id,)
                    )
                    apply(
                        object_id, shadow["server_parent_ref"], bytes(shadow["server_payload"]),
                        shadow["server_version"], shadow["server_is_deleted"],
                    )
                    self._db.execute("DELETE FROM sync_conflicts WHERE object_id = ?", (object_id,))
                outbox.sent(self._db, outbox.ENVELOPE, object_id)
            self._restore_held_edits(pending.get("held_edits") or {}, {})
            pending_states.clear_rekey_batch(self._db)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        self._push_cache.clear()
        logger.warning("The pending re-key had reached the server; closed as sent")

    def _rebase_pending_rekey(self) -> None:
        """Carry a refused member re-key over what the server holds now.

        Runs right after a pull. A server copy still sealed with a revoked DEK
        is re-sealed with its replacement one version above the server's (the
        server's content wins in the batch; a local edit of it is held and
        becomes a conflict after the batch landed). A copy the other
        device deleted or moved out under another key is taken over and leaves
        the batch. Objects and envelopes that reached the re-keyed folders
        under a revoked DEK since the re-key join it; anything else sealed
        with an unknown key inside them stops the re-key (fail closed).
        """
        # Stateful test SM84: the batch landed with its reply lost and a pull
        # already brought its new key back; resent, it is refused for good.
        if self.close_rekey_if_pulled_back():
            return
        # Review 526419e V3: another device of this account re-keyed the same
        # folders first; resent unchanged, this batch was refused for good.
        if superseded_rekey(self):
            abandon_pending_rekey(self)
            return
        pending = pending_states.rekey_batch(self._db)
        dek_map = pending.get("dek_map")
        if not dek_map or self._dek_mgr is None:
            raise RuntimeError(
                "Atomic re-key batch was refused and this device cannot rebase it"
            )
        if self._rekey_batch_landed(pending):
            return
        revoked_user_id = pending["revoked_user_id"]
        object_ids = set(pending["object_ids"])
        # Review 688edcb V1: a row that is not where the re-key left it holds
        # a user's edit. The batch still takes the server copy (re-sealed), the
        # edit is held and comes back as a conflict once the batch landed.
        rekeyed_versions = dict(pending.get("rekeyed_versions") or {})
        held = dict(pending.get("held_edits") or {})
        tombstones = list(pending.get("envelope_tombstones", []))
        tombstoned = {item["id"] for item in tombstones}
        shadows = {
            row["object_id"]: row for row in self._db.fetchall(
                "SELECT object_id, server_version, server_payload, server_parent_ref, "
                "server_is_deleted FROM sync_conflicts"
            )
        }
        settled: set[str] = set()
        revoked_holders = self._revoked_unpinned_holders(list(dek_map), revoked_user_id)
        revoked_holders |= queued_for_removal(self._db)

        def sealed_with(blob: bytes, dek_id: bytes) -> bool:
            try:
                return parse_envelope(blob).dek_id == dek_id
            except ValueError:
                return False

        batch_old_raw = {ulid_to_bytes(old) for old in dek_map}

        self._db.begin()
        try:
            for old_dek_id, new_dek_id in dek_map.items():
                old_dek = self._dek_mgr.unlock_dek(old_dek_id)
                new_dek = self._dek_mgr.unlock_dek(new_dek_id)
                old_raw = ulid_to_bytes(old_dek_id)
                folder_ids = {
                    row["id"] for row in self._db.fetchall(
                        "SELECT id FROM nodes WHERE dek_id = ?", (new_dek_id,)
                    )
                }
                if not folder_ids:
                    continue
                marks = ",".join("?" * len(folder_ids))
                # Nightly run on c78fd19: a batch copy the user moved out of the
                # re-keyed folders here, while the server copy is still in them,
                # was never looked at again and sank the batch on every push.
                moved_out = sorted(
                    oid for oid in object_ids
                    if oid in shadows and shadows[oid]["server_parent_ref"] in folder_ids
                )
                out_marks = ",".join("?" * len(moved_out))

                def reseal(blob: bytes, object_id: str, version: int, kind: BlobKind) -> bytes:
                    plain = decrypt(
                        blob, old_dek, ulid_to_bytes(object_id), version,
                        expected_blob_kind=kind,
                    )
                    return encrypt(
                        plaintext=plain, dek=new_dek, dek_id=ulid_to_bytes(new_dek_id),
                        object_id=ulid_to_bytes(object_id), version=version + 1,
                        blob_kind=kind,
                    )

                for row in self._db.fetchall(
                    "SELECT id, parent_id, encrypted_meta, version, "
                    f"{outbox.queued('nodes')} AS queued FROM nodes "
                    f"WHERE (id IN ({marks}) OR parent_id IN ({marks}) "
                    f"OR (id IN ({out_marks}) AND {outbox.queued('nodes')})) AND is_deleted = 0",
                    tuple(folder_ids) * 2 + tuple(moved_out),
                ):
                    node_id = row["id"]
                    if row["queued"]:
                        shadow = shadows.get(node_id) if node_id in object_ids else None
                        if shadow is None:
                            continue
                        blob = bytes(shadow["server_payload"])
                        version = shadow["server_version"]
                        parent_id = shadow["server_parent_ref"]
                        if not shadow["server_is_deleted"] and not sealed_with(blob, old_raw) and any(
                            sealed_with(blob, raw) for raw in batch_old_raw
                        ):
                            # A re-keyed subfolder's meta is sealed with its
                            # re-keyed parent's key: the parent's pass re-seals
                            # it. Put back as the server has it, the copy went
                            # out at the server's version and sank the batch on
                            # every push (stateful test, second admin).
                            continue
                        if shadow["server_is_deleted"] or not sealed_with(blob, old_raw):
                            governed = parent_id in folder_ids or (
                                not parent_id and node_id in folder_ids
                            )
                            if not shadow["server_is_deleted"] and governed:
                                raise RuntimeError(
                                    f"Folder {node_id} was sealed with another key "
                                    "during the re-key"
                                )
                            own_edit = rekeyed_versions.get(node_id) != row["version"]
                            if own_edit and node_id not in folder_ids:
                                # Stateful test SM41: as SM37 for entries - the
                                # user's edit leaves the batch and stays a conflict.
                                object_ids.discard(node_id)
                                continue
                            if own_edit:
                                # SM41: the re-keyed folder itself rides in the
                                # batch as the server has it; the edit is held
                                # and comes back as a conflict with that copy.
                                held[node_id] = {
                                    "kind": "node", "version": row["version"],
                                    "parent": row["parent_id"],
                                    "meta": bytes(row["encrypted_meta"]).hex(),
                                    "server_deleted": bool(shadow["server_is_deleted"]),
                                }
                            outbox.drop_write(self._db, node_id)
                            self._db.execute(
                                "UPDATE nodes SET version = 0 WHERE id = ?", (node_id,)
                            )
                            self._apply_node(
                                node_id, parent_id, blob, version, shadow["server_is_deleted"]
                            )
                            settled.add(node_id)
                            if node_id in folder_ids:
                                # Still the new DEK's folder: its DEK and
                                # envelopes ride on it, the copy goes back as is.
                                outbox.queue_write(self._db, node_id)
                            else:
                                object_ids.discard(node_id)
                            continue
                        # A row edited again after an earlier rebase held it:
                        # the newer edit is held (review e4cd15a S1).
                        if rekeyed_versions.get(node_id) != row["version"]:
                            held[node_id] = {
                                "kind": "node", "version": row["version"],
                                "parent": row["parent_id"],
                                "meta": bytes(row["encrypted_meta"]).hex(),
                            }
                    else:
                        blob = bytes(row["encrypted_meta"])
                        version = row["version"]
                        parent_id = row["parent_id"]
                        if not sealed_with(blob, old_raw):
                            continue
                    outbox.queue_write(self._db, node_id)
                    self._db.execute(
                        "UPDATE nodes SET parent_id = ?, encrypted_meta = ?, version = ?, "
                        "is_deleted = 0 WHERE id = ?",
                        (
                            parent_id, reseal(blob, node_id, version, BlobKind.NODE_META),
                            version + 1, node_id,
                        ),
                    )
                    self._set_base(node_id, version, row_payload_hash(blob, None))
                    rekeyed_versions[node_id] = version + 1
                    object_ids.add(node_id)
                    settled.add(node_id)

                for row in self._db.fetchall(
                    "SELECT id, node_id, encrypted_meta, encrypted_data, dek_id, version, "
                    f"{outbox.queued('entries')} AS queued, is_deleted FROM entries "
                    f"WHERE (node_id IN ({marks}) "
                    f"OR (id IN ({out_marks}) AND {outbox.queued('entries')})) "
                    f"AND (is_deleted = 0 OR {outbox.queued('entries')})",
                    tuple(folder_ids) + tuple(moved_out),
                ):
                    entry_id = row["id"]
                    if row["queued"]:
                        shadow = shadows.get(entry_id) if entry_id in object_ids else None
                        if shadow is None:
                            continue
                        payload = bytes(shadow["server_payload"])
                        version = shadow["server_version"]
                        node_id = shadow["server_parent_ref"]
                        meta_len = (
                            struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else 0
                        )
                        meta = payload[4:4 + meta_len]
                        data = payload[4 + meta_len:]
                        if shadow["server_is_deleted"] or not sealed_with(meta, old_raw):
                            if not shadow["server_is_deleted"] and node_id in folder_ids:
                                raise RuntimeError(
                                    f"Entry {entry_id} was sealed with another key "
                                    "during the re-key"
                                )
                            if rekeyed_versions.get(entry_id) != row["version"]:
                                # Stateful test SM37: the row holds a user's edit
                                # (made before the re-key or after it). Taken over,
                                # that edit was lost without a conflict; it leaves
                                # the batch and stays a conflict with the server copy.
                                object_ids.discard(entry_id)
                                continue
                            outbox.drop_write(self._db, entry_id)
                            self._db.execute(
                                "UPDATE entries SET version = 0 WHERE id = ?", (entry_id,)
                            )
                            self._apply_entry(
                                entry_id, node_id, payload, version,
                                shadow["server_is_deleted"],
                            )
                            object_ids.discard(entry_id)
                            settled.add(entry_id)
                            continue
                        if rekeyed_versions.get(entry_id) != row["version"]:
                            # Edited again after an earlier rebase held it
                            # (review e4cd15a S1): the newer edit is held, the
                            # earlier one goes to the entry's history.
                            if entry_id in held:
                                self._archive_held_edit(entry_id, held[entry_id])
                            # A local delete is held like an edit: it comes
                            # back as a conflict with the server copy.
                            held[entry_id] = {
                                "kind": "entry", "deleted": True, "parent": row["node_id"],
                            } if row["is_deleted"] else {
                                "kind": "entry", "version": row["version"],
                                "parent": row["node_id"],
                                "meta": bytes(row["encrypted_meta"]).hex(),
                                "data": bytes(row["encrypted_data"]).hex(),
                            }
                    elif row["is_deleted"]:
                        continue
                    else:
                        if row["dek_id"] not in (None, old_dek_id):
                            continue
                        meta = bytes(row["encrypted_meta"])
                        data = bytes(row["encrypted_data"])
                        version = row["version"]
                        node_id = row["node_id"]
                        if not sealed_with(meta, old_raw):
                            continue
                    outbox.queue_write(self._db, entry_id)
                    self._db.execute(
                        "UPDATE entries SET node_id = ?, encrypted_meta = ?, "
                        "encrypted_data = ?, dek_id = ?, version = ?, is_deleted = 0 "
                        "WHERE id = ?",
                        (
                            node_id,
                            reseal(meta, entry_id, version, BlobKind.ENTRY_META),
                            reseal(data, entry_id, version, BlobKind.ENTRY_DATA),
                            None if node_id in folder_ids else new_dek_id,
                            version + 1, entry_id,
                        ),
                    )
                    self._set_base(entry_id, version, row_payload_hash(meta, data))
                    rekeyed_versions[entry_id] = version + 1
                    object_ids.add(entry_id)
                    settled.add(entry_id)

                # Envelopes another device granted on a revoked DEK meanwhile.
                for env in self._db.fetchall(
                    "SELECT id, user_id, created_by, access_level, encrypted_dek "
                    "FROM access_envelopes WHERE dek_id = ?",
                    (old_dek_id,),
                ):
                    if env["id"] not in tombstoned:
                        tombstones.append({
                            "id": env["id"],
                            "dek_id": old_dek_id,
                            "user_id": env["user_id"],
                            "created_by": env["created_by"],
                            "access_level": env["access_level"],
                            "encrypted_dek": bytes(env["encrypted_dek"]).hex(),
                            "unsent": outbox.is_pending(self._db, outbox.ENVELOPE, env["id"]),
                        })
                        tombstoned.add(env["id"])
                        object_ids.add(env["id"])
                    self._db.execute(
                        "DELETE FROM access_envelopes WHERE id = ?", (env["id"],)
                    )
                    if env["user_id"] in revoked_holders or self._db.fetchone(
                        "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?",
                        (new_dek_id, env["user_id"]),
                    ):
                        continue
                    key_row = reseal_key_row(
                        self._db, env["user_id"], env["created_by"], self._user_id
                    )
                    if key_row is None:
                        if env["created_by"] != self._user_id:
                            continue  # review 7c10379 H2: not a grant this account trusts
                        raise RuntimeError(
                            f"Missing verified encryption key for user {env['user_id']}"
                        )
                    from nacl.public import Box, PublicKey

                    box = Box(
                        self._keypair.to_nacl_private_key(),
                        PublicKey(bytes(key_row["encryption_pk"])),
                    )
                    new_env_id = new_ulid()
                    self._db.execute(
                        "INSERT INTO access_envelopes "
                        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            new_env_id, new_dek_id, env["user_id"], self._user_id,
                            vouched_access_level(self._db, env["id"], env["access_level"]),
                            bytes(box.encrypt(bytes(new_dek))),
                        ),
                    )
                    object_ids.add(new_env_id)

            if settled:
                marks = ",".join("?" * len(settled))
                self._db.execute(
                    f"DELETE FROM sync_conflicts WHERE object_id IN ({marks})",
                    tuple(settled),
                )
            self._resolve_entry_deks()
            pending_states.set_rekey_batch(self._db, {
                **pending,
                "object_ids": sorted(object_ids),
                "envelope_tombstones": tombstones,
                "rekeyed_versions": rekeyed_versions,
                "held_edits": held,
            })
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        for obj_id in settled | tombstoned:
            self._push_cache.pop(obj_id, None)

    def _reseal_team_rekey(self, state) -> bool:
        """Seal a pending re-key's new team keys to the recipients of ``state``.

        Review 1141a20 (envelopes go stale when the head moves): the batch's
        envelopes name the log's recipients when it was made. Another device
        of the admin that changed a folder's access since then left the new
        key with a member the log no longer gives it to (the server refused
        the whole batch on every push), or without one it now does. True when
        an envelope changed (the push collects the batch again).
        """
        from nacl.public import Box, PublicKey

        from .. import teamlog

        pending = pending_states.rekey_batch(self._db)
        dek_map = pending.get("dek_map") or {}
        if not dek_map or state is None or self._dek_mgr is None or self._keypair is None:
            return False
        withheld = queued_for_removal(self._db) | {pending.get("revoked_user_id")}
        object_ids = set(pending.get("object_ids") or [])
        own_sk = self._keypair.to_nacl_private_key()
        changed = False
        self._db.begin()
        try:
            for old_dek_id, new_dek_id in sorted(dek_map.items()):
                found = state.dek_index.get(old_dek_id)
                if found is None or new_dek_id in state.dek_index:
                    continue  # not a team folder, or this re-key is in the log already
                want = {
                    uid: (encryption_pk, level)
                    for uid, encryption_pk, level in teamlog.key_recipients(state, found[0])
                    if uid not in withheld and uid != self._user_id
                }
                have: set[str] = set()
                for row in self._db.fetchall(
                    "SELECT id, user_id, access_level, encrypted_dek FROM access_envelopes "
                    "WHERE dek_id = ? AND created_by = ? ORDER BY id",
                    (new_dek_id, self._user_id),
                ):
                    target = want.get(row["user_id"])
                    current = False
                    if target is not None and target[1] == row["access_level"] and row["user_id"] not in have:
                        try:
                            opened = bytearray(Box(own_sk, PublicKey(bytes.fromhex(target[0]))).decrypt(
                                bytes(row["encrypted_dek"])
                            ))
                            opened[:] = bytes(len(opened))
                            current = True
                        except CryptoError:
                            pass
                    if current:
                        have.add(row["user_id"])
                        continue
                    # Never sent (the batch is atomic): it just goes.
                    self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (row["id"],))
                    object_ids.discard(row["id"])
                    self._push_cache.pop(row["id"], None)
                    changed = True
                missing = sorted(set(want) - have)
                if not missing:
                    continue
                new_dek = self._dek_mgr.unlock_dek(new_dek_id)
                for uid in missing:
                    encryption_pk, level = want[uid]
                    envelope_id = new_ulid()
                    self._db.execute(
                        "INSERT INTO access_envelopes "
                        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (envelope_id, new_dek_id, uid, self._user_id, level,
                         bytes(Box(own_sk, PublicKey(bytes.fromhex(encryption_pk))).encrypt(bytes(new_dek)))),
                    )
                    object_ids.add(envelope_id)
                    changed = True
            if changed:
                pending_states.set_rekey_batch(self._db, {**pending, "object_ids": sorted(object_ids)})
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        return changed

    def _archive_held_edit(self, entry_id: str, edit: dict) -> None:
        """Keep a held entry edit that is not coming back as the local copy in
        the entry's local history, under the key it was sealed with."""
        if edit["kind"] != "entry" or "data" not in edit:
            return
        blob = bytes.fromhex(edit["data"])
        raw_dek_id = parse_envelope(blob).dek_id
        dek_id = bytes_to_ulid(raw_dek_id)
        dek = self._dek_mgr.unlock_dek(dek_id)
        plain = decrypt(
            blob, dek, ulid_to_bytes(entry_id), int(edit["version"]),
            enable_padding=True, expected_blob_kind=BlobKind.ENTRY_DATA,
        )
        snapshot_id = new_ulid()
        self._db.execute(
            "INSERT INTO entry_history (id, entry_id, encrypted_snapshot, dek_id, changed_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                snapshot_id, entry_id,
                encrypt(
                    plain, dek, raw_dek_id, ulid_to_bytes(snapshot_id), version=1,
                    blob_kind=BlobKind.HISTORY_SNAPSHOT, enable_padding=True,
                ),
                dek_id, int(time.time() * 1000),
            ),
        )
        logger.warning("Kept an edit of %s held by a re-key in its history", entry_id)

    def _reseal_under_successors(self) -> None:
        """Seal unsent items again under the key their folder has now.

        Stateful test SM26: the laptop created a folder in a shared folder,
        then pulled the phone's re-key after a member was removed. The unsent
        folder was still sealed with the DEK the member holds and went to the
        server so: the revoked member could read it. Before a push, a live
        unsent item sealed with a retired folder DEK is sealed again with that
        folder's current DEK, as a kept conflict copy is (review 526419e N9).

        Stateful test SM28: pushed before the re-key was pulled, the server
        took such an item as it was. After a pull, this device's own write
        that the server holds under a retired DEK is sealed again one version
        up and sent as a change: by the writer, and by the folder's owner for
        any writer's item (capability review run 134).
        """
        if self._dek_mgr is None:
            return
        retired = {
            row["id"] for row in self._db.fetchall(
                "SELECT id FROM deks WHERE scope = 'folder' AND node_id IS NULL"
            )
        }
        if not retired:
            return

        def successor(blob: bytes, folder_id: str) -> Optional[tuple[str, bytes, bytearray]]:
            try:
                dek_id = parse_envelope(blob).dek_id
            except ValueError:
                return None
            old_id = bytes_to_ulid(dek_id)
            if old_id not in retired:
                return None
            new_id, new = self._successor_dek(dek_id, self._dek_mgr.unlock_dek(old_id), folder_id)
            return (old_id, new_id, new) if new_id != dek_id else None

        def reseal(blob: bytes, object_id: str, version: int, new_version: int, kind: BlobKind,
                   old_id: str, new_id: bytes, new: bytearray) -> bytes:
            plain = decrypt(
                blob, self._dek_mgr.unlock_dek(old_id), ulid_to_bytes(object_id), version,
                expected_blob_kind=kind,
            )
            return encrypt(
                plaintext=plain, dek=new, dek_id=new_id, object_id=ulid_to_bytes(object_id),
                version=new_version, blob_kind=kind,
            )

        # Unsent, or this device's own write the server holds (SM28).
        mine = (
            "(EXISTS (SELECT 1 FROM outbox o WHERE o.kind = 'write' AND o.object_id = {t}.id) "
            "OR EXISTS (SELECT 1 FROM object_sent_version s "
            "WHERE s.object_id = {t}.id AND s.version = {t}.version)) AS mine"
        )
        # Capability review run 134: the writer's own record of its write can
        # be lost (a web tab signed in again after a password change elsewhere,
        # a new tab, a device never used again), and then nothing resealed it.
        # The folder's owner, whose KEK holds the folder's current key, finishes
        # the re-key for every live item, whoever wrote it, as the re-key does.
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])

        replaced: dict[str, bool] = {}

        def due(row, blob: bytes, folder_id: str) -> Optional[tuple[str, bytes, bytearray]]:
            if not row["mine"]:
                try:
                    found = successor(blob, folder_id)
                except (CryptoError, KeyError, ValueError):
                    return None  # another account's key this device does not open
                if found is None or bytes_to_ulid(found[1]) in foreign:
                    return None
                # Only a key a re-key replaced (its archive opens to it): an
                # unlabelled tier-2 DEK also looks unbound here.
                if found[0] not in replaced:
                    replaced[found[0]] = self._dek_mgr.successor_of(found[0]) is not None
                return found if replaced[found[0]] else None
            try:
                return successor(blob, folder_id)
            except (CryptoError, KeyError, ValueError):
                # Review c78fd19 (R13-8): a new admin's handover re-key moves a
                # folder whose name the former admin sealed with the root key
                # of theirs (unbound here). Nothing of this device's is under it.
                return None

        resealed: list[str] = []
        self._db.begin()
        try:
            for row in self._db.fetchall(
                f"SELECT id, parent_id, encrypted_meta, version, {outbox.queued('nodes')} AS queued, "
                + mine.format(t="nodes") + " FROM nodes WHERE is_deleted = 0"
            ):
                blob = bytes(row["encrypted_meta"])
                # A folder's name is sealed with its parent's key (a root's with its own).
                found = due(row, blob, row["parent_id"] or row["id"])
                if found is None:
                    continue
                old_id, new_id, new = found
                version = row["version"] + (0 if row["queued"] else 1)
                outbox.queue_write(self._db, row["id"])
                self._db.execute(
                    "UPDATE nodes SET encrypted_meta = ?, version = ? WHERE id = ?",
                    (reseal(blob, row["id"], row["version"], version, BlobKind.NODE_META,
                            old_id, new_id, new),
                     version, row["id"]),
                )
                resealed.append(row["id"])
            for row in self._db.fetchall(
                "SELECT id, node_id, dek_id, encrypted_meta, encrypted_data, version, "
                f"{outbox.queued('entries')} AS queued, "
                + mine.format(t="entries") + " FROM entries WHERE is_deleted = 0"
            ):
                meta = bytes(row["encrypted_meta"])
                found = due(row, meta, row["node_id"])
                if found is None:
                    continue
                old_id, new_id, new = found
                version = row["version"] + (0 if row["queued"] else 1)
                outbox.queue_write(self._db, row["id"])
                self._db.execute(
                    "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, dek_id = ?, "
                    "version = ? WHERE id = ?",
                    (
                        reseal(meta, row["id"], row["version"], version, BlobKind.ENTRY_META,
                               old_id, new_id, new),
                        reseal(bytes(row["encrypted_data"]), row["id"], row["version"], version,
                               BlobKind.ENTRY_DATA, old_id, new_id, new),
                        bytes_to_ulid(new_id) if row["dek_id"] == old_id else row["dek_id"],
                        version, row["id"],
                    ),
                )
                resealed.append(row["id"])
            if resealed:
                # Stateful test SM33: a resealed own write in a folder deleted
                # elsewhere was refused ('parent folder is deleted') on every
                # push; the pull had revived such folders before this ran.
                self._revive_folders_of_unsent()
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        for object_id in resealed:
            self._push_cache.pop(object_id, None)

    def _grant_again_on_successors(self) -> None:
        """Give a member granted under a key a re-key replaced the folder's current key.

        Stateful test SM62: the phone shared a folder while the laptop's
        re-key of it (another member removed) was built but not yet sent. The
        server took both; the re-key gave envelopes on the new key only to
        the members the laptop knew of, so the phone's member lost the folder
        on every device. This account's envelope under a retired folder key
        whose folder has a current one is sealed again on that key for a
        member not removed on the server.

        Review d615826 H2: only grants this device made itself. A grant it got
        from the server may be a replay of one a re-key withdrew (the server
        also decides who counts as removed), and its own device seals it again.

        Capability review run 139: and only grants made after every re-key
        on the way to the current key was built. A re-key built later may have
        withdrawn the grant on another device (a member removed there), and the
        server can withhold that tombstone and call the member active. The
        successor key's id is signed by its re-key, and a ULID carries the
        time it was made: a grant that is not newer than it was the re-key's
        to keep or drop (SM62's grant came after the re-key was built).

        Capability review run 140: time alone dropped a grant the re-key never
        saw (the phone granted and pushed, then the laptop, not pulled,
        removed someone else). A removal re-key now tags its archive id with
        the member it removed, under the new key (dek.removal_archive_id):
        such a link withholds only that member, whatever the grant's age. The
        time rule stays for archives without the tag.
        """
        if self._dek_mgr is None or self._keypair is None:
            return
        if pending_states.blocker(self._db, pending_states.GRANT_AGAIN):
            return  # the pending re-key decides about these members
        from ulid import ULID

        from .dek import archive_removed

        def current_key(dek_id: str, user_id: str, granted_at: int) -> tuple[Optional[str], bool]:
            seen = {dek_id}
            withdrawn = False
            while True:
                link = self._dek_mgr.successor_link(dek_id)
                if link is None or link[0] in seen:
                    return None, withdrawn
                dek_id, archive_id = link
                removed = archive_removed(
                    archive_id, dek_id, self._dek_mgr.unlock_dek(dek_id), user_id
                )
                if removed is None:
                    removed = granted_at <= ULID.from_str(dek_id).milliseconds
                withdrawn = withdrawn or removed
                row = self._db.fetchone("SELECT node_id, scope FROM deks WHERE id = ?", (dek_id,))
                if row is not None and row["node_id"] and row["scope"] in ("folder", "root"):
                    return dek_id, withdrawn
                seen.add(dek_id)

        candidates = []
        for env in self._db.fetchall(
            "SELECT e.id, e.dek_id, e.user_id, e.access_level FROM access_envelopes e "
            "JOIN deks d ON d.id = e.dek_id "
            "WHERE e.created_by = ? AND e.user_id != ? AND d.scope = 'folder' AND d.node_id IS NULL "
            "AND NOT EXISTS (SELECT 1 FROM pulled_envelopes p WHERE p.envelope_id = e.id)",
            (self._user_id, self._user_id),
        ):
            current, withdrawn = current_key(
                env["dek_id"], env["user_id"], ULID.from_str(env["id"]).milliseconds
            )
            if current is None or withdrawn or self._db.fetchone(
                "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?",
                (current, env["user_id"]),
            ):
                continue
            candidates.append((env, current))
        if not candidates:
            return
        try:
            self.pin_envelope_holder_keys()
            revoked = {u.get("id") for u in self.list_users() if u.get("status") == "revoked"}
        except (RuntimeError, OSError) as exc:
            logger.warning("Members granted under a re-keyed folder key not checked: %s", exc)
            return
        from ..crypto.envelope_crypto import create_envelope

        own_sk = self._keypair.to_nacl_private_key().encode()
        withheld = queued_for_removal(self._db)
        with self._db.transaction():
            for env, current in candidates:
                key_row = self._db.fetchone(
                    "SELECT encryption_pk FROM known_keys WHERE user_id = ?", (env["user_id"],)
                )
                if env["user_id"] in revoked | withheld or key_row is None or self._db.fetchone(
                    "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?",
                    (current, env["user_id"]),
                ):
                    continue
                self._db.execute(
                    "INSERT INTO access_envelopes "
                    "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        new_ulid(), current, env["user_id"], self._user_id, env["access_level"],
                        create_envelope(
                            self._dek_mgr.unlock_dek(current), own_sk, bytes(key_row["encryption_pk"])
                        ),
                    ),
                )
                # Envelopes are pushed with their folder.
                outbox.queue_writes(
                    self._db, "nodes", "id = (SELECT node_id FROM deks WHERE id = ?)", (current,)
                )

    def _seal_to_rotated_members(self) -> None:
        """Seal the current team keys again to a member who rotated its identity.

        Review 1141a20 H1 / goal #369: a member cannot seal team keys, so after
        its member.keys only envelopes on its retired encryption key existed
        and its next unlock opened nothing. An admin device holding a folder's
        current key seals it to the member's new key (the signed record names
        it), once per member.keys record; the marker moves in the same
        transaction as the envelopes, which go out with their folder.
        """
        from .. import teamlog
        from ..crypto.envelope_crypto import create_envelope, open_envelope

        if self._dek_mgr is None or self._keypair is None:
            return
        state = self.team_state()
        if state is None or pending_states.blocker(self._db, pending_states.GRANT_AGAIN):
            return  # a pending re-key seals its keys to the log's current recipients
        done = int(self._db.get_meta(ROTATION_SEALED_META) or -1)
        rotated = {
            teamlog.parse_body(row["body"])["data"]["user_id"]
            for row in self._db.fetchall(
                "SELECT body FROM team_log WHERE seq > ? AND seq <= ? ORDER BY seq",
                (done, state.head_seq),
            )
            if teamlog.parse_body(row["body"])["type"] == "member.keys"
        } - {self._user_id}
        if not rotated:
            if done < state.head_seq:
                self._db.set_meta(ROTATION_SEALED_META, str(state.head_seq))
            return
        if teamlog.is_admin(state, self._user_id) and not self.team_log_trusted(state):
            return  # nothing is sealed until the founder is confirmed; retried after
        own_sk = self._keypair.to_nacl_private_key().encode()
        withheld = queued_for_removal(self._db)
        # docs/SYNC_SINGLE_SOURCE.md 3.5: a folder a queued removal leaves
        # stale gets no envelope under the key that removal retires; its
        # re-key seals to the rotated keys. Until then this is not done.
        projected = projected_team_state(self._db, self._user_id)
        waiting = False
        with self._db.transaction():
            for folder in sorted(state.folders) if teamlog.is_admin(state, self._user_id) else ():
                dek_id = teamlog.current_key(state, folder)
                if teamlog.may_seal(state, folder) and not teamlog.may_seal(projected, folder):
                    waiting = True
                    continue
                if not teamlog.may_seal(state, folder) or not self._db.fetchone(
                    "SELECT 1 FROM deks WHERE id = ?", (dek_id,)
                ):
                    continue  # a re-key seals to the current keys; another admin holds it
                for uid, encryption_pk, level in teamlog.key_recipients(state, folder):
                    if uid not in rotated or uid in withheld:
                        continue
                    pk = bytes.fromhex(encryption_pk)
                    sealed = False
                    for env in self._db.fetchall(
                        "SELECT encrypted_dek, access_level FROM access_envelopes "
                        "WHERE dek_id = ? AND user_id = ? AND created_by = ?",
                        (dek_id, uid, self._user_id),
                    ):
                        try:
                            open_envelope(bytes(env["encrypted_dek"]), own_sk, pk)[:] = bytes(32)
                            sealed = sealed or env["access_level"] == level
                        except CryptoError:
                            pass
                    if sealed:
                        continue  # a retry after a crash, or a grant made after the rotation
                    self._db.execute(
                        "INSERT INTO access_envelopes "
                        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (new_ulid(), dek_id, uid, self._user_id, level,
                         create_envelope(self._dek_mgr.unlock_dek(dek_id), own_sk, pk)),
                    )
                    outbox.queue_write(self._db, folder)
            if not waiting:
                self._db.set_meta(ROTATION_SEALED_META, str(state.head_seq))

    def _successor_dek(
        self, dek_id: bytes, dek: bytearray, folder_id: Optional[str]
    ) -> tuple[bytes, bytearray]:
        """The folder's current DEK when ``dek_id`` is a retired folder DEK
        (re-keyed away: scope 'folder', bound to no folder), else the same DEK.

        Review 526419e N9: a held edit, and 'keep local' on any conflict,
        resealed the local copy under the DEK it was written with. After a
        member re-key that is the DEK the removed member holds, so the kept
        copy went to the server readable with the revoked key."""
        row = self._db.fetchone(
            "SELECT scope, node_id FROM deks WHERE id = ?", (bytes_to_ulid(dek_id),)
        )
        if folder_id is None or row is None or row["scope"] != "folder" or row["node_id"]:
            return dek_id, dek
        try:
            current_id, current = self._dek_mgr.get_dek_for_node(folder_id)
        except KeyError:
            return dek_id, dek
        if current_id is None:
            return dek_id, dek
        # The shared core decides (capability review run 365): the folder's
        # current key, and for a team folder only one the log lets us hold.
        to = sync_core.call(
            "reseal_targets",
            team=sync_core.team_input(local_team_state(self._db), self._user_id),
            successors={bytes_to_ulid(dek_id): current_id}, held=[current_id], keys=[bytes_to_ulid(dek_id)],
        )[0]
        if to["send"] == "wait" or (to["send"] == "reseal" and to["key"] != current_id):
            # Review c78fd19: this went out under the retired key, which the
            # removed member still reads.
            raise RuntimeError(
                f"Folder {folder_id} has a new key this device does not hold yet; "
                "the change waits. Sync again."
            )
        return (ulid_to_bytes(current_id), current) if to["send"] == "reseal" else (dek_id, dek)

    def _restore_held_edits(self, held: dict, resp: dict) -> None:
        """Bring back the local edits a rebased re-key held, as conflicts (M1).

        Runs in the transaction that marks the landed batch clean. The copy the
        server now has becomes the conflict shadow; the held edit is sealed at
        the same version, so it is not pushed over the other device's change
        until the user picks one (resolve_conflict).
        """
        commit_seqs = {acc["id"]: acc.get("commit_seq") for acc in resp.get("accepted", [])}
        for object_id, edit in held.items():
            is_node = edit["kind"] == "node"
            table = "nodes" if is_node else "entries"
            parent_column = "parent_id" if is_node else "node_id"
            row = self._db.fetchone(
                f"SELECT {parent_column} AS parent, encrypted_meta, "
                + ("" if is_node else "encrypted_data, ")
                + f"version, is_deleted FROM {table} WHERE id = ?",
                (object_id,),
            )
            # SM41: the batch took the server's delete of a folder edited here
            # (SM63: a dropped re-key, of any item).
            server_deleted = bool(edit.get("server_deleted")) and row is not None
            if row is not None and row["is_deleted"] and not server_deleted:
                row = None
            if row is None:
                # Deleted here meanwhile (review e4cd15a S1): the delete
                # stands, the held edit is kept in the entry's history (trash
                # restore brings both back).
                self._archive_held_edit(object_id, edit)
                continue
            version = row["version"]
            payload = bytes(row["encrypted_meta"])
            if not is_node:
                payload = struct.pack(">I", len(payload)) + payload + bytes(row["encrypted_data"])
            self._db.execute(
                "INSERT OR REPLACE INTO sync_conflicts "
                "(object_id, object_type, local_version, server_version, server_payload, "
                "server_parent_ref, server_is_deleted, server_payload_hash, "
                "server_commit_seq, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    # Stateful test SM73: what the batch sent, not what the
                    # rebase saw - a folder deleted there that holds unsent work
                    # went back live, and 'Use server' then deleted it here only.
                    object_id, edit["kind"], version, version, payload, row["parent"],
                    int(bool(row["is_deleted"])),
                    hashlib.sha256(payload).hexdigest(), commit_seqs.get(object_id),
                    int(time.time() * 1000),
                ),
            )
            if edit.get("deleted"):
                # The local copy is the delete; the server copy's blobs stay
                # (a tombstone's blobs are read at or below its version).
                outbox.queue_write(self._db, object_id)
                self._db.execute(f"UPDATE {table} SET is_deleted = 1 WHERE id = ?", (object_id,))
                continue

            def reseal(blob_hex: str, kind: BlobKind) -> bytes:
                blob = bytes.fromhex(blob_hex)
                dek_id = parse_envelope(blob).dek_id
                dek = self._dek_mgr.unlock_dek(bytes_to_ulid(dek_id))
                plain = decrypt(
                    blob, dek, ulid_to_bytes(object_id), int(edit["version"]),
                    expected_blob_kind=kind,
                )
                dek_id, dek = self._successor_dek(
                    dek_id, dek, (edit["parent"] or object_id) if is_node else edit["parent"]
                )
                return encrypt(
                    plaintext=plain, dek=dek, dek_id=dek_id,
                    object_id=ulid_to_bytes(object_id), version=version, blob_kind=kind,
                )

            outbox.queue_write(self._db, object_id)
            if is_node:
                self._db.execute(
                    "UPDATE nodes SET parent_id = ?, encrypted_meta = ?, "
                    "is_deleted = 0 WHERE id = ?",
                    (edit["parent"], reseal(edit["meta"], BlobKind.NODE_META), object_id),
                )
            else:
                self._db.execute(
                    "UPDATE entries SET node_id = ?, encrypted_meta = ?, encrypted_data = ?, "
                    "is_deleted = 0 WHERE id = ?",
                    (
                        edit["parent"], reseal(edit["meta"], BlobKind.ENTRY_META),
                        reseal(edit["data"], BlobKind.ENTRY_DATA), object_id,
                    ),
                )
        if held:
            self._resolve_entry_deks()
