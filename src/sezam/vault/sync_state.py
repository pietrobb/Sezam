"""Sync checkpoint, rollback check, per-object base versions (spec 8.3) and folders revived for unsent work.

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from typing import Optional

from ..crypto.aead import BlobKind, decrypt, encrypt, parse_envelope
from ..models import bytes_to_ulid, new_ulid, ulid_to_bytes

from . import outbox, sync_core
from .schema import row_payload_hash
from .sealed import open_sealed
from .sync_common import (
    _CHECKPOINT_META_KEY,
    COMMIT_ANCHOR_META,
    compute_state_hash,
    legacy_state_hash,
    logger,
    STATE_HASH_VERSION,
    SyncRollbackWarning,
)


class SyncStateMixin:
    """SyncClient methods: sync checkpoint, rollback check, per-object base versions, revived folders."""

    def _forget_session_after_lost_rotation(self) -> None:
        """Drop what this session learned before the identity rotation is sent again.

        R16-Z SM26b: the ring loaded before the server went back named this
        device's key as the account's: the rotation's lists came out empty
        (as for one that landed, SM43) and the server refused every push
        with key_vouchers_incomplete.
        """
        self._token = None
        self._push_cache.clear()
        self._signing_key_rings.pop(self._user_id, None)
        self._rotation_authorizer = None

    # ── Sync Checkpoint (spec 8.3) ──

    def _compute_state_hash(self) -> str:
        """Compute state_hash (sync_common.compute_state_hash) over all local
        vault objects with their parent and deleted flag (R17-N1).

        Includes every locally represented sync object, including tombstones,
        access envelopes, DEK archives, and audit records.
        """
        return compute_state_hash(self._local_objects())

    def _held_entries(self) -> set[tuple[str, int, str]]:
        """(id, version, digest) of every server copy this device holds
        (goal #443: what it may vouch for under the account's current key).

        R17-N1: the digest of the message its signer signed (held_signed,
        written when the copy verified or the server took it), and only while
        the copy held is that version and payload: what the server serves
        again with other signed fields matches none.

        A queued row is its server copy only when a conflict keeps one; a
        version this device made and has not sent is none (R16-Z: a voucher of
        an unsent tombstone let a retired key sign that version live)."""
        unsent = {
            row["object_id"] for row in self._db.fetchall(
                "SELECT object_id FROM outbox WHERE kind = 'write' AND object_id NOT IN "
                "(SELECT object_id FROM sync_conflicts)"
            )
        }
        signed: dict[str, list] = {}
        for row in self._db.fetchall("SELECT object_id, version, payload_hash, digest FROM held_signed"):
            signed.setdefault(row["object_id"], []).append(
                (row["version"], row["payload_hash"], row["digest"])
            )
        out = set()
        for obj_id, version, payload, *_signed in self._local_objects():
            if obj_id in unsent or obj_id not in signed:
                continue
            payload_hash = hashlib.sha256(payload).hexdigest()
            out.update(
                (obj_id, version, digest) for held_version, held_hash, digest in signed[obj_id]
                if held_version == version and held_hash == payload_hash
            )
        return out

    def _local_objects(self) -> list[tuple[str, int, bytes, Optional[str], int]]:
        """(id, version, payload, parent_ref, is_deleted) of every locally
        represented sync object, as the server holds it (a queued row's server
        copy)."""
        objects: list[tuple[str, int, bytes, Optional[str], int]] = []
        server_shadows = {
            row["object_id"]: row
            for row in self._db.fetchall(
                "SELECT object_id, server_version, server_payload, server_parent_ref, "
                "server_is_deleted FROM sync_conflicts"
            )
        }

        def shadowed(row) -> bool:
            shadow = server_shadows.get(row["id"]) if row["queued"] else None
            if shadow:
                objects.append((
                    row["id"], shadow["server_version"], bytes(shadow["server_payload"]),
                    shadow["server_parent_ref"], shadow["server_is_deleted"],
                ))
            return bool(shadow)

        # Nodes: payload = encrypted_meta
        for row in self._db.fetchall(
            "SELECT id, parent_id, version, is_deleted, encrypted_meta, "
            f"{outbox.queued('nodes')} AS queued FROM nodes"
        ):
            if not shadowed(row):
                objects.append((
                    row["id"], row["version"], bytes(row["encrypted_meta"]),
                    row["parent_id"], row["is_deleted"],
                ))

        # Entries: payload = u32be(len(encrypted_meta)) + encrypted_meta + encrypted_data
        for row in self._db.fetchall(
            "SELECT id, node_id, version, is_deleted, encrypted_meta, encrypted_data, "
            f"{outbox.queued('entries')} AS queued FROM entries"
        ):
            if not shadowed(row):
                meta_bytes = bytes(row["encrypted_meta"])
                payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + bytes(row["encrypted_data"])
                objects.append((row["id"], row["version"], payload, row["node_id"], row["is_deleted"]))

        # DEKs (parent: the folder) and archived DEKs (parent: the successor):
        # payload = encrypted_dek
        for table, parent in (("deks", "node_id"), ("dek_archive", "replaced_by")):
            for row in self._db.fetchall(f"SELECT id, version, encrypted_dek, {parent} AS parent FROM {table}"):
                objects.append((row["id"], row["version"], bytes(row["encrypted_dek"]), row["parent"], 0))

        # Access envelopes: payload = encrypted_dek, parent: the key, protocol version = 1
        for row in self._db.fetchall("SELECT id, dek_id, encrypted_dek FROM access_envelopes"):
            objects.append((row["id"], 1, bytes(row["encrypted_dek"]), row["dek_id"], 0))

        # Audit objects hash the complete canonical signed record, not only details.
        for row in self._db.fetchall(
            "SELECT id, parent_ids, actor_id, action, encrypted_details, timestamp, "
            "signature FROM audit_log"
        ):
            objects.append((row["id"], 2, self._serialize_audit_row(row), None, 0))
        return objects

    def _get_checkpoint_dek(self) -> tuple[Optional[str], Optional[bytearray]]:
        """Get the audit DEK for checkpoint encryption.

        Returns (dek_id, raw_dek) or (None, None) if DEK manager not set.
        """
        if self._dek_mgr is None:
            return None, None
        try:
            return self._dek_mgr.get_audit_dek()
        except (KeyError, Exception):
            logger.warning("Audit DEK not available for checkpoint encryption")
            return None, None

    @staticmethod
    def _checkpoint_record(commit_seq: int, state_hash: str) -> dict:
        return {
            "last_sync_seq": commit_seq,
            "state_hash": state_hash,
            "state_v": STATE_HASH_VERSION,
            "timestamp": int(time.time() * 1000),
        }

    def _save_sync_checkpoint(self, commit_seq: int, state_hash: str) -> None:
        """Encrypt and store sync checkpoint in vault_meta.

        Checkpoint JSON:
        {
          "last_sync_seq": <int>,
          "state_hash": "<hex>",
          "timestamp": <unix_ms>
        }

        Encrypted with audit DEK, base64-encoded for TEXT storage.
        """
        checkpoint = self._checkpoint_record(commit_seq, state_hash)
        checkpoint_json = json.dumps(checkpoint, separators=(",", ":")).encode("utf-8")

        dek_id, dek = self._get_checkpoint_dek()
        if dek_id is not None and dek is not None:
            # Encrypt checkpoint with audit DEK
            checkpoint_obj_id = new_ulid()
            encrypted = encrypt(
                plaintext=checkpoint_json,
                dek=dek,
                dek_id=ulid_to_bytes(dek_id),
                object_id=ulid_to_bytes(checkpoint_obj_id),
                version=1,
                blob_kind=BlobKind.AUDIT_DETAILS,
            )
            # Store as: object_id(26-char ULID) + ":" + base64(encrypted_blob)
            encoded = checkpoint_obj_id + ":" + base64.b64encode(encrypted).decode("ascii")
            self._db.set_meta(_CHECKPOINT_META_KEY, encoded)
        else:
            raise RuntimeError(
                "Cannot store sync checkpoint without the audit DEK"
            )

    def _load_sync_checkpoint(self) -> Optional[dict]:
        """Load and decrypt sync checkpoint from vault_meta.

        Returns the checkpoint dict or None if not found.
        """
        raw = self._db.get_meta(_CHECKPOINT_META_KEY)
        if not raw:
            return None

        try:
            if raw.startswith("plain:"):
                raise SyncRollbackWarning(
                    "Refusing unauthenticated plaintext sync checkpoint"
                )

            # Encrypted format: object_id(26 chars) + ":" + base64(encrypted_blob)
            colon_pos = raw.index(":")
            checkpoint_obj_id = raw[:colon_pos]
            encrypted_blob = base64.b64decode(raw[colon_pos + 1:])

            dek_id, dek = self._get_checkpoint_dek()
            if dek_id is None or dek is None:
                logger.warning("Cannot decrypt checkpoint: no DEK manager")
                return None

            checkpoint_json = decrypt(
                envelope_blob=encrypted_blob,
                dek=dek,
                object_id=ulid_to_bytes(checkpoint_obj_id),
                version=1,
            )
            return json.loads(checkpoint_json)
        except SyncRollbackWarning:
            raise
        except Exception:
            logger.exception("Failed to load sync checkpoint")
            return None

    def _check_rollback(self, new_seq: int, new_state_hash: str, *, served: bool = True) -> None:
        """Compare the state after a pull with the stored checkpoint (the
        decision is the shared core's ``check_state``).

        Raises SyncRollbackWarning if commit_seq went backwards or the state
        at an unchanged seq differs. ``served``: the reply brought objects the
        server sent now, not only writes re-judged here.
        """
        old_checkpoint = self._load_sync_checkpoint()
        old_seq = (old_checkpoint or {}).get("last_sync_seq", 0)
        old_hash = (old_checkpoint or {}).get("state_hash", "")
        if old_checkpoint is not None and old_checkpoint.get("state_v") != STATE_HASH_VERSION:
            # R17-N1: a checkpoint from before is compared by its own formula.
            new_state_hash = legacy_state_hash(self._local_objects())
        verdict = sync_core.call(
            "check_state",
            stored=None if old_checkpoint is None else {"seq": old_seq, "state_hash": old_hash},
            candidate={"max_commit_seq": new_seq, "state_hash": new_state_hash, "served": served},
        )["state"]
        if verdict == "rollback":
            msg = (
                f"Sync rollback detected: server commit_seq {new_seq} "
                f"< stored checkpoint seq {old_seq}"
            )
            logger.error(msg)
            raise SyncRollbackWarning(msg)
        if verdict == "mismatch":
            msg = (
                f"Sync state mismatch at seq {new_seq}: "
                f"computed hash {new_state_hash[:16]}... "
                f"!= stored hash {old_hash[:16]}..."
            )
            logger.error(msg)
            raise SyncRollbackWarning(msg)

    def _commit_anchor(self) -> tuple[int, Optional[str]]:
        """The highest commit_seq this device saw committed, and its server token."""
        anchor = json.loads(self._db.get_meta(COMMIT_ANCHOR_META) or "{}")
        return int(anchor.get("seq") or 0), anchor.get("token")

    def _advance_commit_anchor(self, seq: int, token: Optional[str], *, reset: bool = False) -> None:
        if reset or seq > self._commit_anchor()[0]:
            self._db.set_meta(COMMIT_ANCHOR_META, json.dumps({"seq": seq, "token": token}))

    def _set_base(
        self, object_id: str, version: int, payload_hash: str, *, own: bool = False,
        parent: Optional[str] = None,
    ) -> None:
        """This device's copy of the object now builds on server copy
        (``version``, ``payload_hash``) — docs/SYNC_SINGLE_SOURCE.md point 1.

        ``own``: the server holds this device's own write of ``version``.
        ``parent``: that copy's parent_ref ('' none; None not known here).
        """
        for table in ("nodes", "entries"):
            self._db.execute(
                f"UPDATE {table} SET base_version = ?, base_hash = ?, base_parent = ? WHERE id = ?",
                (version, payload_hash, parent, object_id),
            )
        # The row of ``version`` itself stays: it tells this device's write of
        # that version from another one a restored server took (SM13). On top
        # of its own write, this device keeps what it sent since the last copy
        # it took from another device (SM17): a restore can lose all of it.
        keep_from = self._sent_from(object_id, version) if own else version
        self._db.execute(
            "DELETE FROM object_sent_version WHERE object_id = ? AND version < ?",
            (object_id, keep_from),
        )
        self._db.execute(
            "DELETE FROM object_sent_base WHERE object_id = ? AND version "
            + ("< ?" if own else "<= ?"),
            (object_id, keep_from),
        )

    def _sent_from(self, object_id: str, version: int) -> int:
        """The version of another device's copy this device's write of ``version`` stems from."""
        row = self._db.fetchone(
            "SELECT base_version FROM object_sent_base WHERE object_id = ? AND version = ?",
            (object_id, version),
        )
        return version if row is None else row["base_version"]

    def _written_without_my_write(self, object_id: str, version: int, server_copy: dict) -> bool:
        """The server's older copy was made past the base of this device's writes.

        Stateful test SM17: a restored server lost this device's writes up to
        ``version`` and another device then wrote on top of the backup. Its
        copy has a lower version when this device wrote several times, so it
        looked like a copy this device had already superseded, and the next
        push overwrote it without a conflict.
        """
        server_version = int(server_copy.get("version", 1))
        return server_version > self._sent_from(object_id, version) and not self._own_sent_version(
            object_id, server_version, server_copy.get("payload_hash")
        )

    @staticmethod
    def _committed_after(server_copy: dict, confirmed: tuple) -> bool:
        """The server's older copy was committed after this device's newer one.

        Nightly stateful-deep run on adc393a: a restored server lost a version
        another device wrote and this one pulled; a third device then wrote a
        lower version on top of the backup. One history commits a lower
        version before a higher one, so a copy committed later was made
        without this device's: building on it overwrote it unseen. The
        restored server counts commit_seq again from the backup, so a write
        made there can sit below the confirmed seq; its server clock cannot.
        ``confirmed`` is (commit_seq, modified_at) of this device's copy.
        """
        seq, modified_at = confirmed
        server_seq = server_copy.get("commit_seq")
        server_time = server_copy.get("modified_at")
        return (
            isinstance(server_seq, int) and isinstance(seq, int) and server_seq > seq
        ) or (
            isinstance(server_time, int) and isinstance(modified_at, int) and server_time > modified_at
        )

    def _base(self, object_id: str) -> Optional[tuple[int, str]]:
        """The server copy (version, payload_hash) the local row builds on.

        A row with no queued write is that copy; one with a queued write keeps
        the copy the write was made on. None: never on the server (or no such row).
        """
        row = self._db.fetchone(
            f"SELECT version, {outbox.queued('nodes')} AS queued, base_version, base_hash, "
            "encrypted_meta, NULL AS encrypted_data FROM nodes WHERE id = ?",
            (object_id,),
        ) or self._db.fetchone(
            f"SELECT version, {outbox.queued('entries')} AS queued, base_version, base_hash, "
            "encrypted_meta, encrypted_data FROM entries WHERE id = ?",
            (object_id,),
        )
        if row is None:
            return None
        if not row["queued"]:
            return row["version"], row_payload_hash(row["encrypted_meta"], row["encrypted_data"])
        if row["base_version"] is None:
            return None
        return row["base_version"], row["base_hash"]

    def _all_bases(self) -> dict[str, tuple[int, str]]:
        """``_base`` of every folder and entry that has one."""
        bases: dict[str, tuple[int, str]] = {}
        for table, data in (("nodes", "NULL"), ("entries", "encrypted_data")):
            for row in self._db.fetchall(
                f"SELECT id, version, {outbox.queued(table)} AS queued, base_version, "
                f"base_hash, encrypted_meta, {data} AS encrypted_data FROM {table}"
            ):
                if not row["queued"]:
                    bases[row["id"]] = (
                        row["version"],
                        row_payload_hash(row["encrypted_meta"], row["encrypted_data"]),
                    )
                elif row["base_version"] is not None:
                    bases[row["id"]] = (row["base_version"], row["base_hash"])
        return bases

    def _base_version(self, object_id: str) -> Optional[int]:
        base = self._base(object_id)
        return None if base is None else base[0]

    def _lost_same_version(self, object_id: str, server_copy: dict) -> bool:
        """The server holds another write of a version this device wrote (SM13)."""
        row = self._db.fetchone(
            "SELECT payload_hash FROM object_sent_version WHERE object_id = ? AND version = ?",
            (object_id, server_copy.get("version", 1)),
        )
        return row is not None and row["payload_hash"] != server_copy.get("payload_hash")

    def _is_server_copy(self, table: str, object_id: str, server_copy: dict) -> bool:
        """The local row is the server's copy at its own version.

        Stateful test SM60: a delete a dropped re-key held came back at the
        server copy's version (its blobs, the same payload hash), and a full
        resync took it for an unsent change of that copy. Sent at a version
        the server holds with another delete flag, it was refused on every
        push, and no conflict was left to settle it.
        """
        parent_column = "parent_id" if table == "nodes" else "node_id"
        row = self._db.fetchone(
            f"SELECT {parent_column} AS parent, is_deleted FROM {table} WHERE id = ?",
            (object_id,),
        )
        return row is not None and bool(row["is_deleted"]) == bool(
            server_copy.get("is_deleted")
        ) and (row["parent"] or None) == (server_copy.get("parent_ref") or None)

    def _own_sent_version(self, object_id: str, version, payload_hash) -> bool:
        if not isinstance(version, int) or not payload_hash:
            return False
        return self._db.fetchone(
            "SELECT 1 FROM object_sent_version WHERE object_id = ? AND version = ? "
            "AND payload_hash = ?",
            (object_id, version, payload_hash),
        ) is not None

    def _stamp_base_versions(self, objects: list[dict]) -> None:
        """Send folders and entries as changes of the server copy they were
        made on (stateful test SM1), and remember what was sent."""
        self._db.begin()
        try:
            for obj in objects:
                if obj["object_type"] not in ("node", "entry"):
                    continue
                found = self._base(obj["id"])
                if found is None:
                    # Never in step with the server: sent as a new object.
                    obj.pop("base_version", None)
                    obj.pop("base_payload_hash", None)
                else:
                    base, obj["base_payload_hash"] = found
                    obj["base_version"] = base
                    self._db.execute(
                        "INSERT OR REPLACE INTO object_sent_base (object_id, version, base_version) "
                        "VALUES (?, ?, ?)",
                        (obj["id"], obj["version"], self._sent_from(obj["id"], base)),
                    )
                self._db.execute(
                    "INSERT OR REPLACE INTO object_sent_version (object_id, version, payload_hash) "
                    "VALUES (?, ?, ?)",
                    (obj["id"], obj["version"], obj["payload_hash"]),
                )
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _record_server_seq(self, object_id: str, commit_seq, modified_at=None) -> None:
        if isinstance(commit_seq, int) and commit_seq > 0:
            self._db.execute(
                "INSERT OR REPLACE INTO object_server_seq (object_id, commit_seq) VALUES (?, ?)",
                (object_id, commit_seq),
            )
        if isinstance(modified_at, int) and modified_at > 0:
            self._db.execute(
                "INSERT OR REPLACE INTO object_server_time (object_id, modified_at) VALUES (?, ?)",
                (object_id, modified_at),
            )
        else:
            # A push reply carries no server time: no older one stands for it.
            self._db.execute("DELETE FROM object_server_time WHERE object_id = ?", (object_id,))

    def _revive_folders_of_unsent(self) -> None:
        """Bring back a folder deleted elsewhere that holds unsent work.

        Capability review 100: another device deleted the folder while this
        one created or edited an item in it. The pulled tombstone (or a full
        resync's snapshot) left the unsent item below a deleted folder, which
        the server refuses on every push (review d150605 #1), so the item never
        left this device. The folder is restored one version above the
        tombstone, as the trash does, and goes out ahead of the item.
        """
        for _ in range(64):  # one level of folders per round
            rows = self._db.fetchall(
                "SELECT n.id, n.encrypted_meta, n.version FROM nodes n WHERE n.is_deleted = 1 "
                "AND (EXISTS (SELECT 1 FROM entries e WHERE e.node_id = n.id "
                f"AND {outbox.queued('e')} AND e.is_deleted = 0) "
                "OR EXISTS (SELECT 1 FROM nodes c WHERE c.parent_id = n.id "
                f"AND {outbox.queued('c')} AND c.is_deleted = 0))"
            )
            if not rows:
                return
            if self._dek_mgr is None:
                raise RuntimeError("Unlock the vault to keep work in a folder deleted elsewhere")
            for row in rows:
                blob = bytes(row["encrypted_meta"])
                dek_id = parse_envelope(blob).dek_id
                dek = self._dek_mgr.unlock_dek(bytes_to_ulid(dek_id))
                meta = open_sealed(
                    blob, dek, row["id"], row["version"], BlobKind.NODE_META, deleted=True
                )[0]
                # R16-Z SM18: above every version this device sent, too, as
                # _rebase_local does (SM22). A rename this device sent at the
                # tombstone's version + 1 can be on the server (its reply lost
                # or lied about); revived at that version, a second content of
                # it went out, the server's copy no longer read as this
                # device's own write, and the folder was refused on every push
                # with no conflict left to settle.
                sent = self._db.fetchone(
                    "SELECT MAX(version) AS v FROM object_sent_version WHERE object_id = ?",
                    (row["id"],),
                )["v"]
                version = max(row["version"], sent or 0) + 1
                outbox.queue_write(self._db, row["id"])
                self._db.execute(
                    "UPDATE nodes SET encrypted_meta = ?, version = ?, is_deleted = 0 "
                    "WHERE id = ?",
                    (encrypt(
                        plaintext=meta, dek=dek, dek_id=dek_id,
                        object_id=ulid_to_bytes(row["id"]), version=version,
                        blob_kind=BlobKind.NODE_META,
                    ), version, row["id"]),
                )
                outbox.mark_revived(self._db, row["id"])
                logger.warning(
                    "Folder %s was deleted on another device but holds unsent work "
                    "here; it is kept and sent again", row["id"],
                )

    def _revived_ancestors(self, object_ids: set[str]) -> set[str]:
        """Revived folders not sent yet that hold one of the given objects."""
        revived = outbox.revived_folders(self._db)
        found: set[str] = set()
        for obj_id in object_ids:
            row = self._db.fetchone(
                "SELECT parent_id AS p FROM nodes WHERE id = ? UNION ALL "
                "SELECT node_id AS p FROM entries WHERE id = ?", (obj_id, obj_id),
            )
            parent = row["p"] if row else None
            for _ in range(64):
                if parent is None or parent not in revived or parent in found:
                    break
                found.add(parent)
                row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (parent,))
                parent = row["parent_id"] if row else None
        return found
