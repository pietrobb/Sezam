"""Sync checkpoint, rollback check and per-object base versions (spec 8.3).

Part of SyncClient (sync_client.py); split out without a change of behaviour.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from typing import Optional

from ..crypto.aead import BlobKind, decrypt, encrypt
from ..models import new_ulid, ulid_to_bytes

from . import outbox, sync_core
from .schema import row_payload_hash
from .sync_common import (
    _CHECKPOINT_META_KEY,
    COMMIT_ANCHOR_META,
    compute_state_hash,
    logger,
    SyncRollbackWarning,
)


class SyncStateMixin:
    """SyncClient methods: sync checkpoint, rollback check and per-object base versions (spec 8.3)."""

    # ── Sync Checkpoint (spec 8.3) ──

    def _compute_state_hash(self) -> str:
        """Compute state_hash over all local vault objects.

        state_hash = SHA-256( concat( sort_by_object_id(
            object_id(26B) || u32be(version) || SHA-256(payload)(32B)
        )))

        Each element is 62 bytes fixed. Sort lexicographically by object_id bytes.
        Includes every locally represented sync object, including tombstones,
        access envelopes, DEK archives, and audit records.
        """
        return compute_state_hash(self._local_objects())

    def _held_entries(self) -> set[tuple[str, int, str]]:
        """(id, version, payload_hash) of every server copy this device holds
        (goal #443: what it may vouch for under the account's current key).

        A queued row is its server copy only when a conflict keeps one; a
        version this device made and has not sent is none (R16-Z: a voucher of
        an unsent tombstone let a retired key sign that version live)."""
        unsent = {
            row["object_id"] for row in self._db.fetchall(
                "SELECT object_id FROM outbox WHERE kind = 'write' AND object_id NOT IN "
                "(SELECT object_id FROM sync_conflicts)"
            )
        }
        return {
            (obj_id, version, hashlib.sha256(payload).hexdigest())
            for obj_id, version, payload in self._local_objects()
            if obj_id not in unsent
        }

    def _local_objects(self) -> list[tuple[str, int, bytes]]:
        """(id, version, payload) of every locally represented sync object, as
        the server holds it (a queued row's server copy)."""
        objects: list[tuple[str, int, bytes]] = []
        server_shadows = {
            row["object_id"]: row
            for row in self._db.fetchall(
                "SELECT object_id, server_version, server_payload FROM sync_conflicts"
            )
        }

        # Nodes: payload = encrypted_meta
        for row in self._db.fetchall(
            f"SELECT id, version, encrypted_meta, {outbox.queued('nodes')} AS queued FROM nodes"
        ):
            shadow = server_shadows.get(row["id"]) if row["queued"] else None
            if shadow:
                objects.append((row["id"], shadow["server_version"], bytes(shadow["server_payload"])))
            else:
                objects.append((row["id"], row["version"], bytes(row["encrypted_meta"])))

        # Entries: payload = u32be(len(encrypted_meta)) + encrypted_meta + encrypted_data
        for row in self._db.fetchall(
            "SELECT id, version, encrypted_meta, encrypted_data, "
            f"{outbox.queued('entries')} AS queued FROM entries"
        ):
            shadow = server_shadows.get(row["id"]) if row["queued"] else None
            if shadow:
                objects.append((row["id"], shadow["server_version"], bytes(shadow["server_payload"])))
            else:
                meta_bytes = bytes(row["encrypted_meta"])
                payload = struct.pack(">I", len(meta_bytes)) + meta_bytes + bytes(row["encrypted_data"])
                objects.append((row["id"], row["version"], payload))

        # DEKs and archived DEKs: payload = encrypted_dek
        for table in ("deks", "dek_archive"):
            for row in self._db.fetchall(f"SELECT id, version, encrypted_dek FROM {table}"):
                objects.append((row["id"], row["version"], bytes(row["encrypted_dek"])))

        # Access envelopes: payload = encrypted_dek, protocol version = 1
        for row in self._db.fetchall("SELECT id, encrypted_dek FROM access_envelopes"):
            objects.append((row["id"], 1, bytes(row["encrypted_dek"])))

        # Audit objects hash the complete canonical signed record, not only details.
        for row in self._db.fetchall(
            "SELECT id, parent_ids, actor_id, action, encrypted_details, timestamp, "
            "signature FROM audit_log"
        ):
            objects.append((row["id"], 2, self._serialize_audit_row(row)))
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
        checkpoint = {
            "last_sync_seq": commit_seq,
            "state_hash": state_hash,
            "timestamp": int(time.time() * 1000),
        }
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
        self, object_id: str, version: int, payload_hash: str, *, own: bool = False
    ) -> None:
        """This device's copy of the object now builds on server copy
        (``version``, ``payload_hash``) — docs/SYNC_SINGLE_SOURCE.md point 1.

        ``own``: the server holds this device's own write of ``version``.
        """
        for table in ("nodes", "entries"):
            self._db.execute(
                f"UPDATE {table} SET base_version = ?, base_hash = ? WHERE id = ?",
                (version, payload_hash, object_id),
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
