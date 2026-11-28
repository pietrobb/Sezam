"""Local edits a rebased re-key held: back as conflicts once the batch lands, or into history.

Split from sync_rekey.py (review d615826 R6-H, MAX_LINES)."""

from __future__ import annotations

import hashlib
import struct
import time

from ..crypto.aead import BlobKind, decrypt, encrypt, parse_envelope
from ..models import bytes_to_ulid, new_ulid, ulid_to_bytes
from . import outbox
from .sealed import open_sealed
from .sync_common import logger


class HeldEditsMixin:
    """Local edits a rebased re-key held: back as conflicts once the batch lands, or into history."""

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
            if edit.get("deleted") and "meta" not in edit:
                # The local copy is the delete; the server copy's blobs stay
                # (a tombstone's blobs are read at or below its version).
                outbox.queue_write(self._db, object_id)
                self._db.execute(f"UPDATE {table} SET is_deleted = 1 WHERE id = ?", (object_id,))
                continue

            def reseal(blob_hex: str, kind: BlobKind) -> bytes:
                blob = bytes.fromhex(blob_hex)
                dek_id = parse_envelope(blob).dek_id
                dek = self._dek_mgr.unlock_dek(bytes_to_ulid(dek_id))
                # A held delete's blobs are sealed at or below its version (R16-N23).
                plain = open_sealed(
                    blob, dek, object_id, int(edit["version"]), kind, deleted=bool(edit.get("deleted")),
                )[0]
                dek_id, dek = self._successor_dek(
                    dek_id, dek, (edit["parent"] or object_id) if is_node else edit["parent"]
                )
                return encrypt(
                    plaintext=plain, dek=dek, dek_id=dek_id,
                    object_id=ulid_to_bytes(object_id), version=version, blob_kind=kind,
                )

            # A held delete that carries its own change stays a delete, with it.
            deleted = int(bool(edit.get("deleted")))
            outbox.queue_write(self._db, object_id)
            if is_node:
                self._db.execute(
                    "UPDATE nodes SET parent_id = ?, encrypted_meta = ?, "
                    "is_deleted = ? WHERE id = ?",
                    (edit["parent"], reseal(edit["meta"], BlobKind.NODE_META), deleted, object_id),
                )
            else:
                self._db.execute(
                    "UPDATE entries SET node_id = ?, encrypted_meta = ?, encrypted_data = ?, "
                    "is_deleted = ? WHERE id = ?",
                    (
                        edit["parent"], reseal(edit["meta"], BlobKind.ENTRY_META),
                        reseal(edit["data"], BlobKind.ENTRY_DATA), deleted, object_id,
                    ),
                )
        if held:
            self._resolve_entry_deks()
