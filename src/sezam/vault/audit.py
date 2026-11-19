"""Audit log with Merkle DAG + Ed25519 signatures.

Spec 4.3: Each audit record references a list of known leaf nodes (DAG, not linear chain).
Ed25519 signature is independently verifiable.

Canonical signed data (all fields fixed-length or length-prefixed):
  id(26B) || actor_id(26B) || u16be(len(parent_ids_json)) || parent_ids_json
  || u16be(len(action)) || action || timestamp_u64be(8B) || SHA-256(encrypted_details)(32B)
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
from typing import Optional

from nacl.signing import SigningKey

from ..crypto.aead import BlobKind, encrypt
from ..models import new_ulid, ulid_to_bytes
from .db import VaultDB


class AuditLog:
    """Merkle DAG audit log with Ed25519 signatures."""

    def __init__(self, db: VaultDB):
        self._db = db

    def append(
        self,
        actor_id: str,
        action: str,
        signing_key: SigningKey,
        encrypted_details: Optional[bytes] = None,
        detail_plaintext: Optional[bytes] = None,
        audit_dek: Optional[bytearray] = None,
        audit_dek_id: Optional[str] = None,
    ) -> str:
        """Append a new audit record.

        Args:
            actor_id: ULID of the user performing the action.
            action: One of 'read', 'write', 'delete', 'approve', 'deny', 'share', 'rekey'.
            signing_key: Actor's Ed25519 signing key.
            encrypted_details: Pre-encrypted details blob (optional).
            detail_plaintext: Plaintext details to encrypt with audit DEK (optional).
            audit_dek: Audit DEK for encrypting details (required if detail_plaintext given).
            audit_dek_id: ULID of the audit DEK.

        Returns:
            Audit record ULID.
        """
        record_id = new_ulid()
        now_ms = int(time.time() * 1000)

        # Find current leaf nodes (records with no children)
        parent_ids = self._get_current_leaves()
        parent_ids_json = json.dumps(sorted(parent_ids), separators=(",", ":"))

        # Encrypt details if plaintext provided
        if detail_plaintext is not None and audit_dek is not None and audit_dek_id is not None:
            encrypted_details = encrypt(
                plaintext=detail_plaintext,
                dek=audit_dek,
                dek_id=ulid_to_bytes(audit_dek_id),
                object_id=ulid_to_bytes(record_id),
                version=1,
                blob_kind=BlobKind.AUDIT_DETAILS,
            )

        # Build canonical signed data
        details_hash = (
            hashlib.sha256(encrypted_details).digest()
            if encrypted_details
            else b"\x00" * 32
        )
        canonical = self._build_canonical(
            record_id, actor_id, parent_ids_json, action, now_ms, details_hash
        )

        # Sign
        signature = signing_key.sign(canonical).signature

        # Insert record
        self._db.execute(
            "INSERT INTO audit_log (id, parent_ids, actor_id, action, encrypted_details, timestamp, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (record_id, parent_ids_json, actor_id, action, encrypted_details, now_ms, signature),
        )

        # Materialize DAG edges
        for parent_id in parent_ids:
            self._db.execute(
                "INSERT OR IGNORE INTO audit_dag_edges (child_id, parent_id) VALUES (?, ?)",
                (record_id, parent_id),
            )

        return record_id

    def verify_record(self, record_id: str, verify_key_bytes: bytes) -> bool:
        """Verify the Ed25519 signature of an audit record.

        Args:
            record_id: ULID of the record.
            verify_key_bytes: 32-byte Ed25519 public key of the actor.

        Returns:
            True if signature is valid.
        """
        from nacl.signing import VerifyKey

        row = self._db.fetchone(
            "SELECT id, parent_ids, actor_id, action, encrypted_details, timestamp, signature "
            "FROM audit_log WHERE id = ?",
            (record_id,),
        )
        if row is None:
            return False

        details_hash = (
            hashlib.sha256(row["encrypted_details"]).digest()
            if row["encrypted_details"]
            else b"\x00" * 32
        )

        canonical = self._build_canonical(
            row["id"],
            row["actor_id"],
            row["parent_ids"],
            row["action"],
            row["timestamp"],
            details_hash,
        )

        try:
            vk = VerifyKey(verify_key_bytes)
            vk.verify(canonical, row["signature"])
            return True
        except Exception:
            return False

    def get_records(
        self,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[int] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query audit records with optional filters."""
        conditions = []
        params: list = []

        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)
        if action:
            conditions.append("action = ?")
            params.append(action)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = self._db.fetchall(
            f"SELECT id, parent_ids, actor_id, action, timestamp "
            f"FROM audit_log WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            tuple(params) + (limit,),
        )

        return [
            {
                "id": row["id"],
                "parent_ids": json.loads(row["parent_ids"]),
                "actor_id": row["actor_id"],
                "action": row["action"],
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]

    def _get_current_leaves(self) -> list[str]:
        """Get current DAG leaf nodes (records with no children)."""
        rows = self._db.fetchall(
            "SELECT id FROM audit_log WHERE id NOT IN "
            "(SELECT parent_id FROM audit_dag_edges)"
        )
        return [row["id"] for row in rows]

    def reattribute_unpushed(
        self, old_actor_id: str, new_actor_id: str, signing_key: SigningKey
    ) -> int:
        """Re-sign never-pushed records of ``old_actor_id`` as ``new_actor_id``.

        Used when a local vault is bound to its server identity: records written
        before connecting carry the local-only id, which the server and peers can
        never resolve to a signing key. Record ids and parent links are kept, so
        the DAG stays intact. Already pushed records are left untouched.
        """
        rows = self._db.fetchall(
            "SELECT a.id, a.parent_ids, a.action, a.encrypted_details, a.timestamp "
            "FROM audit_log a WHERE a.actor_id = ? AND EXISTS (SELECT 1 FROM outbox o "
            "WHERE o.kind = 'audit' AND o.object_id = a.id AND o.state = 'queued')",
            (old_actor_id,),
        )
        for row in rows:
            details = row["encrypted_details"]
            details_hash = hashlib.sha256(details).digest() if details else b"\x00" * 32
            canonical = self._build_canonical(
                row["id"], new_actor_id, row["parent_ids"], row["action"],
                row["timestamp"], details_hash,
            )
            self._db.execute(
                "UPDATE audit_log SET actor_id = ?, signature = ? WHERE id = ?",
                (new_actor_id, signing_key.sign(canonical).signature, row["id"]),
            )
        return len(rows)

    @staticmethod
    def _build_canonical(
        record_id: str,
        actor_id: str,
        parent_ids_json: str,
        action: str,
        timestamp_ms: int,
        details_hash: bytes,
    ) -> bytes:
        """Build canonical signed data for Ed25519 signature.

        Format: id(26B) || actor_id(26B)
                || u16be(len(parent_ids_json)) || parent_ids_json
                || u16be(len(action)) || action
                || timestamp_u64be(8B)
                || SHA-256(encrypted_details)(32B)
        """
        pid_bytes = parent_ids_json.encode("utf-8")
        action_bytes = action.encode("utf-8")

        return (
            ulid_to_bytes(record_id)  # 26B
            + ulid_to_bytes(actor_id)  # 26B
            + struct.pack(">H", len(pid_bytes))
            + pid_bytes
            + struct.pack(">H", len(action_bytes))
            + action_bytes
            + struct.pack(">Q", timestamp_ms)  # 8B
            + details_hash  # 32B
        )
