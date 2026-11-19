"""Recovering deleted entries and folders, and earlier versions of an entry.

A delete only marks rows as tombstones (lockout review M2): the encrypted
blobs stay, sealed at the version they had before the delete. Restoring
decrypts them with the DEK named in their header and seals them again,
one version higher, so the restore syncs like any other edit.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from nacl.exceptions import CryptoError

from ..crypto.aead import BlobKind, decrypt, encrypt, parse_envelope
from ..models import EntryData, EntryMeta, NodeMeta, bytes_to_ulid, ulid_to_bytes
from . import outbox
from .sealed import open_sealed

if TYPE_CHECKING:
    from .crud import Vault


class TrashError(RuntimeError):
    """The deleted item cannot be restored as asked."""


def _open_sealed(vault: Vault, blob: bytes, object_id: str, version: int, kind: BlobKind) -> bytes:
    blob = bytes(blob)
    try:
        dek_id = bytes_to_ulid(parse_envelope(blob).dek_id)
        dek = vault.dek_mgr.unlock_dek(dek_id)
    except (KeyError, ValueError, CryptoError) as exc:
        raise TrashError(f"{object_id} cannot be opened on this device") from exc
    try:
        return open_sealed(blob, dek, object_id, version, kind, deleted=True)[0]
    except CryptoError as exc:
        raise TrashError(f"{object_id} cannot be opened on this device") from exc


def _node_alive(vault: Vault, node_id: str | None) -> bool:
    if node_id is None:
        return False
    return vault.db.fetchone(
        "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (node_id,)
    ) is not None


def _entry_name(vault: Vault, row) -> str:
    try:
        meta = EntryMeta.from_json(
            _open_sealed(vault, row["encrypted_meta"], row["id"], row["version"], BlobKind.ENTRY_META)
        )
        return meta.name
    except TrashError:
        return "(unreadable here)"


def _node_name(vault: Vault, row) -> str:
    try:
        meta = NodeMeta.from_json(
            _open_sealed(vault, row["encrypted_meta"], row["id"], row["version"], BlobKind.NODE_META)
        )
        return meta.name
    except TrashError:
        return "(unreadable here)"


def list_trash(vault: Vault) -> list[dict]:
    """Deleted folders and entries whose parent folder still exists.

    Entries inside a deleted folder come back with that folder, so they are
    counted on the folder instead of listed one by one.
    """
    vault._require_unlocked()
    items = []
    for row in vault.db.fetchall(
        "SELECT n.id, n.parent_id, n.encrypted_meta, n.version FROM nodes n "
        "JOIN nodes p ON p.id = n.parent_id "
        "WHERE n.is_deleted = 1 AND p.is_deleted = 0"
    ):
        subtree = _deleted_subtree(vault, row["id"])
        marks = ",".join("?" for _ in subtree)
        entries = vault.db.fetchone(
            f"SELECT COUNT(*) AS count FROM entries WHERE is_deleted = 1 AND node_id IN ({marks})",
            tuple(subtree),
        )["count"]
        items.append({
            "id": row["id"],
            "type": "folder",
            "name": _node_name(vault, row),
            "path": vault._build_node_path(row["parent_id"]),
            "entries": entries,
        })
    for row in vault.db.fetchall(
        "SELECT e.id, e.node_id, e.encrypted_meta, e.version FROM entries e "
        "JOIN nodes p ON p.id = e.node_id "
        "WHERE e.is_deleted = 1 AND p.is_deleted = 0"
    ):
        items.append({
            "id": row["id"],
            "type": "entry",
            "name": _entry_name(vault, row),
            "path": vault._build_node_path(row["node_id"]),
        })
    return sorted(items, key=lambda item: (item["path"].lower(), item["name"].lower()))


def _deleted_subtree(vault: Vault, node_id: str) -> list[str]:
    rows = vault.db.fetchall(
        "WITH RECURSIVE subtree(id) AS ("
        "SELECT id FROM nodes WHERE id = ? AND is_deleted = 1 "
        "UNION ALL "
        "SELECT nodes.id FROM nodes JOIN subtree ON nodes.parent_id = subtree.id "
        "WHERE nodes.is_deleted = 1"
        ") SELECT id FROM subtree",
        (node_id,),
    )
    return [row["id"] for row in rows]


def _resealed_entry(vault: Vault, row) -> tuple:
    meta = _open_sealed(vault, row["encrypted_meta"], row["id"], row["version"], BlobKind.ENTRY_META)
    data = _open_sealed(vault, row["encrypted_data"], row["id"], row["version"], BlobKind.ENTRY_DATA)
    if row["dek_id"] is None:
        dek_id, dek = vault.dek_mgr.get_dek_for_node(row["node_id"])
    else:
        dek_id, dek = row["dek_id"], vault.dek_mgr.unlock_dek(row["dek_id"])
    version = row["version"] + 1
    seal = dict(dek=dek, dek_id=ulid_to_bytes(dek_id), object_id=ulid_to_bytes(row["id"]), version=version)
    return (
        encrypt(plaintext=meta, blob_kind=BlobKind.ENTRY_META, **seal),
        encrypt(plaintext=data, blob_kind=BlobKind.ENTRY_DATA, **seal),
        version,
        row["id"],
    )


def _resealed_node(vault: Vault, row) -> tuple:
    meta = _open_sealed(vault, row["encrypted_meta"], row["id"], row["version"], BlobKind.NODE_META)
    header_dek_id = bytes_to_ulid(parse_envelope(bytes(row["encrypted_meta"])).dek_id)
    if row["dek_id"] is not None and header_dek_id == row["dek_id"]:
        dek_id, dek = row["dek_id"], vault.dek_mgr.unlock_dek(row["dek_id"])
    else:
        dek_id, dek = vault.dek_mgr.get_dek_for_node(row["parent_id"])
    version = row["version"] + 1
    blob = encrypt(
        plaintext=meta, dek=dek, dek_id=ulid_to_bytes(dek_id),
        object_id=ulid_to_bytes(row["id"]), version=version, blob_kind=BlobKind.NODE_META,
    )
    return blob, version, row["id"]


def _write(vault: Vault, nodes: list[tuple], entries: list[tuple]) -> None:
    db = vault.db
    db.begin()
    try:
        for row in nodes + entries:
            outbox.queue_write(db, row[-1])
        db.executemany(
            "UPDATE nodes SET encrypted_meta = ?, version = ?, is_deleted = 0 "
            "WHERE id = ?",
            nodes,
        )
        db.executemany(
            "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, version = ?, "
            "is_deleted = 0 WHERE id = ?",
            entries,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    vault._rebuild_search_index()


def restore_entry(vault: Vault, entry_id: str) -> None:
    """Bring back a deleted entry into its folder (which must exist)."""
    vault._require_unlocked()
    row = vault.db.fetchone(
        "SELECT id, node_id, encrypted_meta, encrypted_data, dek_id, version "
        "FROM entries WHERE id = ? AND is_deleted = 1",
        (entry_id,),
    )
    if row is None:
        raise KeyError(f"No deleted entry {entry_id}")
    if not _node_alive(vault, row["node_id"]):
        raise TrashError("Its folder is deleted too; restore the folder instead")
    vault._require_trusted_node_write(row["node_id"])
    _write(vault, [], [_resealed_entry(vault, row)])
    vault._audit_log("write", json.dumps({"target": entry_id, "action": "restore"}).encode())


def restore_node(vault: Vault, node_id: str) -> int:
    """Bring back a deleted folder with its deleted subfolders and entries.

    Returns the number of entries restored. All of it is restored in one
    transaction, or nothing is.
    """
    vault._require_unlocked()
    row = vault.db.fetchone(
        "SELECT parent_id FROM nodes WHERE id = ? AND is_deleted = 1", (node_id,)
    )
    if row is None:
        raise KeyError(f"No deleted folder {node_id}")
    if not _node_alive(vault, row["parent_id"]):
        raise TrashError("Its parent folder is deleted too; restore that folder instead")
    vault._require_trusted_node_write(node_id)
    subtree = _deleted_subtree(vault, node_id)
    marks = ",".join("?" for _ in subtree)
    node_rows = {
        r["id"]: r
        for r in vault.db.fetchall(
            f"SELECT id, parent_id, encrypted_meta, dek_id, version FROM nodes WHERE id IN ({marks})",
            tuple(subtree),
        )
    }
    entry_rows = vault.db.fetchall(
        "SELECT id, node_id, encrypted_meta, encrypted_data, dek_id, version FROM entries "
        f"WHERE is_deleted = 1 AND node_id IN ({marks})",
        tuple(subtree),
    )
    nodes = [_resealed_node(vault, node_rows[item]) for item in subtree]
    entries = [_resealed_entry(vault, item) for item in entry_rows]
    _write(vault, nodes, entries)
    vault._audit_log(
        "write",
        json.dumps({
            "target": node_id, "action": "restore",
            "nodes": len(nodes), "entries": len(entries),
        }).encode(),
    )
    return len(entries)


# ── Entry history ──


def list_history(vault: Vault, entry_id: str) -> list[dict]:
    """Earlier field versions of a live entry, newest first."""
    vault._require_unlocked()
    if vault.db.fetchone(
        "SELECT 1 FROM entries WHERE id = ? AND is_deleted = 0", (entry_id,)
    ) is None:
        raise KeyError(f"Entry not found: {entry_id}")
    rows = vault.db.fetchall(
        "SELECT id, changed_at FROM entry_history WHERE entry_id = ? "
        "ORDER BY changed_at DESC, id DESC",
        (entry_id,),
    )
    return [{"id": row["id"], "changed_at": row["changed_at"]} for row in rows]


def read_history(vault: Vault, entry_id: str, snapshot_id: str) -> list[dict]:
    """Fields of one history version of the entry."""
    vault._require_unlocked()
    row = vault.db.fetchone(
        "SELECT id, encrypted_snapshot, dek_id FROM entry_history WHERE id = ? AND entry_id = ?",
        (snapshot_id, entry_id),
    )
    if row is None:
        raise KeyError(f"No history version {snapshot_id} for this entry")
    try:
        dek = vault.dek_mgr.unlock_dek(row["dek_id"])
        plaintext = decrypt(
            bytes(row["encrypted_snapshot"]), dek, ulid_to_bytes(row["id"]), 1,
            expected_blob_kind=BlobKind.HISTORY_SNAPSHOT,
        )
    except (KeyError, ValueError, CryptoError) as exc:
        raise TrashError(f"History version {snapshot_id} cannot be opened on this device") from exc
    vault._audit_log("read", json.dumps({"target": entry_id, "history": snapshot_id}).encode())
    return [field.to_dict() for field in EntryData.from_json(plaintext).fields]


def restore_history(vault: Vault, entry_id: str, snapshot_id: str) -> None:
    """Put the fields of a history version back; the current ones go to history."""
    vault.update_entry(entry_id, fields=read_history(vault, entry_id, snapshot_id))
