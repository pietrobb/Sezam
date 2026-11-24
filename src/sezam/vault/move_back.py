"""A folder move the server refused as crossed (R16-Z SM22, FOLDER_MOVE_CYCLE).

Another device's move put the new parent inside the folder first. Sent again
the move is refused again, so the folder goes back to the parent the server
keeps it under - taken only from the server's signed copy of the folder, and
only when that copy is the one this device's move was made on (INV-3: a lie
in an unsigned parent would have moved the folder, and resealed its subtree's
keys, below any folder the device holds).
"""

from __future__ import annotations

from typing import Optional

from ..crypto.aead import BlobKind, encrypt, parse_envelope
from ..models import bytes_to_ulid, ulid_to_bytes
from . import outbox
from .personal_root import in_personal_tree, moved_subtree_keys, personal_root_ids, reseal_moved_subtree
from .sealed import open_sealed
from .sync_common import FOLDER_MOVE_CYCLE
from .team_log_local import local_team_state, team_folder_at_or_above

_NO_PARENT = object()


def signed_server_parent(client, conflict: dict):
    """For a FOLDER_MOVE_CYCLE refusal, the parent the server keeps the folder
    under, from ``stored_object``: signed (``_verify_object_signature``) and
    the very copy the refused move was made on (the row's base version and
    hash). ``_NO_PARENT`` otherwise: the write stays queued, as for any
    refusal (the server could drop it)."""
    node_id, copy = conflict.get("id"), conflict.get("stored_object")
    if conflict.get("code") != FOLDER_MOVE_CYCLE or not isinstance(copy, dict) or (
        copy.get("id") != node_id or copy.get("object_type") != "node"
    ):
        return _NO_PARENT
    row = client._db.fetchone("SELECT base_version, base_hash FROM nodes WHERE id = ?", (node_id,))
    if row is None or row["base_version"] is None or (
        copy.get("version"), copy.get("payload_hash")
    ) != (row["base_version"], row["base_hash"]):
        return _NO_PARENT
    if not client._verify_object_signature(copy):
        return _NO_PARENT
    return copy.get("parent_ref")


def move_back_refused(client, node_id: str, parent_id: Optional[str]) -> None:
    """Put the folder back below ``parent_id`` as ``Vault.move_node`` would: its
    name sealed for that parent, its subtree's keys as there, one version above
    every one sent. Inside the caller's transaction."""
    db, dek_mgr = client._db, client._dek_mgr
    row = db.fetchone(
        "SELECT parent_id, encrypted_meta, version, is_deleted FROM nodes WHERE id = ?", (node_id,)
    )
    if row is None or row["parent_id"] == parent_id:
        return
    deleted = bool(row["is_deleted"])
    blob = bytes(row["encrypted_meta"])
    meta_dek_id = bytes_to_ulid(parse_envelope(blob).dek_id)
    meta_dek = dek_mgr.unlock_dek(meta_dek_id)
    plain = open_sealed(blob, meta_dek, node_id, row["version"], BlobKind.NODE_META, deleted=deleted)[0]
    here = dek_mgr.get_dek_for_node(row["parent_id"])[0] if row["parent_id"] else None
    changes = {}
    if parent_id is None or meta_dek_id != here:
        new_dek_id, new_dek = meta_dek_id, meta_dek  # a personal root keeps its own key
    else:
        new_dek_id, new_dek = dek_mgr.get_dek_for_node(parent_id)
        into_personal = in_personal_tree(db, parent_id, set(personal_root_ids(db, dek_mgr)))
        team = None if into_personal else local_team_state(db)
        changes = moved_subtree_keys(
            db, node_id, new_dek_id, into_personal,
            team.dek_index if team_folder_at_or_above(db, team, parent_id) else None,
        )
    sent = db.fetchone("SELECT MAX(version) AS v FROM object_sent_version WHERE object_id = ?", (node_id,))
    new_version = max(row["version"], (sent["v"] or 0) if sent else 0) + 1
    outbox.queue_write(db, node_id)
    db.execute(
        "UPDATE nodes SET parent_id = ?, encrypted_meta = ?, version = ? WHERE id = ?",
        (
            parent_id,
            encrypt(
                plaintext=plain, dek=new_dek, dek_id=ulid_to_bytes(new_dek_id),
                object_id=ulid_to_bytes(node_id),
                version=new_version - 1 if deleted else new_version,
                blob_kind=BlobKind.NODE_META,
            ),
            new_version, node_id,
        ),
    )
    reseal_moved_subtree(db, dek_mgr, node_id, changes)
    client._push_cache.pop(node_id, None)
