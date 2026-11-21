"""Personal roots (TL7, docs/DESIGN_TEAM_LOG.md §10).

A member's personal folder is a top-level folder whose meta is sealed with a
key of the member's own and says ``personal: true``. It is never the account's
or the organisation's root; the label comes from the signed, sealed meta, so
the server cannot make the org root personal or a personal root the org root.
"""

from __future__ import annotations

from nacl.exceptions import CryptoError

from ..crypto.aead import BlobKind, decrypt, encrypt, parse_envelope
from ..models import NodeMeta, bytes_to_ulid, ulid_to_bytes
from . import outbox
from .sync_common import REFUSED_DEKS_META


# Review 4acfdde R11 (low): a server older than TL7 refuses every top-level
# node of a member with this error, the member's personal root too. Those
# roots wait on the device (meta below) until the server is updated.
TOP_LEVEL_REFUSED = "write_acl denied (top-level)"
PERSONAL_ROOTS_WAITING_META = "personal_roots_waiting_for_server"


def personal_roots_refused(db, dek_mgr, conflicts: list[dict], accepted: list[str]) -> list[str]:
    """Record which personal roots a pre-TL7 server refused; returns them."""
    before = db.get_meta_json(PERSONAL_ROOTS_WAITING_META) or []
    waiting = set(before) - set(accepted)
    waiting |= {
        c["id"] for c in conflicts
        if c.get("error") == TOP_LEVEL_REFUSED and is_personal_root(db, dek_mgr, c.get("id") or "")
    }
    waiting = {i for i in waiting if db.fetchone("SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (i,))}
    if sorted(waiting) != before:
        db.set_meta_json(PERSONAL_ROOTS_WAITING_META, sorted(waiting))
    return sorted(waiting)


def is_personal_root(db, dek_mgr, node_id: str) -> bool:
    """Is ``node_id`` a top-level folder whose own sealed meta marks it personal?"""
    row = db.fetchone(
        "SELECT parent_id, encrypted_meta, version FROM nodes WHERE id = ? AND is_deleted = 0",
        (node_id,),
    )
    if row is None or row["parent_id"] is not None or dek_mgr is None:
        return False
    try:
        blob = bytes(row["encrypted_meta"])
        dek = dek_mgr.unlock_dek(bytes_to_ulid(parse_envelope(blob).dek_id))
        plain = decrypt(blob, dek, ulid_to_bytes(node_id), row["version"],
                        expected_blob_kind=BlobKind.NODE_META)
        return NodeMeta.from_json(plain).personal
    except (CryptoError, KeyError, ValueError, TypeError):
        return False


def personal_root_ids(db, dek_mgr) -> list[str]:
    """This device's openable personal roots."""
    rows = db.fetchall("SELECT id FROM nodes WHERE parent_id IS NULL AND is_deleted = 0 ORDER BY id")
    return [row["id"] for row in rows if is_personal_root(db, dek_mgr, row["id"])]


def in_personal_tree(db, node_id, roots) -> bool:
    """Is ``node_id`` one of ``roots`` (personal_root_ids) or below one?"""
    current = node_id
    for _ in range(64):
        if current is None:
            return False
        if current in roots:
            return True
        row = db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (current,))
        current = row["parent_id"] if row else None
    return False


def fold_personal_tree_keys(db, dek_mgr) -> int:
    """Move folders below a personal root off keys the server never took.

    The desktop gave such a folder a key of its own. The server takes no key
    of a member's that names a folder, so the folder's name went up (sealed
    under its parent's key) and its items under a key no other device ever
    got. A personal tree has one key, as on the web and the phone: the
    folder's items, subfolders' names and history are resealed under its
    parent's key, and the stray key is dropped. Keys the server holds stay.
    Returns how many keys were folded.
    """
    landed = db.get_meta_json("pushed_dek_versions") or {}
    rows = [
        row for row in db.fetchall(
            "SELECT d.id, d.node_id FROM deks d JOIN nodes n ON n.id = d.node_id AND n.dek_id = d.id "
            "WHERE d.scope = 'folder' AND n.parent_id IS NOT NULL AND n.is_deleted = 0"
        )
        if row["id"] not in landed and not db.fetchone(
            "SELECT 1 FROM access_envelopes WHERE dek_id = ? UNION ALL "
            "SELECT 1 FROM dek_archive WHERE replaced_by = ?", (row["id"], row["id"])
        )
    ]
    if not rows:
        return 0
    roots = set(personal_root_ids(db, dek_mgr))
    rows = [row for row in rows if in_personal_tree(db, row["node_id"], roots)]

    def depth(node_id):
        n = 0
        while node_id is not None and n < 64:
            row = db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (node_id,))
            node_id, n = (row["parent_id"] if row else None), n + 1
        return n

    for row in sorted(rows, key=lambda r: depth(r["node_id"])):  # parents first
        _fold_key(db, dek_mgr, row["id"], row["node_id"])
    return len(rows)


def _resealer(old_key, new_key, new_id: str):
    def reseal(blob, object_id, version, deleted, kind, padded=True):
        from .sealed import open_sealed

        plain, _ = open_sealed(blob, old_key, object_id, version, kind, deleted=deleted)
        # A tombstone's blobs stay one version below the row (sealed.py).
        return encrypt(
            plain, new_key, ulid_to_bytes(new_id), ulid_to_bytes(object_id),
            version=version if deleted else version + 1, blob_kind=kind, enable_padding=padded,
        )
    return reseal


def moved_subtree_keys(
    db, node_id: str, new_parent_key: str, into_personal: bool, logged=None,
) -> dict[str, tuple]:
    """The key each folder of a moved subtree takes: {node_id: (old_key, new_key)}.

    Review 1141a20 (R9-E): a folder without a key of its own uses its
    parent's, so after a move it takes the new parent's; one with its own key
    keeps it. A personal tree has one key, the owner's: there every folder
    takes it. Only the folders whose key changes are named.

    ``logged``: the team log's key ids when the target is in a team folder.
    There a folder keeps its own key only if the log names it (review e443cbc
    R15: every client refuses what a key the log does not know seals).
    """
    changes: dict[str, tuple] = {}
    todo = [(node_id, new_parent_key)]
    while todo:
        current, parent_key = todo.pop()
        row = db.fetchone(
            "SELECT n.dek_id, d.node_id AS key_owner FROM nodes n "
            "LEFT JOIN deks d ON d.id = n.dek_id WHERE n.id = ?", (current,)
        )
        keeps = row["key_owner"] == current and (logged is None or row["dek_id"] in logged)
        key = parent_key if into_personal or not keeps else row["dek_id"]
        if key != row["dek_id"]:
            changes[current] = (row["dek_id"], key)
        todo.extend((r["id"], key) for r in db.fetchall("SELECT id FROM nodes WHERE parent_id = ?", (current,)))
    return changes


def reseal_moved_subtree(db, dek_mgr, node_id: str, changes: dict[str, tuple]) -> None:
    """Reseal what a moved subtree's folders hold under their new keys.

    Inside the caller's transaction. For each folder in ``changes``: its items
    sealed with the folder's key and their history, and the names of its
    subfolders; the moved folder's own name the caller has resealed.
    """
    keys: dict[str, bytearray] = {}

    def key(dek_id):
        if dek_id not in keys:
            keys[dek_id] = dek_mgr.unlock_dek(dek_id)
        return keys[dek_id]

    for folder, (old_id, new_id) in changes.items():
        reseal = _resealer(key(old_id), key(new_id), new_id)
        for entry in db.fetchall(
            "SELECT id, encrypted_meta, encrypted_data, version, is_deleted FROM entries "
            "WHERE node_id = ? AND dek_id IS NULL", (folder,)
        ):
            deleted = bool(entry["is_deleted"])
            outbox.queue_write(db, entry["id"])
            db.execute(
                "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, version = ? "
                "WHERE id = ?",
                (reseal(entry["encrypted_meta"], entry["id"], entry["version"], deleted, BlobKind.ENTRY_META),
                 reseal(entry["encrypted_data"], entry["id"], entry["version"], deleted, BlobKind.ENTRY_DATA),
                 entry["version"] + 1, entry["id"]),
            )
            for snap in db.fetchall(
                "SELECT id, encrypted_snapshot FROM entry_history WHERE entry_id = ? AND dek_id = ?",
                (entry["id"], old_id),
            ):
                plain = decrypt(bytes(snap["encrypted_snapshot"]), key(old_id), ulid_to_bytes(snap["id"]), 1,
                                expected_blob_kind=BlobKind.HISTORY_SNAPSHOT)
                db.execute(
                    "UPDATE entry_history SET encrypted_snapshot = ?, dek_id = ? WHERE id = ?",
                    (encrypt(plain, key(new_id), ulid_to_bytes(new_id), ulid_to_bytes(snap["id"]),
                             version=1, blob_kind=BlobKind.HISTORY_SNAPSHOT), new_id, snap["id"]),
                )
        for child in db.fetchall(
            "SELECT id, encrypted_meta, version, is_deleted FROM nodes "
            "WHERE parent_id = ? AND substr(encrypted_meta, 4, 26) = ?", (folder, ulid_to_bytes(old_id))
        ):
            outbox.queue_write(db, child["id"])
            db.execute(
                "UPDATE nodes SET encrypted_meta = ?, version = ? WHERE id = ?",
                (reseal(child["encrypted_meta"], child["id"], child["version"],
                        bool(child["is_deleted"]), BlobKind.NODE_META),
                 child["version"] + 1, child["id"]),
            )
    for folder, (_, new_id) in changes.items():
        outbox.queue_write(db, folder)
        db.execute("UPDATE nodes SET dek_id = ? WHERE id = ?", (new_id, folder))


def _fold_key(db, dek_mgr, old_id: str, node_id: str) -> None:
    parent = db.fetchone(
        "SELECT p.dek_id FROM nodes n JOIN nodes p ON p.id = n.parent_id WHERE n.id = ?", (node_id,)
    )
    new_id = parent["dek_id"]
    old_key, new_key = dek_mgr.unlock_dek(old_id), dek_mgr.unlock_dek(new_id)
    reseal = _resealer(old_key, new_key, new_id)

    with db.transaction():
        folders = [r["id"] for r in db.fetchall("SELECT id FROM nodes WHERE dek_id = ?", (old_id,))]
        header = ulid_to_bytes(old_id)
        for folder in folders:
            for entry in db.fetchall(
                "SELECT id, encrypted_meta, encrypted_data, version, is_deleted FROM entries "
                "WHERE node_id = ? AND dek_id IS NULL", (folder,)
            ):
                deleted = bool(entry["is_deleted"])
                outbox.queue_write(db, entry["id"])
                db.execute(
                    "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, version = ? "
                    "WHERE id = ?",
                    (reseal(entry["encrypted_meta"], entry["id"], entry["version"], deleted,
                            BlobKind.ENTRY_META),
                     reseal(entry["encrypted_data"], entry["id"], entry["version"], deleted,
                            BlobKind.ENTRY_DATA),
                     entry["version"] + 1, entry["id"]),
                )
            for child in db.fetchall(
                "SELECT id, encrypted_meta, version, is_deleted FROM nodes "
                "WHERE parent_id = ? AND substr(encrypted_meta, 4, 26) = ?", (folder, header)
            ):
                outbox.queue_write(db, child["id"])
                db.execute(
                    "UPDATE nodes SET encrypted_meta = ?, version = ? WHERE id = ?",
                    (reseal(child["encrypted_meta"], child["id"], child["version"],
                            bool(child["is_deleted"]), BlobKind.NODE_META),
                     child["version"] + 1, child["id"]),
                )
        for snap in db.fetchall(
            "SELECT id, encrypted_snapshot FROM entry_history WHERE dek_id = ?", (old_id,)
        ):
            plain = decrypt(bytes(snap["encrypted_snapshot"]), old_key, ulid_to_bytes(snap["id"]), 1,
                            expected_blob_kind=BlobKind.HISTORY_SNAPSHOT)
            db.execute(
                "UPDATE entry_history SET encrypted_snapshot = ?, dek_id = ? WHERE id = ?",
                (encrypt(plain, new_key, ulid_to_bytes(new_id), ulid_to_bytes(snap["id"]), version=1,
                         blob_kind=BlobKind.HISTORY_SNAPSHOT), new_id, snap["id"]),
            )
        db.execute("UPDATE nodes SET dek_id = ? WHERE dek_id = ?", (new_id, old_id))
        db.execute("DELETE FROM deks WHERE id = ?", (old_id,))
        old_key[:] = b"\x00" * len(old_key)
        dek_mgr._dek_cache.pop(old_id, None)
        refused = db.get_meta_json(REFUSED_DEKS_META) or []
        if old_id in refused:
            db.set_meta_json(REFUSED_DEKS_META, [k for k in refused if k != old_id])
