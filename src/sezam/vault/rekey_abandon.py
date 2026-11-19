"""Drop a pending member re-key batch (review 526419e V3).

A re-key batch is atomic and always goes first, so a batch the server can
never take blocked every sync of the device, and every other way out
(conflict resolution, full resync, another re-key, identity rotation) is
refused while it is pending. Dropping it undoes the re-key locally:

* an object the server holds a newer copy of takes that copy; a local edit
  of it comes back as an ordinary conflict;
* any other object sealed with the batch's new DEK is sealed again with the
  key its folder uses now (the old DEK, or the one another device's re-key
  of the same member put there) and is pushed as a normal change;
* the new DEKs, their archive records and envelopes are removed and the
  envelopes the re-key deleted come back for folders still on the old DEK.

A member who can still open a folder here is queued for a fresh re-key, so
the next push cuts them off from the current state.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Optional

from ..crypto.aead import BlobKind, encrypt, parse_envelope
from ..models import bytes_to_ulid, new_ulid, ulid_to_bytes
from . import oplock, outbox, pending_states
from .sealed import open_sealed
from .sync_common import queued_for_removal, reseal_key_row, vouched_access_level

if TYPE_CHECKING:
    from .sync_client import SyncClient

logger = logging.getLogger(__name__)


def superseded_rekey(client: "SyncClient") -> bool:
    """True when no folder uses one of the pending batch's new DEKs any more.

    That happens when another device of this account re-keyed that folder
    and the pull bound it to its DEK: resent unchanged, the batch is refused
    for good. Stateful test SM58: one such folder is enough (the batch still
    carried its items under its own new key); dropped, the member is queued
    for a fresh re-key of what they can still open.
    """
    pending = pending_states.rekey_batch(client._db)
    dek_map = pending.get("dek_map") or {}
    if not dek_map or pending.get("identity_rotation"):
        return False
    return any(
        client._db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ?", (new,)) is None
        for new in dek_map.values()
    )


def _grant_again(client: "SyncClient", grant, dek_id: Optional[str]) -> None:
    """Seal a grant the dropped batch held under its new key for ``dek_id``,
    the key the folder uses now, to the member's pinned key.

    Review a159e97 H1: any envelope on the new key was sealed again, whoever
    made it; one the server made up (an account 'Eve' signing her own grant)
    got the folder key. As for a re-key, only a grant this account made or a
    member whose fingerprint it confirmed is sealed again.
    """
    from ..crypto.envelope_crypto import create_envelope

    db = client._db
    if dek_id is None or db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?",
        (dek_id, grant["user_id"]),
    ):
        return
    if grant["user_id"] in queued_for_removal(db):
        return  # review a159e97: revoked here, whatever the server says
    if grant["created_by"] != db.get_meta("user_id") and reseal_key_row(
        db, grant["user_id"], grant["created_by"], db.get_meta("user_id")
    ) is None:
        return
    pin = db.fetchone("SELECT encryption_pk FROM known_keys WHERE user_id = ?", (grant["user_id"],))
    if pin is None:
        logger.warning(
            "The grant of %s made while the re-key waited was dropped: the member's "
            "key is not pinned here; share the folder again", grant["user_id"],
        )
        return
    db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            new_ulid(), dek_id, grant["user_id"], db.get_meta("user_id"),
            vouched_access_level(db, grant["id"], grant["access_level"]),
            create_envelope(
                client._dek_mgr.unlock_dek(dek_id),
                client._keypair.to_nacl_private_key().encode(),
                bytes(pin["encryption_pk"]),
            ),
        ),
    )
    outbox.queue_write(db, grant["node_id"])


@oplock.held
def abandon_pending_rekey(client: "SyncClient") -> dict:
    """Undo this device's pending member re-key (see the module docstring).

    Returns ``{"member": user_id, "conflicts": n, "requeued": bool}``.
    """
    db = client._db
    dek_mgr = client._dek_mgr
    pending_states.refuse_if_blocked(db, pending_states.ABANDON_REKEY)
    pending = pending_states.rekey_batch(db)
    if dek_mgr is None:
        raise RuntimeError("The vault must be unlocked to drop the re-key")
    # Stateful test SM84: the batch landed with its reply lost and a pull
    # brought one of its new keys back. Dropped, the re-key took the folders
    # back under the old key here while the server and the other admin kept
    # the new one, which this device deleted: the next envelope sealed to it
    # broke the foreign key on every pull. The re-key is done; it is closed
    # as sent (the member stays removed) instead.
    if client.close_rekey_if_pulled_back():
        held = pending.get("held_edits") or {}
        return {"member": pending.get("revoked_user_id"), "conflicts": len(held), "requeued": False}
    dek_map: dict[str, str] = dict(pending.get("dek_map") or {})
    old_of = {new: old for old, new in dek_map.items()}
    new_raw = {ulid_to_bytes(new): new for new in old_of}
    member = pending.get("revoked_user_id")
    rekeyed_versions = dict(pending.get("rekeyed_versions") or {})
    held = dict(pending.get("held_edits") or {})
    object_ids = set(pending.get("object_ids") or [])
    shadows = {
        row["object_id"]: row for row in db.fetchall(
            "SELECT object_id, server_version, server_payload, server_parent_ref, "
            "server_is_deleted FROM sync_conflicts"
        )
    }

    def batch_dek(blob: bytes) -> Optional[str]:
        try:
            return new_raw.get(parse_envelope(blob).dek_id)
        except ValueError:
            return None

    def node_dek(node_id: Optional[str]) -> Optional[str]:
        row = db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,)) if node_id else None
        return row["dek_id"] if row else None

    def reseal(
        blob: bytes, object_id: str, version: int, kind: BlobKind, target: str,
        deleted: bool = False, bump: int = 0,
    ) -> bytes:
        # Review d150605 #2: a tombstone's blobs are sealed below its row
        # version; they stay at the version they were sealed at (``bump``
        # moves both together).
        source = bytes_to_ulid(parse_envelope(blob).dek_id)
        plain, sealed_at = open_sealed(
            blob, dek_mgr.unlock_dek(source), object_id, version, kind, deleted=deleted
        )
        return encrypt(
            plaintext=plain, dek=dek_mgr.unlock_dek(target), dek_id=ulid_to_bytes(target),
            object_id=ulid_to_bytes(object_id), version=sealed_at + bump, blob_kind=kind,
        )

    # Stateful test SM78: the batch may have landed with its reply lost. A copy
    # the re-key made, sealed back at the version the batch sent, was then
    # refused on every push: the server held that version already, under the
    # new key. It goes out one version above, which lands whether the batch
    # reached the server or not.
    def bump_for(object_id: str, row_version: int) -> int:
        return 1 if rekeyed_versions.get(object_id) == row_version else 0

    def target_for(blob: bytes, governing: Optional[str]) -> str:
        """The key a blob sealed with a batch DEK goes back to."""
        if governing and governing not in old_of:
            return governing
        return old_of[batch_dek(blob)]

    old_raw = {ulid_to_bytes(old) for old in dek_map}

    def only_rekeyed_elsewhere(object_id: str, row_version: int, shadow, server_meta: bytes) -> bool:
        """The server copy is another device's re-key of what this batch
        re-keyed, nothing more: the same version step from the same copy,
        sealed with a key that is neither the old one nor this batch's."""
        if shadow["server_is_deleted"] or rekeyed_versions.get(object_id) is None:
            return False
        if shadow["server_version"] != rekeyed_versions[object_id] or row_version <= shadow["server_version"]:
            return False
        try:
            dek_id = parse_envelope(server_meta).dek_id
        except ValueError:
            return False
        return dek_id not in old_raw and dek_id not in new_raw

    def base_version(object_id: str) -> int:
        """The server version this device's copy builds on (-1: never on the server)."""
        base = client._base_version(object_id)
        return -1 if base is None else base

    def entry_meta(payload: bytes) -> bytes:
        size = int.from_bytes(payload[:4], "big") if len(payload) >= 4 else 0
        return payload[4:4 + size]

    conflicts = 0
    db.begin()
    try:
        marks = ",".join("?" * len(old_of))
        # Review d615826: a grant made while the batch waited sealed one of
        # its new keys and was deleted with them, without a word. Taken here,
        # while the new DEK still names its folder, and sealed again below.
        later_grants = [
            row for row in db.fetchall(
                "SELECT ae.id, ae.user_id, ae.created_by, ae.access_level, d.node_id "
                "FROM access_envelopes ae "
                f"JOIN deks d ON d.id = ae.dek_id WHERE ae.dek_id IN ({marks})",
                tuple(old_of),
            )
            if row["id"] not in object_ids and row["user_id"] != member and row["node_id"]
        ]

        # Folders still on a new DEK go back to the old one (a superseded
        # batch has none left: the pull moved them to the other device's).
        for new, old in old_of.items():
            owner = db.fetchone("SELECT node_id FROM deks WHERE id = ?", (new,))
            if db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ?", (new,)):
                db.execute("UPDATE nodes SET dek_id = ? WHERE dek_id = ?", (old, new))
                if owner and owner["node_id"]:
                    db.execute("UPDATE deks SET node_id = ? WHERE id = ?", (owner["node_id"], old))
            db.execute("UPDATE deks SET node_id = NULL WHERE id = ?", (new,))

        # Held edits are sealed back too: they return as conflicts below.
        for object_id, edit in held.items():
            parent_dek = node_dek(edit.get("parent"))
            for field, kind in (
                ("meta", BlobKind.NODE_META if edit["kind"] == "node" else BlobKind.ENTRY_META),
                ("data", BlobKind.ENTRY_DATA),
            ):
                if field not in edit:
                    continue
                blob = bytes.fromhex(edit[field])
                if batch_dek(blob):
                    edit[field] = reseal(
                        blob, object_id, int(edit["version"]), kind,
                        target_for(blob, parent_dek),
                    ).hex()

        for row in db.fetchall(
            "SELECT id, parent_id, encrypted_meta, version, is_deleted FROM nodes n "
            f"WHERE {outbox.queued('n')}"
        ):
            node_id = row["id"]
            blob = bytes(row["encrypted_meta"])
            deleted = bool(row["is_deleted"])
            in_batch = node_id in object_ids
            if not in_batch and not batch_dek(blob):
                continue
            own_edit = rekeyed_versions.get(node_id) != row["version"]
            shadow = shadows.get(node_id)
            if (
                shadow is not None and own_edit and not deleted and node_id not in held
                and only_rekeyed_elsewhere(node_id, row["version"], shadow, bytes(shadow["server_payload"]))
            ):
                # As for entries below: an edit on top of the other re-key.
                target = bytes_to_ulid(parse_envelope(bytes(shadow["server_payload"])).dek_id)
                db.execute(
                    "UPDATE nodes SET encrypted_meta = ? WHERE id = ?",
                    (reseal(blob, node_id, row["version"], BlobKind.NODE_META, target), node_id),
                )
                client._set_base(
                    node_id, shadow["server_version"],
                    hashlib.sha256(bytes(shadow["server_payload"])).hexdigest(),
                )
                db.execute("DELETE FROM sync_conflicts WHERE object_id = ?", (node_id,))
            elif shadow is not None:
                if own_edit and deleted and node_id not in held:
                    held[node_id] = {"kind": "node", "deleted": True, "parent": row["parent_id"]}
                elif own_edit and node_id not in held:
                    # Stateful test SM49: an edit not sealed with the batch's
                    # key (a rename made before a re-key another device's
                    # superseded) is held as it is; before, it was dropped.
                    held[node_id] = {
                        "kind": "node", "version": row["version"], "parent": row["parent_id"],
                        "server_deleted": bool(shadow["server_is_deleted"]),
                        "meta": (reseal(
                            blob, node_id, row["version"], BlobKind.NODE_META,
                            target_for(blob, node_dek(row["parent_id"]) or node_dek(node_id)),
                        ) if batch_dek(blob) else blob).hex(),
                    }
                outbox.drop_write(db, node_id)
                db.execute("UPDATE nodes SET version = 0 WHERE id = ?", (node_id,))
                client._apply_node(
                    node_id, shadow["server_parent_ref"], bytes(shadow["server_payload"]),
                    shadow["server_version"], shadow["server_is_deleted"],
                )
                db.execute("DELETE FROM sync_conflicts WHERE object_id = ?", (node_id,))
            elif batch_dek(blob):
                bump = bump_for(node_id, row["version"])
                db.execute(
                    "UPDATE nodes SET encrypted_meta = ?, version = ? WHERE id = ?",
                    (
                        reseal(
                            blob, node_id, row["version"], BlobKind.NODE_META,
                            target_for(blob, node_dek(row["parent_id"]) or node_dek(node_id)),
                            deleted, bump,
                        ),
                        row["version"] + bump,
                        node_id,
                    ),
                )
            elif not own_edit and row["version"] <= base_version(node_id):
                # Dirty only because the re-key moved its folder to a new DEK.
                # Stateful test SM55: one version above the server's, the
                # batch re-sealed it (a folder that reached a re-keyed folder
                # under the revoked DEK; the pull then moved it to another
                # device's re-key). The server still holds it under the
                # revoked DEK, so it stays unsent.
                outbox.drop_write(db, node_id)

        for row in db.fetchall(
            "SELECT id, node_id, encrypted_meta, encrypted_data, version, is_deleted "
            f"FROM entries e WHERE {outbox.queued('e')}"
        ):
            entry_id = row["id"]
            meta = bytes(row["encrypted_meta"])
            data = bytes(row["encrypted_data"])
            if entry_id not in object_ids and not batch_dek(meta):
                continue
            own_edit = rekeyed_versions.get(entry_id) != row["version"]
            governing = node_dek(row["node_id"])
            sealed_new = batch_dek(meta) is not None

            def resealed() -> tuple[bytes, bytes]:
                target = target_for(meta, governing)
                deleted = bool(row["is_deleted"])
                return (
                    reseal(meta, entry_id, row["version"], BlobKind.ENTRY_META, target, deleted),
                    reseal(data, entry_id, row["version"], BlobKind.ENTRY_DATA, target, deleted),
                )

            shadow = shadows.get(entry_id)
            server_meta = entry_meta(bytes(shadow["server_payload"])) if shadow is not None else b""
            if (
                shadow is not None and own_edit and entry_id not in held and not row["is_deleted"]
                and only_rekeyed_elsewhere(entry_id, row["version"], shadow, server_meta)
            ):
                # An edit made after this re-key goes out on top of the other
                # device's re-key of the same copy, under its key: the server
                # takes a change only over the copy it holds (stateful test SM1).
                # Stateful test SM88: an entry moved out to a folder outside the
                # batch is sealed with that folder's key already; sealed with the
                # server copy's key it went out under the old folder's key and
                # no device could open it in its new folder.
                moved_out = row["node_id"] != shadow["server_parent_ref"] and not sealed_new
                if not moved_out:
                    target = bytes_to_ulid(parse_envelope(server_meta).dek_id)
                    db.execute(
                        "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, dek_id = NULL "
                        "WHERE id = ?",
                        (
                            reseal(meta, entry_id, row["version"], BlobKind.ENTRY_META, target),
                            reseal(data, entry_id, row["version"], BlobKind.ENTRY_DATA, target),
                            entry_id,
                        ),
                    )
                client._set_base(
                    entry_id, shadow["server_version"],
                    hashlib.sha256(bytes(shadow["server_payload"])).hexdigest(),
                )
                db.execute("DELETE FROM sync_conflicts WHERE object_id = ?", (entry_id,))
            elif shadow is not None:
                if own_edit and entry_id not in held:
                    if row["is_deleted"]:
                        held[entry_id] = {"kind": "entry", "deleted": True, "parent": row["node_id"]}
                    else:
                        new_meta, new_data = resealed() if sealed_new else (meta, data)
                        # Stateful test SM63: the server copy is another
                        # device's delete. Without the flag the edit counted as
                        # deleted here and went to the history, with no conflict.
                        held[entry_id] = {
                            "kind": "entry", "version": row["version"], "parent": row["node_id"],
                            "meta": new_meta.hex(), "data": new_data.hex(),
                            "server_deleted": bool(shadow["server_is_deleted"]),
                        }
                outbox.drop_write(db, entry_id)
                db.execute("UPDATE entries SET version = 0 WHERE id = ?", (entry_id,))
                client._apply_entry(
                    entry_id, shadow["server_parent_ref"], bytes(shadow["server_payload"]),
                    shadow["server_version"], shadow["server_is_deleted"],
                )
                db.execute("DELETE FROM sync_conflicts WHERE object_id = ?", (entry_id,))
            elif sealed_new:
                bump = bump_for(entry_id, row["version"])
                target = target_for(meta, governing)
                deleted = bool(row["is_deleted"])
                db.execute(
                    "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, dek_id = NULL, "
                    "version = ? WHERE id = ?",
                    (
                        reseal(meta, entry_id, row["version"], BlobKind.ENTRY_META, target, deleted, bump),
                        reseal(data, entry_id, row["version"], BlobKind.ENTRY_DATA, target, deleted, bump),
                        row["version"] + bump, entry_id,
                    ),
                )

        # The batch's own key material never reached the server. A withdrawn
        # envelope comes back with its own sender (review 8595ec1, stateful
        # hunt seed 377001): as this account's, the envelope the server made
        # up for an account of its own was re-sealed to it by the next
        # identity rotation. Batches written before the sender was kept
        # name none.
        tombstones = pending.get("envelope_tombstones") or []
        db.execute(f"DELETE FROM access_envelopes WHERE dek_id IN ({marks})", tuple(old_of))
        own_user_id = db.get_meta("user_id")
        withheld = queued_for_removal(db)
        regrant = False
        for item in tombstones:
            if item["dek_id"] not in dek_map:
                continue
            if not db.fetchone("SELECT 1 FROM nodes WHERE dek_id = ?", (item["dek_id"],)):
                # Review 8595ec1 (reviewer's stateful seed, goal #377): the
                # batch was superseded - another device of this account
                # re-keyed the folder without knowing every grant this
                # device had on the old key. Dropped with the batch, a member
                # who stays lost the folder on every device, and the removed
                # member's envelope stayed live on the server. A grant that
                # re-key did not withdraw comes back on the retired key, as
                # the server still holds it: a removed member's is re-queued
                # below (the next re-key withdraws it), anyone else's is
                # sealed again on the folder's current key
                # (_grant_again_on_successors' rules).
                if (
                    item.get("created_by") != own_user_id
                    or item.get("user_id") in (None, own_user_id)
                    or db.fetchone(
                        "SELECT 1 FROM withdrawn_envelopes WHERE envelope_id = ?", (item["id"],)
                    )
                ):
                    continue
                regrant = regrant or item["user_id"] not in withheld | {member}
            outbox.restore_envelope(db, item, item.get("created_by") or own_user_id)
        for grant in later_grants:
            _grant_again(client, grant, node_dek(grant["node_id"]))
        db.execute(f"DELETE FROM dek_archive WHERE replaced_by IN ({marks})", tuple(old_of))
        for new in old_of:
            if not db.fetchone(
                "SELECT 1 FROM entries WHERE dek_id = ? UNION ALL "
                "SELECT 1 FROM entry_history WHERE dek_id = ?",
                (new, new),
            ):
                db.execute("DELETE FROM deks WHERE id = ?", (new,))

        pending_states.clear_rekey_batch(db)
        client._resolve_entry_deks()
        if held:
            client._restore_held_edits(held, {})
            conflicts = len(held)
        requeued = bool(member) and db.fetchone(
            "SELECT 1 FROM access_envelopes WHERE user_id = ?", (member,)
        ) is not None
        queue = pending_states.revocation_queue(db)
        if requeued and member not in queue:
            queue.insert(0, member)
        elif not requeued and member in queue:
            queue.remove(member)
        pending_states.set_revocation_queue(db, queue)
        db.commit()
    except Exception:
        db.rollback()
        raise
    client._push_cache.clear()
    # finish_queued_revocations must not count the dropped batch as landed.
    client.requeued_rekey = member if requeued else None
    if regrant:
        client._grant_again_on_successors()
    logger.warning(
        "Dropped the pending re-key for member %s (%d conflict(s), requeued: %s)",
        member, conflicts, requeued,
    )
    return {"member": member, "conflicts": conflicts, "requeued": requeued}
