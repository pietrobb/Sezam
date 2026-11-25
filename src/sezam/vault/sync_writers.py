"""Pulled writes directly below a top-level node that their author could not make.

Review 7c10379 H4: the personal-tree start of d615826 let a read-only member
write folders directly below the shared root, sealed with the root's shared
key, and items in them ('IT - new VPN login') that colleagues saw as the
company's own. The server refuses that since b8c3cb8; this is the client
side, for what such a server already stored and for a server that lies.

Part of SyncClient (sync_client.py). The rules are the server's
(_has_write_authority), judged by signatures, not by the unsigned owner_id:
directly below a top-level node, a folder or item may be written by this
account, by an account that signed something only an admin may push (a
top-level node, an envelope, a key archive, a folder key, an audit record),
by a member holding a write grant (envelope) on a key of that top-level
node, and - a folder only - by its author when its meta is sealed with a
key of the author's own (a personal folder). Inside such a personal folder
everything is sealed with its owner's own keys: one sealed with the shared
key would again read as the company's to everyone holding that key.
Anything else is not applied, nor anything below it.
"""

from __future__ import annotations

import base64
from typing import Optional

from .. import teamlog
from ..crypto.aead import parse_envelope
from ..models import bytes_to_ulid
from .sync_common import (
    CONFIRMED_MEMBER_KEYS_META,
    DETACHED_DEKS_META,
    logger,
    queued_for_removal,
)
from .team_log_local import log_admins

# id -> parent of a pulled folder or item that was not applied (and below it).
IGNORED_WRITES_META = "ignored_unauthorized_writes"
# Accounts seen signing an object only an admin may push.
WRITER_ACCOUNTS_META = "admin_signers"
# Signer of each pulled key that names no folder (a member's personal key).
DEK_SIGNERS_META = "personal_dek_signers"
# Member's personal folder directly below a top-level node -> its member.
PERSONAL_TREES_META = "member_personal_trees"
# Set once the local tables were checked against the server's whole state.
WRITES_AUDITED_META = "unauthorized_writes_audited"
# id -> pulled folder or item (as the server sent it) written below a folder
# this device did not know; judged once that folder is known (review a159e97 H2).
DEFERRED_WRITES_META = "writes_below_unknown_folders"
# id -> pulled folder or item (as the server sent it) the team log refused
# because its author had no write access there; applied once the log gives it
# (review 8595ec1, R10-C: what a founding hid came back only by a full resync).
LOG_REFUSED_WRITES_META = "writes_without_log_write_access"
NO_WRITE_ACCESS = "team log gives no write access here"
# R16-Z SM26a: id -> pulled folder or item refused as sealed with a key the
# team log does not know (a server that lost the records naming it), judged
# again once the log names that key; and id -> one not applied because the
# folder above it was not, judged again with that folder.
UNKNOWN_KEY_WRITES_META = "writes_on_keys_the_log_lacks"
UNKNOWN_KEY = "sealed with a key the team log does not know"
BELOW_REFUSED_WRITES_META = "writes_below_refused_folders"
# id -> [version, payload_hash] of the server copy last refused here (not
# applied). R16-Z SM4: a refused re-key batch builds on it when it rebases.
REFUSED_COPIES_META = "refused_server_copies"

_ADMIN_ONLY = ("envelope", "dek_archive", "audit")


def _sealing_dek_id(obj: dict) -> Optional[str]:
    """The key named in a folder's meta or an item's meta header."""
    try:
        payload = base64.b64decode(obj.get("payload") or "")
        if obj.get("object_type") == "entry":
            payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
        return bytes_to_ulid(parse_envelope(payload).dek_id)
    except ValueError:
        return None


class WritersMixin:
    """SyncClient methods: skip pulled writes their author had no right to."""

    def _admin_signers(self) -> set[str]:
        stored = self._db.get_meta_json(WRITER_ACCOUNTS_META)
        if stored is not None:
            return set(stored)
        # Vaults from before this record: every envelope was signed by an admin
        # (the server takes envelopes from admins only).
        return {
            row["created_by"]
            for row in self._db.fetchall("SELECT DISTINCT created_by FROM access_envelopes")
        }

    def _vouched_writers(self) -> set[str]:
        """Accounts this device has its own evidence for (capability run 196):
        this account, a member whose fingerprint it confirmed, a member it
        granted a key. Being an admin is the server's word alone (a flag it
        sets; an account it made can sign an admin-only object it takes)."""
        vouched = {self._user_id}
        confirmed = self._db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {}
        for row in self._db.fetchall("SELECT user_id, fingerprint FROM known_keys"):
            if confirmed.get(row["user_id"]) == row["fingerprint"]:
                vouched.add(row["user_id"])
        vouched.update(
            row["user_id"] for row in self._db.fetchall(
                "SELECT DISTINCT user_id FROM access_envelopes WHERE created_by = ?", (self._user_id,)
            )
        )
        return (vouched - queued_for_removal(self._db)) | {self._user_id}

    def _with_held_back_writes(self, objects: list[dict]) -> list[dict]:
        """``objects`` plus the writes held back for a folder that is known
        now (in this batch or here), to be judged with it (review a159e97 H2).
        A newer copy in the batch replaces the held one. Call inside the
        pull's transaction, before _unauthorized_writes."""
        objects = self._with_writes_the_log_now_allows(objects)
        deferred = self._db.get_meta_json(DEFERRED_WRITES_META) or {}
        if not deferred:
            return objects
        in_batch = {obj.get("id") for obj in objects}
        known = {obj["id"] for obj in objects if obj.get("object_type") == "node"}
        revived: list[dict] = []
        waiting = {obj_id: obj for obj_id, obj in deferred.items() if obj_id not in in_batch}
        progress = True
        while progress:
            progress = False
            for obj_id, obj in list(waiting.items()):
                parent = obj.get("parent_ref")
                if parent in known or self._db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (parent,)):
                    revived.append(obj)
                    del waiting[obj_id]
                    if obj.get("object_type") == "node":
                        known.add(obj_id)
                    progress = True
        return revived + objects if revived else objects

    def _with_writes_the_log_now_allows(self, objects: list[dict]) -> list[dict]:
        """``objects`` plus the writes refused for want of write access whose
        author the team log now lets write in the team folder above them, the
        ones refused for a key the log now names, and what was below them."""
        self._revived_write_ids: set[str] = set()
        refused = self._db.get_meta_json(LOG_REFUSED_WRITES_META) or {}
        unknown_key = self._db.get_meta_json(UNKNOWN_KEY_WRITES_META) or {}
        below = self._db.get_meta_json(BELOW_REFUSED_WRITES_META) or {}
        team = self.team_state() if refused or unknown_key or below else None
        if team is None:
            return objects
        in_batch = {obj.get("id") for obj in objects}
        revived = [
            obj for obj_id, obj in unknown_key.items()
            if obj_id not in in_batch and _sealing_dek_id(obj) in team.dek_index
        ]
        for obj_id, obj in refused.items():
            current = obj_id if obj_id in team.folders else obj.get("parent_ref")
            for _ in range(64):
                if current is None or current in team.folders:
                    break
                row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (current,))
                current = row["parent_id"] if row else None
            if (
                obj_id not in in_batch and current is not None
                and teamlog.may_write(team, current, self._signer_id(obj))
            ):
                revived.append(obj)
        ignored = self._db.get_meta_json(IGNORED_WRITES_META) or {}
        judged = in_batch | {obj["id"] for obj in revived}
        waiting = {obj_id: obj for obj_id, obj in below.items() if obj_id not in in_batch}
        progress = True
        while progress:
            progress = False
            for obj_id, obj in list(waiting.items()):
                parent = obj.get("parent_ref")
                if parent in judged or parent not in ignored:
                    revived.append(obj)
                    judged.add(obj_id)
                    del waiting[obj_id]
                    progress = True
        self._revived_write_ids = {obj["id"] for obj in revived}
        return revived + objects if revived else objects

    def _unauthorized_writes(self, objects: list[dict], full: bool = False) -> set[str]:
        """Ids of pulled folders and items not to apply. Call inside the pull's
        transaction; ``full`` for a full resync's complete snapshot."""
        admins = self._admin_signers()

        def stored(key: str) -> dict:
            return {} if full else dict(self._db.get_meta_json(key) or {})

        dek_signers, ignored, personal = (
            stored(DEK_SIGNERS_META), stored(IGNORED_WRITES_META), stored(PERSONAL_TREES_META)
        )
        batch_nodes: dict[str, dict] = {}
        batch_dek_folders: dict[str, str] = {}
        envelopes: list[dict] = []
        for obj in objects:
            kind = obj.get("object_type")
            signer = self._signer_id(obj)
            if kind == "node":
                batch_nodes[obj["id"]] = obj
            elif kind in _ADMIN_ONLY:
                admins.add(signer)
                if kind == "envelope":
                    envelopes.append(obj)
            elif kind == "dek":
                if obj.get("parent_ref"):
                    admins.add(signer)  # a member's key names no folder
                    batch_dek_folders[obj["id"]] = obj["parent_ref"]
                else:
                    dek_signers[obj["id"]] = signer
        for obj in batch_nodes.values():
            # Only an admin writes a top-level node sealed with a folder's key.
            # TL7: one sealed with a key of its signer's own that names no
            # folder is that account's own tree (a member's personal root, the
            # root of a member's own vault); it makes no admin.
            signer = self._signer_id(obj)
            if obj.get("parent_ref") is None and dek_signers.get(_sealing_dek_id(obj) or "") != signer:
                admins.add(signer)
        withdrawn = {env["id"] for env in envelopes if env.get("is_deleted")}
        detached = self._db.get_meta_json(DETACHED_DEKS_META) or {}
        team = self.team_state()
        # Review 1141a20 H6: with a team log only the accounts it made admin
        # are admins (the signers above stay recorded for a vault without
        # one), and no unsigned access_level grants write.
        signers = admins
        if team is not None:
            admins = log_admins(self._db, team)

        def dek_folder(dek_id: str) -> Optional[str]:
            if dek_id in batch_dek_folders:
                return batch_dek_folders[dek_id]
            row = self._db.fetchone("SELECT node_id FROM deks WHERE id = ?", (dek_id,))
            return (row["node_id"] if row else None) or detached.get(dek_id)

        def write_grant(user_id: str, top: str, own: bool) -> bool:
            """``own``: only a grant this account made counts (this account's root)."""
            if team is not None:
                return False
            for env in envelopes:
                if (
                    not env.get("is_deleted") and env.get("target_user_id") == user_id
                    and env.get("access_level") == "write"
                    and dek_folder(env.get("parent_ref") or "") == top
                    and (not own or self._signer_id(env) == self._user_id)
                ):
                    return True
            return any(
                row["id"] not in withdrawn and dek_folder(row["dek_id"]) == top
                and (not own or row["created_by"] == self._user_id)
                for row in self._db.fetchall(
                    "SELECT id, dek_id, created_by FROM access_envelopes "
                    "WHERE user_id = ? AND access_level = 'write'",
                    (user_id,),
                )
            )

        def parent_of(node_id: str) -> tuple[bool, Optional[str]]:
            if node_id in batch_nodes:
                return True, batch_nodes[node_id].get("parent_ref")
            row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (node_id,))
            return (row is not None), (row["parent_id"] if row else None)

        def personal_owner(node_id: str) -> Optional[str]:
            current: Optional[str] = node_id
            for _ in range(64):
                if current is None:
                    return None
                if current in personal:
                    return personal[current]
                current = parent_of(current)[1]
            return None

        deferred = stored(DEFERRED_WRITES_META)
        no_access = stored(LOG_REFUSED_WRITES_META)
        unknown_key = stored(UNKNOWN_KEY_WRITES_META)
        below_refused = stored(BELOW_REFUSED_WRITES_META)
        refused_copies = stored(REFUSED_COPIES_META)
        vouched = self._vouched_writers()
        # This account's top-level nodes: signed by it in this batch (a new
        # device's first pull: its root is adopted only after), or the root
        # under its own KEK (a member's adopted org root is reached by envelope).
        own_tops = {
            node_id for node_id, obj in batch_nodes.items()
            if obj.get("parent_ref") is None and self._signer_id(obj) == self._user_id
        }
        root_id = self._db.get_meta("root_node_id")
        root_row = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (root_id or "",))
        if root_row is not None and root_row["dek_id"] not in set(
            self._db.get_meta_json("foreign_dek_ids") or []
        ):
            own_tops.add(root_id)

        def held_back(obj: dict, author: str) -> bool:
            """Review a159e97 H2: written below a folder this device does not
            know (held back by the server, or never there). Before, it passed
            and the reattach hung it below the root. Only a write by an account
            this device vouches for is applied (as an orphan, review d150605
            #1); an 'admin' is the server's word (capability run 196)."""
            parent = obj.get("parent_ref")
            if not parent or parent in ignored:
                return False
            if parent in deferred:
                return True
            return not parent_of(parent)[0] and author not in vouched

        def allowed(obj: dict, author: str) -> bool:
            obj_id, parent = obj["id"], obj.get("parent_ref")
            sealed_by = dek_signers.get(_sealing_dek_id(obj) or "")
            if not parent:
                # Review 1141a20 H5: with a log a top-level folder is an
                # admin's (the organisation's root) or its signer's own tree
                # under a key of their own, not one the server re-signed.
                return (
                    team is None or obj.get("object_type") != "node" or bool(obj.get("is_deleted"))
                    or author in (self._user_id, sealed_by) or author in admins
                )
            known, grandparent = parent_of(parent)
            if not known:
                return True  # by an account vouched for (held_back): reattached
            if grandparent is not None:
                owner = personal_owner(parent)
                if owner is None:
                    # Review 1141a20 H6: below the first level of the
                    # organisation's own tree (no team folder, no personal
                    # tree) only its admin writes or deletes.
                    return team is None or author == self._user_id or author in admins
                return (
                    owner == self._user_id or sealed_by == owner
                    or (bool(obj.get("is_deleted")) and (team is None or author == owner))
                )
            personal.pop(obj_id, None)
            if author == self._user_id:
                return True
            # Capability run 196: directly below this account's root an
            # 'admin' (who signed something the server took from admins only)
            # is the server's word; only a write grant this account made counts.
            own = parent in own_tops
            if (not own and author in admins) or write_grant(author, parent, own):
                return True
            if obj["object_type"] == "node" and (
                sealed_by == author or (obj.get("is_deleted") and before.get(obj_id) == author)
            ):
                personal[obj_id] = author  # a member's personal folder
                return True
            return False

        def team_folder_above(node_id: Optional[str]) -> Optional[str]:
            current = node_id
            for _ in range(64):
                if current is None or team is None:
                    return None
                if current in team.folders:
                    return current
                known, current = parent_of(current)
                if not known:
                    return None
            return None

        def stored_dek(obj: dict) -> Optional[str]:
            table = "nodes" if obj["object_type"] == "node" else "entries"
            row = self._db.fetchone(f"SELECT encrypted_meta FROM {table} WHERE id = ?", (obj["id"],))
            try:
                return bytes_to_ulid(parse_envelope(bytes(row["encrypted_meta"])).dek_id) if row else None
            except ValueError:
                return None

        def team_refusal(obj: dict, author: str) -> tuple[bool, Optional[str]]:
            """(decided by the team log, why not valid) — docs/DESIGN_TEAM_LOG.md
            §4.3.4: in a team folder only the log says who may write and under
            which key, by the server's own rules (teamlog.item_refusal)."""
            if team is None:
                return False, None
            folder = team_folder_above(obj.get("parent_ref"))
            if obj.get("is_deleted"):
                stored = stored_dek(obj)
                if folder is None and stored not in team.dek_index:
                    return False, None
                return True, teamlog.tombstone_refusal(team, author, stored)
            # Finding 205: leaving a team folder this device holds it in is a removal from it.
            table, column = ("nodes", "parent_id") if obj["object_type"] == "node" else ("entries", "node_id")
            row = self._db.fetchone(f"SELECT {column} FROM {table} WHERE id = ?", (obj["id"],))
            dek_id = _sealing_dek_id(obj)
            # TL7: a personal object (sealed, before and now, with one key outside
            # the log) may leave for the personal root. Only its author holds that
            # key, so nobody else can seal its next version.
            stored = stored_dek(obj) if row else None
            own_personal = stored is not None and stored == dek_id and stored not in team.dek_index
            moved = teamlog.move_refusal(
                team, author, team_folder_above(row[column]) if row else None, folder, own_personal
            )
            if moved:
                return True, moved
            if folder is None and dek_id not in team.dek_index:
                return False, None
            own = dek_id is not None and dek_signers.get(dek_id) == author
            return True, teamlog.item_refusal(
                team, author, obj["id"], folder, dek_id, own, sealing=False
            )

        before = dict(personal)
        skipped: set[str] = set()
        for obj in self._order_pulled_objects(objects):
            if obj.get("object_type") not in ("node", "entry"):
                continue
            obj_id, parent = obj["id"], obj.get("parent_ref")
            author = self._signer_id(obj)
            deferred.pop(obj_id, None)  # this copy decides now
            no_access.pop(obj_id, None)
            unknown_key.pop(obj_id, None)
            below_refused.pop(obj_id, None)
            if held_back(obj, author):
                logger.warning(
                    "Pulled %s %s below folder %s, which this device does not know; "
                    "held back until that folder arrives", obj["object_type"], obj_id, parent,
                )
                deferred[obj_id] = obj
                skipped.add(obj_id)
                continue
            decided, refusal = team_refusal(obj, author)
            if decided and parent not in ignored:
                if refusal is None:
                    ignored.pop(obj_id, None)
                    refused_copies.pop(obj_id, None)
                    continue
                logger.warning(
                    "Pulled %s %s below folder %s by %s: %s; not applied",
                    obj["object_type"], obj_id, parent, author, refusal,
                )
                ignored[obj_id] = parent
                refused_copies[obj_id] = [obj.get("version"), obj.get("payload_hash")]
                if refusal == NO_WRITE_ACCESS and not obj.get("is_deleted"):
                    no_access[obj_id] = obj
                elif refusal == UNKNOWN_KEY and not obj.get("is_deleted"):
                    unknown_key[obj_id] = obj
                skipped.add(obj_id)
                continue
            if parent not in ignored and allowed(obj, author):
                ignored.pop(obj_id, None)
                refused_copies.pop(obj_id, None)
                continue
            if parent not in ignored:
                logger.warning(
                    "Pulled %s %s below folder %s by %s, who may not write it there "
                    "or not under that key; not applied", obj["object_type"], obj_id, parent, author,
                )
            else:
                below_refused[obj_id] = obj
            ignored[obj_id] = parent
            refused_copies[obj_id] = [obj.get("version"), obj.get("payload_hash")]
            skipped.add(obj_id)

        self._db.set_meta_json(REFUSED_COPIES_META, refused_copies)
        self._db.set_meta_json(WRITER_ACCOUNTS_META, sorted(signers))
        self._db.set_meta_json(DEK_SIGNERS_META, dek_signers)
        self._db.set_meta_json(IGNORED_WRITES_META, ignored)
        self._db.set_meta_json(PERSONAL_TREES_META, personal)
        self._db.set_meta_json(DEFERRED_WRITES_META, deferred)
        self._db.set_meta_json(LOG_REFUSED_WRITES_META, no_access)
        self._db.set_meta_json(UNKNOWN_KEY_WRITES_META, unknown_key)
        self._db.set_meta_json(BELOW_REFUSED_WRITES_META, below_refused)
        if full:
            self._db.set_meta(WRITES_AUDITED_META, "1")
        return skipped

    def _audit_applied_writes(self) -> int:
        """Remove what an older client applied before this check (capability
        run 174): a delta pull never brings it again. Runs once, against the
        server's whole state; returns how many folders and items went."""
        resp = self._fetch_pull_pages(0, full_resync=True)
        objects = (resp or {}).get("objects")
        if not isinstance(objects, list):
            raise RuntimeError("Sync returned an invalid snapshot")
        for obj in objects:
            if not self._verify_object_signature(obj):
                raise RuntimeError(
                    f"Pull rejected object {obj.get('id', '?')}: {self._rejected(obj)}"
                )
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("PRAGMA defer_foreign_keys = ON")
            forged = sorted(self._unauthorized_writes(objects, full=True))
            removed = 0
            if forged:
                marks = ",".join("?" for _ in forged)
                self._db.execute(f"DELETE FROM entry_history WHERE entry_id IN ({marks})", tuple(forged))
                for table in ("entries", "nodes"):
                    removed += self._db.execute(
                        f"DELETE FROM {table} WHERE id IN ({marks})", tuple(forged)
                    ).rowcount
                self._db.execute(f"DELETE FROM object_server_seq WHERE object_id IN ({marks})", tuple(forged))
                self._db.execute(f"DELETE FROM object_server_time WHERE object_id IN ({marks})", tuple(forged))
                self._detach_orphan_deks()
                self._reattach_orphans()
                seq = int(self._db.get_meta("last_known_commit_seq") or "0")
                self._save_sync_checkpoint(seq, self._compute_state_hash())
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        if removed:
            logger.warning("Removed %d folder(s)/item(s) their authors could not write there", removed)
        return removed
