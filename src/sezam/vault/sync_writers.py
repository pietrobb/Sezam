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
from . import outbox, sync_core
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


def _head(obj: dict) -> str:
    """The start of a pulled object's payload (hex): enough for its header."""
    try:
        return base64.b64decode(obj.get("payload") or "")[:57].hex()
    except ValueError:
        return ""


def _sealing_dek_id(obj: dict) -> Optional[str]:
    """The key named in a folder's meta or an item's meta header (the core's rule)."""
    return sync_core.call("authority_sealing_dek_id", object_type=obj.get("object_type") or "", head=_head(obj))


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
        """``objects`` plus the writes held back before (review a159e97 H2):
        the core judges them again with the batch and holds back the ones
        whose folder is still not known. A newer copy in the batch replaces
        the held one. Call inside the pull's transaction, before
        _unauthorized_writes."""
        objects = self._with_writes_the_log_now_allows(objects)
        deferred = self._db.get_meta_json(DEFERRED_WRITES_META) or {}
        in_batch = {obj.get("id") for obj in objects}
        revived = [obj for obj_id, obj in deferred.items() if obj_id not in in_batch]
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
        transaction; ``full`` for a full resync's complete snapshot.

        The rules are the core's (core/src/authority.rs, the web's and the
        phone's too; docs/CORE_UNIFICATION.md U5). This device judges each
        batch against its database, so the core gets what it holds as
        context: its folders (walked only), the ids it did not apply, the
        keys and personal trees it learned, its write grants, the accounts it
        vouches for and what it holds back. Storing a held-back write and
        judging it again once its folder arrives stay here.
        """
        def stored(key: str) -> dict:
            return {} if full else dict(self._db.get_meta_json(key) or {})

        dek_signers, ignored, personal = (
            stored(DEK_SIGNERS_META), stored(IGNORED_WRITES_META), stored(PERSONAL_TREES_META)
        )
        deferred = stored(DEFERRED_WRITES_META)
        no_access = stored(LOG_REFUSED_WRITES_META)
        unknown_key = stored(UNKNOWN_KEY_WRITES_META)
        below_refused = stored(BELOW_REFUSED_WRITES_META)
        refused_copies = stored(REFUSED_COPIES_META)
        judged = self._order_pulled_objects(objects)
        was_held = set(deferred)
        for obj in judged:
            if obj.get("object_type") in ("node", "entry"):
                deferred.pop(obj["id"], None)  # this copy decides now
                no_access.pop(obj["id"], None)
                unknown_key.pop(obj["id"], None)
                below_refused.pop(obj["id"], None)

        team = self.team_state()
        previous = self._authority_previous(judged)
        # Review 1141a20 H6: with a team log only the accounts it made admin
        # are admins, and no unsigned access_level grants write.
        with_team = {} if team is None else {
            "team_admins": sorted(log_admins(self._db, team)), **teamlog.core_argument(team)
        }
        verdict = sync_core.call(
            "authority_unauthorized_writes",
            objects=[self._authority_object(obj) for obj in judged],
            own_user_id=self._user_id,
            previous=previous,
            context={
                **self._authority_context(judged, previous, ignored, dek_signers, personal, team is None),
                # Review a159e97 H2 (the core holds back): before, a write below
                # an unknown folder passed and the reattach hung it below the
                # root; one by an account vouched for is applied (as an orphan,
                # review d150605 #1).
                "vouched": sorted(self._vouched_writers()),
            },
            **with_team,
        )
        held = set(verdict["held"])
        by_id = {obj["id"]: obj for obj in judged}
        for obj_id in verdict["held"]:
            obj = by_id[obj_id]
            if obj_id not in was_held:
                logger.warning(
                    "Pulled %s %s below folder %s, which this device does not know; "
                    "held back until that folder arrives", obj["object_type"], obj_id, obj.get("parent_ref"),
                )
            deferred[obj_id] = obj
        blocked = set(verdict["blocked"])
        refusals = verdict["refusals"]
        below = set(verdict["below_refused"])
        for obj in judged:
            if obj.get("object_type") not in ("node", "entry") or obj["id"] in held:
                continue
            obj_id, parent = obj["id"], obj.get("parent_ref")
            if obj_id not in blocked:
                ignored.pop(obj_id, None)
                refused_copies.pop(obj_id, None)
                continue
            if obj_id in below:
                below_refused[obj_id] = obj
            elif obj_id in refusals:
                refusal = refusals[obj_id]
                logger.warning(
                    "Pulled %s %s below folder %s by %s: %s; not applied",
                    obj["object_type"], obj_id, parent, self._signer_id(obj), refusal,
                )
                if refusal == NO_WRITE_ACCESS and not obj.get("is_deleted"):
                    no_access[obj_id] = obj
                elif refusal == UNKNOWN_KEY and not obj.get("is_deleted"):
                    unknown_key[obj_id] = obj
            else:
                logger.warning(
                    "Pulled %s %s below folder %s by %s, who may not write it there "
                    "or not under that key; not applied", obj["object_type"], obj_id, parent,
                    self._signer_id(obj),
                )
            ignored[obj_id] = parent
            refused_copies[obj_id] = [obj.get("version"), obj.get("payload_hash")]

        self._db.set_meta_json(REFUSED_COPIES_META, refused_copies)
        self._db.set_meta_json(WRITER_ACCOUNTS_META, verdict["admin_signers"])
        self._db.set_meta_json(DEK_SIGNERS_META, verdict["personal_dek_signers"])
        self._db.set_meta_json(IGNORED_WRITES_META, ignored)
        self._db.set_meta_json(PERSONAL_TREES_META, verdict["personal_trees"])
        self._db.set_meta_json(DEFERRED_WRITES_META, deferred)
        self._db.set_meta_json(LOG_REFUSED_WRITES_META, no_access)
        self._db.set_meta_json(UNKNOWN_KEY_WRITES_META, unknown_key)
        self._db.set_meta_json(BELOW_REFUSED_WRITES_META, below_refused)
        if full:
            self._db.set_meta(WRITES_AUDITED_META, "1")
        return (blocked & {obj["id"] for obj in judged}) | held

    def _authority_object(self, obj: dict) -> dict:
        """A pulled object as the core judges it: by the account whose
        signature verified, not the unsigned owner_id."""
        return {
            "id": obj["id"],
            "object_type": obj.get("object_type") or "",
            "parent_ref": obj.get("parent_ref"),
            "is_deleted": bool(obj.get("is_deleted")),
            "signer": self._signer_id(obj),
            "access_level": obj.get("access_level"),
            "target_user_id": obj.get("target_user_id"),
            "head": _head(obj),
        }

    def _authority_previous(self, judged: list[dict]) -> list[dict]:
        """The rows the pulled folders and items replace (where a removal or
        a move was). R16-N2 (nightly TeamLogMachine): a row with an unsent
        move left from the server copy it builds on, as web and phone do."""
        previous = []
        for obj in judged:
            kind = obj.get("object_type")
            if kind not in ("node", "entry"):
                continue
            table, column = ("nodes", "parent_id") if kind == "node" else ("entries", "node_id")
            row = self._db.fetchone(
                f"SELECT CASE WHEN {outbox.queued('t')} AND t.base_parent IS NOT NULL "
                f"THEN NULLIF(t.base_parent, '') ELSE t.{column} END AS parent, "
                f"t.encrypted_meta, t.is_deleted FROM {table} t WHERE t.id = ?",
                (obj["id"],),
            )
            if row is not None:
                previous.append({
                    "id": obj["id"], "object_type": kind, "parent_ref": row["parent"],
                    "is_deleted": bool(row["is_deleted"]), "head": bytes(row["encrypted_meta"])[:57].hex(),
                })
        return previous

    def _authority_context(
        self, judged: list[dict], previous: list[dict], ignored: dict,
        dek_signers: dict, personal: dict, without_log: bool,
    ) -> dict:
        """What this device holds that the batch does not carry: the folders
        above the batch's (and above where it was), walked only."""
        batch = {obj["id"] for obj in judged}
        batch_parents = {obj["id"]: obj.get("parent_ref") for obj in judged if obj.get("object_type") == "node"}
        known: dict[str, dict] = {}
        pending = [obj.get("parent_ref") for obj in judged] + [p["parent_ref"] for p in previous]
        seen: set[str] = set()
        while pending:
            node_id = pending.pop()
            if not node_id or node_id in seen or node_id in known:
                continue
            seen.add(node_id)
            if node_id in batch_parents:
                pending.append(batch_parents[node_id])
                continue
            row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (node_id,))
            if row is not None:
                known[node_id] = {"id": node_id, "object_type": "node", "parent_ref": row["parent_id"]}
                pending.append(row["parent_id"])
        context: dict = {
            "known_nodes": [node for node_id, node in known.items() if node_id not in batch],
            "refused": sorted(ignored),
            "personal_dek_signers": dek_signers,
            "personal_trees": personal,
            # Stored with a log too, as before.
            "admin_signers": sorted(self._admin_signers()),
        }
        if not without_log:
            return context
        detached = self._db.get_meta_json(DETACHED_DEKS_META) or {}
        batch_dek_folders = {
            obj["id"]: obj["parent_ref"] for obj in judged
            if obj.get("object_type") == "dek" and obj.get("parent_ref")
        }

        def dek_folder(dek_id: str) -> Optional[str]:
            if dek_id in batch_dek_folders:
                return batch_dek_folders[dek_id]
            row = self._db.fetchone("SELECT node_id FROM deks WHERE id = ?", (dek_id,))
            return (row["node_id"] if row else None) or detached.get(dek_id)

        named = {obj.get("parent_ref") for obj in judged if obj.get("object_type") == "envelope"}
        context["dek_folders"] = {
            dek_id: folder for dek_id in named - set(batch_dek_folders) - {None}
            if (folder := dek_folder(dek_id))
        }
        grants = []
        for row in self._db.fetchall(
            "SELECT id, user_id, dek_id, created_by FROM access_envelopes WHERE access_level = 'write'"
        ):
            folder = dek_folder(row["dek_id"])
            if folder:
                grants.append({"id": row["id"], "user_id": row["user_id"], "folder": folder, "by": row["created_by"]})
        context["write_grants"] = grants
        # This account's root: the root under its own KEK (a member's adopted
        # org root is reached by envelope). One signed by it in this batch the
        # core sees itself.
        root_id = self._db.get_meta("root_node_id")
        root_row = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (root_id or "",))
        if root_row is not None and root_row["dek_id"] not in set(
            self._db.get_meta_json("foreign_dek_ids") or []
        ):
            context["own_tops"] = [root_id]
        return context

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
