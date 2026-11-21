"""DEK management — KEK/DEK key hierarchy.

Spec 2.3:
  Master Password → Argon2id → Root KEK (256-bit)
    ├── Root DEK (scope='root')  — encrypts root node and top-level nodes
    ├── Folder DEK "servers"     — encrypts entries in servers/
    ├── Audit DEK (scope='audit')— encrypts audit log details
    └── ...

Rules:
- Root KEK unlocks individual DEKs. Never encrypts data directly.
- DEK granularity: per-folder.
- Tier 2 entries have separate DEK (scope='tier2').
- Audit DEK versioned independently from master password lifecycle.
- deks.encrypted_dek is ALWAYS KEK-wrapped (even in multi-user).
- access_envelopes are ADDITIONAL access paths for colleagues.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Callable, Optional

from nacl.exceptions import CryptoError

from ..crypto.aead import (
    decrypt_dek_wrap,
    encrypt_dek_wrap,
)
from ..models import new_ulid, ulid_to_bytes
from . import sync_core
from .db import VaultChangedElsewhere, VaultDB


DEK_SIZE = 32  # 256-bit


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_REMOVAL_MARK = b"sezam-rekey-archive-v1\x00"
_REMOVAL_MEMBER = b"sezam-rekey-removed-v1\x00"


def _archive_chars(new_dek: bytes, label: bytes, new_dek_id: str, user_id: str = "") -> str:
    digest = hashlib.blake2b(
        label + new_dek_id.encode("ascii") + b"\x00" + user_id.encode("utf-8"),
        digest_size=16,
        key=bytes(new_dek),
    ).digest()
    return "".join(_CROCKFORD[b & 0x1F] for b in digest[:8])


def removal_archive_id(new_dek_id: str, new_dek: bytes, removed_user_id: str) -> str:
    """Archive id of a re-key that removed ``removed_user_id`` (capability
    review run 140).

    The 16 random characters of the ULID carry two tags keyed by the new DEK:
    'a removal re-key' and 'it removed this member'. The id is the archive's
    AEAD associated data under the new DEK, which neither the server nor the
    removed member holds, so they can neither forge nor strip it, and an
    archive without the tag hides the successor too. Web and mobile read the
    id as an opaque ULID.
    """
    return (
        new_ulid()[:10]
        + _archive_chars(new_dek, _REMOVAL_MARK, new_dek_id)
        + _archive_chars(new_dek, _REMOVAL_MEMBER, new_dek_id, removed_user_id)
    )


def archive_removed(archive_id: str, new_dek_id: str, new_dek: bytes, user_id: str) -> Optional[bool]:
    """Whether the re-key behind ``archive_id`` removed ``user_id``; None when
    the archive carries no removal tag (older or other re-keys)."""
    tail = archive_id[10:26]
    if not hmac.compare_digest(tail[:8], _archive_chars(new_dek, _REMOVAL_MARK, new_dek_id)):
        return None
    return hmac.compare_digest(
        tail[8:], _archive_chars(new_dek, _REMOVAL_MEMBER, new_dek_id, user_id)
    )


def generate_dek() -> bytearray:
    """Generate a random 256-bit DEK."""
    return bytearray(os.urandom(DEK_SIZE))


class KeyChangedElsewhere(VaultChangedElsewhere):
    """Another process changed the vault's KEK after this one unlocked."""


class TeamKeyRefused(CryptoError, RuntimeError):
    """A stored key no longer has authority in the trusted team log."""


SHARED_BEFORE_TEAM_LOG = (
    "This folder was shared with you before the organisation had a team log. This "
    "device takes another account's key only through the log: ask an admin to run "
    "'sezam team-log init', then confirm their fingerprint with 'sezam team-log "
    "confirm-founder FINGERPRINT' and pull. The admin does not need to share it again."
)


def shared_before_team_log(db: VaultDB, user_id: str) -> set[str]:
    """Keys other accounts shared with ``user_id`` while the organisation has
    no team log. Review 8595ec1 (low): the desktop never opened them and the
    member got a bare "Decryption failed"; founding the log carries them over."""
    from .team_log_local import GENESIS_META, TeamLogMismatch, local_team_state

    if not user_id or db.get_meta(GENESIS_META):
        return set()
    try:
        if local_team_state(db) is not None:
            return set()
    except TeamLogMismatch:
        return set()  # capability run 406: a log this device refuses is still a log

    return {
        row["dek_id"] for row in db.fetchall(
            "SELECT dek_id FROM access_envelopes WHERE user_id = ? AND created_by != ? "
            "AND id NOT IN (SELECT envelope_id FROM withdrawn_envelopes) "
            "AND dek_id IN (SELECT dek_id FROM nodes WHERE is_deleted = 0)",
            (user_id, user_id),
        )
    }


class DEKManager:
    """Manages the KEK/DEK hierarchy."""

    def __init__(self, db: VaultDB, kek: bytearray, identity: Optional[Callable] = None):
        """Initialize with an unlocked KEK.

        Args:
            db: Open vault database.
            kek: 32-byte Key Encryption Key (from Argon2id).
        """
        self._db = db
        self._kek = kek
        self._identity = identity
        # Cache of unlocked DEKs: dek_id → bytearray
        self._dek_cache: dict[str, bytearray] = {}
        self._box_keys: set[str] = set()
        # We use a synthetic "KEK dek_id" for AAD when wrapping DEKs with KEK.
        # This is stored in vault_meta as "kek_dek_id".
        self._kek_dek_id: Optional[str] = db.get_meta("kek_dek_id")

    def _wrapping_kek_id(self) -> str:
        """``kek_dek_id`` for a new KEK wrap, if the vault still has this KEK.

        Review d615826 H4: the GUI or 'mcp-serve' stayed unlocked with its KEK
        while another process changed the password and re-wrapped every DEK.
        A DEK it then wrapped under its old KEK opened with neither password.
        """
        stored = self._db.get_meta("kek_dek_id")
        if self._kek_dek_id is not None and stored is not None and stored != self._kek_dek_id:
            raise KeyChangedElsewhere(
                "The master password was changed in another Sezam program; "
                "lock the vault and unlock it again with the new password."
            )
        self._db.require_generation()
        return self.kek_dek_id

    def require_current_kek(self) -> None:
        """KeyChangedElsewhere when another process changed the vault's KEK."""
        self._wrapping_kek_id()

    @property
    def kek_dek_id(self) -> str:
        """ULID used as dek_id in AAD when wrapping DEKs with KEK."""
        if self._kek_dek_id is None:
            val = self._db.get_meta("kek_dek_id")
            if val is None:
                val = new_ulid()
                self._db.set_meta("kek_dek_id", val)
            self._kek_dek_id = val
        return self._kek_dek_id

    def create_dek(
        self,
        scope: str,
        node_id: Optional[str] = None,
    ) -> tuple[str, bytearray]:
        """Create a new DEK, wrap it with KEK, store in DB.

        Returns (dek_id, raw_dek).
        """
        dek_id = new_ulid()
        raw_dek = generate_dek()

        # Review 7c10379 (R7-H): checked and inserted as two autocommit
        # statements, a password change committed in between missed this DEK
        # and a tier-2 entry made then opened with neither password. The
        # write lock is held from the check to the insert.
        with self._db.transaction(immediate=True):
            kek_dek_id = self._wrapping_kek_id()
            encrypted_dek = encrypt_dek_wrap(
                dek_to_wrap=raw_dek,
                wrapping_key=self._kek,
                wrapping_key_id=ulid_to_bytes(kek_dek_id),
                dek_archive_id=ulid_to_bytes(dek_id),
            )
            self._db.execute(
                "INSERT INTO deks (id, node_id, scope, encrypted_dek, version) "
                "VALUES (?, ?, ?, ?, 1)",
                (dek_id, node_id, scope, encrypted_dek),
            )

        self._dek_cache[dek_id] = raw_dek
        return dek_id, raw_dek

    def _team_key_state(self, dek_id: str):
        from .. import teamlog
        from .team_log_local import (
            CONFIRMED_GENESIS_META, GENESIS_META, TeamLogMismatch, local_team_state, log_trusted, team_key_ids,
        )

        if dek_id not in team_key_ids(self._db):
            return None  # INV-7: a personal key never waits for the team log
        try:
            team = local_team_state(self._db)
        except TeamLogMismatch as exc:
            raise TeamKeyRefused(str(exc)) from exc
        observed = self._db.get_meta(GENESIS_META)
        confirmed = self._db.get_meta(CONFIRMED_GENESIS_META)
        if observed and (team is None or team.genesis_hash != observed):
            raise CryptoError("The pinned team log is missing or differs")
        if team is None or dek_id not in team.dek_index:
            return None
        user_id, keys = self._identity() if self._identity else (None, None)
        if keys is None or (confirmed and confirmed != team.genesis_hash):
            raise CryptoError("The team key has no trusted identity")
        trusted = log_trusted(self._db, user_id, keys, team)
        if not trusted:
            from ..crypto.keys import KeyPair
            from . import pending_states
            from .key_rotation import open_old_keypair

            journal = pending_states.key_change_journal(self._db)
            if "identity" in journal and int(journal.get("epoch", -1)) > pending_states.last_pushed_key_epoch(self._db):
                private = open_old_keypair(journal, self._kek, user_id)
                if private is not None:
                    try:
                        previous = KeyPair.from_private_only(private)
                        try:
                            trusted = log_trusted(self._db, user_id, previous, team)
                        finally:
                            previous.zeroize()
                    finally:
                        private[:] = bytes(len(private))
        if not trusted:
            raise TeamKeyRefused("The team log's founder is not confirmed on this device")
        # A key the log replaced opens while the log lets this account hold
        # the folder's current one (unlock_dek).
        if not teamlog.may_hold_key(team, user_id, dek_id) and not sync_core.call(
                "may_open_superseded", team=sync_core.team_input(team, user_id), key=dek_id):
            raise TeamKeyRefused("The confirmed team log does not permit this key")
        return team

    def _open_team_envelope(self, dek_id: str, team) -> bytearray:
        from .. import teamlog
        from ..crypto.envelope_crypto import open_envelope

        user_id, keys = self._identity()
        for env in self._db.fetchall(
            "SELECT * FROM access_envelopes WHERE dek_id = ? AND user_id = ? "
            "AND id NOT IN (SELECT envelope_id FROM withdrawn_envelopes)", (dek_id, user_id)
        ):
            if not teamlog.envelope_valid(team, env["created_by"], user_id, dek_id,
                                          env["access_level"], bytes(keys.encryption_pk).hex()):
                continue
            sender_pk = team.members[env["created_by"]].encryption_pk
            try:
                receipt = self._db.get_meta_json("team_envelope_receipt:" + env["id"])
                if receipt is not None:
                    from .team_log_local import received_envelope_sender
                    sender_pk = received_envelope_sender(self._db, env, receipt)
                raw = open_envelope(env["encrypted_dek"], keys.encryption_sk, bytes.fromhex(sender_pk))
            except (CryptoError, ValueError):
                continue
            if len(raw) == DEK_SIZE:
                return raw
            raw[:] = bytes(len(raw))
        raise CryptoError("No authorized team envelope opens this key")

    def unlock_dek(self, dek_id: str) -> bytearray:
        """Unlock through KEK or a trusted team envelope; recheck cached authority.

        A team folder's earlier key opens too while the log lets this account
        hold the folder's current one (sync core may_open_superseded): what
        was sealed under it before the re-key is read and sealed again under
        the current key. Whether a live copy under it is valid is decided
        when it is accepted (teamlog.item_refusal: old key generation, on
        every pull and on the server's push), not here; design §4.3.3: an old
        key reads history. Review e443cbc R15 (goal #429): opened only to seal
        again, an admin device whose log a push, a revocation check or a
        paginated pull moved past a re-key could not read the copies it held
        until their re-sealed versions came, nor ever its trash and earlier
        versions there (no restore).
        """
        try:
            team = self._team_key_state(dek_id)
            if dek_id in self._dek_cache and dek_id in self._box_keys:
                if team is None:
                    raise CryptoError("The team envelope has no verified log")
                opened = self._open_team_envelope(dek_id, team)
                try:
                    if not hmac.compare_digest(opened, self._dek_cache[dek_id]):
                        raise CryptoError("The team envelope changed its key")
                finally:
                    opened[:] = bytes(len(opened))
        except Exception:
            for raw in self._dek_cache.values():
                raw[:] = bytes(len(raw))
            self._dek_cache.clear()
            raise
        if dek_id in self._dek_cache:
            return self._dek_cache[dek_id]

        row = self._db.fetchone(
            "SELECT encrypted_dek, version FROM deks WHERE id = ?", (dek_id,)
        )
        if row is None:
            raise KeyError(f"DEK not found: {dek_id}")

        version = row["version"] if row["version"] else 1
        try:
            raw_dek = decrypt_dek_wrap(
                envelope_blob=row["encrypted_dek"],
                wrapping_key=self._kek,
                dek_archive_id=ulid_to_bytes(dek_id),
                version=version,
            )
        except CryptoError:
            # Stateful test SM79: a DEK made by the process that changed the
            # password is under the new KEK; this one failed with a bare
            # "Decryption failed" instead of saying to unlock again.
            self._wrapping_kek_id()
            if team is None or self._identity is None:
                if self._identity is not None and dek_id in shared_before_team_log(
                        self._db, self._identity()[0]):
                    raise TeamKeyRefused(SHARED_BEFORE_TEAM_LOG) from None
                raise
            raw_dek = self._open_team_envelope(dek_id, team)
            self._box_keys.add(dek_id)

        self._dek_cache[dek_id] = raw_dek
        return raw_dek

    def can_unwrap(self, dek_id: str, encrypted_dek: bytes, version: int) -> bool:
        """True when this user's KEK opens the wrap (i.e. the DEK is ours)."""
        try:
            raw = decrypt_dek_wrap(
                envelope_blob=encrypted_dek,
                wrapping_key=self._kek,
                dek_archive_id=ulid_to_bytes(dek_id),
                version=version or 1,
            )
        except (CryptoError, ValueError):
            return False
        for i in range(len(raw)):
            raw[i] = 0
        return True

    def rewrap_from(
        self, dek_id: str, encrypted_dek: bytes, version: int, old_kek: bytes
    ) -> Optional[bytes]:
        """The wrap under ``old_kek`` re-wrapped under the current KEK at
        ``version + 1``, or None when ``old_kek`` does not open it."""
        try:
            raw = decrypt_dek_wrap(
                envelope_blob=encrypted_dek,
                wrapping_key=old_kek,
                dek_archive_id=ulid_to_bytes(dek_id),
                version=version or 1,
            )
        except (CryptoError, ValueError):
            return None
        try:
            return encrypt_dek_wrap(
                dek_to_wrap=raw,
                wrapping_key=self._kek,
                wrapping_key_id=ulid_to_bytes(self._wrapping_kek_id()),
                dek_archive_id=ulid_to_bytes(dek_id),
                version=(version or 1) + 1,
            )
        finally:
            raw[:] = b"\x00" * len(raw)

    def classify_legacy_foreign_deks(self) -> None:
        """Upgrade old sync databases that predate explicit foreign-DEK metadata."""
        if self._db.get_meta("foreign_dek_ids") is not None:
            return

        foreign_dek_ids = set()
        rows = self._db.fetchall("SELECT id, node_id, scope, encrypted_dek, version FROM deks")
        for row in rows:
            if row["scope"] != "folder" or row["node_id"] is not None:
                continue
            if not self.can_unwrap(row["id"], row["encrypted_dek"], row["version"]):
                foreign_dek_ids.add(row["id"])
        self._db.set_meta_json("foreign_dek_ids", sorted(foreign_dek_ids))

    def unlock_all_deks(self) -> None:
        """Unlock every locally owned DEK; foreign personal wraps stay opaque."""
        from .team_log_local import team_key_ids

        foreign_dek_ids = set(self._db.get_meta_json("foreign_dek_ids") or [])
        team_keys = team_key_ids(self._db)
        rows = self._db.fetchall("SELECT id FROM deks")
        for row in rows:
            if row["id"] not in foreign_dek_ids:
                try:
                    self.unlock_dek(row["id"])
                except CryptoError:
                    if row["id"] not in team_keys:
                        raise  # A refused team key must not lock personal data.

    def get_dek_for_node(self, node_id: str) -> tuple[str, bytearray]:
        """Get the DEK for a given node. Returns (dek_id, raw_dek)."""
        row = self._db.fetchone(
            "SELECT dek_id FROM nodes WHERE id = ?", (node_id,)
        )
        if row is None:
            raise KeyError(f"Node not found: {node_id}")
        dek_id = row["dek_id"]
        return dek_id, self.unlock_dek(dek_id)

    def get_dek_for_entry(self, entry_id: str) -> tuple[str, bytearray]:
        """Get the DEK for a given entry. If entry.dek_id is NULL, inherits from node."""
        row = self._db.fetchone(
            "SELECT dek_id, node_id FROM entries WHERE id = ?", (entry_id,)
        )
        if row is None:
            raise KeyError(f"Entry not found: {entry_id}")
        dek_id = row["dek_id"]
        if dek_id is None:
            # Inherit from parent node
            return self.get_dek_for_node(row["node_id"])
        return dek_id, self.unlock_dek(dek_id)

    def get_root_dek(self) -> tuple[str, bytearray]:
        """Get the root DEK (scope='root')."""
        row = self._db.fetchone(
            "SELECT id FROM deks WHERE scope = 'root'"
        )
        if row is None:
            raise KeyError("Root DEK not found")
        return row["id"], self.unlock_dek(row["id"])

    def get_audit_dek(self) -> tuple[str, bytearray]:
        """Get the audit DEK (scope='audit')."""
        row = self._db.fetchone(
            "SELECT id FROM deks WHERE scope = 'audit'"
        )
        if row is None:
            raise KeyError("Audit DEK not found")
        return row["id"], self.unlock_dek(row["id"])

    def rekey_folder(
        self, old_dek_id: str, node_id: str, removed_user_id: Optional[str] = None
    ) -> tuple[str, bytearray]:
        """Generate new DEK for a folder, archive old one.

        Used during access revocation (spec 9.3).
        Returns (new_dek_id, new_raw_dek).
        """
        old_raw_dek = self.unlock_dek(old_dek_id)
        new_dek_id, new_raw_dek = self.create_dek("folder", node_id)

        # Archive old DEK wrapped by new DEK (chain wrapping)
        archive_id = (
            removal_archive_id(new_dek_id, new_raw_dek, removed_user_id)
            if removed_user_id else new_ulid()
        )
        encrypted_old = encrypt_dek_wrap(
            dek_to_wrap=old_raw_dek,
            wrapping_key=new_raw_dek,
            wrapping_key_id=ulid_to_bytes(new_dek_id),
            dek_archive_id=ulid_to_bytes(archive_id),
        )

        now_ms = int(time.time() * 1000)
        self._db.execute(
            "INSERT INTO dek_archive (id, replaced_by, encrypted_dek, archived_at, version) "
            "VALUES (?, ?, ?, ?, 1)",
            (archive_id, new_dek_id, encrypted_old, now_ms),
        )

        # Update deks table: point node to new DEK
        self._db.execute(
            "UPDATE deks SET node_id = NULL WHERE id = ?", (old_dek_id,)
        )

        return new_dek_id, new_raw_dek

    def successor_of(self, dek_id: str) -> Optional[str]:
        """The DEK a re-key replaced ``dek_id`` with, or None.

        An archive row names only the new DEK; it is the one whose archive
        opens to ``dek_id``'s key."""
        link = self.successor_link(dek_id)
        return link[0] if link else None

    def successor_link(
        self, dek_id: str, _seen: frozenset = frozenset()
    ) -> Optional[tuple[str, str]]:
        """``(successor DEK id, archive id)`` of the re-key that replaced ``dek_id``.

        Review a159e97 (state machine): two devices of one account re-keyed
        the same folder, so two archives wrap its old key. The first row in
        table order won, and that is pull order: devices picked different
        successors, and a grant made again on the dead one cut the member
        off. The successor whose chain reaches a key a folder uses now wins,
        then the lowest id.
        """
        links = self._successor_links(dek_id)
        if len(links) <= 1:
            return links[0] if links else None
        seen = _seen | {dek_id}

        def reaches_current(candidate: str) -> bool:
            path = set(seen)
            while candidate not in path:
                row = self._db.fetchone("SELECT node_id FROM deks WHERE id = ?", (candidate,))
                if row is not None and row["node_id"]:
                    return True
                path.add(candidate)
                link = self.successor_link(candidate, frozenset(path))
                if link is None:
                    return False
                candidate = link[0]
            return False

        return min(links, key=lambda link: (not reaches_current(link[0]), link[0]))

    def removed_from(self, dek_id: str, user_id: str) -> bool:
        """Whether a re-key of ``dek_id`` this vault can open removed ``user_id``."""
        for successor, archive_id in self._successor_links(dek_id):
            try:
                if archive_removed(archive_id, successor, self.unlock_dek(successor), user_id):
                    return True
            except (KeyError, CryptoError, ValueError):
                continue
        return False

    def _successor_links(self, dek_id: str) -> list[tuple[str, str]]:
        try:
            raw = self.unlock_dek(dek_id)
        except (KeyError, CryptoError, ValueError):
            return []
        links = []
        for row in self._db.fetchall(
            "SELECT id, replaced_by, encrypted_dek, version FROM dek_archive"
        ):
            try:
                old = decrypt_dek_wrap(
                    envelope_blob=row["encrypted_dek"],
                    wrapping_key=self.unlock_dek(row["replaced_by"]),
                    dek_archive_id=ulid_to_bytes(row["id"]),
                    version=row["version"] or 1,
                )
            except (KeyError, CryptoError, ValueError):
                continue
            same = hmac.compare_digest(bytes(old), bytes(raw))
            old[:] = b"\x00" * len(old)
            if same:
                links.append((row["replaced_by"], row["id"]))
        return links

    def rewrap_all_deks(self, new_kek: bytearray, bump_version: bool = True) -> None:
        """Re-wrap all DEKs with a new KEK (change-password, spec 9.1).

        Also updates kek_dek_id. ``bump_version=False`` re-wraps in place for
        a device taking over a rotation another device already pushed: the
        server's newer versions win on the next pull, so this device must not
        publish rival wraps at the same versions.
        """
        self._wrapping_kek_id()  # a stale process would keep only its cached DEKs
        new_kek_dek_id = new_ulid()
        # Ownership is what the current KEK opens, not the foreign list: a
        # stale list entry would leave our DEK under the old KEK for good.
        foreign_dek_ids = set()
        rows = self._db.fetchall("SELECT id, version, encrypted_dek FROM deks")
        for row in rows:
            dek_id = row["id"]
            version = (row["version"] if row["version"] else 1) + int(bump_version)
            try:
                raw_dek = decrypt_dek_wrap(row["encrypted_dek"], self._kek,
                                           ulid_to_bytes(dek_id), row["version"] or 1)
            except (CryptoError, ValueError):
                foreign_dek_ids.add(dek_id)
                continue
            try:
                new_encrypted = encrypt_dek_wrap(
                    dek_to_wrap=raw_dek,
                    wrapping_key=new_kek,
                    wrapping_key_id=ulid_to_bytes(new_kek_dek_id),
                    dek_archive_id=ulid_to_bytes(dek_id),
                    version=version,
                )
            finally:
                raw_dek[:] = bytes(len(raw_dek))
            self._db.execute(
                "UPDATE deks SET encrypted_dek = ?, version = ? WHERE id = ?",
                (new_encrypted, version, dek_id),
            )

        self._db.set_meta_json("foreign_dek_ids", sorted(foreign_dek_ids))
        from .ai_access import rewrap_macs

        rewrap_macs(self._db, self._kek, new_kek)
        self._db.set_meta("kek_dek_id", new_kek_dek_id)
        self._kek_dek_id = new_kek_dek_id
        self._kek = new_kek

    def zeroize(self) -> None:
        """Zeroize all cached DEKs and KEK (lock)."""
        for dek in self._dek_cache.values():
            dek[:] = b"\x00" * len(dek)
        self._dek_cache.clear()
        if self._kek:
            self._kek[:] = b"\x00" * len(self._kek)
