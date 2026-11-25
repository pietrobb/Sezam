"""CRUD operations for vault nodes and entries.

Spec Phase 1a: Full CRUD with lazy unlock, FTS5 search.
"""

from __future__ import annotations

import logging
import json
import time
from hmac import compare_digest
from pathlib import Path
from typing import Callable, Optional

from .. import teamlog
from ..crypto.aead import HEADER_SIZE, TAG_SIZE, BlobKind, decrypt, encrypt, parse_envelope
from ..crypto.padding import pad
from ..crypto.kdf import Argon2Params, derive_kek, derive_kek_and_proof, generate_salt
from ..crypto.keys import KeyPair, generate_keypair
from ..models import (
    EntryData,
    EntryField,
    EntryMeta,
    NodeMeta,
    bytes_to_ulid,
    new_ulid,
    ulid_to_bytes,
)
from . import oplock, outbox, pending_states
from .audit import AuditLog
from .db import IdentityChangedElsewhere, VaultDB
from .dek import DEKManager
from .key_rotation import (
    ORG_RECOVERY_VERSIONS,
    make_journal,
    open_current_auth_proof,
    open_old_kek,
    open_old_keypair,
    org_recovery_box_key,
    org_recovery_server_wrap,
    org_recovery_signing_key,
)
from .personal_root import (
    fold_personal_tree_keys,
    in_personal_tree,
    is_personal_root,
    moved_subtree_keys,
    personal_root_ids,
    reseal_moved_subtree,
)
from .search import SearchIndex
from .snapshots import (
    SnapshotError,
    drop_snapshot_of_other_password,
    drop_snapshots_of_other_passwords,
    take_snapshot,
)
from .sync_common import (
    STALE_OWN_WRAPS_META,
    queued_for_removal,
    reseal_key_row,
    server_error,
    vouched_access_level,
)
from .sync_writers import WRITES_AUDITED_META
from .team_log_local import (
    CONFIRMED_GENESIS_META, identity_continuation, import_account_anchor, local_team_state, log_trusted,
    publishable_anchor,
    record_account_anchor, team_folder_at_or_above,
)
from .sync_limits import (
    MAX_OBJECT_PAYLOAD_BYTES,
    SyncUnitTooLarge,
    estimated_object_bytes,
    payload_too_large,
    require_fits_atomic_unit,
)

logger = logging.getLogger(__name__)

# The snapshot a password change took; removed once the new password opened the vault.
KEY_CHANGE_SNAPSHOT_META = "key_change_snapshot"
# Capability run 273: every password state this device left while the account
# had no anchor (aead pre-anchor format). A later publication carries them all.
PRE_ANCHOR_HISTORY_META = "pre_anchor_history"
PRE_ANCHOR_PASSWORD_REFUSED = (
    "This password opened the account before the team anchor was published; a server "
    "could still give a new device the older keys under it. Choose a password never used before."
)


def open_server_keypair(recover_resp: dict, server_kek: bytes | bytearray) -> KeyPair | None:
    """Decrypt the account keypair returned by /api/auth/recover.

    Returns None when the server holds no keypair yet. Raises RuntimeError if
    it cannot be opened with the KEK derived from the server's salt.
    """
    from ..crypto.aead import decrypt_account_bundle

    blob_hex = recover_resp.get("encrypted_keypair") or ""
    if not blob_hex:
        return None
    try:
        kp_data, genesis, pre_anchor = decrypt_account_bundle(
            envelope_blob=bytes.fromhex(blob_hex),
            kek=server_kek,
            user_object_id=ulid_to_bytes(recover_resp["user_id"]),
        )
    except Exception as exc:
        raise RuntimeError("Server keypair cannot be opened") from exc
    try:
        keypair = KeyPair.from_private_only(bytes(kp_data))
        keypair.confirmed_genesis = genesis
        keypair.pre_anchor = pre_anchor
        return keypair
    finally:
        kp_data[:] = b"\x00" * len(kp_data)


def recover_with_password(
    post: Callable[[dict], Optional[dict]],
    username: str,
    password: str,
    salt: bytes,
    params: Argon2Params,
    unlock_code: Optional[str] = None,
) -> tuple[bytearray, dict]:
    """POST /api/auth/recover with the auth proof of ``password``.

    ``unlock_code`` is an admin's one-time unlock code ('sezam
    unlock-recovery'): it gets the proof checked while the name is locked.

    ``post(body)`` sends the request and raises ServerError on a refusal. The canonical NFC proof goes first; an account
    created before normalization (lockout review M8) gets the typed and the
    decomposed form after a 401. Returns the KEK and the response; the
    caller zeroizes the KEK.
    """
    from ..crypto.kdf import password_forms

    forms = password_forms(password)
    for index, form in enumerate(forms):
        kek, auth_proof = derive_kek_and_proof(form, salt, params, exact=True)
        try:
            # The params let an account stored without them adopt the real
            # ones once the proof matches (lockout review N2).
            body = {
                "username": username,
                "auth_proof": auth_proof.hex(),
                "argon2_params": params.account_dict(),
            }
            if unlock_code:
                body["unlock_code"] = unlock_code.strip()
            resp = post(body) or {}
        except RuntimeError as exc:
            kek[:] = b"\x00" * len(kek)
            if index + 1 < len(forms) and server_error(exc, 401):
                continue
            raise
        finally:
            auth_proof[:] = b"\x00" * len(auth_proof)
        return kek, resp
    raise AssertionError("password_forms is never empty")


def recover_refusal(exc: Exception) -> Optional[str]:
    """What to tell the user when /recover refused to check the password.

    Review 688edcb V2: 423/429 fell through to "you have no account here" and
    the invitation prompt, steering the owner to create a second account.
    """
    if server_error(exc, 429):
        return (
            "Server docasne odmieta dalsie pokusy o prihlasenie heslom pre tento ucet "
            "alebo z tejto adresy (prilis vela zlych pokusov). Skus to znova o par minut, "
            "zo siete, z ktorej si sa uz prihlasoval, alebo s jednorazovym kodom od admina "
            "('sezam unlock-recovery <user-id>' na jeho zariadeni, potom "
            "'sezam connect URL --unlock-code KOD')."
        )
    if server_error(exc, 423):
        return (
            "Heslo nesedi a ucet je po vela zlych pokusoch docasne zamknuty: dalsi pokus "
            "server overi az o par minut. Zamok moze hned zrusit administrator "
            "('sezam unlock-recovery <user-id>' da jednorazovy kod pre "
            "'sezam connect URL --unlock-code KOD')."
        )
    return None


def server_account_kdf(meta: dict, db: Optional[VaultDB] = None) -> Argon2Params:
    """KDF params of the account key material described by ``/api/meta``.

    Lockout review N2: an account stored before per-account params is
    reported with the server default (128 MiB), which opens nothing when it
    was created with other params. A local vault holding the SAME salt holds
    the material's real params, so they win; otherwise the server's params
    are used, and none at all is an error instead of a guess.
    """
    if db is not None:
        local_salt = db.get_meta("argon2_salt")
        local_params = db.get_meta_json("argon2_params")
        if local_salt and local_params and local_salt.lower() == str(
            meta.get("argon2_salt") or ""
        ).lower():
            return Argon2Params.from_dict(local_params)
    if not meta.get("argon2_params"):
        raise RuntimeError("Server did not return the account KDF parameters")
    params = Argon2Params.from_dict(meta["argon2_params"])
    # Review d615826: a server announcing a password change elsewhere (new
    # salt, higher key_epoch) chose the params too, and cheap ones made the
    # auth proof this device then sends crackable offline. The web's hard
    # floor applies, lowered only to params this vault itself was made with.
    floor_time, floor_memory = Argon2Params.WEB_FLOOR_TIME, Argon2Params.WEB_FLOOR_MEMORY
    local_params = db.get_meta_json("argon2_params") if db is not None else None
    if local_params:
        floor_time = min(floor_time, int(local_params["time_cost"]))
        floor_memory = min(floor_memory, int(local_params["memory_cost"]))
    if params.time_cost < floor_time or params.memory_cost < floor_memory or params.parallelism < 1:
        raise RuntimeError(
            "Server returned KDF parameters below the minimum "
            f"(time {params.time_cost}, memory {params.memory_cost} KiB); "
            "the password is not derived with them"
        )
    return params


def reseal_envelopes_for_rotation(
    db: VaultDB, dek_mgr: DEKManager, user_id: str, new_keypair: KeyPair
) -> None:
    """Reissue held team keys by the log, and re-seal this user's legacy grants.

    A recipient opens an envelope with the sender's current key; the old one
    is withdrawn in the same atomic push (the outbox ``rekey`` row with
    ``identity_rotation``).
    """
    from ..crypto.envelope_crypto import create_envelope

    tombstones, new_ids = [], []
    team = local_team_state(db)
    withheld = queued_for_removal(db)
    if team is not None and teamlog.is_admin(team, user_id):
        foreign = set(db.get_meta_json("foreign_dek_ids") or [])
        for folder in sorted(team.folders):
            dek_id = teamlog.current_key(team, folder)
            if not db.fetchone("SELECT 1 FROM deks WHERE id = ?", (dek_id,)):
                continue
            # A different device may never have received the old envelopes.
            # The trusted log, not that cache or known_keys, defines recipients.
            dek_mgr._team_key_state(dek_id)
            if not teamlog.may_seal(team, folder):
                raise RuntimeError("The team folder needs a re-key before identity rotation")
            recipients = [r for r in teamlog.key_recipients(team, folder) if r[0] != user_id]
            if dek_id in foreign:
                # R15 #441 (stateful run): a key the admin holds only by an
                # envelope (the former admin re-keyed the folder and handed the
                # role back) is sealed to this account's old key, and nobody
                # else may reissue it: after the rotation no device of the
                # account opened the folder. The admin seals it to itself.
                recipients.append((
                    user_id, bytes(new_keypair.encryption_pk).hex(),
                    team.access.get(folder, {}).get(user_id, "write"),
                ))
            for uid, encryption_pk, level in recipients:
                if uid in withheld:
                    continue
                new_id = new_ulid()
                db.execute(
                    "INSERT INTO access_envelopes "
                    "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (new_id, dek_id, uid, user_id, level, create_envelope(
                        dek_mgr.unlock_dek(dek_id), new_keypair.to_nacl_private_key().encode(),
                        bytes.fromhex(encryption_pk),
                    )),
                )
                new_ids.append(new_id)
                outbox.queue_write(db, folder)
    # Stateful test SM47: an envelope under a folder key a member re-key
    # replaced (another device's grant, pulled after this device re-keyed)
    # opens nothing current. Re-sealed, it went out with that key, now
    # re-wrapped without its folder, and the server refused the whole
    # rotation for good ("envelope references unknown DEK").
    for env in db.fetchall(
        "SELECT e.id, e.dek_id, e.user_id, e.access_level, e.encrypted_dek "
        "FROM access_envelopes e LEFT JOIN deks d ON d.id = e.dek_id "
        "WHERE e.created_by = ? "
        "AND NOT (d.scope = 'folder' AND d.node_id IS NULL)",
        (user_id,),
    ):
        if env["id"] in new_ids:
            continue
        if team is not None and env["dek_id"] in team.dek_index:
            tombstones.append({
                "id": env["id"], "dek_id": env["dek_id"], "user_id": env["user_id"],
                "access_level": env["access_level"],
                "encrypted_dek": bytes(env["encrypted_dek"]).hex(),
                "unsent": outbox.is_pending(db, outbox.ENVELOPE, env["id"]),
            })
            db.execute("DELETE FROM access_envelopes WHERE id = ?", (env["id"],))
            continue
        if env["user_id"] in withheld:
            # Public CI run 44260509986: a member this account revoked, whose
            # re-key is queued. Re-sealed after a full resync, the envelope
            # went out under the key that re-key replaces and the server
            # refused every push ("envelope references unknown DEK"). The
            # queued re-key withdraws the old envelope.
            continue
        key_row = db.fetchone(
            "SELECT encryption_pk FROM known_keys WHERE user_id = ?", (env["user_id"],)
        )
        if key_row is None:
            raise RuntimeError(f"Missing verified encryption key for user {env['user_id']}")
        new_id = new_ulid()
        db.execute(
            "INSERT INTO access_envelopes "
            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                new_id, env["dek_id"], env["user_id"], user_id,
                vouched_access_level(db, env["id"], env["access_level"]),
                create_envelope(
                    dek_mgr.unlock_dek(env["dek_id"]),
                    new_keypair.to_nacl_private_key().encode(),
                    bytes(key_row["encryption_pk"]),
                ),
            ),
        )
        unsent = outbox.is_pending(db, outbox.ENVELOPE, env["id"])
        grant = outbox.body(db, outbox.TEAM_GRANT, env["id"])
        db.execute("DELETE FROM access_envelopes WHERE id = ?", (env["id"],))
        # Envelopes are pushed with their folder.
        outbox.queue_writes(
            db, "nodes", "id = (SELECT node_id FROM deks WHERE id = ?)", (env["dek_id"],)
        )
        if grant is not None:
            # R16-Z SM26b: a grant still waiting with its log records stays a
            # grant: the new envelope goes with them (_push_team_grants, after
            # the key change). In the rotation's batch it went without its
            # access.set and the server refused every push.
            outbox.sent(db, outbox.TEAM_GRANT, env["id"])
            outbox.put(db, outbox.TEAM_GRANT, grant, new_id)
        tombstones.append({
            "id": env["id"],
            "dek_id": env["dek_id"],
            "user_id": env["user_id"],
            "access_level": env["access_level"],
            "encrypted_dek": bytes(env["encrypted_dek"]).hex(),
            "unsent": unsent,
        })
        if grant is None:
            new_ids.append(new_id)
    if tombstones or new_ids:
        pending_states.set_rekey_batch(db, {
            "object_ids": new_ids + [t["id"] for t in tombstones],
            "envelope_tombstones": tombstones,
            "identity_rotation": True,
        })


def require_usable_password(password: str) -> None:
    """Refuse a new master password that some client could never type.

    A control character (a trailing \\r left by a Windows file piped into the
    CLI, a pasted tab or newline) cannot be entered in a browser or phone
    password field, so the account would be locked out of them (review
    688edcb, low).
    """
    if not password:
        raise ValueError("Master password cannot be empty.")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in password):
        raise ValueError(
            "Master password contains a control character (for example a line "
            "break or a \\r from a Windows file); other devices could not enter it."
        )


class VaultLocked(Exception):
    """Raised when vault operations are attempted while locked."""


class OrgRecoveryExistsError(Exception):
    """A repeated org-recovery setup was not confirmed (it voids old shares)."""


def _sealed_len(plaintext: bytes) -> int:
    """Exact length of encrypt(plaintext) with padding."""
    return HEADER_SIZE + len(pad(plaintext)) + TAG_SIZE


def require_syncable_entry(meta_plaintext: bytes, data_plaintext: bytes) -> None:
    """Review 526419e #1: an entry the server can never take is not saved.

    Stored locally it stayed unsynced for good; before the push split it also
    blocked every other object of the vault.
    """
    size = 4 + _sealed_len(meta_plaintext) + _sealed_len(data_plaintext)
    if payload_too_large(size):
        raise SyncUnitTooLarge(
            f"The entry is {size // 1024} KiB encrypted; the server takes at most "
            f"{MAX_OBJECT_PAYLOAD_BYTES // 1024} KiB per entry. Shorten the note or "
            "split it into several entries."
        )


class RekeyBlockedByConflicts(RuntimeError):
    """The folders to re-key hold unresolved sync conflicts (review e4cd15a #3)."""

    def __init__(self, object_ids: list[str]):
        super().__init__(
            "The folders to re-key have unresolved sync conflicts "
            f"({', '.join(object_ids)}). Settle them with 'sezam conflicts resolve ID "
            "--keep local|server' (the re-key then runs with the next 'sezam push')."
        )
        self.object_ids = object_ids


class Vault:
    """Main vault object — manages the encrypted store.

    Lifecycle:
      1. Vault.create(path, password) — first run
      2. vault = Vault(path)
      3. vault.unlock(password)
      4. ... CRUD operations ...
      5. vault.lock()
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._db = VaultDB(self.path / "sezam.db")
        self._dek_mgr: Optional[DEKManager] = None
        self._keypair: Optional[KeyPair] = None
        self._search = SearchIndex()
        self._audit: Optional[AuditLog] = None
        self._user_id: Optional[str] = None
        self._unlocked = False

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked

    def _require_one_sync_unit(self, object_ids, what: str) -> None:
        """An atomic batch must fit the server's staging limits (review d150605 #3)."""
        total = 0
        for object_id in object_ids:
            row = self._db.fetchone(
                "SELECT 4 + length(encrypted_meta) + length(encrypted_data) AS size "
                "FROM entries WHERE id = ? UNION ALL "
                "SELECT length(encrypted_meta) FROM nodes WHERE id = ?",
                (object_id, object_id),
            )
            if row and payload_too_large(row["size"]):
                # Review d150605 S1: an item saved before the per-object check
                # made the batch, then failed every sync.
                raise SyncUnitTooLarge(
                    f"{what} has to send item {object_id}, which is "
                    f"{row['size'] // 1024} KiB encrypted; the server takes at most "
                    f"{MAX_OBJECT_PAYLOAD_BYTES // 1024} KiB per item. Shorten or split "
                    "it (e.g. a long note into several entries), then push again."
                )
            total += estimated_object_bytes(row["size"] if row else 200)
        require_fits_atomic_unit(len(object_ids), total, what)

    def _require_epoch_unit_fits(self, what: str) -> None:
        """Every own DEK goes in one atomic push (review 526419e #1, d150605 #3)."""
        if self._db.get_meta("server_url"):
            foreign = set(self._db.get_meta_json("foreign_dek_ids") or [])
            self._require_one_sync_unit(
                [r["id"] for r in self._db.fetchall("SELECT id FROM deks")
                 if r["id"] not in foreign],
                what,
            )

    def _require_trusted_node_write(self, node_id: str) -> None:
        # Review 1141a20 (R9-E, state machine seed 737373): a process left
        # unlocked while another one changed the vault's password or identity
        # wrote the item and only then had its audit record refused: the
        # write was reported as failed, yet it was there.
        self.dek_mgr.require_current_kek()
        self._require_current_identity()
        if self._all_personal(node_id):
            return  # INV-7: a personal write never waits for the team log
        team = local_team_state(self._db)
        if team is None and self._db.get_meta(CONFIRMED_GENESIS_META) is None:
            return
        if log_trusted(self._db, self._user_id, self._keypair, team):
            return
        # A founder rotating offline still owns the old identity in the sealed journal.
        journal = pending_states.key_change_journal(self._db)
        if "identity" in journal and int(journal.get("epoch", -1)) > pending_states.last_pushed_key_epoch(self._db):
            private = open_old_keypair(journal, self.dek_mgr._kek, self._user_id)
            if private is not None:
                try:
                    old = KeyPair.from_private_only(bytes(private))
                    try:
                        if log_trusted(self._db, self._user_id, old, team):
                            return
                    finally:
                        old.zeroize()
                finally:
                    private[:] = b"\x00" * len(private)
        # ... as does the kept one of a rotation taken over without the log (R15, goal #429).
        kept = identity_continuation(self._db, self.dek_mgr._kek, self._user_id)
        if kept is not None:
            try:
                if log_trusted(self._db, self._user_id, kept, team):
                    return
            finally:
                kept.zeroize()
        if team is None:
            # R16-Z SM23c: a pin without its log is not an unconfirmed founder;
            # the way out is a pull, as the web and the push guard say (INV-7).
            raise RuntimeError("The independently confirmed team log is not downloaded yet; pull it first.")
        raise RuntimeError(
            "The team log's founder is not confirmed on this device; "
            "compare their fingerprint out of band and use 'sezam team-log confirm-founder'."
        )

    def _all_personal(self, *node_ids: str) -> bool:
        roots = set(personal_root_ids(self._db, self.dek_mgr))
        return all(in_personal_tree(self._db, n, roots) for n in node_ids)

    def _team_for(self, *node_ids: str) -> Optional[teamlog.TeamState]:
        """The team log as far as these nodes go: none for the personal tree,
        which holds no team folder (INV-7, capability run 403: a refused log
        blocks team operations only, never a personal one)."""
        return None if self._all_personal(*node_ids) else local_team_state(self._db)

    def _require_unlocked(self) -> None:
        if not self._unlocked:
            raise VaultLocked("Vault is locked. Call unlock() first.")

    @property
    def dek_mgr(self) -> DEKManager:
        self._require_unlocked()
        assert self._dek_mgr is not None
        return self._dek_mgr

    @property
    def keypair(self) -> KeyPair:
        self._require_unlocked()
        assert self._keypair is not None
        return self._keypair

    @property
    def current_kek(self) -> bytearray:
        """Expose the current KEK for key export/import operations.

        Only available while vault is unlocked.
        """
        self._require_unlocked()
        assert self._dek_mgr is not None
        return self._dek_mgr._kek

    @property
    def db(self) -> VaultDB:
        return self._db

    # ── Initialization ──

    @classmethod
    def create(
        cls,
        path: str | Path,
        password: str,
        argon2_params: Optional[Argon2Params] = None,
    ) -> Vault:
        """Create a new vault (first run wizard).

        1. Generate keypair
        2. Argon2id → KEK
        3. Create sezam.db with schema
        4. Create root DEK + audit DEK
        5. Create root node
        """
        require_usable_password(password)
        path = Path(path)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)

        vault = cls(path)
        vault._db.open()
        vault._db.create_schema()

        # Argon2id params
        if argon2_params is None:
            argon2_params = Argon2Params()
        vault._db.set_meta_json("argon2_params", argon2_params.to_dict())

        # Generate salt and derive KEK
        salt = generate_salt()
        vault._db.set_meta("argon2_salt", salt.hex())
        kek = derive_kek(password, salt, argon2_params)

        # Generate keypair
        kp = generate_keypair()
        user_id = new_ulid()

        # Store encrypted keypair
        from ..crypto.aead import encrypt_keypair_wrap

        kek_dek_id = new_ulid()
        vault._db.set_meta("kek_dek_id", kek_dek_id)

        encrypted_kp = encrypt_keypair_wrap(
            keypair_data=kp.serialize_private(),
            kek=kek,
            kek_dek_id=ulid_to_bytes(kek_dek_id),
            user_object_id=ulid_to_bytes(user_id),
        )
        vault._db.set_meta("encrypted_keypair", encrypted_kp.hex())
        vault._db.set_meta("user_id", user_id)
        vault._db.set_meta("signing_pk", kp.signing_pk.hex())
        vault._db.set_meta("encryption_pk", kp.encryption_pk.hex())
        vault._db.set_meta("key_epoch", "0")

        # Initialize DEK manager
        vault._dek_mgr = DEKManager(vault._db, kek, lambda: (vault._user_id, vault._keypair))
        vault._keypair = kp
        vault._user_id = user_id
        vault._unlocked = True

        # Create root DEK and audit DEK
        root_dek_id, root_dek = vault._dek_mgr.create_dek("root")
        vault._dek_mgr.create_dek("audit")

        # Create root node
        root_node_id = new_ulid()
        root_meta = NodeMeta(name="Root")
        encrypted_meta = encrypt(
            plaintext=root_meta.to_json(),
            dek=root_dek,
            dek_id=ulid_to_bytes(root_dek_id),
            object_id=ulid_to_bytes(root_node_id),
            version=1,
            blob_kind=BlobKind.NODE_META,
        )

        outbox.queue_write(vault._db, root_node_id)
        vault._db.execute(
            "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
            "VALUES (?, NULL, ?, ?, 1, 0)",
            (root_node_id, encrypted_meta, root_dek_id),
        )
        vault._db.set_meta("root_node_id", root_node_id)
        # Nothing an older client applied: no check of the local tables.
        vault._db.set_meta(WRITES_AUDITED_META, "1")
        from .ai_access import seal_new_vault

        seal_new_vault(vault._db, kek)
        vault._db.conn.commit()

        # Same state as after unlock(): actions in this session are audited.
        vault._audit = AuditLog(vault._db)

        # Build search index
        vault._rebuild_search_index()

        return vault

    # ── Unlock / Lock ──

    def unlock(self, password: str) -> None:
        """Unlock vault with master password (lazy unlock flow, spec 5.1).

        1. Argon2id → KEK (~1s)
        2. Decrypt keypair
        3. Unlock all DEKs
        4. Decrypt all encrypted_meta → build FTS index
        5. Values = on-demand
        """
        if not self._db.exists():
            raise FileNotFoundError("Vault not found. Run 'sezam init' first.")

        self._db.open()

        try:
            kek = self._password_kek(password)
        except BaseException:
            self._db.close()
            raise
        if kek is None:
            self._db.close()
            raise ValueError("Wrong master password")
        self._unlock_kek(kek)
        self._drop_key_change_snapshot()

    def unlock_with_kek(self, kek: bytes | bytearray) -> None:
        """Unlock with an already-derived KEK (short-lived CLI session).

        Lets a cached session reopen the vault without ever storing the
        master password itself. Raises ValueError if the KEK is wrong.
        """
        if not self._db.exists():
            raise FileNotFoundError("Vault not found. Run 'sezam init' first.")
        if len(kek) != 32:
            raise ValueError("Wrong master password")
        self._db.open()
        self._unlock_kek(bytearray(kek))

    def verify_password(self, password: str) -> bool:
        """True when ``password`` opens this vault's keypair (no state change).

        Server connect derives the account auth proof and KEK from the typed
        password; a typo there would bind the account to a password that
        opens nothing, so callers check it against the local vault first.
        """
        return self.password_form(password) is not None

    def password_form(self, password: str) -> Optional[str]:
        """The form of ``password`` (see kdf.password_forms) that opens this vault.

        Anything derived from the local salt next to this vault's keypair
        (e.g. the auth proof uploaded with it) must use this form.
        """
        found = self._password_kek(password, with_form=True)
        if found is None:
            return None
        form, kek = found
        kek[:] = b"\x00" * len(kek)
        return form

    def _password_kek(self, password: str, *, with_form: bool = False):
        """The KEK ``password`` derives for this vault, or None if it opens nothing.

        NFC first; a vault created before normalization (lockout review M8)
        opens with the password as typed or decomposed then.
        """
        from ..crypto.aead import decrypt_keypair_wrap
        from ..crypto.kdf import password_forms

        params = Argon2Params.from_dict(self._db.get_meta_json("argon2_params"))
        salt = bytes.fromhex(self._db.get_meta("argon2_salt"))
        envelope = bytes.fromhex(self._db.get_meta("encrypted_keypair"))
        user_object_id = ulid_to_bytes(self._db.get_meta("user_id"))
        for form in password_forms(password):
            kek = derive_kek(form, salt, params, exact=True)
            try:
                kp_data = decrypt_keypair_wrap(
                    envelope_blob=envelope, kek=kek, user_object_id=user_object_id
                )
            except Exception:
                kek[:] = b"\x00" * len(kek)
                continue
            kp_data[:] = b"\x00" * len(kp_data)
            return (form, kek) if with_form else kek
        return None

    def _unlock_kek(self, kek: bytearray) -> None:
        # What is read below is this process's generation of the vault (H10).
        self._db.pin_generation()
        # Decrypt keypair to verify the KEK
        user_id = self._db.get_meta("user_id")
        encrypted_kp_hex = self._db.get_meta("encrypted_keypair")
        signing_pk = bytes.fromhex(self._db.get_meta("signing_pk"))
        encryption_pk = bytes.fromhex(self._db.get_meta("encryption_pk"))

        from ..crypto.aead import decrypt_keypair_wrap

        try:
            kp_data = decrypt_keypair_wrap(
                envelope_blob=bytes.fromhex(encrypted_kp_hex),
                kek=kek,
                user_object_id=ulid_to_bytes(user_id),
            )
        except Exception:
            kek[:] = b"\x00" * len(kek)
            self._db.close()
            raise ValueError("Wrong master password")

        try:
            self._keypair = KeyPair.from_private_bytes(kp_data, signing_pk, encryption_pk)
            with self._db.transaction(immediate=True):
                record_account_anchor(self._db, self._keypair)  # INV-7: never refuses the unlock
        except Exception:
            kek[:] = bytes(len(kek))
            self.lock()
            raise
        finally:
            kp_data[:] = bytes(len(kp_data))

        self._user_id = user_id
        self._dek_mgr = DEKManager(self._db, kek, lambda: (self._user_id, self._keypair))
        self._dek_mgr.classify_legacy_foreign_deks()
        self._dek_mgr.unlock_all_deks()
        self._audit = AuditLog(self._db)
        self._unlocked = True
        try:
            fold_personal_tree_keys(self._db, self._dek_mgr)
        except Exception:
            logger.warning("A personal folder stays on a key the server lacks", exc_info=True)

        # Build FTS index from decrypted metadata
        self._rebuild_search_index()

        from .ai_access import flush_pending_audit

        try:
            flush_pending_audit(self)
        except Exception:
            logger.warning("Queued AI access audit records were not written", exc_info=True)

    def lock(self) -> None:
        """Lock vault — zeroize all key material and search index."""
        if self._dek_mgr:
            self._dek_mgr.zeroize()
            self._dek_mgr = None
        if self._keypair:
            self._keypair.zeroize()
            self._keypair = None
        self._search.clear()
        self._audit = None
        self._unlocked = False
        self._user_id = None
        self._db.close()

    # ── Audit logging ──

    def _audit_log(
        self, action: str, detail_plaintext: Optional[bytes] = None, *, strict: bool = False
    ) -> None:
        """Append an audit log record for the current operation.

        Silently skips if audit log or keypair not available (e.g., during init).
        ``strict=True`` raises instead, for actions that must not run unaudited;
        it also raises when the details cannot be encrypted, because a record
        without them does not say what the action was about.
        """
        if not self._audit or not self._keypair or not self._user_id:
            if strict:
                raise RuntimeError("Audit log is not available")
            return
        # Review 1141a20 (R9-E): the check and the record in one write
        # transaction. Another process rebinding the vault between them got
        # the record signed under the dead id and generation.
        with self._db.transaction(immediate=True):
            self._require_current_identity()
            if strict:
                self._append_audit(action, detail_plaintext, strict=True)
                return
            try:
                with self._db.transaction():
                    self._append_audit(action, detail_plaintext)
            except Exception:
                # Audit log failure must not break CRUD operations, but must not be silent.
                logger.warning("Audit record for %r could not be written", action, exc_info=True)

    def _require_current_identity(self) -> None:
        """Review a159e97 H10: the GUI or 'mcp-serve' stayed unlocked while
        another process rebound the vault to the server's account id (or its
        keypair). Its audit records were signed under the dead id; the server
        refused them as 'Invalid audit signature' and every push of the vault
        stuck on them. A process whose identity is no longer the vault's signs
        nothing."""
        if not self._keypair or not self._user_id:
            return
        stored_id = self._db.get_meta("user_id")
        stored_pk = self._db.get_meta("signing_pk")
        if (stored_id and stored_id != self._user_id) or (
            stored_pk and stored_pk != self._keypair.signing_pk.hex()
        ):
            raise IdentityChangedElsewhere(
                "Another Sezam program bound this vault to another account identity; "
                "lock the vault and unlock it again."
            )
        self._db.require_generation()

    def _append_audit(
        self, action: str, detail_plaintext: Optional[bytes], *, strict: bool = False
    ) -> None:
        # Get audit DEK for encrypting details
        audit_dek = None
        audit_dek_id = None
        if detail_plaintext and self._dek_mgr:
            try:
                row = self._db.fetchone(
                    "SELECT id FROM deks WHERE scope = 'audit' LIMIT 1"
                )
                if row:
                    audit_dek_id = row["id"]
                    audit_dek = self._dek_mgr.unlock_dek(audit_dek_id)
            except Exception:
                if strict:
                    raise
                logger.warning("Audit DEK unavailable; audit detail is omitted", exc_info=True)
                audit_dek = audit_dek_id = None
        if strict and detail_plaintext and audit_dek is None:
            raise RuntimeError("Audit DEK is not available; the record would lose its details")

        self._audit.append(
            actor_id=self._user_id,
            action=action,
            signing_key=self._keypair.to_nacl_signing_key(),
            detail_plaintext=detail_plaintext,
            audit_dek=audit_dek,
            audit_dek_id=audit_dek_id,
        )

    # ── Node operations ──

    def create_node(
        self,
        name: str,
        parent_id: Optional[str] = None,
        tier: Optional[int] = None,
        create_dek: bool = True,
        ai_read_secret: Optional[bool] = None,
    ) -> str:
        """Create a new folder node.

        Args:
            name: Folder name.
            parent_id: Parent node ID (None = under root).
            tier: Access tier (None = inherit).
            create_dek: Whether to create a new folder DEK (True for folders).

        Returns:
            Node ID.
        """
        self._require_unlocked()

        if parent_id is None:
            parent_id = self._db.get_meta("root_node_id")

        self._require_trusted_node_write(parent_id)

        # A personal tree has one key, as on the web and the phone: the server
        # takes no key of a member's that names a folder, so a folder key
        # there never left this device and the folder's items were unreadable
        # on every other one.
        if create_dek and in_personal_tree(
            self._db, parent_id, set(personal_root_ids(self._db, self.dek_mgr))
        ):
            create_dek = False
        # Review e443cbc R15 (goal #429): nor does a folder in a team folder, as
        # on the web and the phone. Its own key was not in the log, so every
        # client refused what it sealed and the server each item put there.
        if create_dek and team_folder_at_or_above(self._db, self._team_for(parent_id), parent_id):
            create_dek = False

        node_id = new_ulid()
        meta = NodeMeta(name=name, tier=tier, ai_read_secret=ai_read_secret)

        # Encrypt meta with the PARENT's DEK (spec: encrypted_meta encrypted by parent's folder DEK)
        parent_dek_id_str, parent_dek = self.dek_mgr.get_dek_for_node(parent_id)

        if not create_dek:
            dek_id = parent_dek_id_str
        else:
            # We'll create the DEK after inserting the node (FK constraint: deks.node_id → nodes.id)
            dek_id = parent_dek_id_str  # temporary — will update after DEK creation

        encrypted_meta = encrypt(
            plaintext=meta.to_json(),
            dek=parent_dek,
            dek_id=ulid_to_bytes(parent_dek_id_str),
            object_id=ulid_to_bytes(node_id),
            version=1,
            blob_kind=BlobKind.NODE_META,
        )

        # A crash between these writes must not leave a folder pointing at
        # its parent's DEK, so they commit together.
        with self._db.transaction():
            # Insert node first (so DEK can reference it)
            outbox.queue_write(self._db, node_id)
            self._db.execute(
                "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
                "VALUES (?, ?, ?, ?, 1, 0)",
                (node_id, parent_id, encrypted_meta, dek_id),
            )

            if create_dek:
                # Now create folder DEK (node exists, FK satisfied)
                new_dek_id, _ = self.dek_mgr.create_dek("folder", node_id)
                # Update node to point to its own DEK
                self._db.execute(
                    "UPDATE nodes SET dek_id = ? WHERE id = ?",
                    (new_dek_id, node_id),
                )

        self._audit_log("write", json.dumps({"target": node_id, "name": name}).encode())
        return node_id

    def create_personal_folder(self, name: str) -> str:
        """Create a personal folder with a DEK that has NO admin envelope.

        Only the creating user can decrypt (DEK wrapped with their KEK only).
        Admin sees the encrypted blob but cannot read contents.

        TL7: a personal root, top-level and not below the (organisation's)
        root; listings show it among the root's folders (``list_nodes``).

        Returns:
            Node ID.
        """
        self._require_unlocked()

        node_id = new_ulid()
        root_id = self._db.get_meta("root_node_id")

        # We need the parent DEK to encrypt meta initially, but the node
        # will have its OWN personal DEK.  Encrypt meta with the personal DEK
        # so only the owner can decrypt the folder name too.

        # Insert node first with a temporary dek_id (root DEK) so FK is valid
        parent_dek_id_str, parent_dek = self.dek_mgr.get_dek_for_node(root_id)

        # Use parent DEK temporarily for the insert
        meta = NodeMeta(name=name, personal=True)
        temp_encrypted_meta = encrypt(
            plaintext=meta.to_json(),
            dek=parent_dek,
            dek_id=ulid_to_bytes(parent_dek_id_str),
            object_id=ulid_to_bytes(node_id),
            version=1,
            blob_kind=BlobKind.NODE_META,
        )

        # Committed together: a half-created personal folder would sit
        # under the root DEK, readable by everyone who holds it.
        with self._db.transaction():
            outbox.queue_write(self._db, node_id)
            self._db.execute(
                "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
                "VALUES (?, NULL, ?, ?, 1, 0)",
                (node_id, temp_encrypted_meta, parent_dek_id_str),
            )

            # Create DEK with scope='personal' — NO access_envelopes for anyone else
            dek_id, dek = self.dek_mgr.create_dek("personal", node_id)

            # Re-encrypt meta with the personal DEK (not root DEK)
            encrypted_meta = encrypt(
                plaintext=meta.to_json(),
                dek=dek,
                dek_id=ulid_to_bytes(dek_id),
                object_id=ulid_to_bytes(node_id),
                version=1,
                blob_kind=BlobKind.NODE_META,
            )

            # Update node to use the personal DEK and re-encrypted meta
            self._db.execute(
                "UPDATE nodes SET dek_id = ?, encrypted_meta = ? WHERE id = ?",
                (dek_id, encrypted_meta, node_id),
            )

        self._audit_log(
            "write",
            json.dumps({"target": node_id, "name": name, "scope": "personal"}).encode(),
        )
        return node_id

    def read_node(self, node_id: str) -> dict:
        """Read and decrypt one folder's metadata."""
        self._require_unlocked()

        row = self._db.fetchone(
            "SELECT id, parent_id, encrypted_meta, dek_id, version "
            "FROM nodes WHERE id = ? AND is_deleted = 0",
            (node_id,),
        )
        if row is None:
            raise KeyError(f"Node not found: {node_id}")

        meta_dek_id, meta_dek = self._node_meta_dek(row)
        meta = self._decrypt_node_meta(
            row["encrypted_meta"], meta_dek, meta_dek_id, row["id"], row["version"]
        )
        return {
            "id": row["id"],
            "parent_id": row["parent_id"],
            "name": meta.name,
            "tier": meta.tier,
            "ai_read_secret": meta.ai_read_secret,
        }

    def list_nodes(self, parent_id: Optional[str] = None) -> list[dict]:
        """List child nodes of a parent (decrypted).

        The root's folders include this account's personal roots (TL7): they
        are top-level, but shown, found by path and tree-listed as the root's.
        """
        self._require_unlocked()

        root_id = self._db.get_meta("root_node_id")
        if parent_id is None:
            parent_id = root_id

        rows = self._db.fetchall(
            "SELECT id, parent_id, encrypted_meta, dek_id, version "
            "FROM nodes WHERE parent_id = ? AND is_deleted = 0",
            (parent_id,),
        )
        if parent_id == root_id:
            personal = [i for i in personal_root_ids(self._db, self.dek_mgr) if i != root_id]
            if personal:
                rows = list(rows) + self._db.fetchall(
                    "SELECT id, parent_id, encrypted_meta, dek_id, version FROM nodes "
                    f"WHERE id IN ({','.join('?' * len(personal))})",
                    tuple(personal),
                )

        results = []
        for row in rows:
            try:
                meta_dek_id, meta_dek = self._node_meta_dek(row)
                meta = self._decrypt_node_meta(
                    row["encrypted_meta"], meta_dek, meta_dek_id, row["id"], row["version"]
                )
                results.append({
                    "id": row["id"],
                    "name": meta.name,
                    "tier": meta.tier,
                    "ai_read_secret": meta.ai_read_secret,
                    "parent_id": row["parent_id"],
                })
            except Exception:
                continue  # Skip nodes we can't decrypt

        return sorted(results, key=lambda x: x["name"].lower())

    @oplock.writes  # R16-M1: the version read is the one replaced (a pull's apply waits)
    def rename_node(self, node_id: str, new_name: str) -> None:
        """Rename a folder node (re-encrypt meta with new name)."""
        self._require_unlocked()
        self._require_trusted_node_write(node_id)

        row = self._db.fetchone(
            "SELECT id, parent_id, encrypted_meta, dek_id, version "
            "FROM nodes WHERE id = ? AND is_deleted = 0",
            (node_id,),
        )
        if row is None:
            raise KeyError(f"Node not found: {node_id}")

        parent_dek_id, parent_dek = self._node_meta_dek(row)
        meta = self._decrypt_node_meta(
            row["encrypted_meta"], parent_dek, parent_dek_id, row["id"], row["version"]
        )
        meta.name = new_name
        new_version = row["version"] + 1

        encrypted_meta = encrypt(
            plaintext=meta.to_json(),
            dek=parent_dek,
            dek_id=ulid_to_bytes(parent_dek_id),
            object_id=ulid_to_bytes(node_id),
            version=new_version,
            blob_kind=BlobKind.NODE_META,
        )

        with self._db.transaction():
            outbox.queue_write(self._db, node_id)
            self._db.execute(
                "UPDATE nodes SET encrypted_meta = ?, version = ? WHERE id = ?",
                (encrypted_meta, new_version, node_id),
            )
        self._rebuild_search_index()

    def delete_node(self, node_id: str) -> None:
        """Soft-delete a folder subtree as versioned sync tombstones.

        Recoverable with vault.trash.restore_node.
        """
        self._require_unlocked()
        self._require_trusted_node_write(node_id)
        row = self._db.fetchone(
            "SELECT parent_id FROM nodes WHERE id = ? AND is_deleted = 0",
            (node_id,),
        )
        if row is None:
            raise KeyError(f"Node not found: {node_id}")
        if row["parent_id"] is None:
            raise ValueError("Cannot delete the root folder")

        subtree = self._db.fetchall(
            "WITH RECURSIVE subtree(id) AS ("
            "SELECT id FROM nodes WHERE id = ? "
            "UNION ALL "
            "SELECT nodes.id FROM nodes JOIN subtree ON nodes.parent_id = subtree.id"
            ") SELECT id FROM subtree",
            (node_id,),
        )
        node_ids = [item["id"] for item in subtree]
        entry_count = self._db.fetchone(
            f"SELECT COUNT(*) AS count FROM entries "
            f"WHERE is_deleted = 0 AND node_id IN ({','.join('?' for _ in node_ids)})",
            tuple(node_ids),
        )["count"]
        node_count = self._db.fetchone(
            f"SELECT COUNT(*) AS count FROM nodes "
            f"WHERE is_deleted = 0 AND id IN ({','.join('?' for _ in node_ids)})",
            tuple(node_ids),
        )["count"]

        # A folder delete is a bulk change: keep a whole-vault copy besides
        # the tombstones (lockout review M2). No copy, no delete.
        take_snapshot(self._db, "delete-folder")
        self._db.begin()
        try:
            for item_id in node_ids:
                outbox.queue_writes(
                    self._db, "entries", "node_id = ? AND is_deleted = 0", (item_id,)
                )
                outbox.queue_writes(self._db, "nodes", "id = ? AND is_deleted = 0", (item_id,))
            self._db.executemany(
                "UPDATE entries SET is_deleted = 1, "
                "version = version + 1 WHERE node_id = ? AND is_deleted = 0",
                [(item_id,) for item_id in node_ids],
            )
            self._db.executemany(
                "UPDATE nodes SET is_deleted = 1, "
                "version = version + 1 WHERE id = ? AND is_deleted = 0",
                [(item_id,) for item_id in node_ids],
            )
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

        self._rebuild_search_index()
        self._audit_log(
            "delete",
            json.dumps(
                {"target": node_id, "nodes": node_count, "entries": entry_count}
            ).encode(),
        )

    # ── Entry operations ──

    def create_entry(
        self,
        node_id: str,
        name: str,
        fields: list[dict],
        tier: Optional[int] = None,
        tags: Optional[list[str]] = None,
        ai_read_secret: Optional[bool] = None,
        allowed_actions: Optional[list[str]] = None,
    ) -> str:
        """Create a new entry in a node.

        Args:
            node_id: Parent node ID.
            name: Entry name.
            fields: List of field dicts: [{key, value, sensitive?, sort_order?, field_type?}].
            tier: Access tier (None = inherit).
            tags: Optional tags.

        Returns:
            Entry ID.
        """
        self._require_unlocked()

        self._require_trusted_node_write(node_id)
        entry_id = new_ulid()
        entry_meta = EntryMeta(
            name=name,
            tier=tier,
            tags=tags or [],
            ai_read_secret=ai_read_secret,
            allowed_actions=allowed_actions,
        )
        entry_data = EntryData(
            fields=[EntryField.from_dict(f) for f in fields]
        )
        require_syncable_entry(entry_meta.to_json(), entry_data.to_json())
        dek_id, dek = self.dek_mgr.get_dek_for_node(node_id)

        # Tier 2 entries get their own DEK (spec 2.3: cryptographic tier enforcement)
        entry_dek_id_str = None  # NULL = inherit from folder
        if tier == 2:
            self._refuse_tier2_in_team_folder(node_id)
            tier2_dek_id, tier2_dek = self.dek_mgr.create_dek("tier2", node_id)
            dek_id = tier2_dek_id
            dek = tier2_dek
            entry_dek_id_str = tier2_dek_id

        encrypted_meta = encrypt(
            plaintext=entry_meta.to_json(),
            dek=dek,
            dek_id=ulid_to_bytes(dek_id),
            object_id=ulid_to_bytes(entry_id),
            version=1,
            blob_kind=BlobKind.ENTRY_META,
        )

        encrypted_data = encrypt(
            plaintext=entry_data.to_json(),
            dek=dek,
            dek_id=ulid_to_bytes(dek_id),
            object_id=ulid_to_bytes(entry_id),
            version=1,
            blob_kind=BlobKind.ENTRY_DATA,
        )

        with self._db.transaction():
            outbox.queue_write(self._db, entry_id)
            self._db.execute(
                "INSERT INTO entries (id, node_id, encrypted_meta, encrypted_data, dek_id, version, is_deleted) "
                "VALUES (?, ?, ?, ?, ?, 1, 0)",
                (entry_id, node_id, encrypted_meta, encrypted_data, entry_dek_id_str),
            )

        # Update search index
        node_path = self._build_node_path(node_id)
        self._search.add_entry(
            entry_id=entry_id,
            node_id=node_id,
            node_path=node_path,
            name=name,
            field_keys=[f["key"] for f in fields],
            tags=tags or [],
        )

        self._audit_log("write", json.dumps({"target": entry_id, "name": name}).encode())
        return entry_id

    def read_entry(self, entry_id: str) -> dict:
        """Read and decrypt an entry (meta + data)."""
        self._require_unlocked()

        row = self._db.fetchone(
            "SELECT id, node_id, encrypted_meta, encrypted_data, dek_id, version "
            "FROM entries WHERE id = ? AND is_deleted = 0",
            (entry_id,),
        )
        if row is None:
            raise KeyError(f"Entry not found: {entry_id}")

        dek_id_str = row["dek_id"]
        if dek_id_str is None:
            dek_id_str, dek = self.dek_mgr.get_dek_for_node(row["node_id"])
        else:
            dek = self.dek_mgr.unlock_dek(dek_id_str)

        meta = EntryMeta.from_json(
            decrypt(
                row["encrypted_meta"],
                dek,
                ulid_to_bytes(row["id"]),
                row["version"],
                expected_blob_kind=BlobKind.ENTRY_META,
            )
        )

        data = EntryData.from_json(
            decrypt(
                row["encrypted_data"],
                dek,
                ulid_to_bytes(row["id"]),
                row["version"],
                expected_blob_kind=BlobKind.ENTRY_DATA,
            )
        )

        result = {
            "id": row["id"],
            "node_id": row["node_id"],
            "name": meta.name,
            "tier": meta.tier,
            "tags": meta.tags,
            "ai_read_secret": meta.ai_read_secret,
            "allowed_actions": meta.allowed_actions,
            "local_root": meta.local_root,
            "max_session_minutes": meta.max_session_minutes,
            "remote_root": meta.remote_root,
            "created_at": meta.created_at,
            "modified_at": meta.modified_at,
            "fields": [f.to_dict() for f in data.fields],
            "version": row["version"],
        }
        self._audit_log("read", json.dumps({"target": entry_id}).encode())
        return result

    def read_entry_policy(self, entry_id: str) -> Optional[dict]:
        """AI policy of an entry (no secret fields, not audited), or None."""
        self._require_unlocked()
        row = self._db.fetchone(
            "SELECT id, node_id, encrypted_meta, dek_id, version "
            "FROM entries WHERE id = ? AND is_deleted = 0",
            (entry_id,),
        )
        if row is None:
            return None
        if row["dek_id"] is None:
            _, dek = self.dek_mgr.get_dek_for_node(row["node_id"])
        else:
            dek = self.dek_mgr.unlock_dek(row["dek_id"])
        meta = EntryMeta.from_json(
            decrypt(
                row["encrypted_meta"], dek, ulid_to_bytes(row["id"]), row["version"],
                expected_blob_kind=BlobKind.ENTRY_META,
            )
        )
        return {
            "id": row["id"],
            "node_id": row["node_id"],
            "tier": meta.tier,
            "allowed_actions": meta.allowed_actions,
            "local_root": meta.local_root,
            "max_session_minutes": meta.max_session_minutes,
            "remote_root": meta.remote_root,
        }

    @oplock.writes  # R16-M1: the version read is the one replaced (a pull's apply waits)
    def update_entry(
        self,
        entry_id: str,
        name: Optional[str] = None,
        fields: Optional[list[dict]] = None,
        tier: Optional[int] = None,
        tags: Optional[list[str]] = None,
        ai_read_secret: Optional[bool] = None,
        allowed_actions: Optional[list[str]] = None,
        inherit_tier: bool = False,
        local_root: Optional[str] = None,
        clear_local_root: bool = False,
        max_session_minutes: Optional[int] = None,
        remote_root: Optional[str] = None,
        clear_remote_root: bool = False,
    ) -> None:
        """Update an existing entry.

        ``tier=None`` keeps the current tier; ``inherit_tier=True`` clears an
        explicit tier so the entry inherits it from its folder again.
        ``local_root=None`` keeps the MCP transfer root; ``clear_local_root``
        removes it so the default transfer directory applies again.
        ``remote_root`` / ``clear_remote_root`` work the same way for the
        remote directory SFTP/FTP paths are confined to.
        """
        if clear_local_root and local_root is not None:
            raise ValueError("local_root and clear_local_root are mutually exclusive")
        if clear_remote_root and remote_root is not None:
            raise ValueError("remote_root and clear_remote_root are mutually exclusive")
        if inherit_tier and tier is not None:
            raise ValueError("tier and inherit_tier are mutually exclusive")
        self._require_unlocked()

        current = self.read_entry(entry_id)
        row = self._db.fetchone(
            "SELECT node_id, dek_id, version FROM entries WHERE id = ?",
            (entry_id,),
        )
        node_id = row["node_id"]
        self._require_trusted_node_write(node_id)
        new_version = row["version"] + 1

        # Merge updates
        updated_name = name if name is not None else current["name"]
        updated_tags = tags if tags is not None else current["tags"]
        if inherit_tier:
            updated_tier = None
        else:
            updated_tier = tier if tier is not None else current["tier"]

        updated_ai_read_secret = (
            ai_read_secret if ai_read_secret is not None else current["ai_read_secret"]
        )
        updated_allowed_actions = (
            allowed_actions if allowed_actions is not None else current["allowed_actions"]
        )
        updated_fields = fields if fields is not None else current["fields"]
        if clear_local_root:
            updated_local_root = None
        else:
            updated_local_root = local_root if local_root is not None else current["local_root"]
        if clear_remote_root:
            updated_remote_root = None
        else:
            updated_remote_root = remote_root if remote_root is not None else current["remote_root"]

        now = int(time.time() * 1000)
        entry_meta = EntryMeta(
            name=updated_name,
            tier=updated_tier,
            tags=updated_tags,
            ai_read_secret=updated_ai_read_secret,
            allowed_actions=updated_allowed_actions,
            local_root=updated_local_root,
            max_session_minutes=(
                max_session_minutes
                if max_session_minutes is not None
                else current["max_session_minutes"]
            ),
            remote_root=updated_remote_root,
            created_at=current["created_at"],
            modified_at=now,
        )
        entry_data = EntryData(
            fields=[EntryField.from_dict(f) for f in updated_fields]
        )
        require_syncable_entry(entry_meta.to_json(), entry_data.to_json())

        # Create history snapshot before update
        self._create_history_snapshot(entry_id)

        # A tier-2 entry keeps its own DEK; becoming tier 2 creates one.
        entry_dek_id = self._tier2_entry_dek(row["dek_id"], updated_tier, node_id)
        dek_id_str = entry_dek_id or row["dek_id"]
        if dek_id_str is None:
            dek_id_str, dek = self.dek_mgr.get_dek_for_node(node_id)
        else:
            dek = self.dek_mgr.unlock_dek(dek_id_str)

        encrypted_meta = encrypt(
            plaintext=entry_meta.to_json(),
            dek=dek,
            dek_id=ulid_to_bytes(dek_id_str),
            object_id=ulid_to_bytes(entry_id),
            version=new_version,
            blob_kind=BlobKind.ENTRY_META,
        )
        encrypted_data = encrypt(
            plaintext=entry_data.to_json(),
            dek=dek,
            dek_id=ulid_to_bytes(dek_id_str),
            object_id=ulid_to_bytes(entry_id),
            version=new_version,
            blob_kind=BlobKind.ENTRY_DATA,
        )

        with self._db.transaction():
            outbox.queue_write(self._db, entry_id)
            self._db.execute(
                "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, "
                "dek_id = ?, version = ? WHERE id = ?",
                (encrypted_meta, encrypted_data, entry_dek_id or row["dek_id"],
                 new_version, entry_id),
            )

        # Keep the in-memory index in step: a renamed entry must not stay
        # findable (and listed) under its old name or field keys.
        self._search.remove_entry(entry_id)
        self._search.add_entry(
            entry_id=entry_id,
            node_id=current["node_id"],
            node_path=self._build_node_path(current["node_id"]),
            name=updated_name,
            field_keys=[f["key"] for f in updated_fields],
            tags=updated_tags,
        )

        self._audit_log("write", json.dumps({"target": entry_id, "action": "update"}).encode())

    def delete_entry(self, entry_id: str) -> None:
        """Soft-delete an entry (tombstone); vault.trash.restore_entry undoes it."""
        self._require_unlocked()
        row = self._db.fetchone("SELECT node_id FROM entries WHERE id = ?", (entry_id,))
        if row is not None:
            self._require_trusted_node_write(row["node_id"])
        with self._db.transaction():
            outbox.queue_writes(self._db, "entries", "id = ? AND is_deleted = 0", (entry_id,))
            self._db.execute(
                "UPDATE entries SET is_deleted = 1, version = version + 1 "
                "WHERE id = ? AND is_deleted = 0",
                (entry_id,),
            )
        self._search.remove_entry(entry_id)
        self._audit_log("delete", json.dumps({"target": entry_id}).encode())

    def _tier2_entry_dek(
        self, dek_id: Optional[str], tier: Optional[int], node_id: str
    ) -> Optional[str]:
        """Own DEK of a tier-2 entry (spec 2.3), created when it has none yet.

        None for any other entry. An entry DEK counts as its own when it is
        a tier-2 DEK, or the entry is tier 2 and the DEK is not its folder's.
        """
        if dek_id is not None:
            dek_row = self._db.fetchone("SELECT scope FROM deks WHERE id = ?", (dek_id,))
            node_row = self._db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))
            if dek_row is not None and (
                dek_row["scope"] == "tier2"
                or (tier == 2 and (node_row is None or node_row["dek_id"] != dek_id))
            ):
                self._refuse_tier2_in_team_folder(node_id)
                return dek_id
        if tier == 2:
            self._refuse_tier2_in_team_folder(node_id)
            new_dek_id, _ = self.dek_mgr.create_dek("tier2", node_id)
            return new_dek_id
        return None

    def _refuse_tier2_in_team_folder(self, node_id: str) -> None:
        """TL7 (docs/DESIGN_TEAM_LOG.md §10): a tier-2 entry's own key is not in
        the team log, so in a team folder nobody else could read it and the
        server refuses it. It goes into a folder of its own key instead."""
        team = self._team_for(node_id)
        if team is None:
            return
        current: Optional[str] = node_id
        for _ in range(64):
            if current is None:
                return
            if teamlog.is_team_folder(team, current):
                raise ValueError(
                    "A tier-2 entry cannot be in a shared team folder (its own key is not "
                    "in the team log). Keep it in a separate folder with its own key: "
                    "your personal folder, or a new team folder shared with whoever may read it."
                )
            row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (current,))
            current = row["parent_id"] if row else None

    @oplock.writes  # R16-M1: the version read is the one replaced (a pull's apply waits)
    def move_entry(self, entry_id: str, new_node_id: str) -> None:
        """Move an entry to a different folder with re-encryption.

        Creates a history snapshot, re-encrypts meta+data with the new
        folder's DEK, and updates node_id.  All inside a transaction.
        """
        self._require_unlocked()

        # Read current entry (decrypted)
        current = self.read_entry(entry_id)
        row = self._db.fetchone(
            "SELECT node_id, dek_id, version FROM entries WHERE id = ?",
            (entry_id,),
        )
        if row is None:
            raise KeyError(f"Entry not found: {entry_id}")

        old_node_id = row["node_id"]
        self._require_trusted_node_write(old_node_id)
        self._require_trusted_node_write(new_node_id)
        if old_node_id == new_node_id:
            return  # No-op

        new_version = row["version"] + 1

        self._db.begin()
        try:
            # A tier-2 entry keeps (or gets) its own DEK; the rest take the
            # new folder's DEK.
            entry_dek_id = self._tier2_entry_dek(row["dek_id"], current["tier"], new_node_id)
            if entry_dek_id is not None:
                new_dek_id, new_dek = entry_dek_id, self.dek_mgr.unlock_dek(entry_dek_id)
            else:
                new_dek_id, new_dek = self.dek_mgr.get_dek_for_node(new_node_id)

            # Create history snapshot before move
            self._create_history_snapshot(entry_id)

            # Re-encrypt meta with new DEK
            now = int(time.time() * 1000)
            entry_meta = EntryMeta(
                name=current["name"],
                tier=current["tier"],
                tags=current["tags"],
                ai_read_secret=current["ai_read_secret"],
                allowed_actions=current["allowed_actions"],
                local_root=current["local_root"],
                max_session_minutes=current["max_session_minutes"],
                remote_root=current["remote_root"],
                created_at=current["created_at"],
                modified_at=now,
            )
            entry_data = EntryData(
                fields=[EntryField.from_dict(f) for f in current["fields"]]
            )

            encrypted_meta = encrypt(
                plaintext=entry_meta.to_json(),
                dek=new_dek,
                dek_id=ulid_to_bytes(new_dek_id),
                object_id=ulid_to_bytes(entry_id),
                version=new_version,
                blob_kind=BlobKind.ENTRY_META,
            )
            encrypted_data = encrypt(
                plaintext=entry_data.to_json(),
                dek=new_dek,
                dek_id=ulid_to_bytes(new_dek_id),
                object_id=ulid_to_bytes(entry_id),
                version=new_version,
                blob_kind=BlobKind.ENTRY_DATA,
            )

            outbox.queue_write(self._db, entry_id)
            self._db.execute(
                "UPDATE entries SET node_id = ?, encrypted_meta = ?, "
                "encrypted_data = ?, dek_id = ?, version = ? "
                "WHERE id = ?",
                (new_node_id, encrypted_meta, encrypted_data, entry_dek_id,
                 new_version, entry_id),
            )

            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

        # Update search index
        node_path = self._build_node_path(new_node_id)
        self._search.remove_entry(entry_id)
        self._search.add_entry(
            entry_id=entry_id,
            node_id=new_node_id,
            node_path=node_path,
            name=current["name"],
            field_keys=[f["key"] for f in current["fields"]],
            tags=current["tags"],
        )

        self._audit_log(
            "move",
            json.dumps({"target": entry_id, "from": old_node_id, "to": new_node_id}).encode(),
        )

    @oplock.writes  # R16-M1: the version read is the one replaced (a pull's apply waits)
    def move_node(self, node_id: str, new_parent_id: str) -> None:
        """Move a folder node to a new parent with re-encryption.

        Re-encrypts the node's meta with the new parent's DEK and
        re-encrypts all entries in the node with the node's own DEK
        (which doesn't change — entries already use the node's DEK).
        The node meta is encrypted with the *parent's* DEK per spec,
        so only the meta blob needs re-encryption.
        """
        self._require_unlocked()

        row = self._db.fetchone(
            "SELECT parent_id, encrypted_meta, dek_id, version FROM nodes WHERE id = ?",
            (node_id,),
        )
        if row is None:
            raise KeyError(f"Node not found: {node_id}")

        old_parent_id = row["parent_id"]
        self._require_trusted_node_write(node_id)
        self._require_trusted_node_write(new_parent_id)
        if old_parent_id == new_parent_id:
            return  # No-op

        # Prevent moving a node into itself or a descendant
        if self._is_descendant(new_parent_id, node_id):
            raise ValueError("Cannot move a folder into its own descendant")

        # Decrypt meta with old parent's DEK (a personal root: its own)
        meta_dek_id, meta_dek = self._node_meta_dek({**dict(row), "id": node_id})
        meta = self._decrypt_node_meta(
            row["encrypted_meta"], meta_dek, meta_dek_id,
            node_id, row["version"],
        )

        # Re-encrypt meta with new parent's DEK; a personal root keeps its own.
        # (a personal root is top-level since TL7: no old parent)
        old_parent_dek_id = self.dek_mgr.get_dek_for_node(old_parent_id)[0] if old_parent_id else None
        if meta_dek_id != old_parent_dek_id:
            new_parent_dek_id, new_parent_dek = meta_dek_id, meta_dek
        else:
            new_parent_dek_id, new_parent_dek = self.dek_mgr.get_dek_for_node(new_parent_id)
        new_version = row["version"] + 1

        # Review 1141a20 (R9-E, M-DESK4): the subtree takes the target's key.
        # Only the name was resealed: out of the personal tree the folder's
        # items stayed under the owner's personal key nobody else holds, into
        # it under the team key every member of the old folder holds.
        changes = {}
        if old_parent_id is not None:  # a personal root keeps its own key
            roots = set(personal_root_ids(self._db, self.dek_mgr))
            into_personal = in_personal_tree(self._db, new_parent_id, roots)
            team = self._team_for(new_parent_id)
            changes = moved_subtree_keys(
                self._db, node_id, self.dek_mgr.get_dek_for_node(new_parent_id)[0], into_personal,
                team.dek_index if team_folder_at_or_above(self._db, team, new_parent_id) else None,
            )
            self._refuse_move_across_team_keys(node_id, new_parent_id, into_personal)

        encrypted_meta = encrypt(
            plaintext=meta.to_json(),
            dek=new_parent_dek,
            dek_id=ulid_to_bytes(new_parent_dek_id),
            object_id=ulid_to_bytes(node_id),
            version=new_version,
            blob_kind=BlobKind.NODE_META,
        )

        with self._db.transaction():
            outbox.queue_write(self._db, node_id)
            self._db.execute(
                "UPDATE nodes SET parent_id = ?, encrypted_meta = ?, "
                "version = ? WHERE id = ?",
                (new_parent_id, encrypted_meta, new_version, node_id),
            )
            reseal_moved_subtree(self._db, self.dek_mgr, node_id, changes)

        self._audit_log(
            "move",
            json.dumps({"target": node_id, "from": old_parent_id, "to": new_parent_id}).encode(),
        )

    def _refuse_move_across_team_keys(
        self, node_id: str, new_parent_id: str, into_personal: bool
    ) -> None:
        """A team folder of the log cannot go into a personal tree (its items
        would leave its key the log names), and a tier-2 item's own key cannot
        go into a team folder (``_refuse_tier2_in_team_folder``)."""
        subtree = [r["id"] for r in self._db.fetchall(
            "WITH RECURSIVE t(id) AS (SELECT ? UNION SELECT n.id FROM nodes n JOIN t ON n.parent_id = t.id) "
            "SELECT id FROM t", (node_id,)
        )]
        team = self._team_for(node_id, new_parent_id)
        if into_personal and team is not None and any(teamlog.is_team_folder(team, n) for n in subtree):
            raise ValueError(
                "A team folder cannot go into a personal folder; its members would lose it. "
                "Move its items instead, or remove the members first."
            )
        marks = ",".join("?" * len(subtree))
        if self._db.fetchone(
            f"SELECT 1 FROM entries e JOIN deks d ON d.id = e.dek_id "
            f"WHERE e.node_id IN ({marks}) AND d.scope = 'tier2'", tuple(subtree)
        ):
            self._refuse_tier2_in_team_folder(new_parent_id)

    def _refuse_team_grant_over_tier2(self, node_id: str) -> None:
        """TL7, as a move (above): with a team log, a grant makes the folder a
        team folder, and a tier-2 item below it keeps a key the log does not
        name. R16-Z deep run on b20ece6: the devices that held it showed it,
        the member and a new sign-in of the page (which judge by the log) did
        not. It moves out first."""
        if self._team_for(node_id) is None:
            return
        if self._db.fetchone(
            "WITH RECURSIVE t(id) AS (SELECT ? UNION SELECT n.id FROM nodes n JOIN t ON n.parent_id = t.id) "
            "SELECT 1 FROM entries e JOIN deks d ON d.id = e.dek_id "
            "WHERE e.node_id IN (SELECT id FROM t) AND e.is_deleted = 0 AND d.scope = 'tier2'",
            (node_id,),
        ):
            raise ValueError(
                "This folder holds a tier-2 entry, whose own key is not in the team log: shared, "
                "nobody else could read it. Move it to a folder of its own first."
            )

    def _is_descendant(self, candidate_id: str, ancestor_id: str) -> bool:
        """Check if candidate_id is a descendant of (or equal to) ancestor_id."""
        current = candidate_id
        seen: set[str] = set()  # R16-Z SM22: a parent cycle ends the walk
        while current and current not in seen:
            if current == ancestor_id:
                return True
            seen.add(current)
            row = self._db.fetchone(
                "SELECT parent_id FROM nodes WHERE id = ?", (current,)
            )
            if row is None:
                break
            current = row["parent_id"]
        return False

    def list_entries(self, node_id: str) -> list[dict]:
        """List entries in a node (decrypted meta only, values on-demand)."""
        self._require_unlocked()

        rows = self._db.fetchall(
            "SELECT id, node_id, encrypted_meta, dek_id, version "
            "FROM entries WHERE node_id = ? AND is_deleted = 0",
            (node_id,),
        )

        dek_id_str, dek = self.dek_mgr.get_dek_for_node(node_id)
        results = []
        for row in rows:
            try:
                entry_dek = dek if row["dek_id"] is None else self.dek_mgr.unlock_dek(row["dek_id"])
                meta = EntryMeta.from_json(
                    decrypt(
                        row["encrypted_meta"],
                        entry_dek,
                        ulid_to_bytes(row["id"]),
                        row["version"],
                        expected_blob_kind=BlobKind.ENTRY_META,
                    )
                )
                results.append({
                    "id": row["id"],
                    "name": meta.name,
                    "tier": meta.tier,
                    "tags": meta.tags,
                    "ai_read_secret": meta.ai_read_secret,
                })
            except Exception:
                continue

        return sorted(results, key=lambda x: x["name"].lower())

    def get_field_value(self, entry_id: str, field_key: str) -> Optional[str]:
        """Get a single field value from an entry (on-demand decryption)."""
        entry = self.read_entry(entry_id)
        for f in entry["fields"]:
            if f["key"] == field_key:
                return f["value"]
        return None

    # ── Search ──

    def search(self, query: str) -> list[dict]:
        """Search entries by name, field keys, tags."""
        self._require_unlocked()
        results = self._search.search(query)
        return [
            {
                "entry_id": r.entry_id,
                "node_id": r.node_id,
                "name": r.name,
                "path": r.node_path,
            }
            for r in results
        ]

    def deep_search(self, query: str) -> list[dict]:
        """Search in decrypted field VALUES (opt-in, spec 5.4).

        Processes entries in batches of 100 to avoid loading entire
        vault into memory at once.  Results are session-only — values
        are never added to the FTS index.
        """
        self._require_unlocked()

        if not query.strip():
            return []

        query_lower = query.strip().lower()
        query_tokens = query_lower.split()

        # First, get standard search results
        standard = self.search(query)
        seen_ids = {r["entry_id"] for r in standard}
        results = list(standard)

        # Batch-scan all entries for value matches
        rows = self._db.fetchall(
            "SELECT id, node_id, encrypted_meta, encrypted_data, dek_id, version "
            "FROM entries WHERE is_deleted = 0"
        )

        BATCH_SIZE = 100
        for batch_start in range(0, len(rows), BATCH_SIZE):
            batch = rows[batch_start : batch_start + BATCH_SIZE]
            for row in batch:
                entry_id = row["id"]
                if entry_id in seen_ids:
                    continue

                try:
                    dek_id_str = row["dek_id"]
                    if dek_id_str is None:
                        dek_id_str, dek = self.dek_mgr.get_dek_for_node(row["node_id"])
                    else:
                        dek = self.dek_mgr.unlock_dek(dek_id_str)

                    meta = EntryMeta.from_json(
                        decrypt(
                            row["encrypted_meta"],
                            dek,
                            ulid_to_bytes(row["id"]),
                            row["version"],
                            expected_blob_kind=BlobKind.ENTRY_META,
                        )
                    )
                    data = EntryData.from_json(
                        decrypt(
                            row["encrypted_data"],
                            dek,
                            ulid_to_bytes(row["id"]),
                            row["version"],
                            expected_blob_kind=BlobKind.ENTRY_DATA,
                        )
                    )

                    # Check if any field value matches all query tokens
                    matched_field = None
                    for field in data.fields:
                        val_lower = field.value.lower()
                        if all(t in val_lower for t in query_tokens):
                            matched_field = field.key
                            break

                    if matched_field:
                        node_path = self._build_node_path(row["node_id"])
                        results.append({
                            "entry_id": entry_id,
                            "node_id": row["node_id"],
                            "name": meta.name,
                            "path": node_path,
                            "matched_field": matched_field,
                        })
                        seen_ids.add(entry_id)

                except Exception:
                    continue

        return results

    # ── Path resolution ──

    def resolve_path(self, path: str) -> tuple[Optional[str], Optional[str]]:
        """Resolve a path like 'servers/hetzner/ssh' to (node_id, entry_name).

        Returns (node_id, None) for folder paths or (node_id, entry_name) for entry paths.
        """
        self._require_unlocked()
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return self._db.get_meta("root_node_id"), None

        current_id = self._db.get_meta("root_node_id")

        for i, part in enumerate(parts):
            # Try to find a child node with this name
            children = self.list_nodes(current_id)
            found = False
            for child in children:
                if child["name"].lower() == part.lower():
                    current_id = child["id"]
                    found = True
                    break

            if not found:
                # Check if it's an entry name (last part)
                if i == len(parts) - 1:
                    entries = self.list_entries(current_id)
                    for entry in entries:
                        if entry["name"].lower() == part.lower():
                            return current_id, entry["name"]
                    return current_id, part  # Return as potential entry name
                return None, None

        return current_id, None

    def find_entry_by_path(self, path: str) -> Optional[dict]:
        """Find an entry by full path (e.g. 'servers/hetzner/SSH Access')."""
        self._require_unlocked()
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            return None

        entry_name = parts[-1]
        folder_path = "/".join(parts[:-1])

        if folder_path:
            node_id, _ = self.resolve_path(folder_path)
        else:
            node_id = self._db.get_meta("root_node_id")

        if node_id is None:
            return None

        entries = self.list_entries(node_id)
        for entry in entries:
            if entry["name"].lower() == entry_name.lower():
                return self.read_entry(entry["id"])

        return None

    # ── Server identity ──

    def rebind_server_identity(
        self, server_user_id: str, server_keypair: KeyPair | None = None
    ) -> None:
        """Bind the local identity to the server-assigned user_id.

        ``encrypted_keypair`` is AAD-bound to ``user_id``, so the keypair must
        be re-wrapped under the current KEK whenever the id changes; otherwise
        the next unlock fails with "Wrong master password" and the keypair
        uploaded to the server is unreadable on every other client. When
        ``server_keypair`` is given (account recovery), it replaces the local
        keypair so this device uses the account's canonical identity.
        """
        self._require_unlocked()
        if not server_user_id:
            raise ValueError("Server did not return a user id")
        if server_user_id == self._db.get_meta("user_id") and server_keypair is None:
            return
        keypair = server_keypair or self.keypair
        from ..crypto.aead import encrypt_keypair_wrap

        # Review 7c10379 (R7-H): checked and wrapped before the transaction, a
        # password change committed in between was overwritten by a wrap
        # under the old KEK and neither password unlocked the vault. The
        # write lock is held from the check to the commit.
        with self._db.transaction(immediate=True):
            # Review 7c10379: a process whose KEK the password moved past wrapped
            # the keypair under it with the new kek_dek_id; no password opened it.
            kek_dek_id = self.dek_mgr._wrapping_kek_id()
            if (server_user_id == self._user_id and self.keypair.confirmed_genesis is not None
                    and keypair.confirmed_genesis is None):
                raise RuntimeError("The recovered account keypair is missing this device's authenticated anchor.")
            if server_user_id == self._user_id and keypair is not self.keypair:
                from ..crypto.aead import merge_pre_anchor

                keypair.pre_anchor = merge_pre_anchor(keypair.pre_anchor, self._known_pre_anchor())
            import_account_anchor(self._db, keypair)
            kp_data = keypair.serialize_private()
            try:
                encrypted_kp = encrypt_keypair_wrap(
                    keypair_data=kp_data,
                    kek=self.dek_mgr._kek,
                    kek_dek_id=ulid_to_bytes(kek_dek_id),
                    user_object_id=ulid_to_bytes(server_user_id),
                )
            finally:
                kp_data[:] = b"\x00" * len(kp_data)

            old_user_id = self._db.get_meta("user_id")
            if server_keypair is not None and old_user_id != server_user_id:
                self._db.set_meta(pending_states.JOINED_UNPULLED, "1")
            AuditLog(self._db).reattribute_unpushed(
                old_user_id, server_user_id, keypair.to_nacl_signing_key()
            )
            self._db.set_meta("encrypted_keypair", encrypted_kp.hex())
            self._db.set_meta("user_id", server_user_id)
            self._db.set_meta("signing_pk", keypair.signing_pk.hex())
            self._db.set_meta("encryption_pk", keypair.encryption_pk.hex())

        if server_keypair is not None and server_keypair is not self._keypair:
            if self._keypair is not None:
                self._keypair.zeroize()
            self._keypair = server_keypair
        self._user_id = server_user_id

    def held_kdf(self) -> tuple[bytes, Argon2Params, bytearray]:
        """Salt, Argon2 params and a copy of the KEK this vault unlocks with."""
        self._require_unlocked()
        return (
            bytes.fromhex(self._db.get_meta("argon2_salt")),
            Argon2Params.from_dict(self._db.get_meta_json("argon2_params")),
            bytearray(self.dek_mgr._kek),
        )

    @oplock.held
    def adopt_account_kek(
        self,
        account_kek: bytes | bytearray,
        salt: bytes,
        params: Argon2Params,
        key_epoch: int | None = None,
        own_rotation_landed: bool = False,
        connect_snapshot: Optional[Path] = None,
    ) -> None:
        """Switch this device to the account KEK after Path B recovery.

        DEKs pushed by the account's other devices are wrapped under the KEK
        derived from the server-held salt. A device created with its own salt
        could never open them, so its local DEKs are re-wrapped under the
        account KEK and future unlocks derive it from the account salt.

        ``key_epoch`` is the server's epoch of that key material: the device
        now holds it, so it takes the epoch over (the server already has the
        rotation, nothing is left to push for it). ``own_rotation_landed``:
        the server's account keypair is this device's own unconfirmed
        identity rotation, so the envelopes it re-sealed are on the server.
        ``connect_snapshot``: the 'server-connect' snapshot of this connect;
        it stays as the way back from the connect (review 7c10379).
        """
        self._require_unlocked()
        # Review 7c10379: an outdated KEK equal to the account's took the
        # server epoch over for a vault whose DEKs it no longer wraps.
        self.dek_mgr._wrapping_kek_id()
        if len(account_kek) != 32:
            raise ValueError("Account KEK must be 32 bytes")
        old_kek = self.dek_mgr._kek
        old_kek_dek_id = self.dek_mgr.kek_dek_id
        if compare_digest(bytes(old_kek), bytes(account_kek)):
            if key_epoch is not None:
                with self._db.transaction():
                    self._adopt_key_epoch(key_epoch, own_rotation_landed)
            return
        new_kek = bytearray(account_kek)
        recovery_wrap = self._org_recovery_wrap(new_kek)
        left_history = None
        if self.keypair.confirmed_genesis is None:
            from ..crypto.aead import add_pre_anchor

            # Capability run 273: the state left here opened keys without the anchor.
            old_params = Argon2Params.from_dict(self._db.get_meta_json("argon2_params"))
            left_history = add_pre_anchor(
                self._known_pre_anchor(), bytes.fromhex(self._db.get_meta("argon2_salt")),
                old_params.time_cost, old_params.memory_cost, old_params.parallelism, old_kek,
            )
        self._db.begin()
        try:
            if left_history is not None:
                self._db.set_meta(PRE_ANCHOR_HISTORY_META, left_history.hex())
            if key_epoch is not None:
                self._adopt_key_epoch(key_epoch, own_rotation_landed)
            # With a server epoch the server already holds this rotation and
            # its DEK versions; rival local versions would conflict with them.
            self.dek_mgr.rewrap_all_deks(new_kek, bump_version=key_epoch is None)
            from ..crypto.aead import encrypt_keypair_wrap

            kp_data = self.keypair.serialize_private()
            try:
                encrypted_kp = encrypt_keypair_wrap(
                    keypair_data=kp_data,
                    kek=new_kek,
                    kek_dek_id=ulid_to_bytes(self.dek_mgr.kek_dek_id),
                    user_object_id=ulid_to_bytes(self._db.get_meta("user_id")),
                )
            finally:
                kp_data[:] = b"\x00" * len(kp_data)
            self._db.set_meta("encrypted_keypair", encrypted_kp.hex())
            self._db.set_meta("argon2_salt", salt.hex())
            self._db.set_meta_json("argon2_params", params.to_dict())
            # Org recovery wraps the KEK itself: left under the old one it
            # would recover a KEK that opens nothing (lockout review #3).
            if recovery_wrap is not None:
                self._db.set_meta("org_recovery_wrapped_kek", recovery_wrap.hex())
                self._db.set_meta("org_recovery_stale", "0")
            elif self._db.get_meta("org_recovery_pk"):
                self._db.set_meta("org_recovery_stale", "1")
            self._drop_pending_org_recovery_registration()
            self._db.commit()
        except Exception:
            self._db.rollback()
            self.dek_mgr._kek = old_kek
            self.dek_mgr._kek_dek_id = old_kek_dek_id
            new_kek[:] = b"\x00" * len(new_kek)
            raise
        old_kek[:] = b"\x00" * len(old_kek)
        if connect_snapshot is None:
            # Review 8595ec1: the snapshots of the old password go below; one
            # under the password taken over keeps a way back.
            try:
                take_snapshot(self._db, "password-adopted")
            except SnapshotError as exc:  # the takeover is done; never undo it here
                logger.warning("No snapshot under the adopted password: %s", exc)
        self._drop_old_password_snapshots(None, keep=connect_snapshot)

    def _drop_old_password_snapshots(
        self, spare: Optional[Path], keep: Optional[Path] = None
    ) -> None:
        """After the vault's password changed: no snapshot opens with the old one.

        ``spare`` (taken by the change) stays until the new password has
        opened the vault once (``unlock``), as a way back from a mistyped one.
        ``keep`` stays until a later password change.
        """
        vault_dir = self._db.path.parent
        kept = spare or keep
        try:
            drop_snapshots_of_other_passwords(
                vault_dir, self._db.get_meta("argon2_salt"), kept.name if kept else None
            )
            if spare is not None:
                self._db.set_meta(KEY_CHANGE_SNAPSHOT_META, spare.name)
        except Exception as exc:  # the change itself is done; never undo it here
            logger.warning("Snapshots of the old password were not removed: %s", exc)

    def _drop_key_change_snapshot(self) -> None:
        name = self._db.get_meta(KEY_CHANGE_SNAPSHOT_META)
        if not name:
            return
        try:
            drop_snapshot_of_other_password(
                self._db.path.parent, name, self._db.get_meta("argon2_salt")
            )
            self._db.execute("DELETE FROM vault_meta WHERE key = ?", (KEY_CHANGE_SNAPSHOT_META,))
        except Exception as exc:
            logger.warning("The snapshot of the old password was not removed: %s", exc)

    def _drop_pending_org_recovery_registration(self) -> None:
        """The KEK changed: an unregistered server body wraps the old one."""
        pending_states.clear_org_recovery_registration(self._db)
        pending_states.clear_org_recovery_rewrap(self._db)

    def _org_recovery_wrap(self, kek: bytes | bytearray) -> Optional[bytes]:
        """``kek`` sealed to the configured org recovery key, or None."""
        recovery_pk_hex = self._db.get_meta("org_recovery_pk")
        if not recovery_pk_hex or not self._db.get_meta("org_recovery_wrapped_kek"):
            return None
        from nacl.public import PublicKey, SealedBox

        try:
            recovery_pk = PublicKey(bytes.fromhex(recovery_pk_hex))
        except (ValueError, TypeError):
            return None
        return SealedBox(recovery_pk).encrypt(bytes(kek))

    def _adopt_key_epoch(self, key_epoch: int, own_rotation_landed: bool = False) -> None:
        if key_epoch < 0:
            raise ValueError("Invalid server key epoch")
        self._db.set_meta("key_epoch", str(key_epoch))
        pending_states.set_last_pushed_key_epoch(self._db, key_epoch)
        # The epoch is now the server's key material, not what this device sent.
        self._db.execute("DELETE FROM vault_meta WHERE key = 'server_key_material_hash'")
        # A local rotation that never reached the server is superseded by the
        # account key material this device just proved it holds.
        pending_states.clear_key_change_journal(self._db)
        if own_rotation_landed:
            self._keep_landed_identity_reseal()
        else:
            self._undo_unsent_identity_reseal()

    def _keep_landed_identity_reseal(self) -> None:
        """The identity rotation's push landed; only its reply was lost.

        Stateful test SM61: taken for a superseded rotation, its re-sealed
        envelopes were dropped and the originals put back, while the server
        held the re-sealed ones and the pull had already passed them: a
        member's grant the server kept live was gone from every device, and
        revoking the member left it on the server.
        """
        pending = pending_states.rekey_batch(self._db)
        if not pending.get("identity_rotation"):
            return
        withdrawn = {item["id"] for item in pending.get("envelope_tombstones", [])}
        for obj_id in pending.get("object_ids", []):
            if obj_id not in withdrawn:
                outbox.sent(self._db, outbox.ENVELOPE, obj_id)
        pending_states.clear_rekey_batch(self._db)

    def _undo_unsent_identity_reseal(self) -> None:
        """Put back the envelopes a superseded identity rotation re-sealed.

        Review 688edcb: the re-sealed envelopes are sealed with the lost
        rotation's key, which no recipient will ever trust; pushed later they
        replaced working envelopes with dead ones. The originals (kept in the
        batch tombstones) come back; a pull then brings whatever the winning
        rotation did with them.
        """
        pending = pending_states.rekey_batch(self._db)
        if not pending.get("identity_rotation"):
            return
        tombstones = pending.get("envelope_tombstones", [])
        restored = {item["id"] for item in tombstones}
        for obj_id in pending.get("object_ids", []):
            if obj_id not in restored:
                self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (obj_id,))
        for item in tombstones:
            outbox.restore_envelope(self._db, item, self._db.get_meta("user_id"))
        pending_states.clear_rekey_batch(self._db)

    def current_auth_proof(self, password: str) -> bytearray:
        """Auth proof of this vault's password (raises ValueError if wrong).

        The server holds the proof of the account password; when this vault
        is in sync it is the same password and salt.
        """
        self._require_unlocked()
        # Review 7c10379: an outdated KEK took the new password for a wrong one.
        self.dek_mgr._wrapping_kek_id()
        from ..crypto.kdf import password_forms

        params = Argon2Params.from_dict(self._db.get_meta_json("argon2_params"))
        salt = bytes.fromhex(self._db.get_meta("argon2_salt"))
        for form in password_forms(password):
            kek, proof = derive_kek_and_proof(form, salt, params, exact=True)
            try:
                if compare_digest(kek, self.dek_mgr._kek):
                    return proof
            finally:
                kek[:] = b"\x00" * len(kek)
            proof[:] = b"\x00" * len(proof)
        raise ValueError("Wrong master password")

    # ── Change password (spec 9.1) ──

    def _known_pre_anchor(self) -> bytes:
        """The anchored bundle's pre-anchor states plus those this device left."""
        from ..crypto.aead import merge_pre_anchor

        history = self._db.get_meta(PRE_ANCHOR_HISTORY_META)
        return merge_pre_anchor(self._keypair.pre_anchor, bytes.fromhex(history) if history else b"")

    @oplock.held
    def change_password(
        self,
        old_password: str,
        new_password: str,
        new_params: Argon2Params | None = None,
        *,
        rotate_identity: bool = False,
        rotation_from: KeyPair | None = None,
        rotation_kdf: tuple[bytes, Argon2Params, bytearray] | None = None,
    ) -> bytes:
        """Change master password (and optionally KDF params).

        Returns the Option B auth proof for the new KEK. Passing the same
        password with ``new_params`` performs an Argon2 parameter upgrade with
        the same verification, org-recovery re-wrap and epoch bump.

        ``rotate_identity`` (idea #11, a leaked identity key) also replaces
        the signing/encryption keypair in the same epoch advance: both keys
        sign the rotation certificate, the access envelopes this user sealed
        are sealed again with the new key (the old ones are withdrawn) and the
        server takes all of it in one push.

        ``rotation_from`` (with ``rotate_identity``): the keypair the server
        still has after it lost this device's rotation (capability run 277);
        the rotation from it to the keypair held here is pushed again.
        ``rotation_kdf`` (with it): :meth:`held_kdf` from before the server's
        KEK was adopted; consumed (its KEK copy is zeroed).
        """
        self._require_unlocked()
        # Review e4cd15a (low): only a NEW password is checked. A KDF upgrade
        # or identity rotation keeps the current one, which may predate the
        # rule; refusing it blocked both until the password itself changed.
        if new_password != old_password:
            require_usable_password(new_password)
        # Review 688edcb K2: a second change would overwrite the journal of
        # the first, which holds what the server still knows (the proof of
        # its password, the identity key it still trusts): every login of
        # this device would then fail for good. Review 526419e V4: pushed
        # together with a member re-key, the change was refused for good.
        pending_states.refuse_if_blocked(
            self._db, pending_states.KEY_CHANGE, rotate_identity=rotate_identity
        )
        self._require_epoch_unit_fits("A password change (it re-wraps every folder key)")

        params = Argon2Params.from_dict(self._db.get_meta_json("argon2_params"))
        old_salt = bytes.fromhex(self._db.get_meta("argon2_salt"))

        recovery_pk_hex = self._db.get_meta("org_recovery_pk")
        recovery_pk = None
        if recovery_pk_hex:
            from nacl.public import PublicKey, SealedBox

            if not self._db.get_meta("org_recovery_wrapped_kek"):
                raise ValueError(
                    "Legacy organizational recovery must be reconfigured before changing password."
                )
            try:
                recovery_pk = PublicKey(bytes.fromhex(recovery_pk_hex))
            except (ValueError, TypeError) as exc:
                raise ValueError("Invalid organizational recovery public key.") from exc

        # Verify old password against the KEK that unlocked this vault.
        from ..crypto.kdf import password_forms

        self.dek_mgr._wrapping_kek_id()  # changed in another process: say so, not 'wrong password'
        active_kek = self.dek_mgr._kek
        old_kek = None
        # The same Argon2 run yields the proof of the password the server
        # still has; it authorizes the key material change (review 688edcb K1).
        current_proof = None
        for form in password_forms(old_password):
            candidate, candidate_proof = derive_kek_and_proof(form, old_salt, params, exact=True)
            if compare_digest(candidate, active_kek):
                old_kek, current_proof = candidate, candidate_proof
                break
            candidate[:] = b"\x00" * len(candidate)
            candidate_proof[:] = b"\x00" * len(candidate_proof)
        if old_kek is None:
            raise ValueError("Wrong master password")
        from ..crypto.aead import add_pre_anchor, password_reopens_pre_anchor
        from ..crypto.kdf import canonical_password

        # Capability run 269: the server may keep the account's pre-anchor
        # bundles; one recorded in the anchor must never open again. Keeping
        # the current password changes nothing (KDF upgrade, rotation). With no
        # anchor in the new bundle (run 273) a return loses no pin: allowed.
        known_pre_anchor = self._known_pre_anchor()
        anchored = publishable_anchor(self._db, self._db.get_meta("user_id"), self._keypair) is not None
        if anchored and canonical_password(new_password) != canonical_password(old_password) and (
            password_reopens_pre_anchor(new_password, known_pre_anchor)
        ):
            old_kek[:] = b"\x00" * len(old_kek)
            current_proof[:] = b"\x00" * len(current_proof)
            raise ValueError(PRE_ANCHOR_PASSWORD_REFUSED)
        old_params = params
        active_kek_dek_id = self.dek_mgr.kek_dek_id
        try:
            change_snapshot = take_snapshot(
                self._db, "kdf-upgrade" if new_params is not None else "change-password"
            )
        except SnapshotError:
            old_kek[:] = b"\x00" * len(old_kek)
            current_proof[:] = b"\x00" * len(current_proof)
            raise

        # Option B: one Argon2id run yields both the new KEK and auth proof.
        if new_params is not None:
            params = new_params
        new_kek = None
        if rotation_kdf is not None:
            # Stateful test SM23b: the account's other devices took the lost
            # rotation over. Under a new salt it came back as another KEK at
            # the epoch they hold: the server took their folder keys under the
            # lost one, which no other device opens. It is the same rotation,
            # so it goes out under the same salt and KDF, i.e. the same KEK.
            held_salt, held_params, held_kek = rotation_kdf
            try:
                new_kek, auth_proof = derive_kek_and_proof(new_password, held_salt, held_params)
                if compare_digest(bytes(new_kek), bytes(held_kek)):
                    new_salt, params = held_salt, held_params
                    if held_params != old_params:
                        new_params = held_params
                else:  # another password: nothing to keep
                    new_kek[:] = b"\x00" * len(new_kek)
                    auth_proof[:] = b"\x00" * len(auth_proof)
                    new_kek = None
            finally:
                held_kek[:] = b"\x00" * len(held_kek)
        if new_kek is None:
            new_salt = generate_salt()
            new_kek, auth_proof = derive_kek_and_proof(new_password, new_salt, params)
        recovery_wrap = (
            SealedBox(recovery_pk).encrypt(bytes(new_kek))
            if recovery_pk is not None
            else None
        )

        held_keypair = self._keypair
        previous_anchor = held_keypair.confirmed_genesis
        previous_pre_anchor = held_keypair.pre_anchor
        if rotation_from is not None:
            # The server lost this device's rotation: the same one again,
            # from the keypair the server still has to the one held here.
            old_keypair, new_keypair = rotation_from, held_keypair
        else:
            old_keypair = held_keypair
            new_keypair = generate_keypair() if rotate_identity else old_keypair
        self._db.begin()
        try:
            # Review 1141a20 H2: every epoch change publishes the genesis this
            # device trusts independently, so a new browser or phone inherits it.
            # Only a NEW password makes that hold against the server: under the
            # same one, the account's older salt + keys without it still open.
            anchor = publishable_anchor(self._db, self._db.get_meta("user_id"), held_keypair)
            new_keypair.confirmed_genesis = anchor
            new_keypair.pre_anchor = previous_pre_anchor
            if previous_anchor is None:
                # The password state left now opened bundles without the anchor;
                # a publication carries it with every earlier one this device left.
                left = add_pre_anchor(
                    known_pre_anchor, old_salt, old_params.time_cost,
                    old_params.memory_cost, old_params.parallelism, old_kek,
                )
                self._db.set_meta(PRE_ANCHOR_HISTORY_META, left.hex())
                if anchor is not None:
                    new_keypair.pre_anchor = left
            if anchor is not None:
                self._db.set_meta(CONFIRMED_GENESIS_META, anchor)
            # Re-wrap all DEKs
            self.dek_mgr.rewrap_all_deks(new_kek)

            # Re-encrypt keypair
            from ..crypto.aead import encrypt_keypair_wrap

            kek_dek_id = self._db.get_meta("kek_dek_id")
            user_id = self._db.get_meta("user_id")
            identity = None
            if rotate_identity:
                identity = self._seal_identity_rotation(user_id, old_keypair, new_keypair)
            encrypted_kp = encrypt_keypair_wrap(
                keypair_data=new_keypair.serialize_private(),
                kek=new_kek,
                kek_dek_id=ulid_to_bytes(kek_dek_id),
                user_object_id=ulid_to_bytes(user_id),
            )

            # Update vault_meta
            self._db.set_meta("argon2_salt", new_salt.hex())
            self._db.set_meta("encrypted_keypair", encrypted_kp.hex())
            if new_params is not None:
                self._db.set_meta_json("argon2_params", new_params.to_dict())

            # Increment key_epoch
            epoch = int(self._db.get_meta("key_epoch") or "0") + 1
            self._db.set_meta("key_epoch", str(epoch))
            # The server half (rewrap batch + epoch + key material, one push)
            # is replayed from this journal until the server accepts it.
            old_private = old_keypair.serialize_private() if identity is not None else None
            try:
                pending_states.set_key_change_journal(self._db, make_journal(
                    new_kek, auth_proof, user_id, epoch,
                    identity=identity, old_keypair_private=old_private,
                    current_auth_proof=current_proof, old_kek=old_kek,
                ))
            finally:
                if old_private is not None:
                    old_private[:] = b"\x00" * len(old_private)
            if identity is not None:
                self._db.set_meta("signing_pk", new_keypair.signing_pk.hex())
                self._db.set_meta("encryption_pk", new_keypair.encryption_pk.hex())

            # Re-wrap the new KEK with the public org recovery key (spec 9.1 step 7).
            if recovery_wrap is not None:
                self._db.set_meta("org_recovery_wrapped_kek", recovery_wrap.hex())
                self._db.set_meta("org_recovery_stale", "0")
            self._drop_pending_org_recovery_registration()

            self._db.commit()
        except Exception:
            self._db.rollback()
            held_keypair.confirmed_genesis = previous_anchor
            held_keypair.pre_anchor = previous_pre_anchor
            self.dek_mgr._kek = active_kek
            self.dek_mgr._kek_dek_id = active_kek_dek_id
            new_kek[:] = b"\x00" * len(new_kek)
            old_kek[:] = b"\x00" * len(old_kek)
            current_proof[:] = b"\x00" * len(current_proof)
            auth_proof[:] = b"\x00" * len(auth_proof)
            if new_keypair is not held_keypair:
                new_keypair.zeroize()
            raise

        active_kek[:] = b"\x00" * len(active_kek)
        old_kek[:] = b"\x00" * len(old_kek)
        current_proof[:] = b"\x00" * len(current_proof)
        self._drop_old_password_snapshots(change_snapshot)
        if new_keypair is not old_keypair:
            self._keypair = new_keypair
            old_keypair.zeroize()
            self._audit_log("key_rotation", json.dumps({
                "identity": True, "key_fingerprint": new_keypair.fingerprint,
            }).encode())
        return auth_proof

    def _seal_identity_rotation(
        self, user_id: str, old_keypair: KeyPair, new_keypair: KeyPair
    ) -> dict:
        """Sign the rotation certificate and re-seal this user's envelopes.

        Runs inside the change_password transaction.
        """
        from .sync_client import key_rotation_message

        message = key_rotation_message(
            user_id, old_keypair.signing_pk, old_keypair.encryption_pk,
            new_keypair.signing_pk, new_keypair.encryption_pk,
        )
        identity = {
            "new_signing_pk": new_keypair.signing_pk.hex(),
            "new_encryption_pk": new_keypair.encryption_pk.hex(),
            "rotation_signature": new_keypair.to_nacl_signing_key().sign(message).signature.hex(),
            "authorization_signature": (
                old_keypair.to_nacl_signing_key().sign(message).signature.hex()
            ),
        }

        reseal_envelopes_for_rotation(self._db, self.dek_mgr, user_id, new_keypair)
        return identity

    # ── Org recovery (Shamir, spec 9.4) ──

    def org_recovery_configured(self) -> bool:
        return bool(self._db.get_meta("org_recovery_pk"))

    # Review 7c10379 (R7-H): outside the lock change_password holds, a change
    # in the gap left the recovery key wrapping the old KEK, marked current.
    @oplock.held
    def setup_org_recovery(
        self, threshold: int = 3, shares: int = 5, *, replace: bool = False,
        replaces: Optional[str] = ...,
    ) -> list[tuple[int, bytes]]:
        """Set up organizational recovery using Shamir's Secret Sharing.

        Generates an X25519 recovery keypair, wraps the root KEK with its
        public key, stores the public key and wrapped KEK in vault_meta,
        then splits the private recovery key into N shares via Shamir.

        Args:
            threshold: Minimum shares needed to reconstruct (default 3).
            shares: Total shares to generate (default 5).
            replace: Required when org recovery is already set up: the new
                key voids every share handed out before (lockout review N4).

        Returns:
            List of (index, share_bytes) tuples for distribution to key holders.
        """
        self._require_unlocked()
        assert self._dek_mgr is not None
        if self.org_recovery_configured() and not replace:
            raise OrgRecoveryExistsError(
                "Org recovery is already set up; a new setup invalidates "
                "every existing share."
            )
        # Review 7c10379: the shares of a process with an outdated KEK
        # restored a key the vault no longer has.
        self._dek_mgr._wrapping_kek_id()

        from nacl.public import SealedBox
        from nacl.utils import random as random_bytes

        from ..crypto.shamir import split_secret

        # R16-L4: the shares carry a secret each key is derived from (version 2).
        recovery_secret = bytearray(random_bytes(32))
        recovery_pk = bytes(org_recovery_box_key(recovery_secret).public_key)
        wrapped_kek = SealedBox(org_recovery_box_key(recovery_secret).public_key).encrypt(
            bytes(self._dek_mgr._kek)
        )
        # What the server keeps (review e4cd15a #1): the key it checks the
        # recovery's reset proof against, with a web-format blob of the KEK.
        # Kept in vault_meta until the server takes it: on a vault not yet
        # connected, 'connect' registers it (capability review run 91).
        signing_pk = bytes(org_recovery_signing_key(recovery_secret).verify_key)
        server_blob = {
            "wrapped_kek": org_recovery_server_wrap(self._dek_mgr._kek, recovery_secret).hex(),
            "recovery_signing_pk": signing_pk.hex(),
            "threshold": threshold,
            "total_shares": shares,
            "key_epoch": int(self._db.get_meta("key_epoch") or "0"),
        }
        # Review c78fd19 R13-10: the registration names the recovery key it
        # replaces (``replaces``: the server's current one; by default the one
        # set up here before), so a newer setup on the web is not voided by it.
        if replaces is ...:
            replaces = self._db.get_meta("org_recovery_signing_pk") or None
        pending_states.set_org_recovery_registration(
            self._db, {**server_blob, "expected_signing_pk": replaces}
        )
        # Capability run 378: kept after the registration, until the team log
        # names the key (org_recovery_server.waiting_setup).
        self._db.set_meta_json("org_recovery_replaces", {
            "recovery_signing_pk": signing_pk.hex(), "expected_signing_pk": replaces,
        })
        # Capability run 316: kept for the team log (org.recovery.wrap), so a
        # server restored from before the registration still serves it.
        self._db.set_meta_json("org_recovery_server_wrap", server_blob)

        self._db.set_meta("org_recovery_pk", recovery_pk.hex())
        # Review 8595ec1 #4: named in the team log, so a restored server
        # still takes the recovery's reset proof (org.recovery record).
        self._db.set_meta("org_recovery_signing_pk", signing_pk.hex())
        self._db.set_meta("org_recovery_wrapped_kek", wrapped_kek.hex())
        self._db.set_meta("org_recovery_stale", "0")
        self._db.set_meta("org_recovery_threshold", str(threshold))
        self._db.set_meta("org_recovery_shares", str(shares))
        self._db.conn.commit()

        shamir_shares = split_secret(bytes(recovery_secret), threshold, shares)
        recovery_secret[:] = b"\x00" * len(recovery_secret)

        self._audit_log(
            "org_recovery_setup",
            json.dumps({"threshold": threshold, "shares": shares}).encode(),
        )

        return shamir_shares

    @oplock.held
    def org_recovery(
        self,
        shares: list[tuple[int, bytes]],
        new_password: str,
    ) -> None:
        """Perform organizational recovery from Shamir shares.

        Reconstructs the recovery key from shares, unwraps the KEK,
        derives a new KEK from the new password, and re-wraps all DEKs.

        The vault does NOT need to be unlocked for this — the recovery
        bypasses the normal password-based unlock flow.

        Args:
            shares: List of (index, share_bytes) Shamir shares.
            new_password: New master password to set.
        """
        from nacl.public import PublicKey, SealedBox

        from ..crypto.shamir import reconstruct_secret

        require_usable_password(new_password)
        # Open DB if not already open
        if not self._db.exists():
            raise FileNotFoundError("Vault not found.")
        self._db.open()

        # Verify org recovery is configured
        recovery_pk_hex = self._db.get_meta("org_recovery_pk")
        wrapped_kek_hex = self._db.get_meta("org_recovery_wrapped_kek")
        if not recovery_pk_hex and not wrapped_kek_hex:
            raise ValueError("Organizational recovery not configured. Run setup first.")
        if not recovery_pk_hex or not wrapped_kek_hex:
            raise ValueError(
                "Legacy organizational recovery must be reconfigured before use."
            )
        try:
            recovery_pk = PublicKey(bytes.fromhex(recovery_pk_hex))
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid organizational recovery public key.") from exc

        # Reconstruct recovery key from Shamir shares
        try:
            recovery_key = bytearray(reconstruct_secret(shares))
        except Exception as e:
            raise ValueError(f"Failed to reconstruct recovery key: {e}") from e

        # Unwrap the KEK only when the reconstructed private key matches the
        # configured public key. This also rejects a valid-but-wrong share set.
        try:
            # R16-L4: a version 2 setup here, or a version 1 one (the secret
            # itself); a web setup adopted by adopt_org_recovery is sealed to
            # its Ed25519 key's X25519 form (the log names only that key).
            candidates = [org_recovery_box_key(recovery_key, version) for version in ORG_RECOVERY_VERSIONS]
            candidates += [
                org_recovery_signing_key(recovery_key, version).to_curve25519_private_key()
                for version in ORG_RECOVERY_VERSIONS
            ]
            recovery_private_key = next(
                (key for key in candidates if bytes(key.public_key) == bytes(recovery_pk)), None
            )
            if recovery_private_key is None:
                raise ValueError("Recovery shares do not match this vault.")
            kek = bytearray(
                SealedBox(recovery_private_key).decrypt(bytes.fromhex(wrapped_kek_hex))
            )
        except Exception as exc:
            recovery_key[:] = b"\x00" * len(recovery_key)
            raise ValueError(
                "Recovery key reconstruction failed — shares may be incorrect."
            ) from exc

        try:
            # Review d150605 #3: refused here, not by every push afterwards
            # (with the way back needing the forgotten password).
            self._require_epoch_unit_fits("A Shamir recovery (it re-wraps every folder key)")
            recovery_snapshot = take_snapshot(self._db, "org-recovery")
        except (SnapshotError, SyncUnitTooLarge):
            kek[:] = b"\x00" * len(kek)
            recovery_key[:] = b"\x00" * len(recovery_key)
            raise

        # Now we have the KEK — bootstrap vault state
        user_id = self._db.get_meta("user_id")
        signing_pk = bytes.fromhex(self._db.get_meta("signing_pk"))
        encryption_pk = bytes.fromhex(self._db.get_meta("encryption_pk"))

        # Decrypt keypair with recovered KEK
        from ..crypto.aead import decrypt_keypair_wrap, encrypt_keypair_wrap

        encrypted_kp_hex = self._db.get_meta("encrypted_keypair")

        try:
            kp_data = decrypt_keypair_wrap(
                envelope_blob=bytes.fromhex(encrypted_kp_hex),
                kek=kek,
                user_object_id=ulid_to_bytes(user_id),
            )
        except Exception:
            kek[:] = b"\x00" * len(kek)
            recovery_key[:] = b"\x00" * len(recovery_key)
            raise ValueError("Failed to decrypt keypair with recovered KEK.")

        try:
            self._keypair = KeyPair.from_private_bytes(kp_data, signing_pk, encryption_pk)
            from ..crypto.aead import add_pre_anchor, password_reopens_pre_anchor

            recovered_pre_anchor = self._known_pre_anchor()
            anchored = publishable_anchor(self._db, self._db.get_meta("user_id"), self._keypair) is not None
            if anchored and password_reopens_pre_anchor(new_password, recovered_pre_anchor):
                raise ValueError(PRE_ANCHOR_PASSWORD_REFUSED)  # capability runs 269, 273
            with self._db.transaction(immediate=True):
                record_account_anchor(self._db, self._keypair)  # INV-7: never refuses the unlock
        except Exception:
            kek[:] = bytes(len(kek))
            recovery_key[:] = bytes(len(recovery_key))
            self.lock()
            raise
        finally:
            kp_data[:] = bytes(len(kp_data))

        self._user_id = user_id
        self._dek_mgr = DEKManager(self._db, kek, lambda: (self._user_id, self._keypair))
        self._dek_mgr.classify_legacy_foreign_deks()
        self._dek_mgr.unlock_all_deks()
        self._audit = AuditLog(self._db)
        self._unlocked = True

        # Review 526419e V4: a member re-key still waiting here would go out
        # together with the new password and be refused for good; the way
        # out ('sezam abandon-pending-change') needs the forgotten password.
        # The re-key is dropped first and the member queued for a fresh one.
        pending_rekey = pending_states.rekey_batch(self._db)
        if pending_rekey and not pending_rekey.get("identity_rotation"):
            from .rekey_abandon import abandon_pending_rekey
            from .sync_client import SyncClient

            client = SyncClient(
                self._db, self._db.get_meta("server_url") or "", self._keypair, user_id
            )
            client.set_dek_manager(self._dek_mgr)
            if not client.close_rekey_if_landed():
                abandon_pending_rekey(client)

        # Now re-derive KEK from new password (like change_password but without old password verification)
        params = Argon2Params.from_dict(self._db.get_meta_json("argon2_params"))
        # Capability run 273: without the anchor the forgotten password opened
        # bundles a server may keep; a later publication must carry it.
        left_history = None if self.keypair.confirmed_genesis is not None else add_pre_anchor(
            recovered_pre_anchor, bytes.fromhex(self._db.get_meta("argon2_salt")),
            params.time_cost, params.memory_cost, params.parallelism, kek,
        )
        new_salt = generate_salt()
        new_kek, auth_proof = derive_kek_and_proof(new_password, new_salt, params)

        # Review 688edcb K2: a change the server has not taken yet still holds
        # what the server knows (the proof of its password, the identity key
        # it trusts). The recovered KEK sealed it; it moves into the new journal.
        pending = pending_states.key_change_journal(self._db)
        carried_proof = open_current_auth_proof(pending, kek, user_id) if pending else None
        carried_old_keypair = open_old_keypair(pending, kek, user_id) if pending else None
        # Stateful test SM40: the KEK the server still wraps DEKs under (the
        # recovered one, or the one a waiting change replaces) lets a DEK made
        # elsewhere, or a full resync, re-wrap into this change (SM31).
        server_kek = open_old_kek(pending, kek, user_id) if pending else bytearray(kek)

        self._db.begin()
        try:
            # Re-wrap all DEKs with new KEK
            self.dek_mgr.rewrap_all_deks(new_kek)

            # Re-encrypt keypair with new KEK
            new_kek_dek_id = self._db.get_meta("kek_dek_id")  # Updated by rewrap_all_deks
            encrypted_kp = encrypt_keypair_wrap(
                keypair_data=self.keypair.serialize_private(),
                kek=new_kek,
                kek_dek_id=ulid_to_bytes(new_kek_dek_id),
                user_object_id=ulid_to_bytes(user_id),
            )

            # Update vault_meta
            if left_history is not None:
                self._db.set_meta(PRE_ANCHOR_HISTORY_META, left_history.hex())
            self._db.set_meta("argon2_salt", new_salt.hex())
            self._db.set_meta("encrypted_keypair", encrypted_kp.hex())

            # Increment key_epoch
            epoch = int(self._db.get_meta("key_epoch") or "0") + 1
            self._db.set_meta("key_epoch", str(epoch))
            pending_states.set_key_change_journal(self._db, make_journal(
                new_kek, auth_proof, user_id, epoch,
                identity=pending.get("identity") if carried_old_keypair is not None else None,
                old_keypair_private=carried_old_keypair,
                current_auth_proof=carried_proof,
                # Review e4cd15a #1: proves the reset to the server without
                # the old password or another admin (a lone admin has none).
                recovery_secret=recovery_key,
                old_kek=server_kek,
            ))

            # Preserve break-glass recovery across the password reset.
            recovery_wrap = SealedBox(recovery_pk).encrypt(bytes(new_kek))
            self._db.set_meta("org_recovery_wrapped_kek", recovery_wrap.hex())
            self._db.set_meta("org_recovery_stale", "0")
            self._drop_pending_org_recovery_registration()

            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        finally:
            auth_proof[:] = b"\x00" * len(auth_proof)
            for secret in (carried_proof, carried_old_keypair, recovery_key, server_kek):
                if secret is not None:
                    secret[:] = b"\x00" * len(secret)

        self._drop_old_password_snapshots(recovery_snapshot)
        self._audit_log("org_recovery", b'{"action": "password_reset_via_recovery"}')

        # Rebuild search index
        self._rebuild_search_index()

    # ── Granting a member access to a folder (spec 2.4, tech docs 5.1) ──

    @oplock.held
    def grant_folder_access(
        self,
        node_id: str,
        user_id: str,
        recipient_encryption_pk: bytes,
        access_level: str = "read",
        *,
        relevel: bool = False,
    ) -> str:
        """Give ``user_id`` the folder's DEK in a crypto_box access envelope.

        Only a folder's own shared DEK can be granted: a personal, tier-2 or
        audit DEK stays private, and a subfolder without a DEK of its own
        would hand out its parent's. ``recipient_encryption_pk`` must be the
        member's verified (TOFU-pinned) X25519 key. The envelope goes with the
        next push. Returns the envelope id (the existing one if the member
        already holds this access level).

        ``relevel``: the team log changes the member's level here; the held
        envelope is replaced by one at the new level in the same atomic push
        (R16-N5: envelope and log level must agree, teamlog.envelope_valid).
        """
        self._require_unlocked()
        assert self._keypair is not None
        # Review c78fd19 R13-10: checked only by the audit record after the
        # envelope, a process another one had re-keyed or rebound reported the
        # grant as failed while its envelope stayed queued for the next push.
        self.dek_mgr.require_current_kek()
        self._require_current_identity()
        if access_level not in ("read", "write"):
            raise ValueError("access_level must be 'read' or 'write'")
        if not user_id or user_id == self._user_id:
            raise ValueError("Access can only be granted to another member")
        if len(recipient_encryption_pk) != 32:
            raise ValueError("The member's encryption key must be 32 bytes")
        if user_id in queued_for_removal(self._db):
            # docs/SYNC_SINGLE_SOURCE.md 3.5: decided on the state after the
            # outbox lands, where this member is already removed.
            raise ValueError("This member is queued for removal and gets no new key")

        row = self._db.fetchone(
            "SELECT d.id, d.scope FROM nodes n JOIN deks d ON d.id = n.dek_id "
            "WHERE n.id = ? AND n.is_deleted = 0 AND d.node_id = n.id",
            (node_id,),
        )
        if row is None:
            raise ValueError("This folder has no key of its own to share")
        if row["scope"] not in ("folder", "root"):
            raise ValueError(f"A {row['scope']} folder key is never shared")
        dek_id = row["id"]
        self._refuse_team_grant_over_tier2(node_id)

        from ..crypto.envelope_crypto import create_envelope, open_envelope

        existing = self._db.fetchone(
            "SELECT id, access_level, encrypted_dek FROM access_envelopes "
            "WHERE dek_id = ? AND user_id = ?",
            (dek_id, user_id),
        )
        stale = None
        if existing is not None:
            # crypto_box is symmetric: our key and the member's current key
            # open it only if it is sealed for that key (review 688edcb: after
            # the member's rotation the old envelope is for a key they no
            # longer have, and returning it never gave the folder back).
            from nacl.exceptions import CryptoError

            try:
                opened = open_envelope(
                    bytes(existing["encrypted_dek"]),
                    self._keypair.to_nacl_private_key().encode(),
                    bytes(recipient_encryption_pk),
                )
                opened[:] = b"\x00" * len(opened)
                current = True
            except CryptoError:
                current = False
            if current and existing["access_level"] == access_level:
                return existing["id"]
            if current and not relevel:
                raise ValueError(
                    f"The member already has {existing['access_level']} access to this folder"
                )
            pending_states.refuse_if_blocked(self._db, pending_states.GRANT_AGAIN)
            stale = existing

        encrypted_dek = create_envelope(
            self.dek_mgr.unlock_dek(dek_id),
            self._keypair.to_nacl_private_key().encode(),
            bytes(recipient_encryption_pk),
        )
        envelope_id = new_ulid()
        with self._db.transaction(immediate=True):
            # Again in the write lock: a change elsewhere since the check above.
            self.dek_mgr.require_current_kek()
            self._require_current_identity()
            self._db.execute(
                "INSERT INTO access_envelopes "
                "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (envelope_id, dek_id, user_id, self._user_id, access_level, encrypted_dek),
            )
            if stale is not None:
                # The dead envelope is withdrawn in the same atomic push.
                unsent = outbox.is_pending(self._db, outbox.ENVELOPE, stale["id"])
                self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (stale["id"],))
                pending_states.set_rekey_batch(self._db, {
                    "object_ids": [envelope_id, stale["id"]],
                    "envelope_tombstones": [{
                        "id": stale["id"],
                        "dek_id": dek_id,
                        "user_id": user_id,
                        "access_level": stale["access_level"],
                        "encrypted_dek": bytes(stale["encrypted_dek"]).hex(),
                        "unsent": unsent,
                    }],
                })
            # Envelopes are pushed with their folder.
            outbox.queue_write(self._db, node_id)
            self._audit_log(
                "grant",
                json.dumps({
                    "target": node_id, "user": user_id, "access_level": access_level,
                }).encode(),
            )
        return envelope_id

    def withdraw_unsent_grant(self, envelope_id: str) -> None:
        """Drop a local envelope the server refused (it was never shared)."""
        self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (envelope_id,))

    def seal_handover_envelopes(
        self, user_id: str, recipient_encryption_pk: bytes, dek_ids: list[str],
    ) -> list[str]:
        """Envelopes of ``dek_ids`` for the new admin of a handover (review 8bc70f7 M1).

        No grant: the log gives the admin the keys by the role, so there is
        no access.set, folder write or audit record; they go only in the
        request of the member.role records (SyncClient.send_handover). A key
        this vault cannot open, or one the member already has an envelope
        of, is left out. Returns the envelope ids.
        """
        from nacl.exceptions import CryptoError

        from ..crypto.envelope_crypto import create_envelope

        self._require_unlocked()
        assert self._keypair is not None
        self.dek_mgr.require_current_kek()
        self._require_current_identity()
        if len(recipient_encryption_pk) != 32:
            raise ValueError("The member's encryption key must be 32 bytes")
        sealed = []
        for dek_id in dek_ids:
            if self._db.fetchone(
                "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (dek_id, user_id)
            ):
                continue
            try:
                dek = self.dek_mgr.unlock_dek(dek_id)
            except (KeyError, CryptoError, ValueError):
                continue
            sealed.append((new_ulid(), dek_id, create_envelope(
                dek, self._keypair.to_nacl_private_key().encode(), bytes(recipient_encryption_pk),
            )))
        with self._db.transaction(immediate=True):
            self.dek_mgr.require_current_kek()
            self._require_current_identity()
            for envelope_id, dek_id, encrypted_dek in sealed:
                self._db.execute(
                    "INSERT INTO access_envelopes "
                    "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                    "VALUES (?, ?, ?, ?, 'write', ?)",
                    (envelope_id, dek_id, user_id, self._user_id, encrypted_dek),
                )
        return [envelope_id for envelope_id, _, _ in sealed]

    def settle_handover_envelopes(self, envelope_ids: list[str], landed: bool) -> None:
        """After a handover request failed: its envelopes are the server's if
        the unit landed (a lost reply), else they never existed."""
        with self._db.transaction():
            for envelope_id in envelope_ids:
                if not landed:
                    self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (envelope_id,))
                outbox.sent(self._db, outbox.ENVELOPE, envelope_id)

    # ── Re-key after user revocation (spec 9.3) ──

    def _refuse_rekey_over_conflicts(self, dek_ids: list[str]) -> None:
        """Review e4cd15a #3: a re-key re-seals every row of the folder one
        version up and pushes it. A row with an open sync conflict (e.g. the
        edit a rebased re-key held, M1) would go out as a plain local edit over
        the other device's change, and the conflict would vanish. The user
        settles it first; the queued re-key then runs with the next push."""
        marks = ",".join("?" * len(dek_ids))
        rows = self._db.fetchall(
            "SELECT c.object_id FROM sync_conflicts c WHERE "
            f"c.object_id IN (SELECT id FROM nodes WHERE dek_id IN ({marks})) "
            "OR c.object_id IN (SELECT id FROM nodes WHERE parent_id IN "
            f"(SELECT id FROM nodes WHERE dek_id IN ({marks}))) "
            "OR c.object_id IN (SELECT id FROM entries WHERE node_id IN "
            f"(SELECT id FROM nodes WHERE dek_id IN ({marks}))) "
            "ORDER BY c.object_id",
            tuple(dek_ids) * 3,
        )
        if rows:
            raise RekeyBlockedByConflicts([r["object_id"] for r in rows])

    def key_change_unpushed(self) -> bool:
        """A password/key change of this connected vault the server lacks."""
        if not self._db.get_meta("server_url"):
            return False
        return pending_states.key_change_pending(self._db)

    @oplock.held
    def rekey_after_handover(self, former_admin_id: str) -> int:
        """New admin: re-key the team folders a former admin held only as admin.

        Review c78fd19 (R13-8): after ``member.role`` admin -> member the
        former admin kept every folder key they made and the log took their
        copies under it (``former_admins``) until a re-key nobody made. Every
        folder that names them there and whose current key this vault opens
        gets a new key, sealed to the log's recipients (the former admin only
        with an ``access.set`` of their own). A folder they may write anyway is
        left alone. Returns the folders re-keyed (the batch is pending).
        """
        return self.rekey_after_revocation(former_admin_id, handover=True)

    def _handover_rekey_rows(self, team, former_admin_id: str) -> list[dict]:
        from nacl.exceptions import CryptoError

        rows = []
        member = team.members.get(former_admin_id)
        for folder in sorted(team.folders):
            # Review e443cbc R15 (TeamLogMachine, goal #429): write lowered to
            # read leaves the member's key stale in the log, which then refuses
            # every new write there until a re-key nobody made.
            downgraded = (
                member is not None and member.active and former_admin_id in team.stale.get(folder, ())
            )
            if not downgraded and former_admin_id not in team.former_admins.get(folder, ()):
                continue
            if not downgraded and teamlog.may_write(team, folder, former_admin_id):
                continue
            dek_id = teamlog.current_key(team, folder)
            if not self._db.fetchone(
                "SELECT 1 FROM nodes WHERE id = ? AND dek_id = ?", (folder, dek_id)
            ):
                continue  # not pulled here yet: the next push re-keys it
            try:
                self._dek_mgr.unlock_dek(dek_id)
            except (KeyError, CryptoError, ValueError):
                continue  # the handover grant has not reached this device
            rows.append({"dek_id": dek_id, "sealed_here": 1})
        return rows

    @oplock.held  # review 8bc70f7 #3: lost in 3975939 (tests/test_review14_oplock_coverage.py)
    def rekey_after_revocation(self, revoked_user_id: str, handover: bool = False) -> int:
        """Re-key all folders where a revoked user had access.

        After revoking a user's access, this method:
        1. Finds all folders where the user had access_envelopes.
        2. Generates new DEKs for those folders (via dek_mgr.rekey_folder).
        3. Re-encrypts all entries in those folders with the new DEKs.
        4. Removes the revoked user's access_envelopes.
        5. Creates new access_envelopes for remaining users.

        Args:
            revoked_user_id: The user_id of the revoked user.

        Returns:
            Number of folders re-keyed.
        """
        self._require_unlocked()
        assert self._dek_mgr is not None
        assert self._keypair is not None
        assert self._user_id is not None

        pending_states.refuse_if_blocked(self._db, pending_states.REKEY)

        if handover:
            team = local_team_state(self._db)
            rows = self._handover_rekey_rows(team, revoked_user_id) if team is not None else []
            # The former admin stays a member: only the members queued for
            # removal are withheld, and the archive names nobody as removed.
            withheld = queued_for_removal(self._db)
            return self._rekey_rows(rows, revoked_user_id, team, withheld, handover=True)

        # Find all DEKs where the revoked user has access_envelopes
        rows = self._db.fetchall(
            "SELECT dek_id, MAX(created_by = ?) AS sealed_here FROM access_envelopes "
            "WHERE user_id = ? GROUP BY dek_id",
            (self._user_id, revoked_user_id),
        )
        # Review 7c10379 (state machine: the second admin gets stuck): a key
        # this account cannot open, shared by another admin, is that admin's to
        # re-key (queue_revoked_holders on their devices). Opened here, every
        # push of this desktop raised CryptoError and the member stayed queued.
        # A key sealed here, or an own key whose copy is stale (a server kept
        # it from before a password change), stays in: it must not pass as
        # re-keyed.
        foreign = set(self._db.get_meta_json("foreign_dek_ids") or []) - set(
            self._db.get_meta_json(STALE_OWN_WRAPS_META) or []
        )
        rows = [r for r in rows if r["sealed_here"] or r["dek_id"] not in foreign]
        # Stateful test SM24a: a key the member knew through a grant of this
        # account withdrawn without a re-key, that a folder here still uses.
        listed = {r["dek_id"] for r in rows}
        rows += [
            {"dek_id": dek_id, "sealed_here": 1}
            for dek_id in sorted(pending_states.withdrawn_holder_keys(self._db, revoked_user_id))
            if dek_id not in listed
        ]
        withheld = queued_for_removal(self._db) | {revoked_user_id}
        team = local_team_state(self._db)
        if team is not None:
            # Folders the team log lists the member in (access, or a key they
            # still know) are re-keyed even where this device holds no
            # envelope of theirs (granted from another device).
            listed = {r["dek_id"] for r in rows}
            for folder in sorted(team.folders):
                if (
                    revoked_user_id in team.access.get(folder, {})
                    or revoked_user_id in team.stale.get(folder, set())
                ):
                    dek_id = teamlog.current_key(team, folder)
                    if dek_id not in listed and self._db.fetchone(
                        "SELECT 1 FROM deks WHERE id = ?", (dek_id,)
                    ):
                        rows.append({"dek_id": dek_id, "sealed_here": 1})
                        listed.add(dek_id)
        return self._rekey_rows(rows, revoked_user_id, team, withheld)

    def _rekey_rows(
        self, rows: list, revoked_user_id: str, team, withheld: set, handover: bool = False,
    ) -> int:
        if not rows:
            return 0
        self._refuse_rekey_over_conflicts([r["dek_id"] for r in rows])

        rekey_count = 0
        new_dek_ids: list[str] = []
        dek_map: dict[str, str] = {}
        archive_ids: list[str] = []
        changed_node_ids: list[str] = []
        changed_entry_ids: list[str] = []
        new_envelope_ids: list[str] = []
        envelope_tombstones: list[dict] = []

        take_snapshot(self._db, "rekey")
        # Unpushed edits made before the re-key: their content is not the
        # server's, so a rebase must not replace it (review 688edcb V1).
        edited_before = outbox.queued_ids(self._db, "nodes") | outbox.queued_ids(
            self._db, "entries"
        )
        self._db.begin()
        try:
            for row in rows:
                old_dek_id = row["dek_id"]

                # Every node sharing this DEK (owner folder plus subfolders
                # created without their own DEK) must move to the new DEK.
                affected_rows = self._db.fetchall(
                    "SELECT id FROM nodes WHERE dek_id = ?", (old_dek_id,)
                )
                if not affected_rows:
                    # DEK not associated with a node (tier2, audit, or a folder
                    # key re-keyed away). Stateful test SM32: two devices granted
                    # the folder; the other one's re-key withdrew only its own
                    # envelope and the member's envelope here stayed live. With
                    # no folder to re-key, the member's envelope still goes.
                    for env in self._db.fetchall(
                        "SELECT id, dek_id, user_id, created_by, access_level, encrypted_dek "
                        "FROM access_envelopes WHERE dek_id = ? AND user_id = ?",
                        (old_dek_id, revoked_user_id),
                    ):
                        envelope_tombstones.append({
                            "id": env["id"],
                            "dek_id": env["dek_id"],
                            "user_id": env["user_id"],
                            "created_by": env["created_by"],
                            "access_level": env["access_level"],
                            "encrypted_dek": bytes(env["encrypted_dek"]).hex(),
                            "unsent": outbox.is_pending(self._db, outbox.ENVELOPE, env["id"]),
                        })
                        self._db.execute("DELETE FROM access_envelopes WHERE id = ?", (env["id"],))
                    continue
                affected_ids = [r["id"] for r in affected_rows]
                owner_row = self._db.fetchone(
                    "SELECT node_id FROM deks WHERE id = ?", (old_dek_id,)
                )
                node_id = (
                    owner_row["node_id"]
                    if owner_row is not None and owner_row["node_id"] in affected_ids
                    else affected_ids[0]
                )
                id_marks = ",".join("?" * len(affected_ids))

                # Get the old DEK (still cached)
                old_dek = self._dek_mgr.unlock_dek(old_dek_id)

                # Generate new DEK for this folder
                new_dek_id, new_dek = self._dek_mgr.rekey_folder(
                    old_dek_id, node_id, removed_user_id=None if handover else revoked_user_id
                )
                new_dek_ids.append(new_dek_id)
                dek_map[old_dek_id] = new_dek_id
                archive_row = self._db.fetchone(
                    "SELECT id FROM dek_archive WHERE replaced_by = ?", (new_dek_id,)
                )
                if archive_row is None:
                    raise RuntimeError(f"Missing DEK archive for re-keyed node {node_id}")
                archive_ids.append(archive_row["id"])
                changed_node_ids.extend(affected_ids)

                outbox.queue_writes(self._db, "nodes", "dek_id = ?", (old_dek_id,))
                self._db.execute(
                    "UPDATE nodes SET dek_id = ? WHERE dek_id = ?",
                    (new_dek_id, old_dek_id),
                )

                # Re-encrypt all entries in these folders that used the old DEK.
                # R15 #441 (stateful run): not those of a deleted folder. The
                # server takes nothing live below one, so the batch was refused
                # on every push; and the push revived the folder for them, which
                # a new admin, who cannot open the parent's key it is sealed
                # with, could not (CryptoError on every push). They keep the
                # old key, as the rest of the trash does.
                entry_rows = self._db.fetchall(
                    "SELECT id, node_id, encrypted_meta, encrypted_data, dek_id, version "
                    f"FROM entries WHERE node_id IN ({id_marks}) AND is_deleted = 0 "
                    "AND node_id IN (SELECT id FROM nodes WHERE is_deleted = 0)",
                    tuple(affected_ids),
                )

                for entry_row in entry_rows:
                    entry_dek_id = entry_row["dek_id"]
                    # Only re-encrypt entries that inherit from the folder DEK (dek_id IS NULL)
                    # or explicitly use the old DEK
                    if entry_dek_id is not None and entry_dek_id != old_dek_id:
                        continue  # This entry uses a different DEK (e.g., tier2)

                    entry_id = entry_row["id"]
                    version = entry_row["version"]
                    new_version = version + 1

                    # Decrypt with old DEK
                    try:
                        meta = EntryMeta.from_json(
                            decrypt(
                                entry_row["encrypted_meta"],
                                old_dek,
                                ulid_to_bytes(entry_id),
                                version,
                                expected_blob_kind=BlobKind.ENTRY_META,
                            )
                        )
                        data = EntryData.from_json(
                            decrypt(
                                entry_row["encrypted_data"],
                                old_dek,
                                ulid_to_bytes(entry_id),
                                version,
                                expected_blob_kind=BlobKind.ENTRY_DATA,
                            )
                        )
                    except Exception as exc:
                        raise RuntimeError(
                            f"Cannot decrypt entry {entry_id}; re-key rolled back"
                        ) from exc

                    # Re-encrypt with new DEK
                    encrypted_meta = encrypt(
                        plaintext=meta.to_json(),
                        dek=new_dek,
                        dek_id=ulid_to_bytes(new_dek_id),
                        object_id=ulid_to_bytes(entry_id),
                        version=new_version,
                        blob_kind=BlobKind.ENTRY_META,
                    )
                    encrypted_data = encrypt(
                        plaintext=data.to_json(),
                        dek=new_dek,
                        dek_id=ulid_to_bytes(new_dek_id),
                        object_id=ulid_to_bytes(entry_id),
                        version=new_version,
                        blob_kind=BlobKind.ENTRY_DATA,
                    )

                    outbox.queue_write(self._db, entry_id)
                    self._db.execute(
                        "UPDATE entries SET encrypted_meta = ?, encrypted_data = ?, "
                        "dek_id = NULL, version = ? WHERE id = ?",
                        (encrypted_meta, encrypted_data, new_version, entry_id),
                    )
                    changed_entry_ids.append(entry_id)

                # Node meta is encrypted with the parent's DEK (personal
                # folders: their own). Re-encrypt every meta blob whose
                # envelope still names the old DEK, otherwise subfolders
                # become undecryptable once the folder points to the new DEK.
                old_dek_raw_id = ulid_to_bytes(old_dek_id)
                meta_rows = self._db.fetchall(
                    "SELECT id, encrypted_meta, version FROM nodes "
                    f"WHERE (id IN ({id_marks}) OR parent_id IN ({id_marks})) "
                    "AND is_deleted = 0",
                    tuple(affected_ids) * 2,
                )
                for meta_row in meta_rows:
                    blob = bytes(meta_row["encrypted_meta"])
                    if parse_envelope(blob).dek_id != old_dek_raw_id:
                        continue
                    meta_node_id = meta_row["id"]
                    meta_version = meta_row["version"]
                    try:
                        node_meta = decrypt(
                            blob, old_dek, ulid_to_bytes(meta_node_id), meta_version,
                            expected_blob_kind=BlobKind.NODE_META,
                        )
                    except Exception as exc:
                        raise RuntimeError(
                            f"Cannot decrypt folder {meta_node_id}; re-key rolled back"
                        ) from exc
                    outbox.queue_write(self._db, meta_node_id)
                    self._db.execute(
                        "UPDATE nodes SET encrypted_meta = ?, version = ? "
                        "WHERE id = ?",
                        (
                            encrypt(
                                plaintext=node_meta,
                                dek=new_dek,
                                dek_id=ulid_to_bytes(new_dek_id),
                                object_id=ulid_to_bytes(meta_node_id),
                                version=meta_version + 1,
                                blob_kind=BlobKind.NODE_META,
                            ),
                            meta_version + 1,
                            meta_node_id,
                        ),
                    )
                    changed_node_ids.append(meta_node_id)

                old_envelopes = self._db.fetchall(
                    "SELECT id, dek_id, user_id, created_by, access_level, encrypted_dek "
                    "FROM access_envelopes WHERE dek_id = ?",
                    (old_dek_id,),
                )
                for env in old_envelopes:
                    envelope_tombstones.append({
                        "id": env["id"],
                        "dek_id": env["dek_id"],
                        "user_id": env["user_id"],
                        "created_by": env["created_by"],
                        "access_level": env["access_level"],
                        "encrypted_dek": bytes(env["encrypted_dek"]).hex(),
                        "unsent": outbox.is_pending(self._db, outbox.ENVELOPE, env["id"]),
                    })

                self._db.execute(
                    "DELETE FROM access_envelopes WHERE dek_id = ?", (old_dek_id,)
                )

                if team is not None and teamlog.is_team_folder(team, node_id):
                    # docs/DESIGN_TEAM_LOG.md §4.3.1: exactly the log's
                    # recipients, with the log's level and key.
                    if not log_trusted(self._db, self._user_id, self._keypair, team):
                        raise RuntimeError(
                            "The team log's founder is not confirmed on this device; "
                            "no folder key is sealed until it is."
                        )
                    # R16-Z deep run (also on 18c300f): this account too, when
                    # the log gives it access of its own (a member who took the
                    # admin role); skipped, it lost the folder on handing back.
                    for uid, encryption_pk, level in teamlog.key_recipients(team, node_id):
                        if uid in withheld:
                            continue
                        from nacl.public import Box, PublicKey as NaClPublicKey

                        box = Box(self._keypair.to_nacl_private_key(),
                                  NaClPublicKey(bytes.fromhex(encryption_pk)))
                        new_env_id = new_ulid()
                        self._db.execute(
                            "INSERT INTO access_envelopes "
                            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (new_env_id, new_dek_id, uid, self._user_id, level,
                             bytes(box.encrypt(bytes(new_dek)))),
                        )
                        new_envelope_ids.append(new_env_id)
                    old_envelopes = []
                elif team is not None:
                    # Review 1141a20 H6 (§9): with a log, who holds a key it
                    # does not know never gets the next one.
                    old_envelopes = [e for e in old_envelopes if e["user_id"] == self._user_id]

                for env in old_envelopes:
                    env_user_id = env["user_id"]
                    if env_user_id in withheld:
                        continue  # review a159e97: a queued member is revoked too
                    key_row = reseal_key_row(
                        self._db, env_user_id, env["created_by"], self._user_id
                    )
                    if key_row is None:
                        if env["created_by"] != self._user_id:
                            continue  # review 7c10379 H2: not a grant this account trusts
                        raise RuntimeError(
                            f"Missing verified encryption key for user {env_user_id}"
                        )

                    from nacl.public import Box, PublicKey as NaClPublicKey

                    recipient_pk = NaClPublicKey(bytes(key_row["encryption_pk"]))
                    sender_sk = self._keypair.to_nacl_private_key()
                    box = Box(sender_sk, recipient_pk)
                    encrypted_new_dek = box.encrypt(bytes(new_dek))

                    new_env_id = new_ulid()
                    self._db.execute(
                        "INSERT INTO access_envelopes "
                        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            new_env_id,
                            new_dek_id,
                            env_user_id,
                            self._user_id,
                            vouched_access_level(self._db, env["id"], env["access_level"]),
                            encrypted_new_dek,
                        ),
                    )
                    new_envelope_ids.append(new_env_id)

                rekey_count += 1

            audit = self._audit or AuditLog(self._db)
            audit_dek_id, audit_dek = self._dek_mgr.get_audit_dek()
            audit_id = audit.append(
                actor_id=self._user_id,
                action="rekey",
                signing_key=self._keypair.to_nacl_signing_key(),
                detail_plaintext=json.dumps({
                    ("former_admin" if handover else "revoked_user"): revoked_user_id,
                    "folders_rekeyed": rekey_count,
                }).encode(),
                audit_dek=audit_dek,
                audit_dek_id=audit_dek_id,
            )

            object_ids = set(
                new_dek_ids
                + archive_ids
                + changed_node_ids
                + changed_entry_ids
                + new_envelope_ids
                + [item["id"] for item in envelope_tombstones]
                + [audit_id]
            )
            # Review 526419e #1: refused here, not by a 422 on every sync.
            self._require_one_sync_unit(
                object_ids,
                "The re-key after the admin handover" if handover
                else "Removing this member (the folder re-key)",
            )
            rekeyed_versions: dict[str, int] = {}
            for table, ids in (("nodes", changed_node_ids), ("entries", changed_entry_ids)):
                for object_id in set(ids) - edited_before:
                    version_row = self._db.fetchone(
                        f"SELECT version FROM {table} WHERE id = ?", (object_id,)
                    )
                    rekeyed_versions[object_id] = version_row["version"]
            pending_states.set_rekey_batch(self._db, {
                # A handover re-key removes nobody (the former admin stays a
                # member): nothing may take them as queued for removal.
                "revoked_user_id": None if handover else revoked_user_id,
                **({"handover_from": revoked_user_id} if handover else {}),
                "folders_rekeyed": rekey_count,
                # Old → new DEK: lets the sync client carry the batch over
                # edits other devices push before it lands.
                "dek_map": dek_map,
                # Versions the re-key alone produced: a row still at its
                # version carries the server's content, anything else a user edit.
                "rekeyed_versions": rekeyed_versions,
                "object_ids": sorted(object_ids),
                "archive_ids": archive_ids,
                "audit_ids": [audit_id],
                "envelope_tombstones": envelope_tombstones,
            })
            self._db.commit()
        except Exception:
            self._db.rollback()
            for dek_id in new_dek_ids:
                cached = self._dek_mgr._dek_cache.pop(dek_id, None)
                if cached is not None:
                    cached[:] = b"\x00" * len(cached)
            raise

        return rekey_count

    # ── Tree display ──

    def get_tree(self, node_id: Optional[str] = None, prefix: str = "") -> list[str]:
        """Get a text representation of the vault tree."""
        self._require_unlocked()

        if node_id is None:
            node_id = self._db.get_meta("root_node_id")

        lines = []
        children = self.list_nodes(node_id)
        entries = self.list_entries(node_id)

        all_items = (
            [(c["name"], c["id"], True) for c in children]
            + [(e["name"], e["id"], False) for e in entries]
        )

        for i, (name, item_id, is_folder) in enumerate(all_items):
            is_last = i == len(all_items) - 1
            connector = "└── " if is_last else "├── "
            icon = "[D] " if is_folder else "[E] "
            lines.append(f"{prefix}{connector}{icon}{name}")

            if is_folder:
                extension = "    " if is_last else "│   "
                lines.extend(self.get_tree(item_id, prefix + extension))

        return lines

    # ── Internal helpers ──

    def _decrypt_node_meta(
        self, blob: bytes, dek: bytearray, dek_id: str, node_id: str, version: int
    ) -> NodeMeta:
        plaintext = decrypt(
            blob, dek, ulid_to_bytes(node_id), version,
            expected_blob_kind=BlobKind.NODE_META,
        )
        return NodeMeta.from_json(plaintext)

    def _node_meta_dek(self, row) -> tuple[str, bytearray]:
        """DEK that encrypts a folder's meta (row: id, parent_id, dek_id, encrypted_meta).

        The parent's DEK, except a personal root, whose name is under its
        own DEK so that only the owner reads it (desktop and web alike).
        """
        own_dek_id = row["dek_id"]
        if own_dek_id is not None and row["parent_id"] is not None:
            header_dek_id = bytes_to_ulid(parse_envelope(bytes(row["encrypted_meta"])).dek_id)
            if header_dek_id == own_dek_id:
                return own_dek_id, self.dek_mgr.unlock_dek(own_dek_id)
        return self.dek_mgr.get_dek_for_node(row["parent_id"] or row["id"])

    def _build_node_path(self, node_id: str) -> str:
        """Build full path for a node (e.g. 'servers/hetzner')."""
        parts = []
        current = node_id
        root_id = self._db.get_meta("root_node_id")
        # R16-Z SM22: a parent cycle (an unsent move crossed by a pulled one,
        # until the server refuses it) made unlock walk this path forever.
        seen: set[str] = set()

        while current and current != root_id and current not in seen:
            seen.add(current)
            row = self._db.fetchone(
                "SELECT parent_id, encrypted_meta, dek_id, version FROM nodes WHERE id = ?",
                (current,),
            )
            if row is None:
                break

            parent_id = row["parent_id"]
            # A personal root (top-level, TL7) is named like a folder of the root.
            if parent_id or is_personal_root(self._db, self.dek_mgr, current):
                try:
                    meta_dek_id, meta_dek = self._node_meta_dek(
                        {**dict(row), "id": current}
                    )
                    meta = self._decrypt_node_meta(
                        row["encrypted_meta"], meta_dek, meta_dek_id, current, row["version"]
                    )
                    parts.append(meta.name)
                except Exception:
                    parts.append("?")

            current = parent_id

        parts.reverse()
        return "/".join(parts)

    def _rebuild_search_index(self) -> None:
        """Build FTS index from all decrypted entry metadata."""
        self._search.clear()
        self._search.build()

        if not self._unlocked:
            return

        rows = self._db.fetchall(
            "SELECT e.id, e.node_id, e.encrypted_meta, e.encrypted_data, e.dek_id, e.version "
            "FROM entries e WHERE e.is_deleted = 0"
        )

        for row in rows:
            try:
                dek_id_str = row["dek_id"]
                if dek_id_str is None:
                    dek_id_str, dek = self.dek_mgr.get_dek_for_node(row["node_id"])
                else:
                    dek = self.dek_mgr.unlock_dek(dek_id_str)

                meta = EntryMeta.from_json(
                    decrypt(
                        row["encrypted_meta"],
                        dek,
                        ulid_to_bytes(row["id"]),
                        row["version"],
                        expected_blob_kind=BlobKind.ENTRY_META,
                    )
                )

                # Decrypt data for field keys (not values — standard search)
                data = EntryData.from_json(
                    decrypt(
                        row["encrypted_data"],
                        dek,
                        ulid_to_bytes(row["id"]),
                        row["version"],
                        expected_blob_kind=BlobKind.ENTRY_DATA,
                    )
                )

                node_path = self._build_node_path(row["node_id"])
                self._search.add_entry(
                    entry_id=row["id"],
                    node_id=row["node_id"],
                    node_path=node_path,
                    name=meta.name,
                    field_keys=[f.key for f in data.fields],
                    tags=meta.tags,
                )
            except Exception:
                continue

    def _create_history_snapshot(self, entry_id: str) -> None:
        """Create a history snapshot of an entry before update."""
        row = self._db.fetchone(
            "SELECT encrypted_data, dek_id, node_id, version FROM entries WHERE id = ?",
            (entry_id,),
        )
        if row is None:
            return

        dek_id = row["dek_id"]
        if dek_id is None:
            node_row = self._db.fetchone(
                "SELECT dek_id FROM nodes WHERE id = ?", (row["node_id"],)
            )
            dek_id = node_row["dek_id"]

        snapshot_id = new_ulid()
        now_ms = int(time.time() * 1000)

        # Re-encrypt as HISTORY_SNAPSHOT (blob_kind=4) instead of copying ENTRY_DATA (blob_kind=3)
        from ..crypto.aead import BlobKind, decrypt, encrypt
        from ..models import ulid_to_bytes

        dek_raw = self._dek_mgr.unlock_dek(dek_id) if self._dek_mgr else None
        if dek_raw:
            # Decrypt the existing entry_data blob
            plaintext = decrypt(
                row["encrypted_data"], dek_raw,
                ulid_to_bytes(entry_id), row["version"],
                enable_padding=True,
                expected_blob_kind=BlobKind.ENTRY_DATA,
            )
            # Re-encrypt as history_snapshot (blob_kind=4)
            snapshot_blob = encrypt(
                plaintext, dek_raw,
                ulid_to_bytes(dek_id), ulid_to_bytes(snapshot_id),
                version=1,
                blob_kind=BlobKind.HISTORY_SNAPSHOT,
                enable_padding=True,
            )
        else:
            # Fallback: store raw (should not happen with unlocked vault)
            snapshot_blob = row["encrypted_data"]

        self._db.execute(
            "INSERT INTO entry_history (id, entry_id, encrypted_snapshot, dek_id, changed_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (snapshot_id, entry_id, snapshot_blob, dek_id, now_ms),
        )
