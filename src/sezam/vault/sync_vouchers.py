"""Key vouchers on the desktop (review e443cbc R15, goal #443, INV-3).

A retired identity key stays in its account's key ring so that what it signed
before the rotation still verifies. Which objects that is was decided by the
server's ``retired_seq`` and each object's ``commit_seq``: a server holding a
leaked retired key signed any object with it and served both numbers to a
device that had not pinned a bound (a new device, a full resync).

Now a retired key's signature counts only for an (id, version, digest of the
signed message, its signer and key: R17-N1) named by a voucher list (src/sezam/key_vouchers.py) signed by the current key
of the signer's account, of this device's own account, or of a current admin
of the verified team log, or held by this device itself. The identity rotation
of this device carries the lists, signed by the new key, of every live object
the old key signed (and of those the old key's lists named); the server
refuses a rotation that leaves one out.

A rotation from before #443 has no list, and its account may never sync again
(an inactive member, web only, not updated). So every desktop and phone posts a
list of the versions it holds (it verified them) on its first sync with #443
and after each identity rotation in the team, signed by its account's key: the
account's other and new devices take them over a full resync, and an admin's
list vouches for every member (capability review runs 480, 482). The web
holds nothing between sessions and posts nothing. A member who never held
such an object gets it once the signer, an admin or a desktop or phone of
their own account that holds it has synced; until then the pull says so.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Iterator, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .. import key_vouchers, teamlog
from .sync_common import server_error

logger = logging.getLogger(__name__)

# Entries per list: a list of ~110 bytes per entry stays well under the
# server's 16 MiB body limit, with the rotation's batch beside it.
VOUCHERS_PER_LIST = 20_000
# The keys of this account and its team this device last posted the list of
# the versions it holds under (_post_legacy_vouchers).
LEGACY_CHECKED_META = "key_vouchers_checked"
# Every retired key of any account this device has seen.
RETIRED_SEEN_META = "key_vouchers_retired_seen"


def legacy_post_allowed(
    *, fingerprint: str, checked: Optional[str], pending_identity: bool,
    own_key: str, server_own_key: Optional[str], held_count: int,
) -> bool:
    """Whether a device posts its held versions now (R16-M4: the desktop's
    and the phone's rule, tests/vectors/key_voucher_post.json).

    Not again under keys it already posted under; not during its own identity
    rotation; not when the server's current key of its account is not its
    own (rotated elsewhere: its list would not count); not before it holds
    anything. ``held_count`` is what it held before this pull: a version a
    pull brings is not named by that pull (a server withholding the team log
    serves a new device what it likes)."""
    return (
        checked != fingerprint and not pending_identity
        and server_own_key == own_key and held_count > 0
    )


def legacy_entries(held, own_listed) -> list:
    """What the device's list names: what it held that its account's lists do not."""
    return sorted(set(held) - set(own_listed))


def _local_key(obj: dict) -> tuple:
    """What VoucherMixin._held_locally keeps of a served copy."""
    parent = obj.get("parent_ref") if obj.get("object_type") in ("node", "entry") else None
    return (obj.get("version", 1), str(obj.get("payload_hash", "")).lower(), parent)


class VoucherMixin:
    """Mixed into SyncClient."""

    def _hold_signed(self, obj: dict, signer_id: str, signing_pk: bytes) -> None:
        """R17-N1: the voucher entry of a server copy this device verified
        (pull) or the server took from it (push). In the caller's transaction."""
        entry = key_vouchers.object_entry(obj, signer_id, signing_pk)
        if entry is None:
            return
        payload_hash = str(obj["payload_hash"]).lower()
        self._db.execute(
            "DELETE FROM held_signed WHERE object_id = ? AND (version <> ? OR payload_hash <> ?)",
            (entry[0], entry[1], payload_hash),
        )
        self._db.execute(
            "INSERT OR IGNORE INTO held_signed (object_id, version, payload_hash, digest, retired) "
            "VALUES (?, ?, ?, ?, ?)",
            (entry[0], entry[1], payload_hash, entry[2], int(self._is_retired(signer_id, signing_pk))),
        )

    def _hold_verified(self) -> None:
        """Keep the entries of what the last verification passed took."""
        verified, self._verified_entries = self._verified_entries, {}
        for obj, signer_id, signing_pk in verified.values():
            self._hold_signed(obj, signer_id, signing_pk)

    def _held_digests(self, obj_id: str, version: int) -> frozenset:
        """The entry digests of the held server copy at ``version`` (none if not held)."""
        self._held()
        return self._held_index.get((obj_id, version), frozenset())

    def _held(self) -> frozenset:
        if self._held_cache is None:
            self._held_cache = frozenset(self._held_entries())
            index: dict = {}
            for obj_id, version, digest in self._held_cache:
                index.setdefault((obj_id, version), set()).add(digest)
            self._held_index = {key: frozenset(value) for key, value in index.items()}
        return self._held_cache

    def _remember_retired_keys(self, user_id: str, response: dict) -> None:
        """The account's retired keys, and its current key whose lists count.

        ``response`` is /api/users/{id}/keys, already checked: its signing_pk
        is the pinned key (or, for this account, the local key or the one that
        authorized this device's pending rotation).
        """
        retired: set[bytes] = set()
        archives = response.get("archived_keys")
        for archive in archives if isinstance(archives, list) else []:
            if isinstance(archive, dict) and isinstance(archive.get("signing_pk"), str):
                retired.add(bytes.fromhex(archive["signing_pk"]))
        self._retired_keys[user_id] = frozenset(retired)
        self._voucher_keys[user_id] = bytes.fromhex(response["signing_pk"])
        self._vouched_cache.clear()
        seen = set(self._db.get_meta_json(RETIRED_SEEN_META) or [])
        if not {pk.hex() for pk in retired} <= seen:
            # The next sync posts this device's list (_post_legacy_vouchers).
            self._db.set_meta_json(RETIRED_SEEN_META, sorted(seen | {pk.hex() for pk in retired}))

    def _is_retired(self, user_id: str, signing_pk: bytes) -> bool:
        return bytes(signing_pk) in self._retired_keys.get(user_id, frozenset())

    def _lists_of(self, poster_id: str, key: Optional[bytes]) -> frozenset:
        """What the lists ``poster_id`` signed with ``key`` name; empty without one."""
        if key is None:
            return frozenset()
        cached = self._lists_cache.get((poster_id, key))
        if cached is not None:
            return cached
        try:
            response = self._request("GET", f"/api/users/{poster_id}/key-vouchers", auth=True) or {}
        except RuntimeError as exc:  # a server from before #443: no list
            logger.warning("No key vouchers of %s: %s", poster_id, exc)
            response = {}
        cached = key_vouchers.vouched(poster_id, key, response.get("lists"))
        self._lists_cache[(poster_id, key)] = cached
        return cached

    def _vouched(self, user_id: str) -> frozenset:
        """What a retired key of ``user_id`` still vouches for: what the lists
        of the account's current key, of this account's key or of a current
        admin of the verified team log name, and the versions this device holds."""
        cached = self._vouched_cache.get(user_id)
        if cached is not None:
            return cached
        out = set(self._lists_of(user_id, self._voucher_keys.get(user_id)))
        out |= self._lists_of(self._user_id, bytes(self._keypair.signing_pk))
        state = self.team_state()
        for admin_id, member in (state.members.items() if state is not None else ()):
            if member.active and member.signing_pk and teamlog.is_admin(state, admin_id):
                out |= self._lists_of(admin_id, bytes.fromhex(member.signing_pk))
        out |= self._held()
        cached = frozenset(out)
        self._vouched_cache[user_id] = cached
        return cached

    def _reset_vouchers(self) -> None:
        """Before a pull or full resync: lists and held versions are read again."""
        self._lists_cache: dict[tuple[str, bytes], frozenset] = {}
        self._vouched_cache: dict[str, frozenset] = {}
        self._held_cache: Optional[frozenset] = None
        # Objects a retired key signed that no list names: id -> signer.
        self._unvouched: dict[str, str] = {}
        # R17-N1: of those, the ones whose held copy has other signed fields.
        self._equivocated: set[str] = set()
        # What verified since the last pull or resync, kept in held_signed
        # once applied: id -> (object, signer, key).
        self._verified_entries: dict[str, tuple[dict, str, bytes]] = {}

    def _unless_retired_signed(self, folders: list[str]) -> list[str]:
        """R17-N1: the folders to fold (fold_unlogged_folder_keys), without any
        whose held copy, or a held copy below it, came signed by a retired key.

        A leaked key that "moved" a private folder under a team folder would
        otherwise have had its content resealed to the team. What its key seals
        stays refused there, and named.
        """
        tainted: set[str] = set()  # those folders and every folder above them
        for row in self._db.fetchall(
            "SELECT h.object_id FROM held_signed h JOIN nodes n "
            "ON n.id = h.object_id AND n.version = h.version WHERE h.retired = 1"
        ):
            node = row["object_id"]
            while node is not None and node not in tainted:
                tainted.add(node)
                up = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (node,))
                node = up["parent_id"] if up is not None else None
        for folder in folders:
            if folder in tainted:
                logger.warning(
                    "Folder %s below a team folder came signed by a retired key: "
                    "not resealed to its parent's key", folder,
                )
        return [folder for folder in folders if folder not in tainted]

    def _rejected(self, obj: dict, generic: str = "invalid or unverifiable signature") -> str:
        """Why a pulled object did not verify, for the error."""
        if obj.get("id") in self._equivocated:
            return (
                f"{generic}: equivocation - the server serves version {obj.get('version')} "
                "signed by a retired key with other signed fields than the copy this "
                "device holds"
            )
        signer = self._unvouched.get(obj.get("id"))
        if signer is None:
            return generic
        return (
            f"{generic}: a retired key of {signer} signed it and no "
            f"voucher list names it; it verifies once {signer}, a team admin or another "
            "device of this account that holds it has synced"
        )

    def _signed_by(self, obj: dict, signing_pk: bytes) -> bool:
        """Whether ``signing_pk`` signed this served object's canonical fields."""
        signature = obj.get("signature") or obj.get("client_signature")
        if not isinstance(signature, str) or not isinstance(obj.get("payload_hash"), str):
            return False
        try:
            canonical = self._build_signature_payload(
                id=obj["id"], object_type=obj["object_type"], parent_ref=obj.get("parent_ref"),
                target_user_id=obj.get("target_user_id"), is_deleted=obj.get("is_deleted", 0),
                version=obj.get("version", 1), payload_hash=obj["payload_hash"],
            )
            VerifyKey(bytes(signing_pk)).verify(canonical, bytes.fromhex(signature))
        except (BadSignatureError, ValueError, KeyError, TypeError):
            return False
        return True

    def _signed_objects(self) -> Iterator[dict]:
        """The live versions this account signed (no payloads), by id."""
        after = ""
        while True:
            page = self._request("GET", f"/api/users/me/signed-objects?after={after}", auth=True) or {}
            objects = [obj for obj in page.get("objects") or [] if isinstance(obj, dict)]
            yield from objects
            last = objects[-1].get("id") if objects else None
            if not page.get("more") or not isinstance(last, str) or last <= after:
                return
            after = last

    def _signed_lists(self, entries: list) -> list[dict]:
        signing_key = self._keypair.to_nacl_signing_key()
        return [
            key_vouchers.sign_vouchers(self._user_id, signing_key, entries[start:start + VOUCHERS_PER_LIST])
            for start in range(0, len(entries), VOUCHERS_PER_LIST)
        ]

    def _rotation_vouchers(self) -> list[dict]:
        """Lists for this device's identity rotation, signed by the new key:
        every live object the old key signed, and every one a list of the old
        key named that a retired key signed."""
        ring = self._get_signing_pks(self._user_id)
        old = self._rotation_authorizer
        if old is None:
            if self._keypair.signing_pk in ring:
                # The rotation landed and its reply was lost (SM43): its lists
                # went with it; the server answers that it needs new keys.
                return []
            raise RuntimeError("The key this device's identity rotation retires is not known yet")
        vouched = self._vouched(self._user_id)
        retired = self._retired_keys.get(self._user_id, frozenset())
        local = self._held_locally()
        entries = []
        for obj in self._signed_objects():
            # R17-N1: an entry names the message the key signed, and only a
            # version this device holds is carried forward: not what the
            # server lists (a version forged before the rotation went on
            # under the new key), nor one the held copy contradicts.
            for pk in (old, *retired):
                entry = key_vouchers.object_entry(obj, self._user_id, pk)
                if entry is None or not self._signed_by(obj, pk):
                    continue
                held = self._held_digests(entry[0], entry[1])
                if held and entry[2] not in held:
                    continue
                if entry in vouched or (pk == old and not held and local.get(obj["id"]) == _local_key(obj)):
                    entries.append(entry)
                    break
        return self._signed_lists(entries)

    def _held_locally(self) -> dict[str, tuple]:
        """A copy held from before held_signed, as its signed fields read here
        (live folders and entries: version, payload hash, parent; other rows:
        version, payload hash)."""
        parents = {
            row["id"]: row["parent"] for row in self._db.fetchall(
                "SELECT id, parent_id AS parent FROM nodes WHERE is_deleted = 0 "
                "UNION ALL SELECT id, node_id FROM entries WHERE is_deleted = 0"
            )
        }
        return {
            obj_id: (version, hashlib.sha256(payload).hexdigest(), parents.get(obj_id))
            for obj_id, version, payload, *_signed in self._local_objects()
        }

    def _voucher_fingerprint(self) -> str:
        """This account's key, every member's key in the verified team log and
        every retired key this device has seen: a rotation anywhere changes it."""
        state = self.team_state()
        keys = sorted(f"{uid}:{m.signing_pk}" for uid, m in state.members.items()) if state else []
        keys += self._db.get_meta_json(RETIRED_SEEN_META) or []
        # The list format is part of it: a v1 list (payload hashes) counts for nothing.
        keys.append(key_vouchers.DOMAIN.hex())
        return hashlib.sha256("\n".join([self._keypair.signing_pk.hex(), *keys]).encode()).hexdigest()

    def _post_legacy_vouchers(self) -> None:
        """A list of the versions this device holds that its account's lists do
        not name yet, signed by its current key: posted on the first sync with
        #443 and after it sees an identity rotation in the team, for rotations whose
        accounts never sync again. Neither retired_seq nor commit_seq is read."""
        fingerprint = self._voucher_fingerprint()
        checked = self._db.get_meta(LEGACY_CHECKED_META)
        own_key = bytes(self._keypair.signing_pk)
        pending = self._pending_identity() is not None
        if checked == fingerprint or pending:
            return
        self._get_signing_pks(self._user_id)
        held = self._held()
        server_own = self._voucher_keys.get(self._user_id)
        if not legacy_post_allowed(
            fingerprint=fingerprint, checked=checked, pending_identity=pending,
            own_key=own_key.hex(), server_own_key=server_own.hex() if server_own else None,
            held_count=len(held),
        ):
            return  # a new device: what it would vouch for, it has not seen yet
        try:
            new = legacy_entries(held, self._lists_of(self._user_id, own_key))
            for voucher_list in self._signed_lists(new):
                self._request("POST", "/api/users/me/key-vouchers", voucher_list, auth=True)
        except RuntimeError as exc:
            if not server_error(exc, 404):
                raise
            logger.warning("Key vouchers not posted: a server from before #443")
            return
        self._db.set_meta(LEGACY_CHECKED_META, fingerprint)
        self._lists_cache.pop((self._user_id, own_key), None)
        self._vouched_cache.clear()
