"""Desktop copy of the signed team log (docs/DESIGN_TEAM_LOG.md §6-7, TL4).

The device keeps every record it accepted in ``team_log`` and replays them
with ``sezam.teamlog``. On every pull it fetches what came after its own
head; a server whose log is shorter, has another record at a seq this device
saw, or another genesis is refused (rollback / fork), never followed.

Trust anchor (§7): the genesis is pinned on first sight. It is trusted when
this account founded it or the founder's fingerprint is one this device
confirmed (``confirmed_member_keys``). Until then nothing is sealed to anyone
from the log (callers ask ``team_log_trusted``).
"""

from __future__ import annotations

import logging
from typing import Optional

from .. import teamlog
from . import oplock, outbox
from ..crypto.keys import compute_fingerprint
from ..models import new_ulid
from .sync_common import CONFIRMED_MEMBER_KEYS_META, TEAM_LOG_HEAD_MOVED, TEAM_LOG_REFUSED, server_error

logger = logging.getLogger(__name__)

GENESIS_META = "team_log_genesis_hash"
CONFIRMED_GENESIS_META = "team_log_confirmed_genesis_hash"
# Genesis hashes the user left ('sezam team-log forget-pin', team_log_forget.py).
FORGOTTEN_GENESIS_META = "team_log_forgotten_genesis"
# Outbox rows (vault/outbox.py):
# - team_change, queued: a team change made here that the server does not hold
#   yet, body [type, data], in queue order. Rebuilt onto the current head at
#   every push; one already in the log is dropped.
# - team_change, refused: one the log or the server refused, body {"change":
#   [type, data], "reason": str}. Review 8595ec1 #2: one such queued change
#   failed every push. It waits for 'sezam team-log retry' or 'discard'; a
#   removal set aside still keeps the member from new keys
#   (sync_common.queued_for_removal).
# - team_grant: the changes of a grant, object_id its envelope. Its access.set
#   (and a first folder.key) lands only in one atomic request with the
#   envelope, never on its own (review 1141a20 H4).
# This admin's org recovery blob in the server format (web-openable), with its
# key: what anchor_org_recovery puts in the log as org.recovery.wrap.
SERVER_WRAP_META = "org_recovery_server_wrap"
FETCH_PAGES = 1000  # pages of up to 1000 records per pull
TEAM_LOG_APPEND_MAX = 1000  # records per append the server takes (TeamLogAppend, PushRequest.team_log)


class TeamLogMismatch(RuntimeError):
    """The server's team log is not a continuation of this device's copy."""


# Review c78fd19: the way out once the team's log is lost for good.
LOST_LOG_HINT = (
    " If the team's log is lost for good (another server, a reseed), "
    "'sezam team-log forget-pin' leaves it on this device."
)


def queued_changes(db) -> list[list]:
    return [change for _, change in outbox.items(db, outbox.TEAM_CHANGE)]


def _set_queued_changes(db, changes: list) -> None:
    outbox.replace_items(db, outbox.TEAM_CHANGE, [(None, change) for change in changes])


def _drop_sent_changes(db, sent: list) -> None:
    """Take ``sent`` off the queue; what was queued meanwhile stays."""
    with db.transaction(immediate=True):
        rest = queued_changes(db)
        for change in sent:
            if change in rest:
                rest.remove(change)
        _set_queued_changes(db, rest)


def set_aside_changes(db) -> list[dict]:
    return [item for _, item in outbox.items(db, outbox.TEAM_CHANGE, outbox.REFUSED)]


def _set_aside(db, aside: list[dict]) -> None:
    outbox.replace_items(db, outbox.TEAM_CHANGE, [(None, item) for item in aside], outbox.REFUSED)


def retry_set_aside(db) -> int:
    """Put every set-aside change back at the end of the queue; how many."""
    with db.transaction(immediate=True):
        aside = set_aside_changes(db)
        if aside:
            _set_queued_changes(db, queued_changes(db) + [item["change"] for item in aside])
            _set_aside(db, [])
    return len(aside)


def discard_set_aside(db, numbers: Optional[list[int]] = None) -> list[dict]:
    """Drop set-aside changes (1-based ``numbers``, all if None); the dropped ones."""
    with db.transaction(immediate=True):
        aside = set_aside_changes(db)
        drop = set(range(len(aside))) if numbers is None else {n - 1 for n in numbers}
        if any(index not in range(len(aside)) for index in drop):
            raise ValueError(f"There are {len(aside)} set-aside team change(s)")
        _set_aside(db, [item for i, item in enumerate(aside) if i not in drop])
    return [item for i, item in enumerate(aside) if i in drop]


def _refusal_from_server(exc: BaseException) -> Optional[dict]:
    """The detail of a 400 team_log_refused that names the refused record's seq."""
    if not server_error(exc, 400, TEAM_LOG_REFUSED):
        return None
    while exc is not None and getattr(exc, "detail", None) is None:
        exc = exc.__cause__
    detail = getattr(exc, "detail", None)
    return detail if isinstance(detail, dict) and isinstance(detail.get("seq"), int) else None


def local_team_state(db) -> Optional[teamlog.TeamState]:
    """The replayed local log of ``db``, or None while it holds none."""
    rows = db.fetchall("SELECT seq, body, sig, hash FROM team_log ORDER BY seq")
    if not rows:
        return None
    # A local copy that does not replay was accepted by no version of this
    # code: refuse rather than decide from part of it.
    state = teamlog.replay([{"body": r["body"], "sig": r["sig"]} for r in rows])
    if state.head_hash != rows[-1]["hash"] or rows[-1]["seq"] != state.head_seq:
        raise TeamLogMismatch("the local team log does not match its stored hashes")
    return state


def projected_team_state(db, author: str) -> Optional[teamlog.TeamState]:
    """The local log with this device's queued team changes applied.

    docs/SYNC_SINGLE_SOURCE.md 3.5: who may get a key, and which key is the
    folder's current one, is decided on the state after the outbox lands — a
    member queued for removal is gone, a folder that removal leaves stale
    waits for its re-key, a queued re-key's key is current. Order as sent: the
    re-key batch, the queued changes, the grants; a set-aside removal still
    counts. A change the rules refuse here is left out (the push refuses it
    too). For decisions only, never a head to build on.
    """
    from . import pending_states

    state = local_team_state(db)
    if state is None:
        return None
    batch = pending_states.rekey_batch(db)
    changes = rekey_changes(state, batch) + [list(c) for c in batch.get("team_changes") or []]
    changes += queued_changes(db)
    changes += [item["change"] for item in set_aside_changes(db) if item["change"][0] == "member.remove"]
    changes += [change for _, kept in outbox.items(db, outbox.TEAM_GRANT) for change in kept]
    for kind, data in changes:
        try:
            resolved = resolve_change(state, kind, data)
            if resolved is not None:
                state = teamlog.apply_change(state, kind, author, resolved)
        except teamlog.TeamLogError:
            continue
    return state


def received_envelope_sender(db, env, receipt: dict) -> str:
    """Resolve only the signer of this exact envelope at its locally observed head."""
    import hashlib
    from nacl.exceptions import CryptoError
    from nacl.signing import VerifyKey
    from .sync_push import PushMixin

    try:
        rows = db.fetchall("SELECT body, sig FROM team_log WHERE seq <= ? ORDER BY seq", (receipt["seq"],))
        state = teamlog.replay([{"body": r["body"], "sig": r["sig"]} for r in rows])
        if state.head_seq != receipt["seq"] or state.head_hash != receipt["hash"]:
            raise ValueError("The envelope receipt is not on the verified log")
        target = state.members[env["user_id"]]
        if not teamlog.envelope_valid(state, env["created_by"], env["user_id"], env["dek_id"],
                                      env["access_level"], target.encryption_pk):
            raise ValueError("The envelope was not authorized at receipt")
        sender = state.members[env["created_by"]]
        canonical = PushMixin._build_signature_payload(
            env["id"], "envelope", env["dek_id"], env["user_id"], 0, receipt["version"],
            hashlib.sha256(bytes(env["encrypted_dek"])).hexdigest(),
        )
        VerifyKey(bytes.fromhex(sender.signing_pk)).verify(canonical, bytes.fromhex(receipt["signature"]))
        return sender.encryption_pk
    except (KeyError, TypeError, ValueError, teamlog.TeamLogError) as exc:
        raise CryptoError("Invalid team envelope receipt") from exc


def import_account_anchor(db, keypair) -> None:
    """Install an authenticated bundle anchor without replacing local continuity."""
    genesis = keypair.confirmed_genesis
    if genesis is None:
        return  # Legacy account keys convey no trust, even after a successful login.
    if genesis in (db.get_meta_json(FORGOTTEN_GENESIS_META) or []):
        # The user left this log here; the server's bundle still names it.
        keypair.confirmed_genesis, keypair.pre_anchor = None, b""
        return
    state = local_team_state(db)
    for existing in (db.get_meta(CONFIRMED_GENESIS_META), db.get_meta(GENESIS_META),
                     state.genesis_hash if state is not None else None):
        if existing is not None and existing != genesis:
            raise TeamLogMismatch("The account anchor conflicts with this device's team log.")
    db.set_meta(CONFIRMED_GENESIS_META, genesis)


def log_admins(db, state: teamlog.TeamState) -> set[str]:
    """Accounts the log ever made admin that are still active members: what
    they wrote outside team folders while admin stays valid after a handover
    (review 1141a20); an account the server calls admin is not one."""
    ever: set[str] = set()
    for row in db.fetchall("SELECT body FROM team_log ORDER BY seq"):
        body = teamlog.parse_body(row["body"])
        data = body["data"]
        if body["type"] == "genesis":
            ever.add(data["user_id"])
        elif body["type"] in ("member.add", "member.role") and data.get("role") == "admin":
            ever.add(data["user_id"])
    return {uid for uid in ever if uid in state.members and state.members[uid].active}


def founder_key_lineage(db) -> tuple[str, set[tuple[str, str]]]:
    """Keys linked to the genesis identity in an already replayed local log."""
    first = db.fetchone("SELECT body FROM team_log WHERE seq = 0")
    genesis = teamlog.parse_body(first["body"])["data"]
    founder_id = genesis["user_id"]
    # Only a two-key rotation extends the genesis identity. A member.add
    # naming a public key does not prove that key's owner signed this genesis.
    known = {(genesis["signing_pk"], genesis["encryption_pk"])}
    linked = True
    # A fingerprint confirmed between rotations remains an anchor of this
    # verified chain, even after another double-signed member.keys record.
    for row in db.fetchall("SELECT body FROM team_log ORDER BY seq"):
        body = teamlog.parse_body(row["body"])
        data = body["data"]
        if data.get("user_id") != founder_id:
            continue
        if body["type"] == "member.remove":
            linked = False
        elif body["type"] == "member.add":
            linked = (data["signing_pk"], data["encryption_pk"]) in known
        elif body["type"] == "member.keys" and linked:
            known.add((data["signing_pk"], data["encryption_pk"]))
    return founder_id, known


def log_trusted(db, user_id: str, keypair, state: Optional[teamlog.TeamState]) -> bool:
    """Is the pinned genesis anchored by our identity or a confirmed founder key?"""
    if state is None:
        return False
    confirmed_genesis = db.get_meta(CONFIRMED_GENESIS_META)
    if confirmed_genesis is not None:
        return confirmed_genesis == state.genesis_hash
    founder_id, known = founder_key_lineage(db)
    own = (bytes(keypair.signing_pk).hex(), bytes(keypair.encryption_pk).hex())
    if founder_id == user_id and own in known:
        return True
    confirmed = (db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {}).get(founder_id)
    return any(
        confirmed == compute_fingerprint(bytes.fromhex(spk), bytes.fromhex(epk)) for spk, epk in known
    )


def publishable_anchor(db, user_id: str, keypair) -> Optional[str]:
    """The genesis this device trusts without the server's word, for the account bundle.

    Only an explicit pin (invitation #g=, confirm-genesis, an anchored bundle)
    or a log trusted through our own founder lineage or a confirmed founder
    fingerprint qualifies; a merely observed genesis is never published.
    """
    if keypair.confirmed_genesis is not None:
        return keypair.confirmed_genesis
    confirmed = db.get_meta(CONFIRMED_GENESIS_META)
    if confirmed is not None:
        return confirmed
    state = local_team_state(db)
    if state is not None and log_trusted(db, user_id, keypair, state):
        return state.genesis_hash
    return None


def resolve_change(state: teamlog.TeamState, kind: str, data: dict) -> Optional[dict]:
    """The record data for a queued change on ``state``, or None if the log has it.

    A queued ``folder.key`` names the key and its predecessor; its generation
    is counted here. When the folder moved on to another key meanwhile, the
    change cannot land (two re-keys of one folder): TeamLogError.
    """
    member = state.members.get(data.get("user_id", ""))
    seen = data.get("_seen")  # the member as the log had it when the change was queued
    data = {k: v for k, v in data.items() if not k.startswith("_")}
    if kind == "genesis":
        if state.head_seq < 0:
            return data
        if state.org == data["org"]:
            return None  # sent before, its reply lost
        # Review 8595ec1: another device founded the log first; built onto it,
        # this founding's access.set lowered members it gave write to read.
        raise teamlog.TeamLogError(
            "founded_elsewhere", state.head_seq + 1, "another device founded the team log first",
        )
    if kind == "member.add":
        done = member is not None and member.active and (member.signing_pk, member.encryption_pk) == (
            data["signing_pk"], data["encryption_pk"])
        if not done and member is not None and not member.active and seen not in (None, "removed"):
            # Review 8595ec1: queued before another device removed the member;
            # sent now it would bring the member back.
            raise teamlog.TeamLogError(
                "removed_meanwhile", state.head_seq + 1, f"member {data['user_id']} was removed meanwhile",
            )
        return None if done else data
    if kind == "member.role":
        return None if member is not None and member.role == data["role"] else data
    if kind == "member.remove":
        return None if member is None or not member.active else data
    if kind == "member.keys":
        done = member is not None and (member.signing_pk, member.encryption_pk) == (
            data["signing_pk"], data["encryption_pk"])
        return None if done else data
    if kind == "access.set":
        current = state.access.get(data["folder"], {}).get(data["user_id"])
        return None if current == data["level"] else data
    if kind == "folder.key":
        if data["dek_id"] in state.dek_index:
            return None
        current = teamlog.current_key(state, data["folder"])
        if current != data["prev_dek_id"]:
            raise teamlog.TeamLogError(
                "folder_key_moved", state.head_seq + 1,
                f"folder {data['folder']} is at key {current}, not {data['prev_dek_id']}",
            )
        gens = state.folders.get(data["folder"])
        return {**data, "gen": len(gens) if gens else 0}
    if kind == "org.recovery":  # only queued by this device's admin, for a new key
        return None if data["recovery_pk"] in state.org_recovery.values() else data
    return data


def rekey_changes(state: Optional[teamlog.TeamState], batch: dict) -> list[list]:
    """folder.key changes of a pending re-key batch for folders in the log."""
    if state is None:
        return []
    changes = []
    for old, new in sorted((batch.get("dek_map") or {}).items()):
        found = state.dek_index.get(old)
        if found is not None:
            changes.append(["folder.key", {"folder": found[0], "dek_id": new, "prev_dek_id": old}])
    return changes


class TeamLogMixin:
    """Mixed into SyncClient (``_db``, ``_request``, ``_user_id``, ``_keypair``)."""

    _team_state_cache: Optional[teamlog.TeamState] = None

    # ── Local copy ──────────────────────────────────────────────────

    def team_state(self) -> Optional[teamlog.TeamState]:
        """The replayed local log, or None while this device holds none."""
        head = self._db.fetchone("SELECT seq, hash FROM team_log ORDER BY seq DESC LIMIT 1")
        if head is None:
            return None
        cached = self._team_state_cache
        if cached is not None and cached.head_seq == head["seq"] and cached.head_hash == head["hash"]:
            return cached
        state = local_team_state(self._db)
        self._team_state_cache = state
        return state

    def _named_by_team_log(self, keypair) -> bool:
        """The local team log names this account as a current member with ``keypair``."""
        state = self.team_state()
        member = state.members.get(self._user_id) if state is not None else None
        return bool(member and member.active and member.signing_pk == bytes(keypair.signing_pk).hex())

    def _log_retired_key(self, user_id: str, signing_pk: bytes) -> bool:
        """The local log retired ``signing_pk`` although the server calls it current.

        A server restored from before the rotation (or lying) still serves the
        retired key; it vouches for nothing (capability run 294). The one
        exception: this account's own old key while this device re-sends its
        rotation the restore lost - this device signed that rotation with it and
        verifies its own history under it until the rotation lands. Every other
        device keeps refusing the key.
        """
        if not teamlog.signing_key_retired(self.team_state(), user_id, bytes(signing_pk).hex()):
            return False
        if user_id == self._user_id and bytes(signing_pk) == bytes(self._keypair.signing_pk):
            # Review 8595ec1 (R10-F): the account's own keypair here, the device
            # with the log's key lost. It reads its history (pushed before the
            # rotation: the server takes nothing else from a retired key) to
            # rotate to fresh keys on an admin's grant; others still refuse it.
            return False
        return not (
            user_id == self._user_id
            and self._rotation_authorizer == bytes(signing_pk)
            and self._pending_identity() is not None
        )

    def _server_lost_own_rotation(self, server_keypair, local) -> bool:
        """The local team log retired the server's keypair for the one held here."""
        state = self.team_state()
        member = state.members.get(self._user_id) if state is not None else None
        server_pks = (server_keypair.signing_pk.hex(), server_keypair.encryption_pk.hex())
        local_pks = (local.signing_pk.hex(), local.encryption_pk.hex())
        return (
            member is not None and member.active and server_pks != local_pks
            and (member.signing_pk, member.encryption_pk) == local_pks
            and all(state.seen_keys.get(pk) == self._user_id for pk in server_pks)
        )

    def team_log_trusted(self, state: Optional[teamlog.TeamState] = None) -> bool:
        """Is the pinned genesis anchored (own, or the founder's key confirmed)?"""
        state = state or self.team_state()
        if log_trusted(self._db, self._user_id, self._keypair, state):
            return True
        # A pending identity rotation still anchors the log with its old key.
        old = self._pending_old_keypair()
        if old is None:
            return False
        try:
            return log_trusted(self._db, self._user_id, old, state)
        finally:
            old.zeroize()

    def require_trusted_team_log(self) -> None:
        if self.team_state() is None and self._db.get_meta(CONFIRMED_GENESIS_META) is not None:
            raise RuntimeError("The independently confirmed team log is not downloaded yet; pull it first.")
        if self.team_state() is not None and not self.team_log_trusted():
            raise RuntimeError(
                "The team log's founder is not confirmed on this device; "
                "compare their fingerprint out of band and use 'sezam team-log confirm-founder'."
            )

    def _store_team_log(self, records: list[dict], state: teamlog.TeamState) -> None:
        start = state.head_seq - len(records) + 1
        current = None
        for offset, record in enumerate(records):
            current = teamlog.record_hash(record)
            self._db.execute(
                "INSERT INTO team_log (seq, body, sig, hash) VALUES (?, ?, ?, ?)",
                (start + offset, record["body"], record["sig"], current),
            )
        if self._db.get_meta(GENESIS_META) is None:
            self._db.set_meta(GENESIS_META, state.genesis_hash)
        self._team_state_cache = state

    # ── Following the server ────────────────────────────────────────

    def _sync_team_log(self, server_head: Optional[dict]) -> Optional[teamlog.TeamState]:
        """Bring the local copy up to ``server_head`` (from the pull answer).

        Raises TeamLogMismatch when the server's log is not a continuation of
        what this device accepted.
        """
        local = self.team_state()
        pinned = self._db.get_meta(GENESIS_META)
        confirmed = self._db.get_meta(CONFIRMED_GENESIS_META)
        if local is not None and (server_head is None or server_head.get("seq", -1) < local.head_seq):
            # Restored from a backup (or moved): records this device accepted
            # are missing at the end. It puts them back; any other server log
            # (fork, another genesis, a refused upload) stays a mismatch below.
            restored = self._restore_server_team_log(local, server_head)
            if restored is not False:
                server_head = restored
        if confirmed is not None and (server_head is None or server_head.get("genesis_hash") != confirmed):
            raise TeamLogMismatch(
                "The server's team log differs from the independently confirmed genesis." + LOST_LOG_HINT
            )
        if server_head is None:
            if local is not None or pinned:
                raise TeamLogMismatch(
                    "The server no longer has the team log this device holds "
                    "(restored from a backup, or another server)." + LOST_LOG_HINT
                )
            return None
        if pinned and server_head.get("genesis_hash") != pinned:
            raise TeamLogMismatch(
                "The server's team log starts with another genesis than this device pinned." + LOST_LOG_HINT
            )
        local_seq = local.head_seq if local is not None else -1
        if server_head.get("seq", -1) < local_seq:
            raise TeamLogMismatch(
                f"The server's team log went back (head {server_head.get('seq')} < {local_seq} seen here)."
            )
        if server_head.get("seq") == local_seq:
            if server_head.get("hash") != local.head_hash:
                raise TeamLogMismatch(f"The server's team log differs at record {local_seq}.")
            return local
        state = local
        fetched: list[dict] = []
        for _ in range(FETCH_PAGES):
            since = state.head_seq if state is not None else -1
            resp = self._request("GET", f"/api/team-log?since={since}", auth=True)
            records = resp.get("records") or []
            if not records:
                break
            try:
                # prev of the first record must be this device's head: a fork
                # at an earlier seq is refused here.
                state = teamlog.replay(records, state)
            except teamlog.TeamLogError as exc:
                raise TeamLogMismatch(f"The server's team log does not replay: {exc}") from exc
            fetched.extend(records)
            if state.head_seq >= server_head["seq"]:
                break
        if state is None or state.head_seq != server_head["seq"] or state.head_hash != server_head.get("hash"):
            raise TeamLogMismatch("The server's team log does not reach the head it announced.")
        if pinned is None and state.genesis_hash != server_head.get("genesis_hash"):
            raise TeamLogMismatch("The server's team log genesis differs from the head it announced.")
        refusal = teamlog.admin_policy_refusal(state)
        if refusal:
            # TL7: the server refuses such an append; a head with it is not followed.
            raise TeamLogMismatch(f"The server's team log is refused at its head: {refusal}.")
        with self._db.transaction(immediate=True):
            # Another process of this vault may have stored part of it meanwhile.
            raced = self._local_head_seq() != local_seq
            if not raced:
                self._store_team_log(fetched, state)
        if raced:
            self._team_state_cache = None
            return self._sync_team_log(server_head)
        return state

    def _put_back_lost_team_log(self, server_head: Optional[dict]) -> None:
        """A server restored from a backup gets the log records it lost now.

        Review 8595ec1 #4: the pull stops at the rollback (full resync), and a
        password change waiting to go out first is authorized by the recovery
        key the lost records name; without them it was refused for good.
        """
        local = self.team_state()
        if local is not None and (server_head is None or server_head.get("seq", -1) < local.head_seq):
            self._restore_server_team_log(local, server_head)

    def _restore_server_team_log(self, local: teamlog.TeamState, server_head: Optional[dict]):
        """Upload the records the server lost; its new head, or False.

        Only onto a server log that is a prefix of this device's: no log at
        all, or the same genesis and the same hash at the server's head.
        """
        server_seq = -1 if server_head is None else server_head.get("seq", -1)
        if server_head is not None:
            row = self._db.fetchone("SELECT hash FROM team_log WHERE seq = ?", (server_seq,))
            if (
                row is None or row["hash"] != server_head.get("hash")
                or server_head.get("genesis_hash") != local.genesis_hash
            ):
                return False
        rows = self._db.fetchall(
            "SELECT body, sig FROM team_log WHERE seq > ? AND seq <= ? ORDER BY seq",
            (server_seq, local.head_seq),
        )
        head = server_head
        for start in range(0, len(rows), TEAM_LOG_APPEND_MAX):
            part = [{"body": r["body"], "sig": r["sig"]} for r in rows[start:start + TEAM_LOG_APPEND_MAX]]
            try:
                head = self._request("POST", "/api/team-log/restore", {"records": part}, auth=True).get("head")
            except RuntimeError as exc:
                # 409: its head is not the one it announced (another device
                # put them back meanwhile, or a lie): the next pull compares again.
                level = logging.WARNING if server_error(exc, 409, TEAM_LOG_HEAD_MOVED) else logging.ERROR
                logger.log(level, "The server did not take back the team log records it lost: %s", exc)
                return False
            logger.warning("Put back team log records the server had lost (now at %s)", (head or {}).get("seq"))
        if rows:
            # Review c78fd19 #2: the admin's own device puts back its lost
            # rotation; its session proved the key the log named before, which
            # is retired now. The next request signs in proving the log's key.
            self._token = None
        return head

    def _local_head_seq(self) -> int:
        row = self._db.fetchone("SELECT MAX(seq) AS seq FROM team_log")
        return row["seq"] if row is not None and row["seq"] is not None else -1

    # ── Changing the team ───────────────────────────────────────────

    def team_log_records(self, changes) -> list[dict]:
        """Sign ``changes`` ((type, data) pairs) onto the local head.

        A change the log already holds is left out (a resend after a lost
        reply). Raises TeamLogError when the rules refuse one: nothing is
        built that this device's own replay would not accept.
        """
        return [record for _, record in self._indexed_team_log_records(changes)]

    def _indexed_team_log_records(self, changes) -> list[tuple[int, dict]]:
        """``team_log_records`` with the index of the change each record is for."""
        self.require_trusted_team_log()
        state = self.team_state() or teamlog.TeamState()
        signing_key = self._keypair.to_nacl_signing_key()
        records = []
        for index, (kind, data) in enumerate(changes):
            resolved = resolve_change(state, kind, data)
            if resolved is None:
                continue
            record = teamlog.sign_record(teamlog.next_body(state, kind, self._user_id, resolved), signing_key)
            state = teamlog.apply_record(state, record)
            records.append((index, record))
        return records

    def add_identity_team_record(self, records: list[dict]) -> list[dict]:
        """Rebuild the two-key proof on each CAS attempt, inside the epoch push."""
        from . import pending_states

        journal = pending_states.key_change_journal(self._db)
        if not journal.get("identity"):
            return records
        state = self.team_state()
        if state is None:
            return records
        if records:
            state = teamlog.replay(records, state)
        member = state.members.get(self._user_id)
        if member is None:
            return records
        spk = self._keypair.signing_pk.hex()
        epk = self._keypair.encryption_pk.hex()
        if (member.signing_pk, member.encryption_pk) == (spk, epk):
            return records  # The response was lost and the accepted record was pulled.
        old = self._pending_old_keypair()
        if old is None:
            raise RuntimeError("The team identity rotation has no old signing key")
        if teamlog.signing_key_retired(state, self._user_id, bytes(old.signing_pk).hex()):
            # Review 8595ec1 (R10-F): rotating away from a key the log already
            # retired (a restore, the device with the log's key lost) on an
            # admin's key-reset grant. Nobody holds the key that could sign
            # member.keys; the admin readmits the new keys instead.
            old.zeroize()
            return records
        try:
            data = {
                "user_id": self._user_id, "signing_pk": spk, "encryption_pk": epk,
                "new_key_sig": self._keypair.to_nacl_signing_key().sign(
                    teamlog.new_key_message(state.head_hash, self._user_id, spk, epk)
                ).signature.hex(),
            }
            record = teamlog.sign_record(
                teamlog.next_body(state, "member.keys", self._user_id, data),
                old.to_nacl_signing_key(),
            )
            teamlog.apply_record(state, record)
            records.append(record)
            return records
        finally:
            old.zeroize()

    def pending_team_changes(self) -> list[list]:
        return queued_changes(self._db)

    def set_aside_team_changes(self) -> list[dict]:
        return set_aside_changes(self._db)

    def retry_set_aside_team_changes(self) -> int:
        return retry_set_aside(self._db)

    def discard_set_aside_team_changes(self, numbers: Optional[list[int]] = None) -> list[dict]:
        return discard_set_aside(self._db, numbers)

    def _refused_team_changes(self, changes) -> dict[int, str]:
        """Index -> reason of each change the rules refuse on the local head."""
        state = self.team_state() or teamlog.TeamState()
        signing_key = self._keypair.to_nacl_signing_key()
        refused = {}
        lost_founding = None
        for index, (kind, data) in enumerate(changes):
            if lost_founding is not None:
                # Queued on that founding (there was no log): not onto another one.
                refused[index] = f"part of a founding that did not land: {lost_founding}"
                continue
            try:
                resolved = resolve_change(state, kind, data)
                if resolved is not None:
                    body = teamlog.next_body(state, kind, self._user_id, resolved)
                    state = teamlog.apply_record(state, teamlog.sign_record(body, signing_key))
            except teamlog.TeamLogError as exc:
                refused[index] = str(exc)
                if kind == "genesis":
                    lost_founding = str(exc)
        return refused

    @staticmethod
    def _with_batch_partners(pending: list, refused: dict[int, str]) -> dict[int, str]:
        """``refused`` plus every change queued in one append with one of them.

        Review 4acfdde R11 #4: a readmit is member.remove + member.add of one
        member. With only the refused member.add set aside, the removal went
        out on its own: the member was removed, lost write_acl and share
        links, and a second readmit no longer found them. A hand-over
        (member.role twice) must not split either.
        """
        refused = dict(refused)
        for index in list(refused):
            batch = pending[index][1].get("_batch")
            if batch is None:
                continue
            for partner, (_kind, data) in enumerate(pending):
                if partner not in refused and data.get("_batch") == batch:
                    refused[partner] = f"goes with a refused change made with it: {refused[index]}"
        return refused

    def _set_aside(self, pending: list, refused: dict[int, str]) -> bool:
        """Move the ``refused`` changes of ``pending`` out of the queue."""
        if not refused:
            return False
        refused = self._with_batch_partners(pending, refused)
        with self._db.transaction(immediate=True):
            now = self.pending_team_changes()
            if now[:len(pending)] != pending:
                return False  # the queue changed meanwhile: the next flush looks again
            aside = set_aside_changes(self._db)
            for index in sorted(refused):
                logger.error("Team change %s set aside: %s", pending[index], refused[index])
                aside.append({"change": pending[index], "reason": refused[index]})
            _set_aside(self._db, aside)
            _set_queued_changes(self._db, [c for i, c in enumerate(now) if i not in refused])
        return True

    def set_aside_refused_team_changes(self) -> None:
        """A queued change the log no longer takes stops holding up the rest."""
        pending = self.pending_team_changes()
        if pending:
            self._set_aside(pending, self._refused_team_changes(pending))

    def _server_refused_team_changes(self, pending: list, exc: BaseException) -> dict[int, str]:
        """The queued change whose record the server refused (by seq), if it is one."""
        detail = _refusal_from_server(exc)
        if detail is None:
            return {}
        for index, record in self._indexed_team_log_records(pending):
            if teamlog.parse_body(record["body"])["seq"] == detail["seq"]:
                return {index: f"the server refused it: {detail.get('message') or detail}"}
        return {}

    @oplock.held
    def queue_team_changes(self, changes) -> None:
        """Keep ``changes`` for the next push; refused now if the rules would.

        Review c78fd19 #3: 'sezam revoke' queued while the GUI pushed; the
        push then emptied the whole queue and the member.remove was gone (CLI
        said removed). The queue is read and written in one BEGIN IMMEDIATE
        under the sync lock, so it waits for a push; a push removes only what
        it sent.
        """
        with self._db.transaction(immediate=True):
            self._queue_team_changes(changes)

    def _queue_team_changes(self, changes) -> None:
        self.set_aside_refused_team_changes()
        state = self.team_state()

        def seen(user_id: str) -> str:
            member = state.members.get(user_id) if state is not None else None
            return "absent" if member is None else ("active" if member.active else "removed")

        removed_here: set[str] = set()  # a re-add after its removal in one batch (readmit)
        pending = self.pending_team_changes()
        for kind, data in changes:
            if kind == "member.add":
                user_id = data["user_id"]
                data = {**data, "_seen": "removed" if user_id in removed_here else seen(user_id)}
            elif kind == "member.remove":
                removed_here.add(data["user_id"])
            pending.append([kind, data])
        self.team_log_records(pending)  # TeamLogError: nothing is queued
        _set_queued_changes(self._db, pending)

    def adopt_logged_org_recovery(self) -> None:
        """Admin: keep a local KEK wrap of a recovery set up on another client.

        Review 8595ec1 #4 (capability run 314): a recovery set up on the web
        lived only in the server's blob, so a server restored from before it
        lost the KEK wrap and the shares opened nothing. When the log names a
        recovery key of this admin that this vault does not hold and the
        server's blob is of that key, the KEK is wrapped here too (to the
        X25519 form of the Ed25519 recovery key): 'sezam org-recovery' then
        works with those shares and puts the blob back. Only a key the log
        names (signed by this admin) is taken, never one the server reports.
        """
        from nacl.public import SealedBox
        from nacl.signing import VerifyKey

        state = self.team_state()
        if state is None or self._dek_mgr is None or not teamlog.is_admin(state, self._user_id):
            return
        logged = teamlog.recovery_key(state, self._user_id)
        if logged is None or logged == self._db.get_meta("org_recovery_signing_pk"):
            return
        if any(kind == "org.recovery" for kind, _ in self.pending_team_changes()):
            return  # a setup here waits to replace it
        try:
            status = self._request("GET", "/api/org-recovery/status") or {}
        except RuntimeError as exc:
            logger.warning("Org recovery status not known: %s", exc)
            return
        if (
            not status.get("configured") or status.get("stale")
            or status.get("created_by") != self._user_id
            or status.get("recovery_signing_pk") != logged
        ):
            return
        recovery_pk = VerifyKey(bytes.fromhex(logged)).to_curve25519_public_key()
        wrapped = SealedBox(recovery_pk).encrypt(bytes(self._dek_mgr._kek))
        with self._db.transaction(immediate=True):
            self._db.set_meta("org_recovery_pk", bytes(recovery_pk).hex())
            self._db.set_meta("org_recovery_signing_pk", logged)
            self._db.set_meta("org_recovery_wrapped_kek", wrapped.hex())
            self._db.set_meta("org_recovery_stale", "0")
            self._db.set_meta("org_recovery_threshold", str(int(status.get("threshold") or 0)))
            self._db.set_meta("org_recovery_shares", str(int(status.get("total_shares") or 0)))
            logged_wrap = teamlog.recovery_wrap(state, self._user_id)
            if logged_wrap is not None:
                self._db.set_meta_json(SERVER_WRAP_META, {**logged_wrap, "recovery_signing_pk": logged})
            # A setup of this vault the server never took is replaced too.
            from . import pending_states

            pending_states.clear_org_recovery_registration(self._db)
            pending_states.clear_org_recovery_rewrap(self._db)

    def anchor_org_recovery(self, *, replace: bool = False) -> None:
        """Admin: queue an org.recovery record naming this vault's recovery key.

        Review 8595ec1 #4: a server restored from before the registration no
        longer knew the key, and a lone admin's reset after a forgotten
        password was refused for good. The log the devices put back names it.
        Only a key set up here is named, never one a server reports. A push
        names it only while the log names none for this admin: a newer key
        set up on another client (web) stays; ``replace`` is for a setup here.

        Capability run 316: the server-format KEK wrap of that key goes with
        it (org.recovery.wrap), so a restored server serves the shares' blob
        to any client; a newer wrap in the log (a later recovery) stays.
        """
        pk = self._db.get_meta("org_recovery_signing_pk")
        state = self.team_state()
        if not pk or state is None or not teamlog.is_admin(state, self._user_id):
            return
        logged = teamlog.recovery_key(state, self._user_id)
        if logged is not None and logged != pk and not replace:
            return
        changes = [] if logged == pk else [["org.recovery", {"recovery_pk": pk}]]
        wrap = dict(self._db.get_meta_json(SERVER_WRAP_META) or {})
        if wrap.pop("recovery_signing_pk", None) == pk:
            current = None if changes else teamlog.recovery_wrap(state, self._user_id)
            if current is None or (current != wrap and wrap["key_epoch"] > current["key_epoch"]):
                changes.append(["org.recovery.wrap", wrap])
        waiting = self.pending_team_changes() + [item.get("change") for item in self.set_aside_team_changes()]
        changes = [change for change in changes if change not in waiting]
        if not changes:
            return
        try:
            self.queue_team_changes(changes)
        except teamlog.TeamLogError as exc:
            logger.warning("The team log does not take this vault's org recovery key: %s", exc)

    def pending_team_grants(self) -> dict[str, list]:
        return dict(outbox.items(self._db, outbox.TEAM_GRANT))

    def queue_team_grant(self, envelope_id: str, changes) -> None:
        """Keep a grant's ``changes`` to go with its envelope; refused now if the rules would."""
        self.set_aside_refused_team_changes()
        grants = self.pending_team_grants()
        grants.pop(envelope_id, None)
        queued = [change for kept in grants.values() for change in kept]
        added = [[kind, data] for kind, data in changes]
        self.team_log_records(self.pending_team_changes() + queued + added)
        with self._db.transaction():
            outbox.sent(self._db, outbox.TEAM_GRANT, envelope_id)
            outbox.put(self._db, outbox.TEAM_GRANT, added, envelope_id)

    def drop_team_grant(self, envelope_id: str) -> None:
        outbox.sent(self._db, outbox.TEAM_GRANT, envelope_id)

    def _refresh_team_log(self) -> None:
        if not self._token:
            self.authenticate()
        local = self.team_state()
        since = local.head_seq if local is not None else -1
        resp = self._request("GET", f"/api/team-log?since={since}", auth=True)
        self._sync_team_log(resp.get("head"))

    def _send_team_records(self, send, extra=()) -> None:
        """Build the pending changes (+ ``extra``) and ``send(records)``.

        The server appends only onto its head; when it moved, the log is
        pulled and the records built once more. On success they are stored
        here and the queue is emptied.
        """
        from .sync_common import TEAM_LOG_HEAD_MOVED, TEAM_LOG_REFUSED, server_error

        self._send_queue_overflow(len(extra))
        for attempt in range(2):
            pending = self.pending_team_changes()
            records = self.team_log_records(pending + [list(c) for c in extra])
            try:
                result = send(records)
            except RuntimeError as exc:
                if attempt == 0 and server_error(exc, 409, TEAM_LOG_HEAD_MOVED):
                    self._refresh_team_log()
                    continue
                if server_error(exc, 400, TEAM_LOG_REFUSED) and pending:
                    # A refusal is not an acknowledgement: dropping a removal
                    # would give this member the next generation's key again.
                    logger.error("The server refused queued team changes %s: %s", pending, exc)
                    # Keep the queue until the change is accepted or explicitly resolved.
                raise
            if records:
                self.accept_own_team_log(records)
            if pending:
                _drop_sent_changes(self._db, pending)
            return result
        raise AssertionError("unreachable")

    def _send_queue_overflow(self, extra: int) -> None:
        """Append the queue's head on its own while it exceeds one append.

        The server takes at most TEAM_LOG_APPEND_MAX records per request; a
        longer queue (founding a large organisation) was refused whole on
        every push. Each accepted part is stored and leaves the queue, so a
        failure keeps only what has not landed. The last part (with
        ``extra`` and an identity record) goes with the caller's request.
        """
        from .sync_common import TEAM_LOG_HEAD_MOVED, server_error

        moved = 0
        while True:
            pending = self.pending_team_changes()
            built = self._indexed_team_log_records(pending)
            if len(built) + extra + 1 <= TEAM_LOG_APPEND_MAX:
                return
            part = built[:TEAM_LOG_APPEND_MAX]
            records = [record for _, record in part]
            try:
                self._request("POST", "/api/team-log", {"records": records}, auth=True)
            except RuntimeError as exc:
                if moved < 2 and server_error(exc, 409, TEAM_LOG_HEAD_MOVED):
                    moved += 1
                    self._refresh_team_log()
                    continue
                raise
            self.accept_own_team_log(records)
            with self._db.transaction(immediate=True):
                now = self.pending_team_changes()
                if now[:len(pending)] == pending:  # what another process queued meanwhile stays
                    _set_queued_changes(self._db, now[part[-1][0] + 1:])

    def flush_team_log(self) -> None:
        """Send queued team changes on their own (before a push)."""
        if not self.pending_team_changes():
            return
        if not self._token:
            self.authenticate()

        def post(records):
            if records:
                self._request("POST", "/api/team-log", {"records": records}, auth=True)

        # Review 8595ec1 #2: a change the log or the server refuses is set
        # aside (status shows it), the rest goes out and the push goes on.
        for _ in range(len(self.pending_team_changes()) + 2):
            self.set_aside_refused_team_changes()
            if not self.pending_team_changes():
                return
            try:
                self._send_team_records(post)
                return
            except teamlog.TeamLogError:
                continue  # the log moved on (pulled on 409): what it no longer takes goes aside
            except RuntimeError as exc:
                pending = self.pending_team_changes()
                if not self._set_aside(pending, self._server_refused_team_changes(pending, exc)):
                    raise
        raise RuntimeError("The queued team changes were refused again and again; see 'sezam team-log queue'.")

    def accept_own_team_log(self, records: list[dict]) -> teamlog.TeamState:
        """Store records the server accepted (it answered 200 on them)."""
        local = self.team_state()
        state = teamlog.replay(records, local)
        with self._db.transaction(immediate=True):
            if self._local_head_seq() != (local.head_seq if local is not None else -1):
                # Another process pulled them (or more) meanwhile; the next
                # pull replays them from the server.
                return self.team_state()
            self._store_team_log(records, state)
        return state

    def append_team_log(self, changes) -> teamlog.TeamState:
        """Queue ``changes`` and send them now; kept for the next push if that fails.

        Raises RuntimeError when the log or the server refused one of them
        (it is set aside, not lost: 'sezam team-log queue').
        """
        before = len(self.set_aside_team_changes())
        if len(changes) > 1:
            batch = new_ulid()  # set aside together or not at all (review 4acfdde R11 #4)
            changes = [(kind, {**data, "_batch": batch}) for kind, data in changes]
        self.queue_team_changes(changes)
        self.flush_team_log()
        def plain(change) -> list:
            return [change[0], {k: v for k, v in change[1].items() if not k.startswith("_")}]

        made = [plain(change) for change in changes]
        refused = [item for item in self.set_aside_team_changes()[before:] if plain(item["change"]) in made]
        if refused:
            raise RuntimeError(
                "The team log did not take the change: " + "; ".join(item["reason"] for item in refused)
                + ". It is set aside ('sezam team-log queue')."
            )
        return self.team_state()

    def found_team_log(self, org_id: str) -> teamlog.TeamState:
        """Admin: start this organisation's log with a genesis of this account."""
        if self.team_state() is not None or self._db.get_meta(GENESIS_META):
            raise RuntimeError("This device already holds a team log.")
        return self.append_team_log([("genesis", {
            "org": org_id,
            "user_id": self._user_id,
            "signing_pk": bytes(self._keypair.signing_pk).hex(),
            "encryption_pk": bytes(self._keypair.encryption_pk).hex(),
        })])
