"""Server side of the signed team log (docs/DESIGN_TEAM_LOG.md §5, TL3).

The server stores the log and replays it with the very same rules as every
client (``sezam.teamlog``; the Docker image ships that file as
``teamlog_core.py``). It appends only onto the current head (compare-and-swap
on ``prev`` under the commit_counter lock), so two concurrent changes of the
same thing cannot both land, and it keeps the users table in step with what
the log says (role, removal). The replayed state is cached per process and
checked against the stored head before every use.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import weakref
from dataclasses import dataclass
from typing import Optional

from .errors import TEAM_LOG_HEAD_MOVED, TEAM_LOG_REFUSED, TEAM_LOG_UNREADABLE, ApiError

try:
    from sezam import teamlog as core
except ImportError:  # the Docker image ships only server/ and web/
    from . import teamlog_core as core  # type: ignore[no-redef]

TeamState = core.TeamState
TeamLogError = core.TeamLogError

logger = logging.getLogger(__name__)

MAX_RECORDS_PER_APPEND = 1000
MAX_BODY_CHARS = 4096
# TL7 (docs/DESIGN_TEAM_LOG.md §10): one admin per organisation
# (sezam.teamlog.admin_policy_refusal, the same rule every client applies).

@dataclass(frozen=True)
class _Replayed:
    state: TeamState
    # The seq of each author's last org.recovery record, gathered by the
    # same replay: /api/org-recovery/status and /blob (anyone may ask) read
    # the whole log for it on every call before (review c78fd19).
    recovery_seq: dict


_cache_lock = threading.Lock()
_cache: Optional[_Replayed] = None
# Review c78fd19 (medium): every request that found the cache cold replayed
# the whole log at the same time (a cold start took 19-37 s); one replays,
# the others wait for it and take its result. One lock per event loop.
_replay_locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = (
    weakref.WeakKeyDictionary()
)


def _cached() -> Optional[_Replayed]:
    with _cache_lock:
        return _cache


def _remember(entry: _Replayed) -> None:
    global _cache
    with _cache_lock:
        if _cache is None or entry.state.head_seq >= _cache.state.head_seq:
            _cache = entry


def forget_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = None


def _replay_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    with _cache_lock:
        lock = _replay_locks.get(loop)
        if lock is None:
            lock = _replay_locks[loop] = asyncio.Lock()
        return lock


async def _rows_after(cur, seq: int) -> list[dict]:
    await cur.execute(
        "SELECT seq, body, sig, hash FROM team_log WHERE seq > %s ORDER BY seq", (seq,)
    )
    rows = sorted(await cur.fetchall(), key=lambda row: row[0])
    return [{"seq": int(r[0]), "body": r[1], "sig": r[2], "hash": r[3]} for r in rows]


async def _still_current(cur, entry: Optional[_Replayed]) -> Optional[_Replayed]:
    """``entry`` when this transaction sees the log it replayed, else None.

    The hash chain covers every earlier record: the same hash at the cached
    head means the same log up to there (also across databases).
    """
    if entry is None:
        return None
    await cur.execute("SELECT hash FROM team_log WHERE seq = %s", (entry.state.head_seq,))
    row = await cur.fetchone()
    return entry if row is not None and row[0] == entry.state.head_hash else None


async def _has_rows_after(cur, seq: int) -> bool:
    await cur.execute("SELECT seq FROM team_log WHERE seq > %s ORDER BY seq LIMIT 1", (seq,))
    return await cur.fetchone() is not None


async def _load(cur) -> Optional[_Replayed]:
    entry = await _still_current(cur, _cached())
    if entry is not None and not await _has_rows_after(cur, entry.state.head_seq):
        return entry
    async with _replay_lock():
        # Another request may have replayed while this one waited.
        entry = await _still_current(cur, _cached())
        rows = await _rows_after(cur, entry.state.head_seq if entry is not None else -1)
        if not rows:
            return entry
        # Review 1141a20 (R9-F): a cold cache replays the whole log, a
        # signature check per record; never on the event loop.
        try:
            entry = await asyncio.to_thread(_replay_stored, entry, rows)
        except _Unreadable as exc:
            logger.error("%s", exc)
            raise ApiError(503, TEAM_LOG_UNREADABLE, {
                "message": "the team log stored on this server does not replay; restore the server",
                "seq": exc.seq,
            }) from exc
        _remember(entry)
        return entry


async def load_state(cur) -> Optional[TeamState]:
    """The replayed log, or None when this organisation has none yet.

    A stored log that does not replay is a broken server: refuse (503,
    team_log_unreadable) rather than decide anything from part of it. A log
    stored under older rules replays by them (the "v" of its records).
    """
    entry = await _load(cur)
    return entry.state if entry is not None else None


async def load_recovery_seqs(cur) -> tuple[Optional[TeamState], dict]:
    """The replayed log and the seq of each author's last org.recovery record."""
    entry = await _load(cur)
    return (entry.state, entry.recovery_seq) if entry is not None else (None, {})


def _replay_stored(entry: Optional[_Replayed], rows: list[dict]) -> _Replayed:
    records = [{"body": r["body"], "sig": r["sig"]} for r in rows]
    try:
        state = core.replay(records, entry.state if entry is not None else None)
    except TeamLogError as exc:
        raise _Unreadable(f"stored team log does not replay: {exc}", exc.seq) from exc
    recovery_seq = dict(entry.recovery_seq) if entry is not None else {}
    for row, record in zip(rows, records):
        if core.record_hash(record) != row["hash"]:
            raise _Unreadable(f"stored team log hash mismatch at {row['seq']}", row["seq"])
        body = json.loads(row["body"])
        if body["type"] == "org.recovery":
            recovery_seq[body["author"]] = row["seq"]
    return _Replayed(state, recovery_seq)


class _Unreadable(RuntimeError):
    def __init__(self, message: str, seq: Optional[int]):
        super().__init__(message)
        self.seq = seq


def _replay_batch(state: TeamState, records: list, bodies: list[dict]) -> tuple[TeamState, list[dict]]:
    """Replay an uploaded batch with one copy of ``state`` (review 1141a20, R9-F:
    a copy per record before), noting per record what the users table needs."""
    clean = [{"body": r.get("body"), "sig": r.get("sig")} for r in records]
    steps: list[dict] = []
    current = state
    for index, (body, current) in enumerate(zip(bodies, core.replay_steps(clean, state))):
        data = body["data"]
        user = data.get("user_id")
        member = current.members.get(user) if user is not None else None
        steps.append({
            "seq": current.head_seq, "hash": current.head_hash,
            "admin": user is not None and core.is_admin(current, user),
            "level": current.access.get(data.get("folder"), {}).get(user),
            "keys": (member.signing_pk, member.encryption_pk) if member is not None else None,
            # Review 4acfdde R11 #4: a readmit (member.remove + member.add in
            # one append) is no removal for the member's share links.
            "readded": body["type"] == "member.remove" and any(
                later["type"] == "member.add" and later["data"].get("user_id") == user
                for later in bodies[index + 1:]
            ),
        })
    return current, steps


async def _replayed(state: TeamState, records: list, bodies: list[dict]) -> tuple[TeamState, list[dict]]:
    try:
        return await asyncio.to_thread(_replay_batch, state, records, bodies)
    except TeamLogError as exc:
        raise ApiError(400, TEAM_LOG_REFUSED, {
            "message": str(exc), "team_log_code": exc.code, "seq": exc.seq,
        }) from exc


async def records_after(cur, since: int, limit: int = MAX_RECORDS_PER_APPEND) -> list[dict]:
    rows = await _rows_after(cur, since)
    return [{"body": r["body"], "sig": r["sig"]} for r in rows[:limit]]


def _parse(record) -> dict:
    """Body of a record before replay (for the head check and authorship)."""
    if not isinstance(record, dict) or not isinstance(record.get("body"), str):
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "malformed team log record"})
    if len(record["body"]) > MAX_BODY_CHARS:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "team log record too large"})
    try:
        return core.parse_body(record["body"])
    except TeamLogError as exc:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": str(exc), "team_log_code": exc.code}) from exc


async def _user_row(cur, user_id: str):
    await cur.execute(
        "SELECT status, is_admin, signing_pk, encryption_pk FROM users WHERE id = %s FOR UPDATE",
        (user_id,),
    )
    return await cur.fetchone()


def _keys_match(row, data: dict) -> bool:
    return (
        row is not None and row[2] is not None and row[3] is not None
        and bytes(row[2]).hex() == data["signing_pk"]
        and bytes(row[3]).hex() == data["encryption_pk"]
    )


async def _check_against_users(
    cur, body: dict, pending_identity: Optional[tuple[str, str]], step: dict,
) -> None:
    """The log never gives rights to a key the account does not sign in with."""
    kind, data = body["type"], body["data"]
    # The seq tells the client which queued change it was (review 8595ec1 #2).
    refuse = lambda message: ApiError(400, TEAM_LOG_REFUSED, {  # noqa: E731
        "message": message, "seq": body.get("seq"),
    })
    if kind == "genesis":
        row = await _user_row(cur, data["user_id"])
        if row is None or row[0] != "active" or not row[1] or not _keys_match(row, data):
            raise refuse("genesis must be signed by an active admin with the keys the server holds")
    elif kind == "member.add":
        row = await _user_row(cur, data["user_id"])
        if row is not None and row[0] == "revoked":
            # Review 1141a20 (R9-F): a removed member comes back only through
            # the log (reactivate refuses them); the signed re-add reactivates.
            await cur.execute("SELECT encrypted_keypair FROM users WHERE id = %s", (data["user_id"],))
            material = await cur.fetchone()
            if not (material and material[0]):
                raise refuse("member.add of a revoked account without key material: onboard it again")
        elif row is None or row[0] != "active":
            raise refuse("member.add must name an approved account with its current keys")
        if not _keys_match(row, data):
            raise refuse("member.add must name an approved account with its current keys")
    elif kind == "member.keys":
        row = await _user_row(cur, data["user_id"])
        new = (data["signing_pk"], data["encryption_pk"])
        if not (_keys_match(row, data) or pending_identity == new):
            raise refuse("member.keys must carry the account's rotated keys")
    elif kind == "member.role" and data.get("role") == "admin":
        # Review 4acfdde R11 #5: the role went to an account with no users row,
        # or one that signs in with keys the log does not name (waiting for a
        # readmit): no device of it could sign, and the team froze.
        row = await _user_row(cur, data["user_id"])
        keys = step["keys"]
        if row is None or row[0] != "active" or keys is None or not _keys_match(
            row, {"signing_pk": keys[0], "encryption_pk": keys[1]}
        ):
            raise refuse(
                "member.role admin must name an active account that signs in with the keys "
                "the team log names (readmit it first)"
            )


async def _apply_to_users(cur, body: dict, step: dict) -> None:
    """``step``: the log right after ``body`` (``_replay_batch``)."""
    kind, data = body["type"], body["data"]
    if kind in ("genesis", "member.add", "member.role"):
        user_id = data["user_id"]
        admin = 1 if step["admin"] else 0
        await cur.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
        row = await cur.fetchone()
        if row is not None and int(row[0] or 0) != admin:
            # A demoted admin's tokens still say admin: they stop working.
            await cur.execute(
                "UPDATE users SET is_admin = %s, token_epoch = token_epoch + 1 WHERE id = %s",
                (admin, user_id),
            )
        if kind == "member.add":
            # A re-added member (removed earlier, so revoked) signs in again;
            # tokens from before the removal stay dead (token_epoch).
            await cur.execute(
                "UPDATE users SET status = 'active' WHERE id = %s AND status = 'revoked'", (user_id,)
            )
        if kind == "genesis":
            # Review 1141a20: an admin the founder left out of the log (key
            # not confirmed) kept is_admin and every admin endpoint. From the
            # genesis on, the log alone names the admin.
            await cur.execute("SELECT id FROM users WHERE is_admin = %s", (1,))
            for (other,) in await cur.fetchall():
                if other != user_id:
                    await cur.execute(
                        "UPDATE users SET is_admin = %s, token_epoch = token_epoch + 1 WHERE id = %s",
                        (0, other),
                    )
    elif kind == "member.remove":
        await cur.execute(
            "UPDATE users SET status = 'revoked', is_admin = %s, token_epoch = token_epoch + 1 "
            "WHERE id = %s",
            (0, data["user_id"]),
        )
        await cur.execute("DELETE FROM write_acl WHERE user_id = %s", (data["user_id"],))
        if not step["readded"]:
            await cur.execute("DELETE FROM shared_links WHERE created_by = %s", (data["user_id"],))
    elif kind == "access.set":
        # write_acl of a team folder is the log's access, not the envelopes'.
        await cur.execute(
            "DELETE FROM write_acl WHERE user_id = %s AND node_id = %s",
            (data["user_id"], data["folder"]),
        )
        if step["level"] == "write":
            await cur.execute(
                "INSERT IGNORE INTO write_acl (user_id, node_id, granted_at) VALUES (%s, %s, %s)",
                (data["user_id"], data["folder"], int(time.time() * 1000)),
            )


async def append(
    cur, records: list, user_id: str, *, pending_identity: Optional[tuple[str, str]] = None,
) -> TeamState:
    """Append ``records`` (all by ``user_id``) onto the current head.

    Must run in the caller's transaction after ``commit_counter`` is locked.
    Raises ApiError: 409 team_log_head_moved when the head is not the one the
    first record builds on, 400 team_log_refused for any record the rules or
    the users table refuse, 403 for a record signed by someone else.
    """
    if not records:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "no team log records"})
    if len(records) > MAX_RECORDS_PER_APPEND:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "too many team log records"})
    bodies = [_parse(r) for r in records]
    state = await load_state(cur) or TeamState()
    first = bodies[0]
    if first.get("prev") != state.head_hash or first.get("seq") != state.head_seq + 1:
        raise ApiError(409, TEAM_LOG_HEAD_MOVED, {
            "message": "the team log moved on; pull it and build the change again",
            "head_seq": state.head_seq, "head_hash": state.head_hash,
        })
    if any(b.get("author") != user_id for b in bodies):
        raise ApiError(403, TEAM_LOG_REFUSED, {"message": "team log records must be your own"})
    # Review c78fd19 (medium): a log still at rules 1 took new records under
    # rules 1 too (a member could get a retired key back). Older rules are for
    # records stored earlier (replay, restore); a new one is today's.
    old = next((b for b in bodies if b.get("v") != core.FORMAT_VERSION), None)
    if old is not None:
        raise ApiError(400, TEAM_LOG_REFUSED, {
            "message": f"new team log records follow rules {core.FORMAT_VERSION}",
            "team_log_code": "rules_outdated", "seq": old.get("seq"),
        })
    current, steps = await _replayed(state, records, bodies)
    now_ms = int(time.time() * 1000)
    for record, body, step in zip(records, bodies, steps):
        await _check_against_users(cur, body, pending_identity, step)
        await cur.execute(
            "INSERT INTO team_log (seq, prev, hash, body, sig, author, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (step["seq"], body["prev"], step["hash"], record["body"], record["sig"],
             user_id, now_ms),
        )
        await _apply_to_users(cur, body, step)
    if core.admin_policy_refusal(current):  # the clients refuse such a head too
        # The caller's transaction rolls the records and users changes back.
        raise ApiError(400, TEAM_LOG_REFUSED, {
            "message": "one admin per organisation for now: hand the role over in the same "
                       "append (member.role) instead of adding a second admin",
        })
    return current


def key_retired(state: Optional[TeamState], user_id: str, signing_pk: Optional[bytes]) -> bool:
    """The log rotated ``user_id`` away from ``signing_pk`` (capability run 294).

    Only after a restore (``_rotation_lost_here``) does the account still sign
    in with such a key. Its holder (a lost or stolen device the rotation was
    for) may then send nothing but the rotation to the log's keys.
    """
    return bool(signing_pk) and core.signing_key_retired(state, user_id, bytes(signing_pk).hex())


def _rotation_lost_here(row, member_id: str, state: TeamState) -> bool:
    """The account still signs in with keys the log itself retired for it.

    Capability run 277: a backup from before an identity rotation lacks the
    rotated key material and its member.keys record alike. The record (signed
    by the old key, new_key_sig by the new one) comes back first; the
    rotating device then pushes its rotation again from the key material the
    server has, and the account signs in with the log's keys once more.
    """
    if row[2] is None or row[3] is None:
        return False
    return (
        state.seen_keys.get(bytes(row[2]).hex()) == member_id
        and state.seen_keys.get(bytes(row[3]).hex()) == member_id
    )


async def restore(cur, records: list, user_id: str) -> TeamState:
    """Put back records this server lost (restored from a backup, moved).

    Review 1141a20 (R9-E): every device then reported a mismatch for good.
    A device that accepted the records uploads them again: any author's,
    as long as they continue the current head and replay (each record's own
    signature and the log's rules decide, as on every client). The users
    table still decides keys: the last keys the log gives each member it
    names must be the ones the account signs in with, and a genesis needs
    its founder to be an admin here, or the uploader to be the admin the
    restored log ends with. Same transaction and lock as ``append``.
    """
    if not records:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "no team log records"})
    if len(records) > MAX_RECORDS_PER_APPEND:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "too many team log records"})
    bodies = [_parse(r) for r in records]
    state = await load_state(cur) or TeamState()
    first = bodies[0]
    if first.get("prev") != state.head_hash or first.get("seq") != state.head_seq + 1:
        raise ApiError(409, TEAM_LOG_HEAD_MOVED, {
            "message": "the team log moved on; pull it and compare again",
            "head_seq": state.head_seq, "head_hash": state.head_hash,
        })
    refuse = lambda message: ApiError(400, TEAM_LOG_REFUSED, {"message": message})  # noqa: E731
    uploader = await _user_row(cur, user_id)
    uploader_active = uploader is not None and uploader[0] == "active"
    uploader_admin = uploader_active and bool(uploader[1])
    founder_admin = True
    named: set[str] = set()
    current, steps = await _replayed(state, records, bodies)
    # Review c78fd19 #2: any account put back a member.keys of any member to
    # keys the account does not sign in with (the run 277 exception below),
    # so a thief of a member's identity key (no password) signed one to keys
    # of its own and took the member's place in the team. Such a rotation
    # comes back only from the admin; a member's device still puts back the
    # rest (a lone admin's org.recovery, review 8595ec1 #4).
    uploader_team_admin = uploader_admin or (uploader_active and core.is_admin(current, user_id))
    now_ms = int(time.time() * 1000)
    for record, body, step in zip(records, bodies, steps):
        kind, data = body["type"], body["data"]
        if kind == "genesis":
            row = await _user_row(cur, data["user_id"])
            founder_admin = row is not None and row[0] == "active" and bool(row[1])
        if kind in ("genesis", "member.add", "member.keys"):
            named.add(data["user_id"])
        await cur.execute(
            "INSERT INTO team_log (seq, prev, hash, body, sig, author, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (step["seq"], body["prev"], step["hash"], record["body"], record["sig"],
             body["author"], now_ms),
        )
        await _apply_to_users(cur, body, step)
    if not founder_admin and not (uploader_admin and core.is_admin(current, user_id)):
        raise refuse("a restored genesis needs its founder (or the uploader, its last admin) to be an admin here")
    for member_id in sorted(named):
        member = current.members.get(member_id)
        if member is None or not member.active:
            continue
        row = await _user_row(cur, member_id)
        keys = {"signing_pk": member.signing_pk, "encryption_pk": member.encryption_pk}
        if row is None:
            # Review 8595ec1 #1: the backup is older than this registration.
            # Refusing the log locked the whole organisation out; the account
            # comes back under this id with exactly these keys (POST /auth/rejoin).
            continue
        if row[0] != "active":
            raise refuse(f"the restored team log gives {member_id} keys the account does not sign in with")
        if _keys_match(row, keys):
            continue
        if not _rotation_lost_here(row, member_id, current):
            raise refuse(f"the restored team log gives {member_id} keys the account does not sign in with")
        if not uploader_team_admin:
            raise ApiError(403, TEAM_LOG_REFUSED, {
                "message": f"only the team admin puts back the key rotation of {member_id} "
                           "the server lost",
            })
    if core.admin_policy_refusal(current):
        raise refuse("the restored team log has more than one admin")
    return current


# ── Pushes once the organisation has a log (design §4.3.4–6, §5) ─────────

async def team_folder_above(cur, state: TeamState, node_id: Optional[str], cache: dict) -> Optional[str]:
    """``node_id`` or its nearest ancestor that the log knows as a team folder.

    ``cache`` is the push's authority cache (``("node", id) -> (owner, parent)``).
    """
    current = node_id
    for _ in range(64):
        if current is None:
            return None
        if current in state.folders:
            return current
        key = ("node", current)
        if key not in cache:
            await cur.execute(
                "SELECT owner_id, parent_ref FROM vault_objects "
                "WHERE id = %s AND object_type = 'node' AND is_deleted = 0",
                (current,),
            )
            row = await cur.fetchone()
            cache[key] = tuple(row) if row else None
        row = cache[key]
        if row is None:
            return None
        current = row[1]
    return None


# The same rules decide on every client's pull (shared core).
item_refusal = core.item_refusal
tombstone_refusal = core.tombstone_refusal
move_refusal = core.move_refusal


def envelope_refusal(
    state: TeamState, user_id: str, target_id: str, dek_id: str,
    folder: Optional[str], level: Optional[str], regrant: bool = False,
) -> Optional[str]:
    """A live envelope giving ``target_id`` the key ``dek_id`` (§4.3.5).

    Review c78fd19 R13-10: with a log, another account gets a key only by an
    ``access.set`` (§9); every client ignores another account's envelope on a
    key the log does not know, yet the server took it and its write_acl. Only
    ``regrant`` (the target held this key at this level before the log: a
    re-seal after the sender's identity rotation) stays possible.
    """
    found = state.dek_index.get(dek_id)
    if found is None:
        if folder is not None and folder in state.folders:
            return "envelope for a key the team log does not know"
        if target_id != user_id and not regrant:
            return "team log: another account gets a key only with an access.set"
        return None
    key_folder, _ = found
    if not core.is_admin(state, user_id):
        return "team log: only an admin seals a team key"
    if not core.may_seal(state, key_folder):
        return "folder waits for a re-key"
    if not core.may_hold_key(state, target_id, dek_id):
        return "team log gives this account no access to the key"
    granted = state.access.get(key_folder, {}).get(target_id)
    if granted is not None and granted != level:
        return "envelope access differs from the team log"
    return None


def reserved_refusal(state: TeamState, user_id: str, obj_id: str, stored_type: str) -> Optional[str]:
    """A new object under an id the log announced (review 1141a20, R9-F).

    ``folder.key`` names its folder and key before their objects arrive; a
    member who pushed one of those ids first owned the team folder or key.
    Only an admin or the record's author creates it, and only as that type.
    """
    if obj_id in state.folders:
        expected, author = "node", state.folders[obj_id][0][1]
    elif obj_id in state.dek_index:
        folder, gen = state.dek_index[obj_id]
        expected, author = "dek", state.folders[folder][gen][1]
    else:
        return None
    if stored_type != expected:
        return f"team log reserves this id for a {expected}"
    if user_id != author and not core.is_admin(state, user_id):
        return "team log reserves this id for its admin"
    return None


def is_team_key(state: Optional[TeamState], dek_id: Optional[str], folder: Optional[str]) -> bool:
    return state is not None and (dek_id in state.dek_index or folder in state.folders)


def head(state: Optional[TeamState]) -> Optional[dict]:
    if state is None:
        return None
    return {"seq": state.head_seq, "hash": state.head_hash, "genesis_hash": state.genesis_hash}
