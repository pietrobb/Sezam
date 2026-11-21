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
# Review 8bc70f7 M6: a member signs nothing but its own member.keys, yet it
# could make every push wait on the replay of 1000 records under the lock.
MAX_RECORDS_FROM_MEMBER = 4
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
    replayed = core.replay_steps(clean, state)
    for index, body in enumerate(bodies):
        todays_rules = core.todays_rules_refusal(current, body)  # ``current``: the log before ``body``
        current = next(replayed)
        data = body["data"]
        user = data.get("user_id")
        member = current.members.get(user) if user is not None else None
        steps.append({
            "seq": current.head_seq, "hash": current.head_hash,
            "admin": user is not None and core.is_admin(current, user),
            "level": current.access.get(data.get("folder"), {}).get(user),
            "keys": (member.signing_pk, member.encryption_pk) if member is not None else None,
            "admin_policy": core.admin_policy_refusal(current),
            "todays_rules": todays_rules,
            # Review 4acfdde R11 #4: a readmit (member.remove + member.add in
            # one append) is no removal for the member's share links.
            "readded": body["type"] == "member.remove" and any(
                later["type"] == "member.add" and later["data"].get("user_id") == user
                for later in bodies[index + 1:]
            ),
        })
    return current, steps


@dataclass(frozen=True)
class Prepared:
    """An uploaded batch parsed and replayed before the push lock (review
    8bc70f7 M6); under the lock it is reused while the head is the same (the
    hash chain covers every earlier record), else the head moved: 409."""
    head_seq: int
    head_hash: Optional[str]
    bodies: list
    current: TeamState
    steps: list
    before: TeamState  # the log the batch continues


async def _is_admin_here(cur, state: TeamState, user_id: str) -> bool:
    if state.members:
        return core.is_admin(state, user_id)
    await cur.execute("SELECT status, is_admin FROM users WHERE id = %s", (user_id,))
    row = await cur.fetchone()
    return row is not None and row[0] == "active" and bool(row[1])


async def _prepare(cur, records: list, user_id: str, *, restore: bool) -> Prepared:
    if not records:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "no team log records"})
    if len(records) > MAX_RECORDS_PER_APPEND:
        raise ApiError(400, TEAM_LOG_REFUSED, {"message": "too many team log records"})
    bodies = [_parse(r) for r in records]
    state = await load_state(cur) or TeamState()
    _check_head(state, bodies[0], "compare again" if restore else "build the change again")
    if not restore:
        if any(b.get("author") != user_id for b in bodies):
            raise ApiError(403, TEAM_LOG_REFUSED, {"message": "team log records must be your own"})
        # Review c78fd19 (medium): a log still at rules 1 took new records
        # under rules 1 too (a member could get a retired key back). Older
        # rules are for records stored earlier (replay, restore); a new one is today's.
        old = next((b for b in bodies if b.get("v") != core.FORMAT_VERSION), None)
        if old is not None:
            raise ApiError(400, TEAM_LOG_REFUSED, {
                "message": f"new team log records follow rules {core.FORMAT_VERSION}",
                "team_log_code": "rules_outdated", "seq": old.get("seq"),
            })
        if len(records) > MAX_RECORDS_FROM_MEMBER and not await _is_admin_here(cur, state, user_id):
            raise ApiError(400, TEAM_LOG_REFUSED, {"message": "too many team log records"})
    current, steps = await _replayed(state, records, bodies)
    if restore:
        _refuse_rules_beyond_appends(bodies, steps)
    return Prepared(state.head_seq, state.head_hash, bodies, current, steps, state)


def _refuse_rules_beyond_appends(bodies: list[dict], steps: list[dict]) -> None:
    """INV-2 (review e443cbc H3): the log rules an append holds that a replay
    alone does not, held by a restore too.

    Every append holds the one-admin rule at its end, and an append is one
    author's, so a history the main path wrote holds it wherever the author
    changes; a restore checked only the final log and took admins on the way
    (a second admin, later removed by an account the uploader controls).
    A record under older rules (stored before they tightened) replays under
    them; a restore takes it only where today's rules take it as well, else
    a log still at rules 1 took records today that no append takes."""
    for index, (body, step) in enumerate(zip(bodies, steps)):
        refuse = lambda message: ApiError(400, TEAM_LOG_REFUSED, {  # noqa: E731
            "message": message, "seq": step["seq"],
        })
        if step["todays_rules"]:
            raise ApiError(400, TEAM_LOG_REFUSED, {
                "message": f"the restored team log: {step['todays_rules']}",
                "team_log_code": "rules_outdated", "seq": step["seq"],
            })
        last_of_append = index + 1 == len(bodies) or bodies[index + 1]["author"] != body["author"]
        if last_of_append and step["admin_policy"]:
            raise refuse(f"the restored team log has more than one admin after record {step['seq']}")


def _check_head(state: TeamState, first: dict, then: str) -> None:
    if first.get("prev") != state.head_hash or first.get("seq") != state.head_seq + 1:
        raise ApiError(409, TEAM_LOG_HEAD_MOVED, {
            "message": f"the team log moved on; pull it and {then}",
            "head_seq": state.head_seq, "head_hash": state.head_hash,
        })


async def _under_lock(cur, records: list, user_id: str, prepared: Optional[Prepared], *, restore: bool) -> Prepared:
    """``prepared`` (from before the lock) when the head is still the one it
    replayed onto, else the batch prepared now."""
    if prepared is None:
        return await _prepare(cur, records, user_id, restore=restore)
    state = await load_state(cur) or TeamState()
    if (state.head_seq, state.head_hash) != (prepared.head_seq, prepared.head_hash):
        _check_head(state, prepared.bodies[0], "compare again" if restore else "build the change again")
        return await _prepare(cur, records, user_id, restore=restore)  # same head after all
    return prepared


async def prepare_append(cur, records: list, user_id: str) -> Prepared:
    """Everything ``append`` checks without the users table, outside the push lock."""
    return await _prepare(cur, records, user_id, restore=False)


async def prepare_restore(cur, records: list, user_id: str) -> Prepared:
    """Everything ``restore`` checks without locking, outside the push lock: a
    refused restore never holds the lock."""
    prepared = await _prepare(cur, records, user_id, restore=True)
    uploader = await _user_row(cur, user_id, lock=False)
    await _refuse_restored_founder(cur, prepared.bodies, prepared.current, uploader, user_id, lock=False)
    await _refuse_restored_keys(
        cur, prepared.before, prepared.bodies, prepared.steps, prepared.current,
        _uploader_team_admin(uploader, prepared.current, user_id), lock=False,
    )
    return prepared


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


async def _user_row(cur, user_id: str, *, lock: bool = True):
    await cur.execute(
        "SELECT status, is_admin, signing_pk, encryption_pk FROM users WHERE id = %s"
        + (" FOR UPDATE" if lock else ""),
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
    cur, body: dict, pending_identity: Optional[tuple[str, str]], step: dict, *, history: bool = False,
) -> None:
    """The log never gives rights to a key the account does not sign in with.

    ``history`` (a restore, INV-2 review e443cbc H3): the same checks on
    records the main path took once, in their order, while ``_apply_to_users``
    replays their effects. Two things it cannot know then are left to later
    checks: the keys (the account may have rotated since:
    ``_refuse_restored_keys`` links them) and admin rights of a genesis
    (handed over since: ``_refuse_restored_founder``). An account with no
    row (a backup older than its registration, review 8595ec1 #1) comes back
    through POST /auth/rejoin; only the founder, registered before anyone
    else, has one always."""
    kind, data = body["type"], body["data"]
    # The seq tells the client which queued change it was (review 8595ec1 #2).
    refuse = lambda message: ApiError(400, TEAM_LOG_REFUSED, {  # noqa: E731
        "message": message, "seq": body.get("seq"),
    })
    if kind == "genesis":
        row = await _user_row(cur, data["user_id"])
        if history:
            if row is None:
                raise refuse("a restored genesis names a founder with no account here")
        elif row is None or row[0] != "active" or not row[1] or not _keys_match(row, data):
            raise refuse("genesis must be signed by an active admin with the keys the server holds")
    elif kind == "member.add":
        row = await _user_row(cur, data["user_id"])
        if history and row is None:
            return
        if row is not None and row[0] == "revoked":
            # Review 1141a20 (R9-F): a removed member comes back only through
            # the log (reactivate refuses them); the signed re-add reactivates.
            await cur.execute("SELECT encrypted_keypair FROM users WHERE id = %s", (data["user_id"],))
            material = await cur.fetchone()
            if not (material and material[0]):
                raise refuse("member.add of a revoked account without key material: onboard it again")
        elif row is None or row[0] != "active":
            raise refuse("member.add must name an approved account with its current keys")
        if not history and not _keys_match(row, data):
            raise refuse("member.add must name an approved account with its current keys")
    elif kind == "member.keys" and not history:
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
        if history:
            if row is not None and row[0] not in ("active", "revoked"):  # never approved
                raise refuse("member.role admin must name an approved account")
        elif row is None or row[0] != "active" or keys is None or not _keys_match(
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
    prepared: Optional[Prepared] = None,
) -> TeamState:
    """Append ``records`` (all by ``user_id``) onto the current head.

    Must run in the caller's transaction after ``commit_counter`` is locked;
    ``prepared``: ``prepare_append`` of the same records before the lock.
    Raises ApiError: 409 team_log_head_moved when the head is not the one the
    first record builds on, 400 team_log_refused for any record the rules or
    the users table refuse, 403 for a record signed by someone else.
    """
    prepared = await _under_lock(cur, records, user_id, prepared, restore=False)
    bodies, current, steps = prepared.bodies, prepared.current, prepared.steps
    await _refuse_superseded_recovery(cur, bodies)
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


async def _refuse_superseded_recovery(
    cur, bodies: list[dict], *, restored: Optional[TeamState] = None, uploader: Optional[str] = None,
) -> None:
    """Review c78fd19 R13-10 (operator 2026-11-20): an org.recovery record
    naming a key other than the one its admin's stored blob holds is older
    than that blob (every client stores before it names the key), yet as the
    newer log entry it became the current recovery and voided the newer
    shares. The desktop checks before its push; this closes the window
    between that check and the append. The blob creator's last record of the
    batch counts.

    A restore too (INV-2, review e443cbc H3: any member put back such a
    record of the admin, signed by a stolen key, and voided its shares), with
    ``restored`` the log it ends with: the record counts while it is still the
    current recovery there. The uploader's own record stands: after a backup
    the blob may be older than the log, and its author stores a blob for the
    key on the main path anyway (recovery.store, then the append)."""
    if not any(b["type"] == "org.recovery" for b in bodies):
        return
    await cur.execute("SELECT 1 FROM org_recovery_blobs WHERE id = 1")
    if not await cur.fetchone():
        return
    # Locking read of an existing blob only (gap lock, see recovery.store):
    # a setup stored meanwhile is either seen here or ranked after this record.
    await cur.execute(
        "SELECT created_by, recovery_signing_pk FROM org_recovery_blobs WHERE id = 1 FOR UPDATE"
    )
    row = await cur.fetchone()
    if not row or row[1] is None:
        return
    user_id = row[0]
    named = [b for b in bodies if b["type"] == "org.recovery" and b["author"] == user_id]
    pk = named[-1]["data"].get("recovery_pk") if named else None
    if pk is None or user_id == uploader:
        return
    if restored is not None and core.recovery_key(restored, user_id) != pk:
        return
    if bytes(row[1]).hex() != pk:
        raise ApiError(400, TEAM_LOG_REFUSED, {
            "message": "a newer org recovery was set up after this one (on the web or another "
                       "device); it is kept",
            "team_log_code": "org_recovery_superseded", "seq": named[-1]["seq"],
        })


def key_retired(state: Optional[TeamState], user_id: str, signing_pk: Optional[bytes]) -> bool:
    """The log rotated ``user_id`` away from ``signing_pk`` (capability run 294).

    Only after a restore (``_refuse_restored_keys``, rotations the server lost) does the account still sign
    in with such a key. Its holder (a lost or stolen device the rotation was
    for) may then send nothing but the rotation to the log's keys.
    """
    return bool(signing_pk) and core.signing_key_retired(state, user_id, bytes(signing_pk).hex())


def _own_rotations(before: TeamState, bodies: list[dict], steps: list[dict], member_id: str) -> tuple[set, dict]:
    """Every key pair the upload gives ``member_id``, and its own rotations
    old -> new from the server's head on (whose keys the server took already).

    A member.keys is signed by the old key and proven by the new one
    (new_key_sig), so only the key's holder makes that edge; a genesis or
    member.add starts the member over on keys anyone could name.

    Review e443cbc H3: a re-added member starts over on the keys its account
    signs in with now, so the keys of a membership it left were the account's
    once and are no longer: the honest history was refused for good. Keys of
    such a membership count only where it was admin (then its records shaped
    the team); a member's own records end with its membership (member.keys only).
    """
    member = before.members.get(member_id)
    current = (member.signing_pk, member.encryption_pk) if member is not None else None
    admin = member is not None and member.active and member.role == "admin"
    keys, rotated = set(), {}
    left: tuple[set, dict, bool] = (set(), {}, False)  # the membership before a re-add
    for body, step in zip(bodies, steps):
        data = body["data"]
        if data.get("user_id") != member_id:
            continue
        admin = admin or step["admin"]
        if body["type"] == "member.remove":
            left = (keys | left[0], {**left[1], **rotated}, admin or left[2])
            keys, rotated, admin = set(), {}, False
            continue
        if body["type"] in ("genesis", "member.add"):
            current = (data["signing_pk"], data["encryption_pk"])
        elif body["type"] == "member.keys":
            new = (data["signing_pk"], data["encryption_pk"])
            rotated[current] = new
            current = new
        else:
            continue
        keys.add(current)
    if left[2] or not keys:  # it left as admin, or the upload ends with it gone
        keys, rotated = keys | left[0], {**left[1], **rotated}
    return keys, rotated


def _after(rotated: dict, start) -> list:
    """The keys ``start`` rotated to, in order, each once.

    Review e443cbc H1: rules 1 let a member rotate back to a retired key and
    every version let it swap its keys there and back; walking such a cycle
    until it ended spun the worker forever. Each key is visited once, so no
    upload (and no later hole in the rules) makes this loop."""
    chain, seen = [], {start}
    while start in rotated and rotated[start] not in seen:
        start = rotated[start]
        seen.add(start)
        chain.append(start)
    return chain


def _named_members(bodies: list[dict]) -> list[str]:
    return sorted({
        b["data"]["user_id"] for b in bodies if b["type"] in ("genesis", "member.add", "member.keys")
        or b["type"] == "member.role" and b["data"].get("role") == "admin"
    })


def _uploader_team_admin(uploader, current: TeamState, user_id: str) -> bool:
    # Review c78fd19 #2: any account put back a member.keys of any member to
    # keys the account does not sign in with (the run 277 exception), so a
    # thief of a member's identity key (no password) signed one to keys of its
    # own and took the member's place in the team. Such a rotation comes back
    # only from the admin; a member's device still puts back the rest (a lone
    # admin's org.recovery, review 8595ec1 #4).
    active = uploader is not None and uploader[0] == "active"
    return active and (bool(uploader[1]) or core.is_admin(current, user_id))


async def _refuse_restored_keys(
    cur, before: TeamState, bodies: list[dict], steps: list[dict], current: TeamState,
    uploader_team_admin: bool,
    *, lock: bool,
) -> None:
    """INV-2 (docs/ROOT_CAUSE_PLAN.md): every key a restored log gives a
    member it names is one the account signs in with, or one the member's own
    rotations link to it. Review 8bc70f7 H2 and capability run 385 (a forged
    genesis under the admin's id, then the admin removed, or re-added on its
    real keys) and the property test (the admin re-added a member on keys it
    holds) each gave a member keys no rotation of its own links to the account.

    Keys the member rotated to after the account's (capability run 277: a
    backup from before an identity rotation; the rotating device pushes the
    rotation's key material again) come back only from the team admin
    (review c78fd19 #2: a thief of the identity key signs such a rotation too).
    ``lock``: under the push lock, after the users table took the records."""
    refuse = lambda message: ApiError(400, TEAM_LOG_REFUSED, {"message": message})  # noqa: E731
    for member_id in _named_members(bodies):
        row = await _user_row(cur, member_id, lock=lock)
        if row is None:
            # Review 8595ec1 #1: the backup is older than this registration.
            # Refusing the log locked the whole organisation out; the account
            # comes back under this id with exactly these keys (POST /auth/rejoin).
            continue
        wrong = refuse(f"the restored team log gives {member_id} keys the account does not sign in with")
        if lock and current.members[member_id].active and row[0] != "active":
            raise wrong
        keys, rotated = _own_rotations(before, bodies, steps, member_id)
        if row[2] is None or row[3] is None:
            raise wrong
        account = (bytes(row[2]).hex(), bytes(row[3]).hex())
        later = _after(rotated, account)
        linked = {account, *later} | {k for k in keys if account in _after(rotated, k)}
        member = current.members[member_id]
        if not keys <= linked or (member.signing_pk, member.encryption_pk) not in {account, *later}:
            raise wrong
        if later and not uploader_team_admin:
            raise ApiError(403, TEAM_LOG_REFUSED, {
                "message": f"only the team admin puts back the key rotation of {member_id} "
                           "the server lost",
            })


async def _refuse_restored_founder(
    cur, bodies: list[dict], current: TeamState, uploader, user_id: str, *, lock: bool,
) -> None:
    """A restored genesis needs its founder to be an admin here, else the
    uploader must be an admin here and the restored log's last admin (the
    genesis check of an append). The founder's genesis keys are checked with
    every other key the upload gives a member (``_refuse_restored_keys``)."""
    genesis = next((b for b in bodies if b["type"] == "genesis"), None)
    if genesis is None:
        return
    row = await _user_row(cur, genesis["data"]["user_id"], lock=lock)
    if row is not None and row[0] == "active" and bool(row[1]):
        return
    uploader_admin = uploader is not None and uploader[0] == "active" and bool(uploader[1])
    if uploader_admin and core.is_admin(current, user_id):
        return
    raise ApiError(400, TEAM_LOG_REFUSED, {
        "message": "a restored genesis needs its founder (or the uploader as its last admin) "
                   "to be an admin here",
    })


async def restore(cur, records: list, user_id: str, *, prepared: Optional[Prepared] = None) -> TeamState:
    """Put back records this server lost (restored from a backup, moved).

    Review 1141a20 (R9-E): every device then reported a mismatch for good.
    A device that accepted the records uploads them again: any author's,
    as long as they continue the current head and replay (each record's own
    signature and the log's rules decide, as on every client). The users
    table still decides keys: every key the upload gives a member is the
    account's or linked to it by the member's own rotations, and a genesis
    needs its founder to be an admin here, or the uploader to be the admin
    the restored log ends with. INV-2: a restore takes nothing the main path
    would refuse (tests/test_inv2_restore_within_append.py). Same transaction and lock as ``append``;
    ``prepared``: ``prepare_restore`` of the same records before the lock.
    """
    prepared = await _under_lock(cur, records, user_id, prepared, restore=True)
    bodies, current, steps = prepared.bodies, prepared.current, prepared.steps
    uploader = await _user_row(cur, user_id)
    uploader_team_admin = _uploader_team_admin(uploader, current, user_id)
    await _refuse_restored_founder(cur, bodies, current, uploader, user_id, lock=True)
    await _refuse_superseded_recovery(cur, bodies, restored=current, uploader=user_id)
    now_ms = int(time.time() * 1000)
    for record, body, step in zip(records, bodies, steps):
        await _check_against_users(cur, body, None, step, history=True)
        await cur.execute(
            "INSERT INTO team_log (seq, prev, hash, body, sig, author, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (step["seq"], body["prev"], step["hash"], record["body"], record["sig"],
             body["author"], now_ms),
        )
        await _apply_to_users(cur, body, step)
    await _refuse_restored_keys(cur, prepared.before, bodies, steps, current, uploader_team_admin, lock=True)
    return current  # one admin at the end: _refuse_rules_beyond_appends


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
