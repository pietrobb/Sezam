"""INV-2 (docs/ROOT_CAUSE_PLAN.md): no path has more power than the main path.

POST /api/team-log/restore puts back records a server lost. It may be
stricter than an append, never looser: whatever it takes must be records that
existed once (the honest history) followed by records the uploader could have
appended itself (POST /api/team-log, or a push carrying its own rotation).

Hypothesis builds an honest team history through the normal path (the admin
adds, removes, shares folders, grants and hands the role over; members rotate
their identities), then a server that lost its log or came back from a backup,
and a member who uploads a restore: a prefix of the honest history, then
anything it can sign. That covers a genesis under any id, accounts it makes up,
removals, re-adds on real public keys, role changes and rotations to keys of its
own. The oracle replays the honest prefix and pushes the rest through
``team_log.append``, record by record, as the uploader. A restore that takes
what the oracle refuses breaks INV-2.

Review 8bc70f7 H2 (a forged genesis under the admin's id) and capability run
385 (the same, hidden by re-adding the admin on its real keys) are instances:
this test finds both by itself. On the 8bc70f7 server the default run fails
with B restoring a genesis signed as A; on 0e96ca2 the default run misses it
but a deep run (3000 examples) finds the same, and the kept counterexample
below fails. The helpers drive both server versions (prepare_* came in 0e96ca2).

Default run (every push) is derandomized, 2000 examples each: review e443cbc
P2 found the per-push run catching 1 of 4 reverted restore fixes; at 2000 it
caught each restore mutant of scripts/mutants.py (R1-R6) by itself, until on
d441587 it missed R1 and R5 (nightly 45604036980): each has a scripted test
below now, so the check does not hang on where a derandomized run goes. For a
deep random run (the nightly job uses 10000):

    set SEZAM_PROPERTY_EXAMPLES=10000
    python -m pytest -q tests/test_inv2_restore_within_append.py
"""

from __future__ import annotations

import asyncio
import atexit
import copy
import hashlib
import itertools
import os
from dataclasses import dataclass
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings, target
from hypothesis import event
from hypothesis import strategies as st
from hypothesis.control import currently_in_test_context
from nacl.signing import SigningKey

from sezam import teamlog
from server.app import team_log
from server.app.errors import ApiError
from tests import property_seeds
from tests.test_server_spec import MockDatabase, _create_regular_user

EXAMPLES = int(os.environ.get("SEZAM_PROPERTY_EXAMPLES", "0"))


def coverage_event(value: str) -> None:
    """Hypothesis statistics; the fixed counterexamples below run the oracle outside a property."""
    if currently_in_test_context():
        event(value)
NAMES = ("A", "B", "C")  # registered accounts; A founds the honest log
MADE_UP = "D"  # no account on the server
# Review e443cbc H3: accounts the main path refuses to name, which the generator
# never had: P registered but not approved yet, N approved without keys.
WAITING, KEYLESS = "P", "N"
OTHERS = (WAITING, KEYLESS)
IDS = {name: f"0{name}" + "0" * 24 for name in NAMES + (MADE_UP,) + OTHERS}
NAME_OF = {uid: name for name, uid in IDS.items()}
FOLDERS = ("0F" + "0" * 23 + "1", "0F" + "0" * 23 + "2")


@dataclass(frozen=True)
class Key:
    sk: SigningKey
    enc: str

    @property
    def pk(self) -> str:
        return bytes(self.sk.verify_key).hex()


class Keys:
    """Deterministic keys, so Hypothesis replays and shrinks an example exactly."""

    def __init__(self):
        self._n = itertools.count()

    def new(self) -> Key:
        seed = hashlib.sha256(b"inv2-%d" % next(self._n)).digest()
        return Key(SigningKey(seed), hashlib.sha256(b"enc" + seed).hexdigest())

    def recovery_pk(self) -> str:
        seed = hashlib.sha256(b"inv2-recovery-%d" % next(self._n)).digest()
        return bytes(SigningKey(seed).verify_key).hex()


# One loop for the whole module: a new loop per call opens a socket pair on
# Windows, and a deep run (thousands of examples) used up the local ports
# until creating a loop blocked in accept().
_LOOP = asyncio.Runner()
atexit.register(_LOOP.close)


def _run(coro):
    return _LOOP.run(coro)


async def _locked(db, fn):
    """The endpoints' transaction: the push lock first, then ``fn(cur)``."""
    async with db.transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT next_seq FROM commit_counter WHERE id = 1 FOR UPDATE")
            await cur.fetchone()
            return await fn(cur)


def _active(db, uid: str) -> bool:
    """require_full_jwt: only an active account gets to any endpoint."""
    row = next((u for u in db._storage["users"] if u["id"] == uid), None)
    return row is not None and row["status"] == "active"


def append(db, records: list, uid: str, pending=None) -> bool:
    """POST /api/team-log (or a push with ``pending``: its own new identity)."""
    if not _active(db, uid):
        return False
    team_log.forget_cache()

    async def go():
        if not hasattr(team_log, "prepare_append"):  # the server before 0e96ca2 (M6)
            return await _locked(db, lambda cur: team_log.append(
                cur, records, uid, pending_identity=pending))
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                prepared = await team_log.prepare_append(cur, records, uid)
        await _locked(db, lambda cur: team_log.append(
            cur, records, uid, pending_identity=pending, prepared=prepared))

    try:
        _run(go())
    except ApiError as exc:
        REFUSALS.append(exc.detail)
        return False
    return True


REFUSALS: list = []  # why the last appends were refused, for the failure report


def restore(db, records: list, uid: str) -> bool:
    """POST /api/team-log/restore."""
    if not _active(db, uid):
        return False
    team_log.forget_cache()

    async def go():
        if not hasattr(team_log, "prepare_restore"):  # the server before 0e96ca2 (M6)
            return await _locked(db, lambda cur: team_log.restore(cur, records, uid))
        async with db.acquire() as conn:
            async with conn.cursor() as cur:
                prepared = await team_log.prepare_restore(cur, records, uid)
        await _locked(db, lambda cur: team_log.restore(cur, records, uid, prepared=prepared))

    try:
        _run(go())
    except ApiError as exc:
        REFUSED.append(exc.detail)
        return False
    return True


REFUSED: list = []  # why the last restores were refused


def put_back(db, records: list) -> None:
    """Records that existed once, stored with their effects and no checks."""
    if not records:
        return
    team_log.forget_cache()

    async def go(cur):
        state = await team_log.load_state(cur) or teamlog.TeamState()
        bodies = [team_log._parse(r) for r in records]
        _, steps = team_log._replay_batch(state, records, bodies)
        for record, body, step in zip(records, bodies, steps):
            await cur.execute(
                "INSERT INTO team_log (seq, prev, hash, body, sig, author, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (step["seq"], body["prev"], step["hash"], record["body"], record["sig"],
                 body["author"], 0),
            )
            await team_log._apply_to_users(cur, body, step)

    _run(_locked(db, go))


def _set_row_keys(db, uid: str, signing_pk: str, encryption_pk: str) -> None:
    """What a push carrying the account's own new identity stores."""
    row = next(u for u in db._storage["users"] if u["id"] == uid)
    row["signing_pk"], row["encryption_pk"] = bytes.fromhex(signing_pk), bytes.fromhex(encryption_pk)


def _set_keys(db, uid: str, key: Key) -> None:
    _set_row_keys(db, uid, key.pk, key.enc)


def _db(storage: dict) -> MockDatabase:
    db = MockDatabase()
    db._storage = copy.deepcopy(storage)
    return db


class Honest:
    """The team's real history, built through the normal path only."""

    def __init__(self, keys: Keys, legacy: bool = False):
        """``legacy``: the log was founded under rules 1 and stored before
        today's appends (review e443cbc H3: the generator never had one)."""
        self.keys = keys
        self.db = MockDatabase()
        _run(self.db.create_schema())
        self.account: dict[str, list[Key]] = {}  # name -> its keys, current last
        for name in NAMES + OTHERS:
            _create_regular_user(self.db._storage, IDS[name], name.lower())
            self.account[name] = [keys.new()]
            _set_keys(self.db, IDS[name], self.account[name][-1])
        rows = {u["id"]: u for u in self.db._storage["users"]}
        rows[IDS["A"]]["is_admin"] = 1
        rows[IDS[WAITING]]["status"] = "pending"
        rows[IDS[KEYLESS]]["signing_pk"] = rows[IDS[KEYLESS]]["encryption_pk"] = None
        self.state = teamlog.TeamState()
        self.records: list[dict] = []
        self.snapshots: list[tuple[int, dict]] = []  # (records so far, server storage)
        genesis = [("genesis", "A", {
            "org": "0G" + "0" * 24, "user_id": IDS["A"],
            "signing_pk": self.current("A").pk, "encryption_pk": self.current("A").enc,
        })]
        if legacy:
            genesis.append(("member.add", "A", {
                "user_id": IDS["B"], "signing_pk": self.current("B").pk,
                "encryption_pk": self.current("B").enc, "role": "member",
            }))
        assert self._commit("A", genesis, rules=1 if legacy else None)

    def current(self, name: str) -> Key:
        return self.account[name][-1]

    def admin(self) -> str:
        return next(NAME_OF[uid] for uid, m in self.state.members.items() if m.active and m.role == "admin")

    def _commit(self, by: str, changes: list, rotate: Key | None = None, rules: int | None = None) -> bool:
        """``rules``: records stored under older rules before today (no append)."""
        state, batch = self.state, []
        try:
            for kind, author, data in changes:
                body = teamlog.next_body(state, kind, IDS[author], data)
                if rules is not None:
                    body["v"] = rules
                record = teamlog.sign_record(body, self.current(author).sk)
                state = teamlog.apply_record(state, record)
                batch.append(record)
        except teamlog.TeamLogError:
            return False
        pending = (rotate.pk, rotate.enc) if rotate else None
        if rules is not None:
            put_back(self.db, batch)
        elif not append(self.db, batch, IDS[by], pending):
            return False
        if rotate:
            _set_keys(self.db, IDS[by], rotate)
            self.account[by].append(rotate)
        self.state = state
        self.records += batch
        self.snapshots.append((len(self.records), copy.deepcopy(self.db._storage)))
        return True

    def step(self, data) -> None:
        admin = self.admin()
        members = self.state.members
        active = [n for n in NAMES if IDS[n] in members and members[IDS[n]].active]
        op = data.draw(st.sampled_from(["add", "add", "remove", "folder", "access", "rotate", "handover",
                                        "recovery"]))
        if op == "recovery":
            # The admin stores the org recovery blob, then names its key
            # (review c78fd19 R13-10: every client stores before it names).
            pk = self.keys.recovery_pk()
            self.db._storage["org_recovery_blobs"] = [{
                "id": 1, "created_by": IDS[admin], "recovery_signing_pk": bytes.fromhex(pk),
            }]
            self._commit(admin, [("org.recovery", admin, {"recovery_pk": pk})])
        elif op == "add":
            name = data.draw(st.sampled_from(NAMES + OTHERS))
            self._commit(admin, [("member.add", admin, {
                "user_id": IDS[name], "signing_pk": self.current(name).pk,
                "encryption_pk": self.current(name).enc, "role": "member",
            })])
        elif op == "remove":
            name = data.draw(st.sampled_from(NAMES))
            self._commit(admin, [("member.remove", admin, {"user_id": IDS[name]})])
        elif op == "folder":
            folder = data.draw(st.sampled_from(FOLDERS))
            gens = self.state.folders.get(folder, [])
            self._commit(admin, [("folder.key", admin, {
                "folder": folder, "gen": len(gens), "dek_id": _dek(len(self.records)),
                "prev_dek_id": gens[-1][0] if gens else None,
            })])
        elif op == "access":
            folder = data.draw(st.sampled_from(FOLDERS))
            name = data.draw(st.sampled_from(NAMES))
            level = data.draw(st.sampled_from(["read", "write", None]))
            self._commit(admin, [("access.set", admin, {"folder": folder, "user_id": IDS[name], "level": level})])
        elif op == "rotate":
            name = data.draw(st.sampled_from(active))
            new = self.keys.new()
            self._commit(name, [_rotation(self.state, name, new)], rotate=new)
        else:
            name = data.draw(st.sampled_from(active))
            self._commit(admin, [
                ("member.role", admin, {"user_id": IDS[name], "role": "admin"}),
                ("member.role", admin, {"user_id": IDS[admin], "role": "member"}),
            ])


def _dek(n: int) -> str:
    return "0K" + f"{n:024d}"


def _rotation(state, name: str, new: Key) -> tuple:
    uid = IDS[name]
    sig = new.sk.sign(teamlog.new_key_message(state.head_hash, uid, new.pk, new.enc)).signature.hex()
    return ("member.keys", name, {"user_id": uid, "signing_pk": new.pk, "encryption_pk": new.enc,
                                  "new_key_sig": sig})


class Forger:
    """A member that signs whatever its keys allow on top of a log it chose."""

    def __init__(self, honest: Honest, me: str, state, stolen: str | None = None):
        """``stolen``: an account whose current identity key the forger holds
        too (review e443cbc H3); it signs in and appends as that account."""
        self.honest, self.me, self.state = honest, me, state
        self.held: list[Key] = list(honest.account[me])  # its own account's keys
        if stolen is not None:
            self.held.append(honest.current(stolen))
        self.records: list[dict] = []
        self.labels: list[str] = []
        self.rules = state.rules or teamlog.FORMAT_VERSION

    def _key_of(self, uid: str):
        member = self.state.members.get(uid)
        return next((k for k in self.held if member is not None and k.pk == member.signing_pk), None)

    def _try(self, kind: str, author: str, data: dict, key: Key) -> None:
        body = teamlog.next_body(self.state, kind, author, data)
        body["v"] = self.rules  # a log still at rules 1 takes rules 1 records on replay
        record = teamlog.sign_record(body, key.sk)
        try:
            self.state = teamlog.apply_record(self.state, record)
        except teamlog.TeamLogError:
            return
        self.records.append(record)
        self.labels.append(f"{kind}({NAME_OF.get(author, '?')}->{NAME_OF.get(data.get('user_id'), '-')})")

    def _keys_for(self, data, target: str) -> tuple[str, str]:
        # A real account's public keys pass a check of the final keys; the
        # forger's own keys are the ones it can sign with later.
        choice = data.draw(st.sampled_from(["real", "real", "real", "own", "fresh"]))
        if choice == "real" and target in self.honest.account:
            key = self.honest.current(target)  # a real account's public keys
        elif choice == "own":
            key = self.held[-1]
        else:
            key = self.honest.keys.new()
            self.held.append(key)
        return key.pk, key.enc

    def genesis(self, data) -> None:
        founder = data.draw(st.sampled_from(("A",) + NAMES + (MADE_UP,)))  # A: the real admin
        own = data.draw(st.sampled_from((False, False, True)))
        key = self.held[-1] if own else self.honest.keys.new()
        self.held.append(key)
        self._try("genesis", IDS[founder], {
            "org": "0H" + "0" * 24, "user_id": IDS[founder], "signing_pk": key.pk, "encryption_pk": key.enc,
        }, key)

    def step(self, data) -> None:
        """One record the rules take: the draws only pick among such moves, so
        short examples reach deep forgeries."""
        members = self.state.members
        mine = sorted(uid for uid, m in members.items() if m.active and self._key_of(uid))
        if not mine:
            return
        admins = [uid for uid in mine if members[uid].role == "admin"]
        kinds = ["member.keys"]
        if admins:
            kinds = ["member.add"] * 3 + ["member.remove"] * 3 + ["member.role"] * 2 + kinds + [
                "folder.key", "access.set", "org.recovery"]
        if self.state.rules == 1 and data.draw(st.booleans()):
            self.rules = data.draw(st.sampled_from(teamlog.RULES_VERSIONS))
        kind = data.draw(st.sampled_from(kinds))
        author = data.draw(st.sampled_from(mine if kind == "member.keys" else admins))
        key = self._key_of(author)
        everyone = NAMES + (MADE_UP,) + OTHERS
        if kind == "org.recovery":
            self._try(kind, author, {"recovery_pk": self.honest.keys.recovery_pk()}, key)
            return
        active = [n for n in everyone if IDS[n] in members and members[IDS[n]].active]
        if kind == "member.add":
            outside = [n for n in everyone if n not in active]
            if not outside:
                return
            target = data.draw(st.sampled_from(outside))
            pk, enc = self._keys_for(data, target)
            role = data.draw(st.sampled_from(("admin", "admin", "member")))
            self._try(kind, author, {"user_id": IDS[target], "signing_pk": pk, "encryption_pk": enc, "role": role}, key)
        elif kind == "member.remove":
            target = data.draw(st.sampled_from(active))
            self._try(kind, author, {"user_id": IDS[target]}, key)
        elif kind == "member.role":
            target = data.draw(st.sampled_from(active))
            role = "member" if members[IDS[target]].role == "admin" else "admin"
            self._try(kind, author, {"user_id": IDS[target], "role": role}, key)
        elif kind == "member.keys":
            new = self.honest.keys.new()
            self.held.append(new)
            _, name, payload = _rotation(self.state, NAME_OF[author], new)
            self._try(kind, author, payload, key)
        elif kind == "folder.key":
            folder = data.draw(st.sampled_from(FOLDERS))
            gens = self.state.folders.get(folder, [])
            self._try(kind, author, {
                "folder": folder, "gen": len(gens), "dek_id": _dek(10_000 + self.state.head_seq),
                "prev_dek_id": gens[-1][0] if gens else None,
            }, key)
        else:
            folder = data.draw(st.sampled_from(FOLDERS))
            target = data.draw(st.sampled_from(everyone))
            level = data.draw(st.sampled_from(["read", "write", None]))
            self._try(kind, author, {"folder": folder, "user_id": IDS[target], "level": level}, key)


# What a restore may take that an append would refuse, and why it gives nobody
# more than the main path (docs/ROOT_CAUSE_PLAN.md S5: an exception is a
# recorded decision, never a special case in the code alone). The oracle
# grants exactly these and nothing else.
RESTORE_EXCEPTIONS = {
    # server/app/team_log.py _refuse_restored_keys, row is None (review 8595ec1 #1):
    # a backup older than a member's registration lost the account the log
    # names, and refusing the log locked the whole team out.
    "E2 member without an account": (
        "an admin-signed member.add of an id the server has no account for. It "
        "grants nothing until POST /auth/rejoin, which creates the account only "
        "with the keys the log holds for that id; the log's admin, the only one "
        "who signs a member.add, provisions accounts on the main path anyway"
    ),
    # server/app/team_log.py _refuse_rules_beyond_appends, todays_rules (review
    # e443cbc H3; E3 "one admin at the end" is gone: a restore holds the
    # one-admin rule wherever the author changes, as the appends did).
    "E4 records under older rules": (
        "a log founded before the rules tightened keeps its rules for its records "
        "(a version never goes down), and an append takes only today's. A restore "
        "takes such a record only where today's rules take the same change "
        "(the oracle replays it under them), so it changes the log as a "
        "today's record of the same author would"
    ),
    # server/app/team_log.py _refuse_superseded_recovery, uploader (review e443cbc H3).
    "E5 own org recovery": (
        "the uploader's own org.recovery naming a key its stored blob does not "
        "hold: after a backup the blob is older than the log, and refusing it "
        "locked the team out of its log. On the main path its author stores a "
        "blob for any key (recovery.store) and names it; a member's restore of "
        "another admin's such record is refused"
    ),
}


def _no_account(db, uid: str) -> bool:
    return not any(u["id"] == uid for u in db._storage["users"])


class NormalPath:
    """Would the main path get the server where the restore did?

    The records shared with the honest history existed once; the rest must be
    appends of accounts the uploader controls, in order, or one of
    RESTORE_EXCEPTIONS. Records go in as few appends as the main path allows:
    one author per append and one new identity per push (member.keys ends an
    append)."""

    def __init__(self, server: dict, me: str, stolen: str | None = None, held: tuple = ()):
        """``held``: the identity keys the uploader holds (its own, a stolen one)."""
        self.db = _db(server)
        self.held = {key.pk for key in held}
        self.kept = [{"body": r["body"], "sig": r["sig"]}
                     for r in sorted(server.get("team_log", []), key=lambda r: r["seq"])]
        self.me = me
        # accounts whose appends the uploader can make (a stolen identity key
        # signs in as its account: review c78fd19 #2)
        self.mine = {IDS[me]} | ({IDS[stolen]} if stolen else set())
        self.provisioned: set[str] = set()  # E2
        self.batch: list[tuple[int, dict]] = []

    def _send(self) -> str:
        if not self.batch:
            return ""
        author = self.batch[0][1]["author"]
        rotation = next((b["data"] for _, b, _ in self.batch if b["type"] == "member.keys"), None)
        pending = (rotation["signing_pk"], rotation["encryption_pk"]) if rotation else None
        records = [record for _, _, record in self.batch]
        named = [b["data"]["recovery_pk"] for _, b, _ in self.batch if b["type"] == "org.recovery"]
        if named and named[-1] is not None and author == IDS[self.me]:
            coverage_event("restore exception E5 own org recovery")  # store first, as every client does
            self.db._storage["org_recovery_blobs"] = [{
                "id": 1, "created_by": author, "recovery_signing_pk": bytes.fromhex(named[-1]),
            }]
        self._send_lost_rotations()
        rules = self.batch[0][1]["v"]
        if rules < teamlog.FORMAT_VERSION:  # E4: the append as today's records of the same changes
            coverage_event("restore exception E4 records under older rules")
            with mock.patch.object(team_log.core, "FORMAT_VERSION", rules):
                done = append(self.db, records, author, pending)
        else:
            done = append(self.db, records, author, pending)
        kinds = ", ".join(f"{i} {body['type']}" for i, body, _ in self.batch)
        self.batch.clear()
        if not done:
            return f"POST /api/team-log refuses records [{kinds}] from {NAME_OF[author]}: {REFUSALS[-1:]}"
        if pending:
            _set_row_keys(self.db, author, *pending)
        return ""

    def _send_lost_rotations(self) -> None:
        """An account of the uploader's whose rotation the server lost (it
        signs in with a key the log retired) sends the rotation again: a
        session that proves the log's current key may (server/app/dependencies.py,
        capability runs 294/300), and the uploader holds that key."""
        rows = self.db._storage["team_log"]
        state = teamlog.replay([{"body": r["body"], "sig": r["sig"]} for r in sorted(rows, key=lambda r: r["seq"])])
        for uid in sorted(self.mine):
            row = next((u for u in self.db._storage["users"] if u["id"] == uid), None)
            member = state.members.get(uid)
            if (row is None or row["status"] != "active" or member is None or not member.active
                    or member.signing_pk not in self.held
                    or not team_log.key_retired(state, uid, row["signing_pk"])):
                continue
            coverage_event("main path: a device sends the rotation the server lost again")
            _set_row_keys(self.db, uid, member.signing_pk, member.encryption_pk)

    def _provision(self, data: dict) -> None:
        """E2, as its reason says: the admin provisions the account first, and
        whoever holds its keys signs in as it (POST /auth/rejoin)."""
        coverage_event("restore exception E2 member without an account")
        if data["user_id"] not in self.provisioned:  # a re-add provisions the keys again
            _create_regular_user(self.db._storage, data["user_id"], f"provisioned-{data['user_id'].lower()}")
            self.provisioned.add(data["user_id"])
            self.mine.add(data["user_id"])
        _set_row_keys(self.db, data["user_id"], data["signing_pk"], data["encryption_pk"])

    def takes(self, honest: list, upload: list) -> str:
        """'' when it does, else why not."""
        shared = 0
        while shared < min(len(upload), len(honest)) and upload[shared] == honest[shared]:
            shared += 1
        put_back(self.db, upload[:shared])
        return self._walk(upload, shared)

    def _walk(self, upload: list, start: int) -> str:
        for i in range(start, len(upload)):
            record = upload[i]
            body = teamlog.parse_body(record["body"])
            if body["author"] not in self.mine:
                return f"record {i} ({body['type']}) is signed as {NAME_OF.get(body['author'], '?')}, not by {self.me}"
            if body["v"] < teamlog.FORMAT_VERSION and (why := _todays_rules_refuse(self.kept + upload[:i], body)):
                return f"record {i} ({body['type']}) under rules {body['v']}: today's rules refuse it ({why})"
            # One author and one rules version per append; one new identity
            # per push (review e443cbc H3: records after it may share the append).
            if self.batch and (self.batch[0][1]["author"] != body["author"]
                               or self.batch[0][1]["v"] != body["v"]) and (why := self._send()):
                return why
            if body["type"] == "member.keys" and any(b["type"] == "member.keys" for _, b, _ in self.batch):
                # one new identity per push: cut after the batch's member.keys
                first = next(k for k, (_, b, _) in enumerate(self.batch) if b["type"] == "member.keys")
                return self._cut(upload, i, first + 1)
            uid = body["data"].get("user_id")
            if body["type"] == "member.add" and uid in self.provisioned and self._new_keys(body["data"]):
                # the admin provisions the account again with the record's keys,
                # between appends, after the batch's last record naming its keys
                about = [k for k, (_, b, _) in enumerate(self.batch)
                         if b["data"].get("user_id") == uid and "signing_pk" in b["data"]]
                return self._cut(upload, i, about[-1] + 1 if about else 0)
            self._take(i, body, record)
        return self._send()

    def _new_keys(self, data: dict) -> bool:
        row = next(u for u in self.db._storage["users"] if u["id"] == data["user_id"])
        return (row["signing_pk"], row["encryption_pk"]) != (
            bytes.fromhex(data["signing_pk"]), bytes.fromhex(data["encryption_pk"]))

    def _take(self, i: int, body: dict, record: dict) -> None:
        uid = body["data"].get("user_id")
        if body["type"] == "member.add" and (_no_account(self.db, uid) or uid in self.provisioned):
            self._provision(body["data"])
        self.batch.append((i, body, record))

    def _cut(self, upload: list, i: int, earliest: int) -> str:
        """Record ``i`` cannot join the batch: the append must end at least
        ``earliest`` records into it, anywhere up to record ``i``. The server
        checks the one-admin rule on the head each append leaves, so one cut
        can pass where another is refused (an admin added before the cut and
        the old admin removed after it)."""
        saved = copy.deepcopy(self.db._storage), set(self.provisioned), set(self.mine), list(self.batch)
        body = teamlog.parse_body(upload[i]["body"])
        refused = ""
        for keep in range(len(saved[3]), earliest - 1, -1):
            self.db._storage = copy.deepcopy(saved[0])
            self.provisioned, self.mine = set(saved[1]), set(saved[2])
            self.batch, rest = list(saved[3][:keep]), list(saved[3][keep:])
            why = self._send()
            if not why:
                self.batch = rest  # the next append starts with them, then record i
                self._take(i, body, upload[i])
                why = self._walk(upload, i + 1)
            if not why:
                if keep < len(saved[3]):
                    coverage_event("normal path cuts an append early")
                return ""
            refused = refused or why
        return refused


def _todays_rules_refuse(before: list, body: dict) -> str:
    """E4: the change of ``body`` replayed under today's rules on the log
    ``before`` it ('' when they take it)."""
    if body["type"] == "genesis":
        return ""  # a fresh log retired no key
    state = teamlog.replay(before)
    state.rules = teamlog.FORMAT_VERSION
    try:
        teamlog._apply_change(state, body["seq"], body["type"], body["author"], body["data"], body["prev"])
    except teamlog.TeamLogError as exc:
        return exc.code
    return ""


@settings(
    max_examples=EXAMPLES or 2000, deadline=None, derandomize=not EXAMPLES, print_blob=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(data=st.data())
def test_restore_takes_nothing_the_normal_path_refuses(data):
    keys = Keys()
    honest = Honest(keys, legacy=data.draw(st.sampled_from((False, False, True)), label="rules 1 log"))
    for _ in range(data.draw(st.integers(0, 6), label="honest steps")):
        honest.step(data)
    # The server lost its log (users current) or came back from a backup.
    lost = data.draw(st.sampled_from((True, True, False)), label="log lost")
    if lost:
        kept, storage = 0, copy.deepcopy(honest.snapshots[-1][1])
        storage["team_log"] = []
    else:
        kept, storage = data.draw(st.sampled_from(honest.snapshots[:-1] or honest.snapshots), label="backup")
    me = data.draw(st.sampled_from(("B", "C", "A")), label="uploader")
    if not _active(_db(storage), IDS[me]):
        return
    stolen = data.draw(st.sampled_from((None, None, None) + tuple(n for n in NAMES if n != me)),
                       label="identity key it stole")

    upto = data.draw(st.one_of(st.just(kept), st.integers(kept, len(honest.records))),
                     label="honest records uploaded")
    state = teamlog.replay(honest.records[:upto]) if upto else teamlog.TeamState()
    forger = Forger(honest, me, state, stolen)
    if upto == 0:
        forger.genesis(data)
    for _ in range(data.draw(st.integers(0, 8), label="forged attempts")):
        forger.step(data)
    upload = honest.records[kept:upto] + forger.records
    if not upload:
        return
    coverage_event(f"forged={len(forger.records)} lost={lost}")

    if not restore(_db(storage), upload, IDS[me]):
        coverage_event("restore refused")
        return
    coverage_event(f"restore took forged={len(forger.records)}")
    target(float(len(forger.records)), label="forged records a restore took")
    why = NormalPath(storage, me, stolen, forger.held).takes(honest.records[kept:], upload)
    assert not why, (
        f"restore by {me} took more than the normal path would: {why}\n"
        f"honest kept on the server: {kept}, honest uploaded: {upto - kept}, "
        f"forged: {forger.labels}"
    )


@settings(
    max_examples=EXAMPLES or 2000, deadline=None, derandomize=not EXAMPLES, print_blob=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
@given(data=st.data())
def test_the_admin_puts_back_the_honest_history(data):
    """Review e443cbc H3: a restore at least takes what existed (INV-7: a team
    whose server lost its log has a way back). Once a member was re-added, the
    restore refused the honest history for good. The team admin of the
    honest log uploads every record the server lost."""
    keys = Keys()
    honest = Honest(keys, legacy=data.draw(st.sampled_from((False, False, True)), label="rules 1 log"))
    for _ in range(data.draw(st.integers(0, 8), label="honest steps")):
        honest.step(data)
    lost = data.draw(st.sampled_from((True, True, False)), label="log lost")
    if lost:
        kept, storage = 0, copy.deepcopy(honest.snapshots[-1][1])
        storage["team_log"] = []
    else:
        kept, storage = data.draw(st.sampled_from(honest.snapshots[:-1] or honest.snapshots), label="backup")
    upload = honest.records[kept:]
    admin = IDS[honest.admin()]
    if not upload or not _active(_db(storage), admin):
        return
    coverage_event(f"honest restore of {len(upload)} records")
    REFUSED.clear()
    assert restore(_db(storage), upload, admin), (
        f"the admin could not put back the honest history: {REFUSED[-1:]}\n"
        f"kept on the server: {kept}, uploaded: {[teamlog.parse_body(r['body'])['type'] for r in upload]}"
    )


# Counterexamples the property found, kept as fixed regression cases.

def _handed_over_to_c() -> tuple[Honest, dict]:
    """A founds, adds C and hands the role over; then the server loses its log."""
    honest = Honest(Keys())
    admin = honest.admin()
    assert honest._commit(admin, [("member.add", admin, {
        "user_id": IDS["C"], "signing_pk": honest.current("C").pk,
        "encryption_pk": honest.current("C").enc, "role": "member",
    })])
    assert honest._commit(admin, [
        ("member.role", admin, {"user_id": IDS["C"], "role": "admin"}),
        ("member.role", admin, {"user_id": IDS[admin], "role": "member"}),
    ])
    storage = copy.deepcopy(honest.snapshots[-1][1])
    storage["team_log"] = []
    return honest, storage


def test_counterexample_the_admin_re_adds_a_member_on_keys_of_its_own():
    """Found by the property on main@099d298: the admin removed A and re-added it
    on keys it holds; the account still signs in with keys the log once gave A,
    which the restore took for a rotation the server lost (_rotation_lost_here).
    The admin then signs as A and reads what is sealed to A."""
    honest, storage = _handed_over_to_c()
    forger = Forger(honest, "C", teamlog.replay(honest.records))
    key = forger._key_of(IDS["C"])
    forger._try("member.remove", IDS["C"], {"user_id": IDS["A"]}, key)
    fresh = honest.keys.new()
    forger.held.append(fresh)
    forger._try("member.add", IDS["C"], {
        "user_id": IDS["A"], "signing_pk": fresh.pk, "encryption_pk": fresh.enc, "role": "member",
    }, key)
    assert forger.labels == ["member.remove(C->A)", "member.add(C->A)"]
    upload = honest.records + forger.records

    assert NormalPath(storage, "C").takes(honest.records, upload)  # the main path refuses
    assert not restore(_db(storage), upload, IDS["C"])


def _handover_to_a_lost_rotation() -> tuple[Honest, int, dict, list]:
    """A adds B, B rotates; the server comes back from the backup before the
    rotation. A then hands the role to B and leaves (records the server never had)."""
    honest = Honest(Keys())
    assert honest._commit("A", [("member.add", "A", {
        "user_id": IDS["B"], "signing_pk": honest.current("B").pk,
        "encryption_pk": honest.current("B").enc, "role": "member",
    })])
    new = honest.keys.new()
    assert honest._commit("B", [_rotation(honest.state, "B", new)], rotate=new)
    kept, storage = honest.snapshots[1]
    forger = Forger(honest, "A", teamlog.replay(honest.records))
    key = forger._key_of(IDS["A"])
    forger._try("member.role", IDS["A"], {"user_id": IDS["B"], "role": "admin"}, key)
    forger._try("member.remove", IDS["A"], {"user_id": IDS["A"]}, key)
    assert forger.labels == ["member.role(A->B)", "member.remove(A->A)"]
    return honest, kept, storage, forger.records


def test_counterexample_the_admin_role_to_a_rotation_the_server_lost():
    """Nightly stateful-deep run 45009540361 on 2c6b22e (R15-N1): the restore
    made B the only admin while its account signed in with the key B's lost
    rotation retired. An append refuses that role until B sends its rotation
    again (readmit it first); no device of B was there to do it."""
    honest, kept, storage, forged = _handover_to_a_lost_rotation()
    upload = honest.records[kept:] + forged
    forger_keys = tuple(honest.account["A"])

    assert NormalPath(storage, "A", None, forger_keys).takes(honest.records[kept:], upload)  # main path refuses
    REFUSED.clear()
    assert not restore(_db(storage), upload, IDS["A"])
    assert "admin on keys it does not sign in with" in str(REFUSED[-1:])


def test_the_member_with_the_lost_rotation_uploads_the_handover_itself():
    """The same records from B's device (holding A's key too): on the main path
    B sends its rotation again and A's append takes the role; so does the restore."""
    honest, kept, storage, forged = _handover_to_a_lost_rotation()
    upload = honest.records[kept:] + forged
    held = tuple(honest.account["B"]) + (honest.current("A"),)

    assert not NormalPath(storage, "B", "A", held).takes(honest.records[kept:], upload)
    REFUSED.clear()
    assert restore(_db(storage), upload, IDS["B"]), REFUSED[-1:]


def test_counterexample_a_recovery_key_the_same_batch_retires():
    """Nightly stateful-deep run 45604036980 on d441587 (R16-N3): A stored its
    recovery blob and named it; the server lost its log. C, holding A's key,
    put back a log in which A names another recovery key, makes B admin and
    leaves. The restore took it: at its end A is no admin, so A's record
    names no current recovery (teamlog.recovery_key) and voids no shares.
    The append refused the same batch (org_recovery_superseded) though it
    ends the same way."""
    honest = Honest(Keys())
    pk = honest.keys.recovery_pk()
    honest.db._storage["org_recovery_blobs"] = [{
        "id": 1, "created_by": IDS["A"], "recovery_signing_pk": bytes.fromhex(pk),
    }]
    assert honest._commit("A", [("org.recovery", "A", {"recovery_pk": pk})])
    storage = copy.deepcopy(honest.snapshots[-1][1])
    storage["team_log"] = []
    forger = Forger(honest, "C", teamlog.TeamState(), stolen="A")
    key = honest.current("A")
    forger._try("genesis", IDS["A"], {
        "org": "0H" + "0" * 24, "user_id": IDS["A"], "signing_pk": key.pk, "encryption_pk": key.enc,
    }, key)
    forger._try("org.recovery", IDS["A"], {"recovery_pk": honest.keys.recovery_pk()}, key)
    forger._try("member.add", IDS["A"], {
        "user_id": IDS["B"], "signing_pk": honest.current("B").pk,
        "encryption_pk": honest.current("B").enc, "role": "admin",
    }, key)
    forger._try("member.remove", IDS["A"], {"user_id": IDS["A"]}, key)
    assert forger.labels == ["genesis(A->A)", "org.recovery(A->-)", "member.add(A->B)", "member.remove(A->A)"]

    REFUSED.clear()
    assert restore(_db(storage), forger.records, IDS["C"]), REFUSED[-1:]
    why = NormalPath(storage, "C", "A", forger.held).takes([], forger.records)
    assert not why, why  # the append takes it as well


def _lost_log() -> tuple[Honest, dict, Forger]:
    """A founds the log; the server loses it. A forges on top of the honest history."""
    honest = Honest(Keys())
    storage = copy.deepcopy(honest.snapshots[-1][1])
    storage["team_log"] = []
    return honest, storage, Forger(honest, "A", teamlog.replay(honest.records))


def test_a_restore_holds_the_users_checks_on_its_history():
    """Mutant R1 (4503b79, H3), which the per-push property missed on d441587
    (nightly 45604036980, R16-N4): a restored member.add of an account still
    waiting for approval. The append refuses it; so must the restore."""
    honest, storage, forger = _lost_log()
    key = honest.current("A")
    forger._try("member.add", IDS["A"], {
        "user_id": IDS[WAITING], "signing_pk": honest.current(WAITING).pk,
        "encryption_pk": honest.current(WAITING).enc, "role": "member",
    }, key)
    assert forger.labels == [f"member.add(A->{WAITING})"]
    upload = honest.records + forger.records

    assert NormalPath(storage, "A").takes(honest.records, upload)  # the main path refuses
    REFUSED.clear()
    assert not restore(_db(storage), upload, IDS["A"])
    assert "approved account" in str(REFUSED[-1:])


def test_a_restore_holds_one_admin_between_two_rotations():
    """Mutant R5 (200d5e8), which the per-push property missed on d441587
    (nightly 45604036980, R16-N4): one author's records with two member.keys
    take two appends, the first ending between them. With B a second admin
    all the way through that span, no append could end there."""
    honest, storage, forger = _lost_log()
    old, first, second = honest.current("A"), honest.keys.new(), honest.keys.new()
    forger._try("member.add", IDS["A"], {
        "user_id": IDS["B"], "signing_pk": honest.current("B").pk,
        "encryption_pk": honest.current("B").enc, "role": "admin",
    }, old)
    kind, _, data = _rotation(forger.state, "A", first)
    forger._try(kind, IDS["A"], data, old)
    forger._try("folder.key", IDS["A"], {"folder": FOLDERS[0], "gen": 0, "dek_id": _dek(0), "prev_dek_id": None}, first)
    kind, _, data = _rotation(forger.state, "A", second)
    forger._try(kind, IDS["A"], data, first)
    forger._try("member.remove", IDS["A"], {"user_id": IDS["B"]}, second)
    assert forger.labels == [
        "member.add(A->B)", "member.keys(A->A)", "folder.key(A->-)", "member.keys(A->A)", "member.remove(A->B)",
    ]
    _set_keys_in(storage, "A", second)  # the account signs in with its last keys

    REFUSED.clear()
    assert not restore(_db(storage), honest.records + forger.records, IDS["A"])
    assert "more than one admin" in str(REFUSED[-1:])


def _set_keys_in(storage: dict, name: str, key: Key) -> None:
    row = next(u for u in storage["users"] if u["id"] == IDS[name])
    row["signing_pk"], row["encryption_pk"] = bytes.fromhex(key.pk), bytes.fromhex(key.enc)


@pytest.mark.parametrize("seed", property_seeds.load("test_inv2_restore_within_append.py"), ids=str)
def test_inv2_saved_counterexample(seed):
    """Review e443cbc P2: every counterexample in property_seeds.txt passes."""
    property_seeds.replay_given(globals()[seed.target], seed)
