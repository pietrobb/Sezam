"""Signed team log: replay and decisions (docs/DESIGN_TEAM_LOG.md).

The log is an append-only, hash-chained list of signed records that says who
is a member, who may access which shared folder, and which key is the
current key of a folder. Every client and the server replay it with the same
rules and answer the same questions only from the replayed state; anything
the log does not say is a "no".

This module is self-contained (PyNaCl + stdlib only) so that the server can
use the very same file. Web (web/static/js/teamlog.js) and mobile
(mobile/lib/services/team_log.dart) implement the same rules and must pass
tests/vectors/team_log.json.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

# A body's "v" names the rules its record is judged by (review 8595ec1, R10-B):
# a log stored under older rules still replays after the rules tighten, and a
# version never goes down along the log. 1 = before review 1141a20 (a member
# could get a retired key back); 2 = retired keys stay retired. New records
# are written with the newest version.
RULES_VERSIONS = (1, 2)
FORMAT_VERSION = RULES_VERSIONS[-1]
SIG_DOMAIN = b"sezam-team-log-v1\x00"
HASH_DOMAIN = b"sezam-team-log-hash-v1\x00"
NEW_KEY_DOMAIN = b"sezam-team-log-newkey-v1\x00"
ZERO_HASH = "0" * 64
MAX_INT = 2 ** 53 - 1

ROLES = ("admin", "member")
LEVELS = ("read", "write")

_ULID = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_HEX144 = re.compile(r"^[0-9a-f]{144}$")
_SAFE_STR = re.compile(r'^[\x20-\x21\x23-\x5b\x5d-\x7e]*$')

_BODY_FIELDS = {"v", "seq", "prev", "type", "author", "data"}

# type -> {field: kind}; kinds: ulid, hex64, hex128, hex144, role, level, int, ulid?
_DATA_SCHEMA: dict[str, dict[str, str]] = {
    "genesis": {"org": "ulid", "user_id": "ulid", "signing_pk": "hex64", "encryption_pk": "hex64"},
    "member.add": {"user_id": "ulid", "signing_pk": "hex64", "encryption_pk": "hex64", "role": "role"},
    "member.role": {"user_id": "ulid", "role": "role"},
    "member.remove": {"user_id": "ulid"},
    "member.keys": {
        "user_id": "ulid", "signing_pk": "hex64", "encryption_pk": "hex64", "new_key_sig": "hex128",
    },
    "folder.key": {"folder": "ulid", "gen": "int", "dek_id": "ulid", "prev_dek_id": "ulid?"},
    "access.set": {"folder": "ulid", "user_id": "ulid", "level": "level?"},
    # Review 8595ec1 (R10-D): the admin's org recovery key (null: none), from rules 2.
    "org.recovery": {"recovery_pk": "hex64?"},
    # Review 8595ec1 (capability run 316): the KEK wrap the shares of the
    # author's named recovery key open (web format: nonce || XChaCha20-Poly1305),
    # so a server restored from before the setup still serves it. From rules 2.
    "org.recovery.wrap": {"wrapped_kek": "hex144", "key_epoch": "int", "threshold": "int", "total_shares": "int"},
}
RECOVERY_TYPES = ("org.recovery", "org.recovery.wrap")


class TeamLogError(Exception):
    """A record breaks a rule. Replay stops; nothing may be decided from it."""

    def __init__(self, code: str, seq: Optional[int], detail: str = ""):
        self.code = code
        self.seq = seq
        super().__init__(f"team log record {seq}: {code}" + (f" ({detail})" if detail else ""))


# ── Canonical encoding ────────────────────────────────────────────────

def _check_value(value, seq) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        raise TeamLogError("bad_encoding", seq, "boolean")
    if isinstance(value, int):
        if not 0 <= value <= MAX_INT:
            raise TeamLogError("bad_encoding", seq, "integer out of range")
        return
    if isinstance(value, str):
        if not _SAFE_STR.fullmatch(value):
            raise TeamLogError("bad_encoding", seq, "string")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not _SAFE_STR.fullmatch(key):
                raise TeamLogError("bad_encoding", seq, "key")
            _check_value(item, seq)
        return
    raise TeamLogError("bad_encoding", seq, type(value).__name__)


def canonical(value, seq: Optional[int] = None) -> str:
    """The restricted canonical JSON of the design (§3.3)."""
    _check_value(value, seq)
    return _encode(value)


def _encode(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"' + value + '"'
    return "{" + ",".join(
        '"' + key + '":' + _encode(value[key]) for key in sorted(value, key=lambda k: k.encode())
    ) + "}"


def parse_body(body: str, seq: Optional[int] = None) -> dict:
    """Parse a transmitted body; it must already be in canonical form."""
    if not isinstance(body, str):
        raise TeamLogError("bad_encoding", seq, "body is not a string")

    def no_duplicates(pairs):
        out = {}
        for key, item in pairs:
            if key in out:
                raise TeamLogError("bad_encoding", seq, "duplicate key")
            out[key] = item
        return out

    try:
        parsed = json.loads(
            body, object_pairs_hook=no_duplicates,
            parse_float=lambda _: (_ for _ in ()).throw(TeamLogError("bad_encoding", seq, "float")),
            parse_constant=lambda _: (_ for _ in ()).throw(TeamLogError("bad_encoding", seq, "constant")),
        )
    except TeamLogError:
        raise
    except (ValueError, RecursionError) as exc:
        raise TeamLogError("bad_encoding", seq, "json") from exc
    if not isinstance(parsed, dict) or canonical(parsed, seq) != body:
        raise TeamLogError("bad_encoding", seq, "not canonical")
    return parsed


# ── Records ───────────────────────────────────────────────────────────

def _sig_message(body: str) -> bytes:
    return SIG_DOMAIN + body.encode("ascii")


def record_hash(record: dict) -> str:
    return hashlib.sha256(
        HASH_DOMAIN + record["body"].encode("ascii") + bytes.fromhex(record["sig"])
    ).hexdigest()


def new_key_message(prev: str, user_id: str, signing_pk: str, encryption_pk: str) -> bytes:
    return (
        NEW_KEY_DOMAIN + bytes.fromhex(prev) + user_id.encode("ascii")
        + bytes.fromhex(signing_pk) + bytes.fromhex(encryption_pk)
    )


def sign_record(body: dict, signing_key: SigningKey) -> dict:
    text = canonical(body, body.get("seq"))
    sig = signing_key.sign(_sig_message(text)).signature
    return {"body": text, "sig": sig.hex()}


# ── State ─────────────────────────────────────────────────────────────

@dataclass
class Member:
    user_id: str
    signing_pk: str
    encryption_pk: str
    role: str
    active: bool


@dataclass
class TeamState:
    org: str = ""
    genesis_hash: str = ""
    head_seq: int = -1
    head_hash: str = ZERO_HASH
    members: dict[str, Member] = field(default_factory=dict)
    # folder -> [(dek_id, author)] by generation
    folders: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    access: dict[str, dict[str, str]] = field(default_factory=dict)
    # folder -> members who lost access but may still know the current key
    stale: dict[str, set[str]] = field(default_factory=dict)
    seen_keys: dict[str, str] = field(default_factory=dict)  # pk hex -> user_id
    dek_index: dict[str, tuple[str, int]] = field(default_factory=dict)  # dek_id -> (folder, gen)
    # folder -> admins handed over while its current key was current: what
    # they sealed with it then is still theirs (review 1141a20, admin handover).
    former_admins: dict[str, set[str]] = field(default_factory=dict)
    rules: int = 0  # the rules version of the last record (0: no log yet)
    # admin -> org recovery signing key (hex): its proof replaces the admin's
    # password on any server, also one restored from before the registration.
    org_recovery: dict[str, str] = field(default_factory=dict)
    # admin -> the KEK wrap of that key (org.recovery.wrap data)
    org_recovery_wrap: dict[str, dict] = field(default_factory=dict)

    def to_json(self) -> dict:
        """Comparable form used by the decision vectors."""
        extra = {"org_recovery": dict(sorted(self.org_recovery.items()))} if self.org_recovery else {}
        if self.org_recovery_wrap:
            extra["org_recovery_wrap"] = {
                admin: dict(sorted(wrap.items())) for admin, wrap in sorted(self.org_recovery_wrap.items())
            }
        return {
            **extra,
            "rules": self.rules,
            "org": self.org,
            "genesis_hash": self.genesis_hash,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "members": {
                uid: {
                    "signing_pk": m.signing_pk, "encryption_pk": m.encryption_pk,
                    "role": m.role, "active": 1 if m.active else 0,
                }
                for uid, m in sorted(self.members.items())
            },
            "folders": {f: [dek for dek, _ in gens] for f, gens in sorted(self.folders.items())},
            "access": {f: dict(sorted(a.items())) for f, a in sorted(self.access.items()) if a},
            "stale": {f: sorted(s) for f, s in sorted(self.stale.items()) if s},
        }


def _validate_body(body: dict, seq: int) -> None:
    """Schema of a parsed body, checked in this exact order (the clients mirror it).

    Errors carry the record's position ``seq``.
    """
    if set(body) != _BODY_FIELDS:
        raise TeamLogError("bad_schema", seq, "body fields")
    if body["v"] not in RULES_VERSIONS:
        raise TeamLogError("bad_schema", seq, "version")
    if not isinstance(body["seq"], int):
        raise TeamLogError("bad_schema", seq, "seq")
    if not _is("hex64", body["prev"]):
        raise TeamLogError("bad_schema", seq, "prev")
    if not _is("ulid", body["author"]):
        raise TeamLogError("bad_schema", seq, "author")
    schema = _DATA_SCHEMA.get(body["type"]) if isinstance(body["type"], str) else None
    if schema is None or body["type"] in RECOVERY_TYPES and body["v"] < 2:
        raise TeamLogError("bad_schema", seq, "type")
    data = body["data"]
    if not isinstance(data, dict) or set(data) != set(schema):
        raise TeamLogError("bad_schema", seq, "data fields")
    for name, kind in schema.items():
        value = data[name]
        if value is None and kind.endswith("?"):
            continue
        if not _is(kind.rstrip("?"), value):
            raise TeamLogError("bad_schema", seq, name)


def _is(kind: str, value) -> bool:
    if kind in ("ulid", "hex64", "hex128", "hex144"):
        pattern = {"ulid": _ULID, "hex64": _HEX64, "hex128": _HEX128, "hex144": _HEX144}[kind]
        return isinstance(value, str) and pattern.fullmatch(value) is not None
    if kind == "role":
        return value in ROLES
    if kind == "level":
        return value in LEVELS
    return isinstance(value, int)  # "int"; booleans never get past canonical()


def _verify(pk_hex: str, message: bytes, sig_hex: str, seq: int, code: str = "bad_signature") -> None:
    try:
        VerifyKey(bytes.fromhex(pk_hex)).verify(message, bytes.fromhex(sig_hex))
    except (BadSignatureError, ValueError) as exc:
        raise TeamLogError(code, seq) from exc


def _claim_keys(state: TeamState, user_id: str, seq: int, *pks: str) -> None:
    for pk in pks:
        owner = state.seen_keys.get(pk)
        current = state.members.get(user_id)
        # Rules 2: a key the log retired stays retired, also for its owner.
        if owner is not None and (owner != user_id or state.rules >= 2 and (
            current is None or pk not in (current.signing_pk, current.encryption_pk)
        )):
            raise TeamLogError("key_reused", seq)
    if len(set(pks)) != len(pks):
        raise TeamLogError("key_reused", seq)
    for pk in pks:
        state.seen_keys[pk] = user_id


def todays_rules_refusal(state: TeamState, body: dict) -> Optional[str]:
    """What today's rules refuse in ``body``, a record its own older rules
    take on top of ``state`` (review e443cbc H3: a restore took rules 1
    records no append takes). Rules 2 differ only in a retired key: its
    owner does not get it back either."""
    if body["v"] >= FORMAT_VERSION or body["type"] not in ("genesis", "member.add", "member.keys"):
        return None
    data = body["data"]
    user_id = data["user_id"]
    current = state.members.get(user_id)
    for pk in (data["signing_pk"], data["encryption_pk"]):
        if state.seen_keys.get(pk) == user_id and (
            current is None or pk not in (current.signing_pk, current.encryption_pk)
        ):
            return f"record {body['seq']} gives {user_id} back a key the log retired (rules {FORMAT_VERSION})"
    return None


def signing_key_retired(state: Optional[TeamState], user_id: str, pk_hex: str) -> bool:
    """The log rotated ``user_id`` away from signing key ``pk_hex``.

    Capability run 294: a server restored from before a rotation still has
    the account on such a key. Its holder (the device the rotation shut out)
    signs nothing any client or the server takes as the member's current key.
    """
    member = state.members.get(user_id) if state is not None else None
    return (
        member is not None and member.signing_pk != pk_hex
        and state.seen_keys.get(pk_hex) == user_id
    )


def _active_admins(state: TeamState) -> int:
    return sum(1 for m in state.members.values() if m.active and m.role == "admin")


def _lose_access(state: TeamState, folder: str, user_id: str) -> None:
    state.access.get(folder, {}).pop(user_id, None)
    state.stale.setdefault(folder, set()).add(user_id)


def apply_record(state: TeamState, record: dict) -> TeamState:
    """Return the state after ``record``; raise TeamLogError and leave ``state`` untouched."""
    new = copy.deepcopy(state)
    _apply(new, record)
    return new


def _apply(new: TeamState, record: dict) -> None:
    state = new
    expected_seq = state.head_seq + 1
    if not isinstance(record, dict) or set(record) != {"body", "sig"}:
        raise TeamLogError("bad_schema", expected_seq, "record fields")
    if not _is("hex128", record["sig"]):
        raise TeamLogError("bad_schema", expected_seq, "sig")
    body = parse_body(record["body"], expected_seq)
    _validate_body(body, expected_seq)
    seq = body["seq"]
    if seq != expected_seq:
        raise TeamLogError("bad_seq", expected_seq)
    if body["prev"] != state.head_hash:
        raise TeamLogError("bad_prev", seq)
    if body["v"] < state.rules:
        raise TeamLogError("rules_downgrade", seq)
    new.rules = body["v"]

    kind, author, data = body["type"], body["author"], body["data"]
    message = _sig_message(record["body"])

    if kind == "genesis":
        if seq != 0:
            raise TeamLogError("bad_genesis", seq, "not first")
        if author != data["user_id"]:
            raise TeamLogError("bad_genesis", seq, "author")
        _verify(data["signing_pk"], message, record["sig"], seq)
        _claim_keys(new, author, seq, data["signing_pk"], data["encryption_pk"])
        new.org = data["org"]
        new.members[author] = Member(author, data["signing_pk"], data["encryption_pk"], "admin", True)
    else:
        if seq == 0:
            raise TeamLogError("bad_genesis", seq, "first record is not genesis")
        signer = new.members.get(author)
        if signer is None or not signer.active:
            raise TeamLogError("not_member", seq)
        _verify(signer.signing_pk, message, record["sig"], seq)
        if kind != "member.keys" and signer.role != "admin":
            raise TeamLogError("not_admin", seq)
        _apply_change(new, seq, kind, author, data, body["prev"])

    new.head_seq = seq
    new.head_hash = record_hash(record)
    if seq == 0:
        new.genesis_hash = new.head_hash


def _apply_change(new: TeamState, seq: int, kind: str, author: str, data: dict, prev: str) -> None:
    user_id = data.get("user_id")
    member = new.members.get(user_id) if user_id else None

    if kind == "member.add":
        if member is not None and member.active:
            raise TeamLogError("member_exists", seq)
        _claim_keys(new, user_id, seq, data["signing_pk"], data["encryption_pk"])
        new.members[user_id] = Member(user_id, data["signing_pk"], data["encryption_pk"], data["role"], True)

    elif kind == "member.role":
        if member is None or not member.active:
            raise TeamLogError("not_active", seq)
        if member.role == data["role"]:
            raise TeamLogError("unchanged", seq)
        if member.role == "admin" and _active_admins(new) == 1:
            raise TeamLogError("last_admin", seq)
        if member.role == "admin":
            for folder in new.folders:
                new.former_admins.setdefault(folder, set()).add(user_id)
            new.org_recovery.pop(user_id, None)
            new.org_recovery_wrap.pop(user_id, None)
        member.role = data["role"]

    elif kind == "member.remove":
        if member is None or not member.active:
            raise TeamLogError("not_active", seq)
        if member.role == "admin" and _active_admins(new) == 1:
            raise TeamLogError("last_admin", seq)
        member.active = False
        new.org_recovery.pop(user_id, None)
        new.org_recovery_wrap.pop(user_id, None)
        for folder, gens in new.folders.items():
            if user_id in new.access.get(folder, {}) or gens[-1][1] == user_id:
                _lose_access(new, folder, user_id)

    elif kind == "member.keys":
        if author != user_id:
            raise TeamLogError("not_self", seq)
        _verify(
            data["signing_pk"],
            new_key_message(prev, user_id, data["signing_pk"], data["encryption_pk"]),
            data["new_key_sig"], seq, code="bad_new_key_signature",
        )
        # Review e443cbc H1: two keys the member does not hold in either role
        # (a swap X -> Y -> X made the server's rotation walk loop for good).
        held = (member.signing_pk, member.encryption_pk)
        if data["signing_pk"] in held or data["encryption_pk"] in held:
            raise TeamLogError("key_reused", seq)
        _claim_keys(new, user_id, seq, data["signing_pk"], data["encryption_pk"])
        member.signing_pk = data["signing_pk"]
        member.encryption_pk = data["encryption_pk"]

    elif kind == "folder.key":
        folder, gens = data["folder"], new.folders.get(data["folder"])
        if data["dek_id"] in new.dek_index:
            raise TeamLogError("dek_reused", seq)
        if gens is None:
            if data["gen"] != 0 or data["prev_dek_id"] is not None:
                raise TeamLogError("bad_generation", seq)
            gens = new.folders[folder] = []
        elif data["gen"] != len(gens) or data["prev_dek_id"] != gens[-1][0]:
            raise TeamLogError("bad_generation", seq)
        gens.append((data["dek_id"], author))
        new.dek_index[data["dek_id"]] = (folder, data["gen"])
        new.stale.pop(folder, None)
        new.former_admins.pop(folder, None)

    elif kind == "access.set":
        folder, level = data["folder"], data["level"]
        if folder not in new.folders:
            raise TeamLogError("folder_unknown", seq)
        current = new.access.get(folder, {}).get(user_id)
        if level is None:
            if current is None:
                raise TeamLogError("unchanged", seq)
            _lose_access(new, folder, user_id)
            return
        if member is None or not member.active:
            raise TeamLogError("not_active", seq)
        if current == level:
            raise TeamLogError("unchanged", seq)
        if current == "write" and level == "read":
            new.stale.setdefault(folder, set()).add(user_id)
        new.access.setdefault(folder, {})[user_id] = level

    elif kind == "org.recovery":
        pk = data["recovery_pk"]
        if new.org_recovery.get(author) == pk:
            raise TeamLogError("unchanged", seq)
        if pk in new.seen_keys:  # a member's key is no recovery key
            raise TeamLogError("key_reused", seq)
        new.org_recovery_wrap.pop(author, None)  # it wraps for the old key
        if pk is None:
            del new.org_recovery[author]
        else:
            new.org_recovery[author] = pk

    elif kind == "org.recovery.wrap":
        if author not in new.org_recovery:
            raise TeamLogError("no_recovery_key", seq)
        if not 1 <= data["threshold"] <= data["total_shares"] <= 255:
            raise TeamLogError("bad_shares", seq)
        if new.org_recovery_wrap.get(author) == data:
            raise TeamLogError("unchanged", seq)
        new.org_recovery_wrap[author] = dict(data)


def apply_change(state: TeamState, kind: str, author: str, data: dict) -> TeamState:
    """The state after ``author``'s own unsigned change, for local decisions only.

    Nothing about the head moves: the result is never a log to build on. Raises
    TeamLogError (``state`` untouched) when the rules refuse the change.
    """
    if kind in ("genesis", "member.keys"):
        raise TeamLogError("bad_schema", state.head_seq + 1, f"{kind} is not projected")
    new = copy.deepcopy(state)
    _apply_change(new, state.head_seq + 1, kind, author, data, state.head_hash)
    return new


def replay(records: list[dict], state: Optional[TeamState] = None) -> TeamState:
    """Replay ``records`` onto a copy of ``state`` (a fresh log when None).

    The whole call fails on the first bad record; ``state`` is never changed.
    """
    current = copy.deepcopy(state) if state is not None else TeamState()
    for record in records:
        _apply(current, record)
    return current


def replay_steps(records: list[dict], state: Optional[TeamState] = None):
    """Like ``replay``, yielding the state after each record.

    One copy for the whole batch: every step yields the same object, changed
    in place by the next record, so read what you need before going on.
    """
    current = copy.deepcopy(state) if state is not None else TeamState()
    for record in records:
        _apply(current, record)
        yield current


def next_body(state: TeamState, kind: str, author: str, data: dict) -> dict:
    """The body of the record that would follow ``state`` (to be signed)."""
    return {
        "v": FORMAT_VERSION, "seq": state.head_seq + 1, "prev": state.head_hash,
        "type": kind, "author": author, "data": data,
    }


# ── Decisions (design §4.3). Unknown is always "no". ──────────────────

def is_team_folder(state: TeamState, folder: str) -> bool:
    return folder in state.folders


def current_key(state: TeamState, folder: str) -> Optional[str]:
    gens = state.folders.get(folder)
    return gens[-1][0] if gens else None


def key_generation(state: TeamState, folder: str, dek_id: str) -> tuple[str, Optional[int]]:
    """('current', gen) / ('old', gen) / ('unknown', None) for a key of ``folder``."""
    found = state.dek_index.get(dek_id)
    if found is None or found[0] != folder:
        return ("unknown", None)
    gen = found[1]
    return ("current" if gen == len(state.folders[folder]) - 1 else "old", gen)


def is_stale(state: TeamState, folder: str) -> bool:
    return bool(state.stale.get(folder))


def may_seal(state: TeamState, folder: str) -> bool:
    """New content or keys may be sealed under the folder's current key."""
    return is_team_folder(state, folder) and not is_stale(state, folder)


def is_admin(state: TeamState, user_id: str) -> bool:
    member = state.members.get(user_id)
    return member is not None and member.active and member.role == "admin"


def recovery_key(state: Optional[TeamState], user_id: str) -> Optional[str]:
    """The org recovery key the log names for ``user_id``, an active admin."""
    if state is None or not is_admin(state, user_id):
        return None
    return state.org_recovery.get(user_id)


def recovery_wrap(state: Optional[TeamState], user_id: str) -> Optional[dict]:
    """The KEK wrap the log holds for that admin's named recovery key."""
    if recovery_key(state, user_id) is None:
        return None
    return state.org_recovery_wrap.get(user_id)


def may_write(state: TeamState, folder: str, user_id: str) -> bool:
    member = state.members.get(user_id)
    if member is None or not member.active or not is_team_folder(state, folder):
        return False
    return member.role == "admin" or state.access.get(folder, {}).get(user_id) == "write"


def key_recipients(state: TeamState, folder: str) -> list[tuple[str, str, str]]:
    """Exactly the members a new key of ``folder`` is sealed to: (user_id, encryption_pk, level)."""
    if not is_team_folder(state, folder):
        return []
    return [
        (uid, state.members[uid].encryption_pk, level)
        for uid, level in sorted(state.access.get(folder, {}).items())
        if state.members[uid].active
    ]


def may_hold_key(state: TeamState, user_id: str, dek_id: str) -> bool:
    found = state.dek_index.get(dek_id)
    member = state.members.get(user_id)
    if found is None or member is None or not member.active:
        return False
    folder, gen = found
    gens = state.folders[folder]
    if gen != len(gens) - 1:
        return False
    # Review 8bc70f7 M1: the admin holds every current key by the role, not
    # by an access.set a handover granted (it outlived the role: in A -> B ->
    # C, B kept write access to folders nobody had shared with B).
    return user_id in state.access.get(folder, {}) or gens[-1][1] == user_id or member.role == "admin"


def item_refusal(
    state: TeamState, user_id: str, obj_id: str, folder: Optional[str],
    dek_id: Optional[str], own_dek: bool, sealing: bool = True,
) -> Optional[str]:
    """Why a live folder/item by ``user_id`` sealed with ``dek_id`` is not valid, or None.

    ``sealing``: a new write (push). A pulled copy (``sealing=False``) is not
    refused only because the folder waits for a re-key: it was sealed before.

    ``folder`` is the team folder at or above the object's parent (None: no
    team rules); a folder node may also be sealed with its own key. A key the
    log knows must be the current generation of that folder, the folder must
    not wait for a re-key and the author must be allowed to write there. A key
    the log does not know is only the author's own personal key (``own_dek``,
    §4.3.6), and below a team folder even that needs write access there.
    The server (push) and every client (pull) decide by this.
    """
    def wrote(where: str) -> bool:
        # A pulled copy by an admin who handed the role over while the
        # folder's current key was current was written while admin.
        if may_write(state, where, user_id):
            return True
        member = state.members.get(user_id)
        return (
            not sealing and member is not None and member.active
            and user_id in state.former_admins.get(where, ())
        )

    found = state.dek_index.get(dek_id) if dek_id else None
    if found is None:
        if folder is None:
            return None
        if not own_dek:
            return "sealed with a key the team log does not know"
        if not wrote(folder):
            return "team log gives no write access here"
        return None
    key_folder = found[0]
    if key_folder not in (folder, obj_id):
        return "sealed with another folder's team key"
    if key_generation(state, key_folder, dek_id)[0] != "current":
        return "sealed with an old key generation"
    if sealing and not may_seal(state, key_folder):
        return "folder waits for a re-key"
    if not wrote(key_folder):
        return "team log gives no write access here"
    return None


def admin_policy_refusal(state: TeamState) -> Optional[str]:
    """TL7: one active admin per organisation. Records may pass through two
    (a handover in one append), a head every client follows may not; the
    server refuses such an append, a client a log it serves."""
    if sum(1 for uid in state.members if is_admin(state, uid)) > 1:
        return "more than one admin"
    return None


def readmitted(bodies: list[dict], index: int) -> Optional[int]:
    """Where the member.remove ``bodies[index]`` is undone by its author's
    member.add of the same account in the same run of that author's records
    (one append on the main path: a readmit, no removal for share links)."""
    body = bodies[index]
    if body["type"] != "member.remove":
        return None
    for later in range(index + 1, len(bodies)):
        other = bodies[later]
        if other["author"] != body["author"]:
            return None
        if other["type"] == "member.add" and other["data"].get("user_id") == body["data"].get("user_id"):
            return later
    return None


def restore_part_end(bodies: list[dict], start: int, limit: int) -> int:
    """Review c02cc47 R17-L (tests/vectors/team_log_restore_parts.json): the
    end (exclusive) of a restore upload part from ``start``, at most
    ``limit`` records. Not inside a readmit: split, the server took the
    removal alone and deleted the member's share links. A readmit longer
    than ``limit`` is split anyway."""
    end = min(start + limit, len(bodies))
    if end == len(bodies):
        return end
    for index in range(start, end):
        undone = readmitted(bodies, index)
        if undone is not None and undone >= end:
            return index if index > start else end
    return end


def change_key(body: dict) -> str:
    """The change a record made, as a device makes it again on another head:
    a folder.key's generation and a member.keys' proof are bound to the head."""
    data = {k: v for k, v in body["data"].items() if k not in ("gen", "new_key_sig")}
    return canonical({"type": body["type"], "data": data})


def fork_refusal(
    lost: list[dict], theirs: list[dict], user_id: Optional[str],
    held_keys: Optional[tuple[str, str]], withdrawn,
) -> tuple[Optional[str], list[int]]:
    """Whether a device follows a server log that forks from its copy (review
    18c300f R16-H1, tests/vectors/team_log_fork.json).

    ``lost``: the device's records from the fork on; ``theirs``: the server's.
    A server keeps every record a device signed, also one it refused or one
    the device withdrew; a fork built of them handed the admin role over or
    named keys nobody holds. So: no record of this account in ``theirs`` that
    the device withdrew (``withdrawn``: record hashes); no role change and no
    member added by this account there that was not lost here; no key change of this account there
    unless it was lost here or names the keys this device holds
    (``held_keys``: signing, encryption pk hex). Every lost change of another
    account is on the server's side (its device made it again there); this
    account's own that are not are returned by seq, for the device to make
    again. (reason, []) refuses; (None, missing seqs) follows.
    """
    lost_bodies = [parse_body(record["body"]) for record in lost]
    their_bodies = [parse_body(record["body"]) for record in theirs]
    was = {change_key(body) for body in lost_bodies}
    for record, body in zip(theirs, their_bodies):
        if user_id is None or body["author"] != user_id:
            continue
        seq = body["seq"]
        if record_hash(record) in withdrawn:
            return f"its record {seq} is one this device withdrew", []
        if body["type"] == "member.role" and change_key(body) not in was:
            return f"its record {seq} changes a role this device did not lose", []
        if body["type"] == "member.add" and change_key(body) not in was:
            return f"its record {seq} adds a member this device did not lose", []
        if body["type"] == "member.keys" and change_key(body) not in was and (
                held_keys is None
                or (body["data"]["signing_pk"], body["data"]["encryption_pk"]) != tuple(held_keys)):
            return f"its record {seq} names keys this device does not hold", []
    made = {change_key(body) for body in their_bodies}
    for first, second in zip(lost_bodies, lost_bodies[1:]):
        # A readmit (member.remove + member.add of one member, one append)
        # is on the server's side whole or not at all.
        if (first["type"], second["type"]) == ("member.remove", "member.add") and \
                first["data"]["user_id"] == second["data"]["user_id"] and \
                (change_key(first) in made) != (change_key(second) in made):
            return f"it holds one half of the readmit at record {first['seq']}", []
    # R16-Z SM21: a stale device of this account put the lost log back with
    # one link onto the keys this device holds; the rotations lost here in
    # between are moot (the server's side ends on the same keys).
    own_keys = [body["data"] for body in their_bodies if body["type"] == "member.keys"
                and user_id is not None and body["author"] == user_id and body["data"]["user_id"] == user_id]
    on_held = bool(own_keys) and held_keys is not None and (
        own_keys[-1]["signing_pk"], own_keys[-1]["encryption_pk"]) == tuple(held_keys)
    missing = []
    for body in lost_bodies:
        if change_key(body) in made:
            continue
        if on_held and body["type"] == "member.keys" and body["author"] == user_id \
                and body["data"]["user_id"] == user_id:
            continue
        if user_id is None or body["author"] != user_id:
            return f"record {body['seq']} this device saw is not on the server's side (it follows once its author makes that change again)", []
        missing.append(body["seq"])
    return None, missing


def fork_abandoned(lost: list[dict], user_id: Optional[str]) -> list[str]:
    """The hashes of this account's records in ``lost`` a device goes on
    without when it follows a fork: it withdraws them, so a server that later
    serves them again (a change it set aside, one it made again) is refused
    (review 18c300f capability finding 505)."""
    if user_id is None:
        return []
    return [record_hash(record) for record in lost if parse_body(record["body"])["author"] == user_id]


def tombstone_refusal(state: TeamState, user_id: str, stored_dek_id: Optional[str]) -> Optional[str]:
    """A deletion of an object sealed with a team key needs write access there."""
    found = state.dek_index.get(stored_dek_id) if stored_dek_id else None
    if found is not None and not may_write(state, found[0], user_id):
        return "team log gives no write access here"
    return None


def move_refusal(
    state: TeamState, user_id: str, old_folder: Optional[str], new_folder: Optional[str],
    own_personal: bool = False,
) -> Optional[str]:
    """A folder/item leaving the team folder ``old_folder`` is a removal from it.

    ``old_folder`` / ``new_folder``: the team folder at or above the stored and
    the new parent (None: none). Leaving needs write access in the folder left.
    ``own_personal`` (TL7): the stored object is ``user_id``'s own, sealed with
    a key of theirs the log does not know; it may leave for outside every team
    folder (a personal folder or tier-2 item going to the personal root).
    """
    if own_personal and new_folder is None:
        return None
    if old_folder is not None and old_folder != new_folder and not may_write(state, old_folder, user_id):
        return "team log gives no write access here"
    return None


def envelope_valid(
    state: TeamState, signer_id: str, target_id: str, dek_id: str, level: Optional[str],
    target_encryption_pk: str,
) -> bool:
    """An envelope giving ``target_id`` the key ``dek_id`` (design §4.3.5).

    Sealed by the admin, or by an admin who handed the role over while that
    key was the folder's current one (``former_admins``; review c78fd19
    R13-8: the members kept the key until the new admin's re-key).
    """
    if not may_hold_key(state, target_id, dek_id):
        return False
    folder, _ = state.dek_index[dek_id]
    signer = state.members.get(signer_id)
    if not is_admin(state, signer_id) and not (
        signer is not None and signer.active and signer_id in state.former_admins.get(folder, ())
    ):
        return False
    if state.members[target_id].encryption_pk != target_encryption_pk:
        return False
    by_role = "write" if is_admin(state, target_id) else None
    return state.access.get(folder, {}).get(target_id, by_role) == level


def superseded_envelope_valid(
    state: TeamState, signer_id: str, target_id: str, dek_id: str, target_encryption_pk: str,
) -> bool:
    """An envelope giving ``target_id`` the key ``dek_id`` the log replaced,
    which the caller found ``target_id`` may still open (sync core
    may_open_superseded: it may hold the folder's current key). Review c02cc47
    R17-L: envelope_valid starts with may_hold_key, false for every replaced
    key, so one held only through its envelope never opened.

    Sealed to the member's current key by the generation's author, the admin
    or a former admin of the folder. The level is the one of the key's day:
    the key only reads history, write access is the log's.
    """
    found = state.dek_index.get(dek_id)
    target = state.members.get(target_id)
    signer = state.members.get(signer_id)
    if found is None or target is None or not target.active or signer is None or not signer.active:
        return False
    folder, gen = found
    gens = state.folders[folder]
    if gen == len(gens) - 1 or target.encryption_pk != target_encryption_pk:
        return False
    return signer_id == gens[gen][1] or is_admin(state, signer_id) \
        or signer_id in state.former_admins.get(folder, ())
