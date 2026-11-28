"""Signed team log: the desktop's and the server's door to the Rust core.

The log is an append-only, hash-chained list of signed records that says who
is a member, who may access which shared folder, and which key is the
current key of a folder (docs/DESIGN_TEAM_LOG.md). Its replay and every
decision from it live once in the core (core/src/teamlog,
docs/CORE_UNIFICATION.md); the web page and the phone ask the same core.
This module only checks the signatures the core names (PyNaCl), signs new
records and gives the replayed state to the code that reads it.

It needs PyNaCl, the stdlib and the ``sezam_sync_core`` wheel only, so that
the server can use the very same file.
"""

from __future__ import annotations

import json
import weakref
from dataclasses import dataclass, field
from typing import Any, Optional

import sezam_sync_core
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

# The core's rules this file was written for (core/Cargo.toml).
CORE_VERSION = "0.3.0"

# Wire constants of the format (the core holds the same).
RULES_VERSIONS = (1, 2)
FORMAT_VERSION = RULES_VERSIONS[-1]
ZERO_HASH = "0" * 64
MAX_INT = 2 ** 53 - 1
ROLES = ("admin", "member")
LEVELS = ("read", "write")


class TeamLogError(Exception):
    """A record breaks a rule. Replay stops; nothing may be decided from it."""

    def __init__(self, code: str, seq: Optional[int], detail: str = ""):
        self.code = code
        self.seq = seq
        super().__init__(f"team log record {seq}: {code}" + (f" ({detail})" if detail else ""))


def _call(op: str, **arguments: Any) -> Any:
    out = json.loads(sezam_sync_core.call(op, json.dumps(arguments)))
    if "error" in out:
        raise ValueError(f"sync core {op}: {out['error']}")
    return out["ok"]


def _answer(out: dict, name: str) -> Any:
    if "refused" in out:
        refused = out["refused"]
        raise TeamLogError(refused["code"], refused["seq"], refused["detail"])
    return out[name]


if (_installed := _call("version")) != CORE_VERSION:
    raise ImportError(
        f"sezam-sync-core {_installed} is installed, this Sezam needs {CORE_VERSION}: pip install ./core/py"
    )


# ── State: the core's, read by the code around it ─────────────────────

@dataclass
class Member:
    user_id: str
    signing_pk: str
    encryption_pk: str
    role: str
    active: bool


@dataclass
class TeamState:
    """The replayed state as the core gave it. Read it; never change it
    (the core answers from the state it was given)."""

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
    former_admins: dict[str, set[str]] = field(default_factory=dict)
    rules: int = 0
    org_recovery: dict[str, str] = field(default_factory=dict)
    org_recovery_wrap: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def from_core(cls, core: dict) -> "TeamState":
        state = cls(
            org=core["org"], genesis_hash=core["genesis_hash"], head_seq=core["head_seq"],
            head_hash=core["head_hash"],
            members={
                uid: Member(uid, m["signing_pk"], m["encryption_pk"], m["role"], m["active"])
                for uid, m in core["members"].items()
            },
            folders={f: [(g["dek_id"], g["author"]) for g in gens] for f, gens in core["folders"].items()},
            access={f: dict(a) for f, a in core["access"].items()},
            stale={f: set(s) for f, s in core["stale"].items()},
            seen_keys=dict(core["seen_keys"]),
            dek_index={d: (f, gen) for d, (f, gen) in core["dek_index"].items()},
            former_admins={f: set(s) for f, s in core["former_admins"].items()},
            rules=core["rules"],
            org_recovery=dict(core["org_recovery"]),
            org_recovery_wrap={a: dict(w) for a, w in core["org_recovery_wrap"].items()},
        )
        state.__dict__["_core"] = core
        return state

    def to_core(self) -> dict:
        """The core's form of this state (the one it gave, when it gave it)."""
        if "_core" in self.__dict__:
            return self.__dict__["_core"]
        return {
            "org": self.org, "genesis_hash": self.genesis_hash, "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "members": {
                uid: {"signing_pk": m.signing_pk, "encryption_pk": m.encryption_pk, "role": m.role,
                      "active": m.active}
                for uid, m in self.members.items()
            },
            "folders": {f: [{"dek_id": d, "author": a} for d, a in gens] for f, gens in self.folders.items()},
            "access": {f: dict(a) for f, a in self.access.items()},
            "stale": {f: sorted(s) for f, s in self.stale.items()},
            "seen_keys": dict(self.seen_keys),
            "dek_index": {d: [f, gen] for d, (f, gen) in self.dek_index.items()},
            "former_admins": {f: sorted(s) for f, s in self.former_admins.items()},
            "rules": self.rules,
            "org_recovery": dict(self.org_recovery),
            "org_recovery_wrap": {a: dict(w) for a, w in self.org_recovery_wrap.items()},
        }

    def __deepcopy__(self, memo):
        if "_core" in self.__dict__:
            return self  # the core's state does not change
        return TeamState.from_core(json.loads(json.dumps(self.to_core())))

    def to_json(self) -> dict:
        """Comparable form used by the decision vectors (in the order the
        stored vectors list it)."""
        out = _ask(self, "state_json")
        order = ("org_recovery", "org_recovery_wrap", "rules", "org", "genesis_hash", "head_seq",
                 "head_hash", "members", "folders", "access", "stale")
        member = ("signing_pk", "encryption_pk", "role", "active")
        out["members"] = {uid: {k: m[k] for k in member} for uid, m in out["members"].items()}
        return {k: out[k] for k in order if k in out}


def _free(handle: int) -> None:
    _call("team_log_free", handle=handle)


def _ask_many(state: TeamState, questions: list[tuple[str, list]]) -> list:
    """Answers from the core. A state the core gave is loaded there once
    (review 8bc70f7 M8: reading a large one per question was slow); one
    built here is sent whole."""
    asked = [{"fn": name, "args": args} for name, args in questions]
    if "_core" not in state.__dict__:
        return _call("team_log_ask", state=state.to_core(), questions=asked)
    handle = state.__dict__.get("_handle")
    if handle is None:
        handle = _call("team_log_load", state=state.to_core())
        state.__dict__["_handle"] = handle
        weakref.finalize(state, _free, handle)
    return _call("team_log_ask", handle=handle, questions=asked)


def _ask(state: TeamState, name: str, *args: Any) -> Any:
    return _ask_many(state, [(name, list(args))])[0]


def core_argument(state: TeamState) -> dict:
    """The team as another core operation takes it: by handle when the core
    gave the state, whole otherwise (as _ask_many)."""
    if "_core" not in state.__dict__:
        return {"team": state.to_core()}
    _ask_many(state, [])
    return {"team_handle": state.__dict__["_handle"]}


# ── Records ───────────────────────────────────────────────────────────

def canonical(value, seq: Optional[int] = None) -> str:
    """The restricted canonical JSON of the design (§3.3)."""
    try:
        return _answer(_call("team_log_canonical", value=value), "text")
    except TeamLogError as exc:
        raise TeamLogError(exc.code, seq) from None


def parse_body(body: str, seq: Optional[int] = None) -> dict:
    """Parse a transmitted body; it must already be in canonical form."""
    if not isinstance(body, str):
        raise TeamLogError("bad_encoding", seq, "body is not a string")
    try:
        return _answer(_call("team_log_parse_body", body=body), "body")
    except TeamLogError as exc:
        raise TeamLogError(exc.code, seq) from None


def record_hash(record: dict) -> str:
    return _call("team_log_record_hash", body=record["body"], sig=record["sig"])


def new_key_message(prev: str, user_id: str, signing_pk: str, encryption_pk: str) -> bytes:
    return bytes.fromhex(_call(
        "team_log_new_key_message", prev=prev, user_id=user_id, signing_pk=signing_pk,
        encryption_pk=encryption_pk,
    ))


def sign_record(body: dict, signing_key: SigningKey) -> dict:
    text = canonical(body, body.get("seq"))
    sig = signing_key.sign(bytes.fromhex(_call("team_log_sig_message", body=text))).signature
    return {"body": text, "sig": sig.hex()}


# ── Replay ────────────────────────────────────────────────────────────

def _passed(checks: list[dict]) -> int:
    """How many of the core's signature checks pass, from the first."""
    for index, check in enumerate(checks):
        try:
            VerifyKey(bytes.fromhex(check["pk"])).verify(bytes.fromhex(check["message"]), bytes.fromhex(check["sig"]))
        except (BadSignatureError, ValueError):
            return index
    return len(checks)


def _replay(records: list[dict], state: Optional[TeamState], steps: bool = False) -> dict:
    base = state.to_core() if state is not None else None
    checks = _call("team_log_replay", records=records, state=base)["checks"]
    out = _call("team_log_replay", records=records, state=base, verified=_passed(checks), steps=steps)
    _answer(out, "state")
    return out


def replay(records: list[dict], state: Optional[TeamState] = None) -> TeamState:
    """Replay ``records`` onto ``state`` (a fresh log when None).

    The whole call fails on the first bad record; ``state`` is never changed.
    """
    return TeamState.from_core(_replay(records, state)["state"])


def apply_record(state: TeamState, record: dict) -> TeamState:
    """Return the state after ``record``; raise TeamLogError and leave ``state`` untouched."""
    return replay([record], state)


def replay_batch(records: list[dict], state: Optional[TeamState] = None) -> tuple[TeamState, list[dict]]:
    """Replay an uploaded batch: the state after it and, per record, what the
    server records (seq, hash, admin, level, keys, admin_policy,
    todays_rules, readded; core teamlog::replay::Step)."""
    out = _replay(records, state, steps=True)
    steps = [{**step, "keys": tuple(step["keys"]) if step["keys"] else None} for step in out["steps"]]
    return TeamState.from_core(out["state"]), steps


def apply_change(state: TeamState, kind: str, author: str, data: dict) -> TeamState:
    """The state after ``author``'s own unsigned change, for local decisions only.

    Nothing about the head moves: the result is never a log to build on. Raises
    TeamLogError (``state`` untouched) when the rules refuse the change.
    """
    out = _call("team_log_project", state=state.to_core(), kind=kind, author=author, data=data)
    return TeamState.from_core(_answer(out, "state"))


def next_body(state: TeamState, kind: str, author: str, data: dict) -> dict:
    """The body of the record that would follow ``state`` (to be signed)."""
    return _ask(state, "next_body", kind, author, data)


# ── Decisions (design §4.3), all the core's. Unknown is always "no". ──

def is_team_folder(state: TeamState, folder: str) -> bool:
    return _ask(state, "is_team_folder", folder)


def current_key(state: TeamState, folder: str) -> Optional[str]:
    return _ask(state, "current_key", folder)


def key_generation(state: TeamState, folder: str, dek_id: str) -> tuple[str, Optional[int]]:
    """('current', gen) / ('old', gen) / ('unknown', None) for a key of ``folder``."""
    return tuple(_ask(state, "key_generation", folder, dek_id))


def is_stale(state: TeamState, folder: str) -> bool:
    return _ask(state, "is_stale", folder)


def may_seal(state: TeamState, folder: str) -> bool:
    """New content or keys may be sealed under the folder's current key."""
    return _ask(state, "may_seal", folder)


def is_admin(state: TeamState, user_id: str) -> bool:
    return _ask(state, "is_admin", user_id)


def recovery_key(state: Optional[TeamState], user_id: str) -> Optional[str]:
    """The org recovery key the log names for ``user_id``, an active admin."""
    return None if state is None else _ask(state, "recovery_key", user_id)


def recovery_wrap(state: Optional[TeamState], user_id: str) -> Optional[dict]:
    """The KEK wrap the log holds for that admin's named recovery key."""
    return None if state is None else _ask(state, "recovery_wrap", user_id)


def may_write(state: TeamState, folder: str, user_id: str) -> bool:
    return _ask(state, "may_write", folder, user_id)


def key_recipients(state: TeamState, folder: str) -> list[tuple[str, str, str]]:
    """Exactly the members a new key of ``folder`` is sealed to: (user_id, encryption_pk, level)."""
    return [tuple(r) for r in _ask(state, "key_recipients", folder)]


def may_hold_key(state: TeamState, user_id: str, dek_id: str) -> bool:
    return _ask(state, "may_hold_key", user_id, dek_id)


def item_refusal(
    state: TeamState, user_id: str, obj_id: str, folder: Optional[str],
    dek_id: Optional[str], own_dek: bool, sealing: bool = True,
) -> Optional[str]:
    """Why a live folder/item by ``user_id`` sealed with ``dek_id`` is not
    valid, or None (core teamlog::rules::item_refusal). The server (push) and
    every client (pull) decide by this."""
    return _ask(state, "item_refusal", user_id, obj_id, folder, dek_id, bool(own_dek), bool(sealing))


def admin_policy_refusal(state: TeamState) -> Optional[str]:
    """TL7: one active admin per organisation."""
    return _ask(state, "admin_policy_refusal")


def todays_rules_refusal(state: TeamState, body: dict) -> Optional[str]:
    """What today's rules refuse in ``body``, a record its own older rules
    take on top of ``state`` (review e443cbc H3)."""
    return _ask(state, "todays_rules_refusal", body)


def signing_key_retired(state: Optional[TeamState], user_id: str, pk_hex: str) -> bool:
    """The log rotated ``user_id`` away from signing key ``pk_hex``."""
    return state is not None and _ask(state, "signing_key_retired", user_id, pk_hex)


def tombstone_refusal(state: TeamState, user_id: str, stored_dek_id: Optional[str]) -> Optional[str]:
    """A deletion of an object sealed with a team key needs write access there."""
    return _ask(state, "tombstone_refusal", user_id, stored_dek_id)


def move_refusal(
    state: TeamState, user_id: str, old_folder: Optional[str], new_folder: Optional[str],
    own_personal: bool = False,
) -> Optional[str]:
    """A folder/item leaving the team folder ``old_folder`` is a removal from it."""
    return _ask(state, "move_refusal", user_id, old_folder, new_folder, bool(own_personal))


def write_refusal(
    state: TeamState, obj: dict, objects: list[dict], after: Optional[list[dict]] = None,
    sealing: bool = True,
) -> tuple[bool, Optional[str]]:
    """The log's verdict on folder/item ``obj`` (its ``signer`` writes it):
    (decided, why not or None). ``objects``: the state before it (its copy,
    the folders it left, the keys and their signers); ``after``: the state it
    lands in. ``sealing``: the push rule (core authority::write_refusal,
    docs/CORE_UNIFICATION.md U5)."""
    arguments = {"writes": [obj], "objects": objects, "sealing": sealing, **core_argument(state)}
    if after is not None:
        arguments["after"] = after
    out = _call("authority_write_refusal", **arguments)[0]
    return out["decided"], out["refusal"]


def team_folder_above(state: TeamState, parents: dict, node_id: Optional[str]) -> Optional[str]:
    """The team folder at or above node ``node_id``; ``parents``: each
    folder's parent (core authority::team_folder_above)."""
    return _call("authority_team_folder_above", node_id=node_id, parents=parents, **core_argument(state))


def envelope_valid(
    state: TeamState, signer_id: str, target_id: str, dek_id: str, level: Optional[str],
    target_encryption_pk: str,
) -> bool:
    """An envelope giving ``target_id`` the key ``dek_id`` (design §4.3.5)."""
    return _ask(state, "envelope_valid", signer_id, target_id, dek_id, level, target_encryption_pk)


def superseded_envelope_valid(
    state: TeamState, signer_id: str, target_id: str, dek_id: str, target_encryption_pk: str,
) -> bool:
    """An envelope giving ``target_id`` a key the log replaced (review c02cc47 R17-L)."""
    return _ask(state, "superseded_envelope_valid", signer_id, target_id, dek_id, target_encryption_pk)


# ── Forks and restores ────────────────────────────────────────────────

def readmitted(bodies: list[dict], index: int) -> Optional[int]:
    """Where the member.remove ``bodies[index]`` is undone by its author's
    member.add of the same account in the same run of that author's records."""
    return _call("team_log_readmitted", bodies=bodies, index=index)


def restore_part_end(bodies: list[dict], start: int, limit: int) -> int:
    """The end (exclusive) of a restore upload part from ``start``, at most
    ``limit`` records, not inside a readmit (review c02cc47 R17-L)."""
    return _call("team_log_restore_part_end", bodies=bodies, start=start, limit=limit)


def change_key(body: dict) -> str:
    """The change a record made, as a device makes it again on another head."""
    return _answer(_call("team_log_change_key", body=canonical(body)), "key")


def fork_refusal(
    lost: list[dict], theirs: list[dict], user_id: Optional[str],
    held_keys: Optional[tuple[str, str]], withdrawn,
) -> tuple[Optional[str], list[int]]:
    """Whether a device follows a server log that forks from its copy (review
    18c300f R16-H1, tests/vectors/team_log_fork.json): (reason, []) refuses;
    (None, missing seqs) follows."""
    out = _answer(_call(
        "team_log_fork", lost=lost, theirs=theirs, user_id=user_id,
        held_keys=list(held_keys) if held_keys is not None else None, withdrawn=sorted(withdrawn),
    ), "fork")
    return out["refusal"], out["missing"]


def fork_abandoned(lost: list[dict], user_id: Optional[str]) -> list[str]:
    """The hashes of this account's records in ``lost`` a device withdraws
    when it follows a fork (review 18c300f capability finding 505)."""
    return _answer(_call("team_log_abandoned", lost=lost, user_id=user_id), "hashes")
