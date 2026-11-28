"""Team log state on this device: pins, queued changes, the local copy and
what it says about folders and keys.

Module-level part of team_log_local.py (review 6 R6-H size limit), split out
without a change of behaviour; team_log_local re-exports every name.
"""

from __future__ import annotations
import contextlib
import copy
import hashlib
import logging
import re
from typing import Iterator, Optional
from .. import teamlog
from . import outbox, sync_core
from ..crypto.keys import compute_fingerprint
from .sync_common import CONFIRMED_MEMBER_KEYS_META, TEAM_LOG_REFUSED, server_error

logger = logging.getLogger("sezam.vault.team_log_local")

GENESIS_META = "team_log_genesis_hash"
CONFIRMED_GENESIS_META = "team_log_confirmed_genesis_hash"
# The genesis the account keys name, written at every unlock from the keys
# just opened (record_account_anchor); absent while they name none.
ACCOUNT_ANCHOR_META = "team_log_account_anchor"
# Genesis hashes the user left ('sezam team-log forget-pin', team_log_forget.py).
FORGOTTEN_GENESIS_META = "team_log_forgotten_genesis"
_GENESIS = re.compile(r"[0-9a-f]{64}")
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
# The identity keypair the local log names for this account, kept when this
# device took over account keys another device rotated without the log (no
# member.keys links them: that device never held it, the server had lost it).
# Sealed under the KEK; it anchors the log here and signs that member.keys
# (continue_identity_in_log), then it is dropped.
IDENTITY_CONTINUATION_META = "team_log_identity_continuation"
_CONTINUATION_AAD = b"sezam/team-log-identity-continuation/v1/"
FETCH_PAGES = 1000  # pages of up to 1000 records per pull
TEAM_LOG_APPEND_MAX = 1000  # records per append the server takes (TeamLogAppend, PushRequest.team_log)


# INV-7 (docs/ROOT_CAUSE_PLAN.md): the one list of why a device refuses the
# server's team log, and for which of them "forget the pinned team log" is
# offered: only where the log this device holds is missing or a new log
# starts (another server, a reseed). A fork, a log going back or one that does
# not replay is a server that lies, never forgotten. INV-8: a server can drop
# its log or serve a new genesis on its own, and no device tells that from a
# reseed, so every offer carries RISK_MARKER (no cause is offered plainly). The web page
# (TEAM_LOG_MISMATCH_FORGET in app.js) and the phone (teamLogMismatchForget in
# team_log_client.dart) carry the same list; tests/vectors/team_log_mismatch.json
# is it, and every client must give its cases' answers.
MISMATCH_CAUSES = {
    "confirmed_genesis": True,   # not the genesis confirmed out of band
    "log_gone": True,            # the server has no log, this device holds or pins one
    "other_genesis": True,       # the server's log starts with another genesis
    "left_earlier_log": False,   # no log, and this device left one: it waits for the new one
    "went_back": False,          # the server's head is behind what this device saw
    "differs": False,            # another record at a seq this device saw (a fork)
    "does_not_replay": False,
    "short_of_head": False,      # the records served do not reach the announced head
    "head_genesis": False,       # the records start with another genesis than the head names
    "refused_at_head": False,    # TL7: a head the server must refuse
    "local_damaged": False,      # this device's own copy does not replay or fails its stored hashes
    "anchor_conflict": True,     # the account keys name another log than this device holds or pins
}
# INV-7 (capability run 397): no cause keeps the vault locked. The log is
# checked where the team is used (local_team_state), never in the unlock; a
# damaged copy is fetched again under its pins at the next pull
# (TeamLogMixin._sync_team_log), and conflicting pins are forgotten together.
# Before, the unlock checked it and locked the vault again on any error.

# INV-8: how every client marks the offer to forget as a risk
# (tests/vectors/team_log_mismatch.json "risk_marker").
RISK_MARKER = "RISK:"
# Review c78fd19: the way out once the team's log is lost for good.
LOST_LOG_HINT = (
    f" {RISK_MARKER} a hostile server can cause this on purpose (drop its log, serve a new genesis) "
    "so that this device drops its pin. Only if your admin confirms out of band that the team's log "
    "is lost for good (another server, a reseed), 'sezam team-log forget-pin' leaves it on this device."
)


class TeamLogMismatch(RuntimeError):
    """The server's team log is not a continuation of this device's copy.

    ``cause`` is a key of MISMATCH_CAUSES; ``offers_forget`` and the hint in
    the message follow from it alone.
    """

    def __init__(self, message: str, cause: str):
        if cause not in MISMATCH_CAUSES:
            raise ValueError(f"unknown team log mismatch cause {cause!r}")
        self.cause = cause
        self.offers_forget = MISMATCH_CAUSES[cause]
        super().__init__(message + (LOST_LOG_HINT if self.offers_forget else ""))


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


LOCAL_DAMAGED_HINT = " The next pull fetches it again, held to the genesis and the head this device saw."
FORGOTTEN_DAMAGED_WAY_OUT = (
    "'sezam team-log confirm-genesis GENESIS' (the team's genesis from your admin, not from the "
    "server) replaces it."
)


def forgotten_genesis(db) -> list[str]:
    """The genesis hashes this device left (team_log_forget.py).

    INV-7 (capability run 411): a list that cannot be read failed the unlock
    (record_account_anchor). It is refused where the team is used
    (local_damaged), and confirming the genesis again replaces it.
    """
    try:
        value = db.get_meta_json(FORGOTTEN_GENESIS_META)
    except ValueError as exc:
        value = exc
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(g, str) and _GENESIS.fullmatch(g) for g in value):
        refusal = TeamLogMismatch(
            f"This device's list of team logs it left cannot be read ({value!r:.60}). {FORGOTTEN_DAMAGED_WAY_OUT}",
            "local_damaged",
        )
        refusal.way_out = FORGOTTEN_DAMAGED_WAY_OUT
        raise refusal
    return value


def readable_forgotten_genesis(db) -> Optional[list[str]]:
    """forgotten_genesis, or None while it cannot be read."""
    try:
        return forgotten_genesis(db)
    except TeamLogMismatch:
        return None


_REPLAYED: dict[bytes, teamlog.TeamState] = {}
_REPLAYED_MAX = 16


@contextlib.contextmanager
def log_read_once(db) -> Iterator[None]:
    """Within, the local team log of ``db`` is read and replayed once, and
    every later local_team_state / team_key_ids returns that answer (the same
    state object: read it, never change it).

    Only for work that writes no team log row and no meta its checks read,
    inside one transaction. Review 8bc70f7 M8: a re-key over 40 000 folders
    unlocked each retired key, and each unlock read, hashed and copied the
    whole log again.
    """
    if getattr(db, "_team_log_once", None) is not None:
        yield
        return
    db._team_log_once = {}
    try:
        yield
    finally:
        db._team_log_once = None


def _read_once(db, name: str, read):
    once = getattr(db, "_team_log_once", None)
    if once is None:
        return read()
    if name not in once:
        once[name] = read()
    return once[name]


def local_team_state(db) -> Optional[teamlog.TeamState]:
    """The replayed local log of ``db``, or None while it holds none.

    The one place a team operation reads the log, so the one place it is
    refused (INV-7): a copy that conflicts with the account keys or is damaged.
    """
    return _read_once(db, "state", lambda: _local_team_state(db))


def _local_team_state(db) -> Optional[teamlog.TeamState]:
    forgotten_genesis(db)
    anchor = db.get_meta(ACCOUNT_ANCHOR_META)
    if anchor is not None and _anchor_conflicts(db, anchor):
        raise TeamLogMismatch(
            "The account keys name another team log than the one this device holds or pins.", "anchor_conflict"
        )
    rows = db.fetchall("SELECT seq, body, sig, hash FROM team_log ORDER BY seq")
    if not rows:
        return None
    # Review e443cbc (goal #438): only the replay is kept, under every byte
    # of the rows; the checks above run on each call. A cache under the head
    # row alone outlived damage below it and every refusal by the pins.
    key = hashlib.sha256(repr([tuple(r) for r in rows]).encode()).digest()
    if (state := _REPLAYED.get(key)) is not None:
        return copy.deepcopy(state)
    # A local copy that does not replay was accepted by no version of this
    # code: refuse rather than decide from part of it.
    try:
        state = teamlog.replay([{"body": r["body"], "sig": r["sig"]} for r in rows])
    except teamlog.TeamLogError as exc:
        raise TeamLogMismatch(f"This device's copy of the team log does not replay ({exc}).{LOCAL_DAMAGED_HINT}",
                              "local_damaged") from exc
    if rows[-1]["seq"] != state.head_seq or any(
            teamlog.record_hash({"body": r["body"], "sig": r["sig"]}) != r["hash"] for r in rows):
        raise TeamLogMismatch("This device's copy of the team log does not match its stored hashes."
                              + LOCAL_DAMAGED_HINT, "local_damaged")
    if len(_REPLAYED) >= _REPLAYED_MAX:
        _REPLAYED.clear()
    _REPLAYED[key] = copy.deepcopy(state)
    return state


def held_team_head(db) -> Optional[tuple[int, set[str]]]:
    """The head a (damaged) local copy saw: its last seq, and the hashes it
    stores for it (the stored hash, the stored record's own)."""
    row = db.fetchone("SELECT seq, body, sig, hash FROM team_log ORDER BY seq DESC LIMIT 1")
    if row is None:
        return None
    return row["seq"], {row["hash"], teamlog.record_hash({"body": row["body"], "sig": row["sig"]})}


def team_key_ids(db) -> set[str]:
    """Every key a team envelope or a record of the local copy names, read
    without replaying it: what is not here is personal and opens by the KEK
    alone, whatever the state of the team log (INV-7)."""
    return _read_once(db, "key_ids", lambda: _team_key_ids(db))


def _team_key_ids(db) -> set[str]:
    ids = {row["dek_id"] for row in db.fetchall("SELECT DISTINCT dek_id FROM access_envelopes")}
    bodies = [row["body"] for row in db.fetchall("SELECT body FROM team_log")]
    return ids | set(sync_core.call("authority_team_key_ids", bodies=bodies))


def team_folder_at_or_above(db, team: Optional[teamlog.TeamState], node_id: Optional[str]) -> Optional[str]:
    """The team folder of ``team`` at or above ``node_id`` (None: in none);
    the core's walk over the folders above it here."""
    if team is None or node_id is None:
        return None
    parents: dict[str, Optional[str]] = {}
    current: Optional[str] = node_id
    while current is not None and current not in parents and len(parents) < 64:
        row = db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (current,))
        if row is None:
            break
        parents[current] = row["parent_id"]
        current = row["parent_id"]
    return teamlog.team_folder_above(team, parents, node_id)


def unlogged_folder_keys(db, logged, node_id: str) -> list[tuple[str, str]]:
    """(folder, key) of every folder at or below ``node_id`` with a key of its
    own that is not in ``logged`` (the log's key ids, ``dek_index``). One in
    the trash too: restored, it is below the team folder again.

    Review e443cbc R15 (goal #429): below a team folder every client refuses
    what such a key seals (teamlog.item_refusal: 'sealed with a key the team
    log does not know'). So no folder below a team folder keeps one: a folder
    that becomes a team folder brings these into the log with it.

    R16-N2 (nightly TeamLogMachine on d441587): the walk stops at a folder
    whose own key the log knows. What is below it is that team folder's: an
    unlogged key there takes its parent's (fold_unlogged_folder_keys). Taken
    by a grant of a folder above, a subfolder B made in a shared folder (its
    node refused, still queued) went into the log as a team folder of its
    own: the admin who took the role back did not hold it to re-key, and the
    former admin kept its current key.
    """
    return [(folder, key) for folder, key, below in _own_unlogged_keys(db, logged, node_id) if not below]


def keys_below_team_folders(db, logged, node_id: str) -> set[str]:
    """Folders at or below ``node_id`` whose own unlogged key lies below a team
    folder of ``logged``: no grant of ``node_id`` logs them. A grant made on
    an older copy of the log collected them; built again on the server's
    newer log (team_log_records after 409 team_log_head_moved) they are left
    out (R16-N2)."""
    return {folder for folder, _, below in _own_unlogged_keys(db, logged, node_id) if below}


def _own_unlogged_keys(db, logged, node_id: str) -> list[tuple[str, str, bool]]:
    """(folder, own key not in ``logged``, below a team folder) at or below ``node_id``."""
    rows = db.fetchall(
        "WITH RECURSIVE t(id) AS (SELECT ? UNION SELECT n.id FROM nodes n JOIN t ON n.parent_id = t.id) "
        "SELECT n.id, n.parent_id, d.id AS own_dek, d.scope FROM t JOIN nodes n ON n.id = t.id "
        "LEFT JOIN deks d ON d.id = n.dek_id AND d.node_id = n.id ORDER BY n.id",
        (node_id,),
    )
    parent = {r["id"]: r["parent_id"] for r in rows}
    team_folders = {r["id"] for r in rows if r["own_dek"] is not None and r["own_dek"] in logged}

    def below_a_team_folder(folder: str) -> bool:
        above = parent.get(folder)
        while above is not None and above != node_id and above in parent:
            if above in team_folders:
                return True
            above = parent.get(above)
        return False

    return [
        (r["id"], r["own_dek"], below_a_team_folder(r["id"])) for r in rows
        if r["own_dek"] is not None and r["scope"] == "folder" and r["own_dek"] not in logged
    ]


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


def held_genesis(db) -> Optional[str]:
    """The genesis the local copy holds: its first record's stored hash while
    the record still hashes to it. Capability run 418: a damaged first record
    named its own hash as another genesis, so local damage (repaired by the
    next pull, under the pins) was refused as anchor_conflict instead."""
    first = db.fetchone("SELECT body, sig, hash FROM team_log WHERE seq = 0")
    if first is None:
        return None
    try:
        own = teamlog.record_hash({"body": first["body"], "sig": first["sig"]})
    except ValueError:
        return None
    return first["hash"] if own == first["hash"] else None


def _anchor_conflicts(db, genesis: str) -> bool:
    """A pin or the genesis the local copy holds is another than ``genesis``."""
    return any(pin is not None and pin != genesis
               for pin in (db.get_meta(CONFIRMED_GENESIS_META), db.get_meta(GENESIS_META), held_genesis(db)))


def record_account_anchor(db, keypair) -> None:
    """At unlock: note the genesis the account keys name, and pin it unless
    this device holds or pins another (INV-7: then team operations are
    refused as anchor_conflict, the unlock never is)."""
    genesis = keypair.confirmed_genesis
    forgotten = readable_forgotten_genesis(db)
    if genesis is not None and genesis in (forgotten or []):
        # The user left this log here; the server's bundle still names it.
        keypair.confirmed_genesis, keypair.pre_anchor = None, b""
        genesis = None
    if genesis is None:
        # Legacy account keys convey no trust, even after a successful login.
        db.execute("DELETE FROM vault_meta WHERE key = ?", (ACCOUNT_ANCHOR_META,))
        return
    db.set_meta(ACCOUNT_ANCHOR_META, genesis)
    # An unreadable list may hold this genesis: not pinned from the keys then.
    if forgotten is not None and not _anchor_conflicts(db, genesis):
        db.set_meta(CONFIRMED_GENESIS_META, genesis)


def keep_identity_continuation(db, kek: bytes, user_id: str, old_private: bytes) -> None:
    from .key_rotation import _seal

    db.set_meta(IDENTITY_CONTINUATION_META, _seal(kek, _CONTINUATION_AAD + user_id.encode(), old_private))


def identity_continuation(db, kek: Optional[bytes], user_id: str):
    """The kept keypair the log names for this account, or None."""
    from nacl.exceptions import CryptoError

    from ..crypto.keys import KeyPair
    from .key_rotation import _open

    sealed = db.get_meta(IDENTITY_CONTINUATION_META)
    if sealed is None or kek is None:
        return None
    try:
        private = _open(kek, _CONTINUATION_AAD + user_id.encode(), sealed)
    except CryptoError:
        return None  # sealed under a KEK a later password change replaced
    try:
        return KeyPair.from_private_only(bytes(private))
    finally:
        private[:] = b"\x00" * len(private)


def drop_identity_continuation(db) -> None:
    db.execute("DELETE FROM vault_meta WHERE key = ?", (IDENTITY_CONTINUATION_META,))


def kept_keypair_named(signing_pk: str, kept):
    """``kept`` (identity_continuation) when the log names its key ``signing_pk``, else None (zeroized).

    R16-N12: a lost committed rotation under a pending one goes out again from
    the server's keys; the kept keys the log names sign its member.keys and
    prove the log's key at a login with a retired one.
    """
    if kept is not None and kept.signing_pk.hex() != signing_pk:
        kept.zeroize()
        return None
    return kept


def settle_lost_rotation_keys(db, kek, user_id: str, log_keys, keep: bool) -> None:
    """R16-N12: ``log_keys`` (the pending rotation's old keys, the log's) are kept
    to sign the re-sent rotation's member.keys when ``keep``; zeroized either way."""
    if log_keys is None:
        return
    private = bytearray(log_keys.serialize_private())
    try:
        if keep:
            keep_identity_continuation(db, kek, user_id, bytes(private))
    finally:
        private[:] = b"\x00" * len(private)
        log_keys.zeroize()


def member_keys_record(state: teamlog.TeamState, user_id: str, old, new) -> dict:
    """member.keys moving ``user_id`` from ``old`` to ``new``: signed by the
    key the log names, with the new key's signature over the head."""
    spk, epk = new.signing_pk.hex(), new.encryption_pk.hex()
    data = {
        "user_id": user_id, "signing_pk": spk, "encryption_pk": epk,
        "new_key_sig": new.to_nacl_signing_key().sign(
            teamlog.new_key_message(state.head_hash, user_id, spk, epk)
        ).signature.hex(),
    }
    return teamlog.sign_record(teamlog.next_body(state, "member.keys", user_id, data), old.to_nacl_signing_key())


def import_account_anchor(db, keypair) -> None:
    """Adopt an authenticated bundle anchor without replacing local continuity:
    account keys from the server naming another log are not taken."""
    genesis = keypair.confirmed_genesis
    if (genesis is not None and genesis not in (readable_forgotten_genesis(db) or [])
            and _anchor_conflicts(db, genesis)):
        raise TeamLogMismatch("The account anchor conflicts with this device's team log.", "anchor_conflict")
    record_account_anchor(db, keypair)


def log_admins(db, state: teamlog.TeamState) -> set[str]:
    """Accounts the log ever made admin that are still active members: what
    they wrote outside team folders while admin stays valid after a handover
    (review 1141a20); an account the server calls admin is not one. The
    core's rule (core/src/authority.rs log_admins)."""
    bodies = [row["body"] for row in db.fetchall("SELECT body FROM team_log ORDER BY seq")]
    return set(sync_core.call("authority_log_admins", bodies=bodies, **teamlog.core_argument(state)))


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

    Review e443cbc (goal #438): a copy this device refuses (local_damaged)
    trusts nothing through its lineage. Raised here, it locked the vault
    again after a Shamir recovery or a password change (INV-7).
    """
    if keypair.confirmed_genesis is not None:
        return keypair.confirmed_genesis
    confirmed = db.get_meta(CONFIRMED_GENESIS_META)
    if confirmed is not None:
        return confirmed
    try:
        state = local_team_state(db)
    except TeamLogMismatch:
        return None
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
        # R17-N8 (state machine seed 20261127): a member's removal takes every
        # access they had, also one still queued for them; sent after it, the
        # access.set was refused (not_active) on every push for good.
        removed = member is not None and not member.active and data["level"] is not None
        current = state.access.get(data["folder"], {}).get(data["user_id"])
        return None if removed or current == data["level"] else data
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
    if kind == "org.recovery.wrap":  # R16-M5: made again after a fork lost it
        return None if data in state.org_recovery_wrap.values() else data
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


def rekey_waiting_for_log_key(db, state: Optional[teamlog.TeamState], batch: dict) -> Optional[dict]:
    """A folder of the pending batch that the team log moved on to a key
    this device does not hold, or None.

    R16-Z SM26c (gate 23 on 6858912): another device of this account
    re-keyed the folder too; the server went back to a backup and lost
    that re-key's objects, while the log got its folder.key back (INV-7).
    The log refuses this batch (folder_key_moved) and no pull binds the
    folder to the log's key until the device holding it sends it again:
    the batch then counts as superseded. Until then the push waits; it
    raised 'Atomic re-key batch conflict' on every sync and named
    'sezam abandon-rekey', which would undo a revocation the log made.
    """
    for _kind, data in rekey_changes(state, batch):
        current = teamlog.current_key(state, data["folder"])
        if current in (None, data["prev_dek_id"], data["dek_id"]):
            continue
        if db.fetchone("SELECT 1 FROM deks WHERE id = ?", (current,)) is None:
            return {
                "folder": data["folder"], "dek_id": current,
                "message": (
                    f"The re-key of folder {data['folder']} waits: the team log moved it on to "
                    f"key {current}, which another device re-keyed and this one does not hold "
                    "yet (the server lost it). It goes on once that device has synced."
                ),
            }
    return None
