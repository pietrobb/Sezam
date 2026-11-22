"""Founding the team log of an existing organisation (docs/DESIGN_TEAM_LOG.md §9, TL6).

The admin makes, in one append, the log of what the organisation is now:

- ``genesis`` with this account's keys,
- ``member.add`` for every approved account whose key fingerprint this admin
  confirmed (asked for the others; who stays unconfirmed gets nothing and is
  named in the result). Every account is a ``member``: an admin flag the
  server shows is no proof, and one admin per organisation for now (TL7);
- ``folder.key`` gen 0 for the current key of every folder this device holds
  that is shared with someone (an envelope for another account on its key),
- ``access.set`` for the envelopes this account sealed, at their level. An
  envelope another account sealed is not evidence of anything here.

Only folders with a key of their own (scope ``folder``) are founded; the
root and keys below a shared folder that are not its own are named in the
result and keep no access from the log. A folder with a key of its own below
a founded one is founded too, with nobody's access (review e443cbc R15).
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

from .. import teamlog
from ..models import new_ulid
from . import oplock
from .sync_common import CONFIRMED_MEMBER_KEYS_META, vouched_access_level
from .team_log_local import unlogged_folder_keys

if TYPE_CHECKING:
    from .crud import Vault
    from .sync_client import SyncClient


@dataclass
class HiddenItem:
    """A live folder or item the log would hide: its author gets no write
    access to the founded folder above it (review 8595ec1, R10-C)."""
    item: str
    kind: str
    author: str
    folder: str
    reason: str  # 'read', 'unconfirmed' or 'no access'


@dataclass
class MigrationResult:
    members: list[str] = field(default_factory=list)
    unconfirmed: list[str] = field(default_factory=list)
    folders: list[str] = field(default_factory=list)
    access: dict[str, dict[str, str]] = field(default_factory=dict)
    # Envelopes on a key that is not a founded folder's current own key.
    not_founded: list[str] = field(default_factory=list)
    hidden: list[HiddenItem] = field(default_factory=list)


def _member_keys(vault: Vault, client: SyncClient, user_id: str) -> tuple[str, str, str]:
    """The member's pinned (signing, encryption) keys as hex and their fingerprint."""
    client.verified_encryption_pk(user_id)  # pins them; a key change raises
    row = vault.db.fetchone(
        "SELECT signing_pk, encryption_pk, fingerprint FROM known_keys WHERE user_id = ?",
        (user_id,),
    )
    return bytes(row["signing_pk"]).hex(), bytes(row["encryption_pk"]).hex(), row["fingerprint"]


def plan_team_log(
    vault: Vault,
    client: SyncClient,
    org_id: str,
    confirm_fingerprint: Optional[Callable[[str, str], bool]] = None,
) -> tuple[list[tuple[str, dict]], MigrationResult]:
    """The records that found the log, and what they say.

    ``confirm_fingerprint(user_id, fingerprint)`` is asked for an account
    whose key this device has not confirmed; a yes is remembered as with a grant.
    """
    own = client._user_id
    result = MigrationResult()
    changes: list[tuple[str, dict]] = [("genesis", {
        "org": org_id,
        "user_id": own,
        "signing_pk": bytes(vault.keypair.signing_pk).hex(),
        "encryption_pk": bytes(vault.keypair.encryption_pk).hex(),
    })]

    confirmed = dict(vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
    members: set[str] = set()
    for user in sorted(client.list_users(), key=lambda u: u.get("id", "")):
        user_id = user.get("id")
        if not user_id or user_id == own or user.get("status") != "active":
            continue
        signing_pk, encryption_pk, fingerprint = _member_keys(vault, client, user_id)
        if confirmed.get(user_id) != fingerprint:
            if confirm_fingerprint is None or not confirm_fingerprint(user_id, fingerprint):
                result.unconfirmed.append(user_id)
                continue
            confirmed[user_id] = fingerprint
        changes.append(("member.add", {
            "user_id": user_id, "signing_pk": signing_pk, "encryption_pk": encryption_pk, "role": "member",
        }))
        members.add(user_id)
        result.members.append(user_id)
    vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)

    # Each folder's current own key, and every envelope sealed for someone else.
    own_keys = {
        r["dek_id"]: r["node_id"]
        for r in vault.db.fetchall(
            "SELECT n.id AS node_id, n.dek_id FROM nodes n JOIN deks d ON d.id = n.dek_id "
            "WHERE n.is_deleted = 0 AND d.node_id = n.id AND d.scope = 'folder'"
        )
    }
    envelopes = vault.db.fetchall(
        "SELECT id, dek_id, user_id, created_by, access_level FROM access_envelopes "
        "WHERE user_id != ? ORDER BY dek_id, user_id",
        (own,),
    )
    for env in envelopes:
        folder = own_keys.get(env["dek_id"])
        if folder is None:
            if env["dek_id"] not in result.not_founded:
                result.not_founded.append(env["dek_id"])
            continue
        if folder not in result.folders:
            result.folders.append(folder)
            changes.append(("folder.key", {"folder": folder, "dek_id": env["dek_id"], "prev_dek_id": None}))
    # Review e443cbc R15 (goal #429): a folder with a key of its own below a
    # founded one is founded too, with nobody's access; left out, every client
    # refused what its key sealed (unlogged_folder_keys).
    logged = {data["dek_id"] for kind, data in changes if kind == "folder.key"}
    for founded in list(result.folders):
        for folder, dek_id in unlogged_folder_keys(vault.db, logged, founded):
            logged.add(dek_id)
            result.folders.append(folder)
            changes.append(("folder.key", {"folder": folder, "dek_id": dek_id, "prev_dek_id": None}))
    for env in envelopes:
        folder = own_keys.get(env["dek_id"])
        if folder is None or env["created_by"] != own or env["user_id"] not in members:
            continue
        levels = result.access.setdefault(folder, {})
        if env["user_id"] in levels and levels[env["user_id"]] == "write":
            continue
        levels[env["user_id"]] = vouched_access_level(vault.db, env["id"], env["access_level"])
    for folder in result.folders:
        for user_id, level in sorted(result.access.get(folder, {}).items()):
            changes.append(("access.set", {"folder": folder, "user_id": user_id, "level": level}))
    result.hidden = _hidden_by_founding(vault, client, result)
    return changes, result


def _hidden_by_founding(vault: Vault, client: SyncClient, result: MigrationResult) -> list[HiddenItem]:
    """The server's live folders and items in a founded folder whose author
    the planned log gives no write access there: every client hides them once
    the log decides (teamlog.item_refusal)."""
    page = client._fetch_pull_pages(0) or {}
    objects = [o for o in page.get("objects", []) if o.get("object_type") in ("node", "entry")]
    parents = {o["id"]: o.get("parent_ref") for o in objects if o.get("object_type") == "node"}
    founded = set(result.folders)

    def founded_above(obj: dict) -> Optional[str]:
        current = obj["id"] if obj.get("object_type") == "node" else obj.get("parent_ref")
        for _ in range(64):
            if current is None:
                return None
            if current in founded:
                return current
            if current not in parents:
                row = vault.db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (current,))
                parents[current] = row["parent_id"] if row else None
            current = parents[current]
        return None

    own = client._user_id
    hidden = []
    for obj in sorted(objects, key=lambda o: o["id"]):
        author = client._signer_id(obj)
        if obj.get("is_deleted") or author == own:
            continue
        folder = founded_above(obj)
        level = result.access.get(folder, {}).get(author) if folder else None
        if folder is None or level == "write":
            continue
        reason = "unconfirmed" if author in result.unconfirmed else "read" if level == "read" else "no access"
        hidden.append(HiddenItem(obj["id"], obj["object_type"], author, folder, reason))
    return hidden


def add_member(
    vault: Vault,
    client: SyncClient,
    user_id: str,
    confirm_fingerprint: Optional[Callable[[str], bool]] = None,
) -> None:
    """Admin: ``member.add`` for an approved account whose key fingerprint is
    confirmed (asked once, remembered as with a grant). §7: never for a key
    only the server vouches for."""
    if not client._token:
        client.authenticate()
    client.pull()
    state = client.team_state()
    if state is None:
        raise RuntimeError("This organisation has no team log yet ('sezam team-log init').")
    if not client.team_log_trusted(state):
        raise RuntimeError("This device has not confirmed the founder of the team log.")
    user = next((u for u in client.list_users() if u.get("id") == user_id), None)
    if user is None or user.get("status") != "active":
        raise ValueError("Only an approved account can be added to the team log")
    signing_pk, encryption_pk, fingerprint = _member_keys(vault, client, user_id)
    confirmed = dict(vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
    if confirmed.get(user_id) != fingerprint:
        if confirm_fingerprint is None or not confirm_fingerprint(fingerprint):
            raise ValueError(f"The key fingerprint of {user_id} was not confirmed: {fingerprint}")
        confirmed[user_id] = fingerprint
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
    client.append_team_log([("member.add", {
        "user_id": user_id, "signing_pk": signing_pk, "encryption_pk": encryption_pk, "role": "member",
    })])


def _admin_member(vault: Vault, client: SyncClient, user_id: str):
    """The log's state and ``user_id``'s member there, refused unless this
    account is the trusted log's admin and ``user_id`` another active member."""
    state = client.team_state()
    me = vault.db.get_meta("user_id")
    if state is None:
        raise RuntimeError("This organisation has no team log yet ('sezam team-log init').")
    if not client.team_log_trusted(state):
        raise RuntimeError("This device has not confirmed the founder of the team log.")
    if not teamlog.is_admin(state, me):
        raise RuntimeError("Only the team log's admin hands the role over.")
    member = state.members.get(user_id)
    if user_id == me or member is None or not member.active:
        raise ValueError(f"{user_id} is not another active member of the team log")
    return state, member


def unsent_work(db) -> list[str]:
    """What of this vault the server does not hold yet: queued outbox rows by
    kind, open sync conflicts and set-aside team changes."""
    from .team_log_state import set_aside_changes

    waiting = [
        f"{row['n']} {row['kind']}" for row in db.fetchall(
            "SELECT kind, COUNT(*) AS n FROM outbox WHERE state = 'queued' GROUP BY kind ORDER BY kind"
        )
    ]
    conflicts = db.fetchone("SELECT COUNT(*) AS n FROM sync_conflicts")["n"]
    if conflicts:
        waiting.append(f"{conflicts} open sync conflict(s)")
    if set_aside_changes(db):
        waiting.append("set-aside team changes ('sezam team-log discard')")
    return waiting


@oplock.held  # INV-6: the push before and the handover unit write the outbox
def hand_over_admin(
    vault: Vault,
    client: SyncClient,
    user_id: str,
    confirm_fingerprint: Optional[Callable[[str], bool]] = None,
) -> None:
    """Admin: make member ``user_id`` the organisation's admin, this account a member.

    Review 8595ec1 #3: one admin per organisation (TL7), and nothing let the
    role move, so losing that admin froze the team. Both member.role records
    go in one append: the head never has two admins. Only to a member whose
    key in the log has its fingerprint confirmed here (asked once).

    Review 8bc70f7 M1: the new admin holds every folder key by the role
    (``teamlog.may_hold_key``), not by an ``access.set``: the write access a
    handover granted outlived the role (A -> B -> C: B kept the folders nobody
    shared with B) and stayed when the role change then failed. The envelopes
    of the keys the new admin lacks go in the one request of the member.role
    records, all or nothing. What this account has not sent goes out first;
    after the role change the server takes none of it where it wrote only as
    admin, so with anything still unsent nothing is handed over.
    """
    from ..crypto.keys import compute_fingerprint
    from .revocation import push_with_queued_revocations

    if not client._token:
        client.authenticate()
    client.pull()
    _state, member = _admin_member(vault, client, user_id)
    fingerprint = compute_fingerprint(bytes.fromhex(member.signing_pk), bytes.fromhex(member.encryption_pk))
    confirmed = dict(vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
    if confirmed.get(user_id) != fingerprint:
        if confirm_fingerprint is None or not confirm_fingerprint(fingerprint):
            raise ValueError(f"The key fingerprint of {user_id} was not confirmed: {fingerprint}")
        confirmed[user_id] = fingerprint
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)

    push_with_queued_revocations(vault, client)
    waiting = unsent_work(vault.db)
    if waiting:
        raise RuntimeError(
            "This account has changes the server does not hold yet (" + ", ".join(waiting)
            + "); after the handover it could not send them. Sync first ('sezam push'); "
            "nothing was handed over."
        )
    state, member = _admin_member(vault, client, user_id)
    waits = sorted(folder for folder in state.folders if not teamlog.may_seal(state, folder))
    if waits:
        raise RuntimeError(
            f"{len(waits)} team folder(s) wait for a re-key ('sezam push'); nothing was handed over."
        )
    # Review c78fd19 (R13-8): the new admin re-keys every folder this account
    # held only as admin (revocation.finish_handover_rekeys), so it needs each
    # current key first.
    lacking = [
        key for folder in sorted(state.folders)
        if not teamlog.may_hold_key(state, user_id, key := teamlog.current_key(state, folder))
    ]
    envelope_ids = vault.seal_handover_envelopes(user_id, bytes.fromhex(member.encryption_pk), lacking)
    changes = [
        ("member.role", {"user_id": user_id, "role": "admin"}),
        ("member.role", {"user_id": vault.db.get_meta("user_id"), "role": "member"}),
    ]
    try:
        client.send_handover(envelope_ids, changes)
    except Exception:
        landed = False
        with contextlib.suppress(Exception):  # the send's own failure is what is raised
            client._refresh_team_log()
            landed = teamlog.is_admin(client.team_state(), user_id)
        vault.settle_handover_envelopes(envelope_ids, landed)
        if landed:
            return  # the reply was lost, the unit landed
        raise


READMIT_META = "team_log_readmit"


def readmit_member(
    vault: Vault,
    client: SyncClient,
    user_id: str,
    confirm_fingerprint: Optional[Callable[[str], bool]] = None,
) -> int:
    """Admin: put a member back under the fresh keys their account rotated to.

    Review 8595ec1 (R10-F, low): a server restored from before the member's
    identity rotation knows only the key the log retired, and the device with
    the log's key is lost; member.keys needs that key's signature. After an
    admin's key-reset grant the account rotates to keys the log never saw
    (server: ``_readmission_rotation``); here, once the admin compared their
    fingerprint with the member, ``member.remove`` + ``member.add`` go in one
    append, the member's folders are re-keyed (the lost device held their
    keys) and granted again at the level they had. Interrupted, a second run
    finishes it. Returns the folders granted again.
    """
    from ..crypto.keys import compute_fingerprint
    from .revocation import grant_member
    from .sync_common import TofuKeyChangeError

    if not client._token:
        client.authenticate()
    client.pull()
    state = client.team_state()
    me = vault.db.get_meta("user_id")
    if state is None:
        raise RuntimeError("This organisation has no team log yet ('sezam team-log init').")
    if not client.team_log_trusted(state):
        raise RuntimeError("This device has not confirmed the founder of the team log.")
    if not teamlog.is_admin(state, me):
        raise RuntimeError("Only the team log's admin readmits a member.")
    member = state.members.get(user_id)
    if user_id == me or member is None or not member.active:
        raise ValueError(f"{user_id} is not another active member of the team log")
    pending = dict(vault.db.get_meta_json(READMIT_META) or {})
    change = None
    try:
        client._get_signing_pk(user_id)
    except TofuKeyChangeError as exc:
        change = exc  # pinned below, once the admin compared the fingerprint
    if change is not None:
        spk, epk = change.signing_pk.hex(), change.encryption_pk.hex()
    else:
        row = vault.db.fetchone("SELECT signing_pk, encryption_pk FROM known_keys WHERE user_id = ?", (user_id,))
        if row is None:
            raise RuntimeError(f"No public keys are known for {user_id}")
        spk, epk = bytes(row["signing_pk"]).hex(), bytes(row["encryption_pk"]).hex()
    if (spk, epk) != (member.signing_pk, member.encryption_pk):
        if spk in state.seen_keys or epk in state.seen_keys:
            raise ValueError(
                f"{user_id} signs in with keys the team log has already seen. On their device they "
                "rotate to fresh keys first ('sezam rotate-identity' after your "
                f"'sezam allow-key-reset {user_id}')."
            )
        # Asked every time, even for a key confirmed earlier: these keys get
        # the member's place in the team back.
        fingerprint = compute_fingerprint(bytes.fromhex(spk), bytes.fromhex(epk))
        if confirm_fingerprint is None or not confirm_fingerprint(fingerprint):
            raise ValueError(f"The new key fingerprint of {user_id} was not confirmed: {fingerprint}")
        if change is not None:
            client.confirm_tofu_key_change(change, fingerprint)
        confirmed = dict(vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
        confirmed[user_id] = fingerprint
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
        levels = {f: a[user_id] for f, a in sorted(state.access.items()) if user_id in a}
        pending[user_id] = levels
        vault.db.set_meta_json(READMIT_META, pending)
        before = len(client.set_aside_team_changes())
        try:
            client.append_team_log([
                ("member.remove", {"user_id": user_id}),
                ("member.add", {"user_id": user_id, "signing_pk": spk, "encryption_pk": epk, "role": member.role}),
            ])
        except RuntimeError as exc:
            # Review 4acfdde R11 #4: the pair is set aside or kept whole.
            if any(change[0] == "member.add" and change[1].get("user_id") == user_id
                   for change in client.pending_team_changes()):
                raise RuntimeError(
                    f"The readmit of {user_id} was not sent ({exc}); it goes with the next "
                    f"'sezam push'. Then run 'sezam team-log readmit {user_id}' again: it "
                    "re-keys their folders and grants them again."
                ) from exc
            ours = [
                number for number, item in enumerate(client.set_aside_team_changes(), start=1)
                if number > before and item["change"][0] in ("member.remove", "member.add")
                and item["change"][1].get("user_id") == user_id
            ]
            if ours:
                client.discard_set_aside_team_changes(ours)
            pending.pop(user_id, None)
            vault.db.set_meta_json(READMIT_META, pending)
            raise RuntimeError(
                f"The team log did not take the readmit of {user_id}; nothing changed and they "
                f"stay a member as before ({str(exc).split('. It is set aside')[0]}). Run "
                f"'sezam team-log readmit {user_id}' again "
                "once that is settled."
            ) from exc
        state = client.team_state()
    elif change is not None:
        raise change
    elif user_id not in pending:
        raise ValueError(f"{user_id} already signs in with the keys the team log names")
    if any(user_id in state.stale.get(folder, set()) for folder in pending[user_id]):
        client.pin_envelope_holder_keys(exclude=(user_id,))
        if vault.rekey_after_revocation(user_id) > 0:
            client.push()
        state = client.team_state()
    granted = 0
    for folder, level in pending[user_id].items():
        if folder in state.folders and state.access.get(folder, {}).get(user_id) != level:
            grant_member(vault, client, user_id, folder, level)
            granted += 1
    pending.pop(user_id)
    vault.db.set_meta_json(READMIT_META, pending)
    return granted


def found_team_log(
    vault: Vault,
    client: SyncClient,
    confirm_fingerprint: Optional[Callable[[str, str], bool]] = None,
    org_id: Optional[str] = None,
    confirm_plan: Optional[Callable[[MigrationResult], bool]] = None,
) -> MigrationResult:
    """Found the organisation's log from its current state.

    Pulls first, so the folders and envelopes are the server's latest. Raises
    RuntimeError when this device or the server already has a log.
    ``confirm_plan(result)`` is shown the members and rights the log would
    sign before anything is sent; a no founds nothing (review 1141a20 H3).
    """
    from .team_log_local import GENESIS_META

    if not client._token:
        client.authenticate()
    client._founding_team_log = True
    try:
        client.pull()
    finally:
        client._founding_team_log = False
    if client.team_state() is not None or vault.db.get_meta(GENESIS_META):
        raise RuntimeError("This organisation already has a team log.")
    changes, result = plan_team_log(vault, client, org_id or new_ulid(), confirm_fingerprint)
    if confirm_plan is not None and not confirm_plan(result):
        raise RuntimeError("The members and rights were not confirmed; nothing was signed.")
    client.append_team_log(changes)
    return result
