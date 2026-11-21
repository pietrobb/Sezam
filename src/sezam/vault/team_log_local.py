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
from ..models import new_ulid
from .sync_common import TEAM_LOG_HEAD_MOVED, TEAM_LOG_REFUSED, server_error
from .team_log_state import (  # noqa: F401 - re-exported: callers import these from here
    GENESIS_META,
    CONFIRMED_GENESIS_META,
    ACCOUNT_ANCHOR_META,
    FORGOTTEN_GENESIS_META,
    _GENESIS,
    SERVER_WRAP_META,
    IDENTITY_CONTINUATION_META,
    _CONTINUATION_AAD,
    FETCH_PAGES,
    TEAM_LOG_APPEND_MAX,
    MISMATCH_CAUSES,
    RISK_MARKER,
    LOST_LOG_HINT,
    TeamLogMismatch,
    queued_changes,
    _set_queued_changes,
    _drop_sent_changes,
    set_aside_changes,
    _set_aside,
    retry_set_aside,
    discard_set_aside,
    _refusal_from_server,
    LOCAL_DAMAGED_HINT,
    FORGOTTEN_DAMAGED_WAY_OUT,
    forgotten_genesis,
    readable_forgotten_genesis,
    local_team_state,
    held_team_head,
    team_key_ids,
    team_folder_at_or_above,
    unlogged_folder_keys,
    projected_team_state,
    received_envelope_sender,
    held_genesis,
    _anchor_conflicts,
    record_account_anchor,
    keep_identity_continuation,
    identity_continuation,
    drop_identity_continuation,
    member_keys_record,
    import_account_anchor,
    log_admins,
    founder_key_lineage,
    log_trusted,
    publishable_anchor,
    resolve_change,
    rekey_changes,
)

logger = logging.getLogger(__name__)




class TeamLogMixin:
    """Mixed into SyncClient (``_db``, ``_request``, ``_user_id``, ``_keypair``)."""

    _team_state_cache: Optional[teamlog.TeamState] = None
    # Set by team_migration.found_team_log around its pull: the user founding
    # the team's new log is the one who left the old one.
    _founding_team_log = False

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
        # A pending identity rotation still anchors the log with its old key,
        # as does the kept one of a rotation taken over without the log.
        for old in (self._pending_old_keypair(), self._continuation_old_keypair()):
            if old is None:
                continue
            try:
                if log_trusted(self._db, self._user_id, old, state):
                    return True
            finally:
                old.zeroize()
        return False

    def _continuation_old_keypair(self):
        dek_mgr = getattr(self, "_dek_mgr", None)
        return identity_continuation(self._db, dek_mgr._kek if dek_mgr is not None else None, self._user_id)

    def continue_identity_in_log(self) -> None:
        """Link the account's current keys to the ones the log names.

        Review e443cbc R15 (goal #429): the server lost the log, and a device
        of this account that never held it rotated the identity: no
        member.keys. This device took the new keys over holding the old ones
        (IDENTITY_CONTINUATION_META) and signs that member.keys now, as the
        rotating device would have. Until then every pull and push stopped
        with 'founder is not confirmed'.
        """
        from .sync_common import TEAM_LOG_HEAD_MOVED, server_error

        for attempt in range(2):
            record = self._identity_link(self.team_state())
            if record is None:
                return
            if not self._token:
                self.authenticate()
            try:
                self._request("POST", "/api/team-log", {"records": [record]}, auth=True)
            except RuntimeError as exc:
                if attempt == 0 and server_error(exc, 409, TEAM_LOG_HEAD_MOVED):
                    self._refresh_team_log()  # puts back what the server lost, with the link
                    continue
                raise
            self.accept_own_team_log([record])
            drop_identity_continuation(self._db)
            return

    def _identity_link(self, state: Optional[teamlog.TeamState]) -> Optional[dict]:
        """member.keys from the kept keys onto ``state``, or None (dropped once moot)."""
        if self._db.get_meta(IDENTITY_CONTINUATION_META) is None:
            return None
        old = self._continuation_old_keypair()
        if old is None:
            drop_identity_continuation(self._db)
            return None
        try:
            member = state.members.get(self._user_id) if state is not None else None
            if (
                member is None or not member.active
                or member.signing_pk != old.signing_pk.hex()
                or teamlog.signing_key_retired(state, self._user_id, old.signing_pk.hex())
            ):
                drop_identity_continuation(self._db)  # linked, or no longer this key's to link
                return None
            return member_keys_record(state, self._user_id, old, self._keypair)
        finally:
            old.zeroize()

    def require_trusted_team_log(self) -> None:
        if self.team_state() is None and self._db.get_meta(CONFIRMED_GENESIS_META) is not None:
            # Review e443cbc R15 (goal #429): a pin without its log (the anchor
            # came with account keys taken over from another device, or
            # 'team-log confirm-founder' before the first pull) stopped every
            # push and invitation until a pull. The log is fetched and checked
            # against the pin here.
            self._refresh_team_log()
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
        what this device accepted. A damaged local copy (INV-7) is fetched
        again whole, held to the same pins: its genesis, and the head it saw
        (``held``), at whose seq the server's record must be the one stored.
        """
        held = None
        forgotten_genesis(self._db)  # unreadable: no fetch mends it (FORGOTTEN_DAMAGED_WAY_OUT)
        try:
            local = self.team_state()
        except TeamLogMismatch as exc:
            if exc.cause != "local_damaged":
                raise
            local, held = None, held_team_head(self._db)
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
                "The server's team log differs from the independently confirmed genesis.", "confirmed_genesis"
            )
        if server_head is None:
            if local is not None or held is not None or pinned:
                raise TeamLogMismatch(
                    "The server no longer has the team log this device holds "
                    "(restored from a backup, or another server).", "log_gone"
                )
            if forgotten_genesis(self._db) and not self._founding_team_log:
                # Review 8bc70f7 M2: a device that left a log does not fall
                # back to the rules from before any log because a server sends none.
                raise TeamLogMismatch(
                    "The server has no team log, and this device left an earlier one: it waits for "
                    "the team's new log ('sezam team-log found' on the admin's device) and its confirmed founder.",
                    "left_earlier_log",
                )
            return None
        if pinned and server_head.get("genesis_hash") != pinned:
            raise TeamLogMismatch(
                "The server's team log starts with another genesis than this device pinned.", "other_genesis"
            )
        local_seq = local.head_seq if local is not None else held[0] if held is not None else -1
        if server_head.get("seq", -1) < local_seq:
            raise TeamLogMismatch(
                f"The server's team log went back (head {server_head.get('seq')} < {local_seq} seen here).", "went_back"
            )
        if server_head.get("seq") == local_seq:
            if server_head.get("hash") not in ({local.head_hash} if local is not None else held[1]):
                raise TeamLogMismatch(f"The server's team log differs at record {local_seq}.", "differs")
            if local is not None:
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
                raise TeamLogMismatch(f"The server's team log does not replay: {exc}", "does_not_replay") from exc
            fetched.extend(records)
            if state.head_seq >= server_head["seq"]:
                break
        if held is not None and len(fetched) > held[0] and teamlog.record_hash(fetched[held[0]]) not in held[1]:
            raise TeamLogMismatch(f"The server's team log differs at record {held[0]}.", "differs")
        if state is None or state.head_seq != server_head["seq"] or state.head_hash != server_head.get("hash"):
            raise TeamLogMismatch("The server's team log does not reach the head it announced.", "short_of_head")
        if pinned is None and state.genesis_hash != server_head.get("genesis_hash"):
            raise TeamLogMismatch("The server's team log genesis differs from the head it announced.", "head_genesis")
        refusal = teamlog.admin_policy_refusal(state)
        if refusal:
            # TL7: the server refuses such an append; a head with it is not followed.
            raise TeamLogMismatch(f"The server's team log is refused at its head: {refusal}.", "refused_at_head")
        with self._db.transaction(immediate=True):
            # Another process of this vault may have stored part of it meanwhile.
            raced = self._local_head_seq() != local_seq
            if not raced:
                if held is not None:
                    self._db.execute("DELETE FROM team_log")  # the damaged copy, fetched again above
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
        # The server takes back no log naming keys this account does not sign
        # in with: the link to the ones taken over goes with it (R15, #429).
        link = self._identity_link(local)
        for start in range(0, len(rows), TEAM_LOG_APPEND_MAX):
            part = [{"body": r["body"], "sig": r["sig"]} for r in rows[start:start + TEAM_LOG_APPEND_MAX]]
            if link is not None and start + TEAM_LOG_APPEND_MAX >= len(rows):
                part.append(link)
            try:
                head = self._request("POST", "/api/team-log/restore", {"records": part}, auth=True).get("head")
            except RuntimeError as exc:
                # 409: its head is not the one it announced (another device
                # put them back meanwhile, or a lie): the next pull compares again.
                level = logging.WARNING if server_error(exc, 409, TEAM_LOG_HEAD_MOVED) else logging.ERROR
                logger.log(level, "The server did not take back the team log records it lost: %s", exc)
                return False
            logger.warning("Put back team log records the server had lost (now at %s)", (head or {}).get("seq"))
        if link is not None:
            self.accept_own_team_log([link])
            drop_identity_continuation(self._db)
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
        signing_key = self._log_signing_key(state)
        records = []
        for index, (kind, data) in enumerate(changes):
            resolved = resolve_change(state, kind, data)
            if resolved is None:
                continue
            record = teamlog.sign_record(teamlog.next_body(state, kind, self._user_id, resolved), signing_key)
            state = teamlog.apply_record(state, record)
            records.append((index, record))
        return records

    def _log_signing_key(self, state: teamlog.TeamState):
        """The key the log names for this account signs its records.

        Review e443cbc R15 (goal #429): while this device's identity rotation
        has not landed the log names the old key, and member.keys goes last
        (add_identity_team_record). A grant signed with the new key came
        before it: the device's own replay refused it (bad_signature) and
        the grant could not be made until the rotation was pushed.
        """
        member = state.members.get(self._user_id)
        if member is not None and member.signing_pk != self._keypair.signing_pk.hex():
            for old in (self._pending_old_keypair(), self._continuation_old_keypair()):
                if old is None:
                    continue
                try:
                    if old.signing_pk.hex() == member.signing_pk:
                        return old.to_nacl_signing_key()
                finally:
                    old.zeroize()
        return self._keypair.to_nacl_signing_key()

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
            record = member_keys_record(state, self._user_id, old, self._keypair)
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

    def _log_names_another_own_key(self, state: Optional[teamlog.TeamState]) -> bool:
        """The local log names another signing key of this account than the
        one it holds: an identity rotation taken over from another device that
        this copy of the log is not past yet."""
        own = state.members.get(self._user_id) if state is not None else None
        return own is not None and own.signing_pk != self._keypair.signing_pk.hex()

    def _refused_team_changes(self, changes) -> dict[int, str]:
        """Index -> reason of each change the rules refuse on the local head."""
        state = self.team_state() or teamlog.TeamState()
        if self._log_names_another_own_key(state):
            # Review e443cbc R15 (goal #429): signed with the current key every
            # change failed as bad_signature and was set aside for good, though
            # the rules refuse none of them. They wait (flush_team_log pulls
            # the log first).
            return {}
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

    def fold_unlogged_folder_keys(self) -> None:
        """Below a team folder, no folder keeps a key the log does not know.

        Stateful run on ab915bc (goal #429): B made a subfolder, with a key
        of its own, in a folder whose grant (made on A) it had not pulled yet;
        the grant logged only the subfolders A knew (unlogged_folder_keys).
        Every client refuses what an unlogged key seals below a team folder,
        so each item put there stayed unpushed for good. As a move into a
        team folder does (moved_subtree_keys), what such a key seals is
        resealed under the folder's parent's key, which the folder then uses.
        A folder another device already folded only takes the parent's key
        here (nothing is sealed with its old one); logging the old key would
        have made it a team folder under a key that seals nothing.
        """
        from .personal_root import moved_subtree_keys, reseal_moved_subtree

        state, me = self.team_state(), self._db.get_meta("user_id")
        # Only an admin's devices make folder keys; a member holds rows of the
        # admin's it cannot open.
        if self._dek_mgr is None or state is None or not teamlog.is_admin(state, me):
            return
        projected = projected_team_state(self._db, me)
        missing = {
            folder
            for team_folder in projected.folders
            for folder, _ in unlogged_folder_keys(self._db, projected.dek_index, team_folder)
            if folder not in projected.folders
        }

        def outermost(folder: str) -> bool:
            row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (folder,))
            while row is not None and row["parent_id"] is not None:
                if row["parent_id"] in missing:
                    return False
                row = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (row["parent_id"],))
            return True

        for folder in sorted(f for f in missing if outermost(f)):
            logger.warning("Folder %s below a team folder takes its parent's key", folder)
            with self._db.transaction(immediate=True):
                parent = self._db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (folder,))["parent_id"]
                changes = moved_subtree_keys(
                    self._db, folder, self._dek_mgr.get_dek_for_node(parent)[0], False, projected.dek_index
                )
                reseal_moved_subtree(self._db, self._dek_mgr, folder, changes)

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

    def drop_superseded_org_recovery(self) -> bool:
        """Review c78fd19 R13-10: a setup saved here (offline, or before the
        unlock registered it) and replaced by a newer one on the web is
        forgotten before the push names its key in the log again. True when
        it was (org_recovery_server.SUPERSEDED_NOTE)."""
        from .org_recovery_server import drop_superseded_setup, superseded_by, waiting_setup

        if waiting_setup(self._db) is None:  # registration or log record (capability run 378)
            return False
        try:
            status = self._request("GET", "/api/org-recovery/status") or {}
        except RuntimeError as exc:
            logger.warning("Org recovery status not known: %s", exc)
            return False
        if not superseded_by(self._db, status):
            return False
        drop_superseded_setup(self._db)
        return True

    def _drop_refused_org_recovery(self, exc: BaseException) -> bool:
        """The server refused this device's org.recovery record: a newer setup
        (web) replaced it after drop_superseded_org_recovery looked. The setup
        is forgotten the same way; True when its records left the queue."""
        from .org_recovery_server import drop_superseded_setup

        detail = _refusal_from_server(exc)
        if detail is None or detail.get("team_log_code") != "org_recovery_superseded":
            return False
        before = len(self.pending_team_changes())
        drop_superseded_setup(self._db)
        self._org_recovery_superseded = True
        return len(self.pending_team_changes()) < before

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
        from . import pending_states

        if pending_states.org_recovery_registration(self._db) is not None:
            return  # so does one the server has yet to take (anchored after it)
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
        from . import pending_states

        if pending_states.org_recovery_registration(self._db) is not None:
            return  # the server refuses a key its blob does not hold yet (R13-10)
        logged = teamlog.recovery_key(state, self._user_id)
        replaces = self._db.get_meta_json("org_recovery_replaces") or {}
        # Registered later (offline setup): it still replaces the key it was set up over.
        meant = replaces.get("recovery_signing_pk") == pk and replaces.get("expected_signing_pk") == logged
        if logged is not None and logged != pk and not (replace or meant):
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
        resp = self._request("GET", f"/api/team-log?since={self._local_head_seq()}", auth=True)
        self._sync_team_log(resp.get("head"))

    def team_log_refusal(self) -> Optional[TeamLogMismatch]:
        """Why this device refuses the server's team log now (INV-8: forgetting
        the pin asks this), or None: it follows the server's log."""
        try:
            self._refresh_team_log()
        except TeamLogMismatch as exc:
            return exc
        return None

    def _send_team_records(self, send, extra=()) -> None:
        """Build the pending changes (+ ``extra``) and ``send(records)``.

        The server appends only onto its head; when it moved, the log is
        pulled and the records built once more. On success they are stored
        here and the queue is emptied.
        """
        from .sync_common import TEAM_LOG_HEAD_MOVED, server_error

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
        if self._log_names_another_own_key(self.team_state()):
            # The changes are judged and built on the log that names this
            # account's current key (R15, goal #429).
            self._refresh_team_log()

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
                if self._drop_refused_org_recovery(exc):
                    continue
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
