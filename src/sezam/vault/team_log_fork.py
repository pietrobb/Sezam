"""Following a server team log that forks from this device's copy (goal #442,
review 18c300f R16-H1). Split out of team_log_local so that module stays
within the size the review 6 split set (tests/test_review6_sync_client_split.py).

``client`` is the SyncClient (``_db``, ``_request``, ``_user_id``, ``_keypair``).
"""

from __future__ import annotations

import logging

from .. import teamlog
from . import team_log_withdrawn
from ..models import new_ulid
from .team_log_state import FETCH_PAGES, _set_queued_changes, queued_changes

logger = logging.getLogger(__name__)

# A record of these kinds is queued again as the change it made; a
# genesis or member.keys is bound to the head it was signed on. R16-M5:
# the same kinds as the page and the phone (teamlog.js REMADE_KINDS,
# team_log.dart remadeKinds), org.recovery.wrap too.
REQUEUED_KINDS = frozenset({
    "member.add", "member.role", "member.remove", "access.set", "folder.key", "org.recovery",
    "org.recovery.wrap",
})


def follow_fork(client, local: teamlog.TeamState, server_head: dict):
    """Follow a server log that forks from the local copy, as far as
    teamlog.fork_refusal allows; this account's lost changes that are not
    on the server's side are queued again. (state, None), or (None, why
    not) - the mismatch stands.

    Goal #442 (bg344 random run of TeamLogMachine on a3f84bb): the server
    lost its log, and the admin's device A put back its shorter copy with
    the link of its own rotation; B, which held the grant A had not
    pulled, stayed on 'went back' for good. Nothing of B's is lost: each
    change it made goes out again on the new head (or is set aside,
    shown by 'sezam team-log queue').

    Review 18c300f R16-H1: every fork of this account's records was
    followed. The server keeps what it refused, so a hand-over the admin
    had seen refused (and removed Bob since) made Bob the admin, and a
    dropped identity rotation named keys nobody holds. A member's device
    never followed a fork, also not once the admin's device had made the
    lost changes again on the server's side: 'does not replay' for good.
    """
    db = client._db
    records: list[dict] = []
    for _ in range(FETCH_PAGES):
        page = client._request("GET", f"/api/team-log?since={len(records) - 1}", auth=True).get("records") or []
        page = page[:max(server_head["seq"] + 1 - len(records), 0)]
        if not page:
            break
        records.extend(page)
        if len(records) > server_head["seq"]:
            break
    rows = db.fetchall("SELECT body, sig, hash FROM team_log ORDER BY seq")
    fork = next((i for i, (row, record) in enumerate(zip(rows, records))
                 if teamlog.record_hash(record) != row["hash"]), None)
    if not fork:  # another genesis, or the server's log is a prefix of this copy
        return None, None
    keypair = getattr(client, "_keypair", None)
    held = None if keypair is None else (keypair.signing_pk.hex(), keypair.encryption_pk.hex())
    lost_records = [{"body": row["body"], "sig": row["sig"]} for row in rows[fork:]]
    try:
        reason, missing = teamlog.fork_refusal(
            lost_records, records[fork:], client._user_id, held, team_log_withdrawn.withdrawn(db),
        )
    except teamlog.TeamLogError:
        return None, None
    if reason:
        return None, reason
    lost = [teamlog.parse_body(row["body"]) for row in rows[fork:]]
    missing_bodies = [body for body in lost if body["seq"] in missing]
    links = [body for body in missing_bodies if body["type"] == "member.keys"]
    changes = [body for body in missing_bodies if body["type"] != "member.keys"]
    if any(body["type"] not in REQUEUED_KINDS for body in changes) or len(links) > 1:
        return None, None
    try:
        state = teamlog.replay(records)
    except teamlog.TeamLogError:
        return None, None
    if (state.head_seq != server_head["seq"] or state.head_hash != server_head.get("hash")
            or teamlog.admin_policy_refusal(state)):
        return None, None
    if links and not rotation_linked_again(client, state, links[0]):
        return None, None
    batch = new_ulid()  # set aside together or not at all, as they were made
    requeued = [[body["type"], {**body["data"], "_batch": batch}] for body in changes]
    with db.transaction(immediate=True):
        if client._local_head_seq() != local.head_seq:
            return None, None  # another process moved the copy meanwhile: the next pull compares again
        db.execute("DELETE FROM team_log WHERE seq >= ?", (fork,))
        # Capability finding 505: this account's records left behind are
        # withdrawn - a server serving them again later is not followed
        # (their changes go out again, or are set aside).
        team_log_withdrawn.withdraw(db, teamlog.fork_abandoned(lost_records, client._user_id))
        client._store_team_log(records[fork:], state)
        if requeued:
            _set_queued_changes(db, requeued + queued_changes(db))
    logger.warning("Followed the server's team log from record %s, which forks from this device's copy; "
                   "%s own change(s) queued again", fork, len(requeued))
    return state, None


def rotation_linked_again(client, state: teamlog.TeamState, body: dict) -> bool:
    """``body`` (a member.keys lost in the fork) links to this device's keys
    from the old ones of its unpushed identity rotation, which the log
    ``state`` still names: the push signs it again on that head
    (add_identity_team_record), so nothing is lost by following.

    Goal #442 (bg34 targeted run on c7a0e49): the server went back to a
    backup from before B's rotation, A then put its org recovery on the
    restored log, and B's every push stopped on 'does not replay'.
    """
    data = body["data"]
    member = state.members.get(client._user_id)
    if (data.get("user_id") != client._user_id or member is None or not member.active
            or (data.get("signing_pk"), data.get("encryption_pk"))
            != (client._keypair.signing_pk.hex(), client._keypair.encryption_pk.hex())):
        return False
    old = client._pending_old_keypair()
    if old is None:
        return False
    try:
        old_pk = old.signing_pk.hex()
        return member.signing_pk == old_pk and not teamlog.signing_key_retired(state, client._user_id, old_pk)
    finally:
        old.zeroize()
