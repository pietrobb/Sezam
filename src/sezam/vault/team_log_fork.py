"""Following a server team log that forks from this device's copy (goal #442,
review 18c300f R16-H1). Split out of team_log_local so that module stays
within the size the review 6 split set (tests/test_review6_sync_client_split.py).

U7d (docs/CORE_UNIFICATION.md): where the log forks, whether it is followed,
what is made again and what is withdrawn are the core's
(core/src/teamlog/fork_follow.rs, tests/vectors/team_log_fork_follow.json);
this module fetches, replays and stores.

``client`` is the SyncClient (``_db``, ``_request``, ``_user_id``, ``_keypair``).
"""

from __future__ import annotations

import logging

from .. import teamlog
from . import sync_core, team_log_withdrawn
from ..models import new_ulid
from .team_log_state import FETCH_PAGES, _set_queued_changes, queued_changes

logger = logging.getLogger(__name__)


def follow_fork(client, local: teamlog.TeamState, server_head: dict):
    """Follow a server log that forks from the local copy, as far as the
    core allows; this account's lost changes that are not on the server's
    side are queued again. (state, None), or (None, why not) - the mismatch
    stands.

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
    rows = db.fetchall("SELECT body, sig FROM team_log ORDER BY seq")
    copy = [{"body": row["body"], "sig": row["sig"]} for row in rows]
    keypair = getattr(client, "_keypair", None)
    held = None if keypair is None else [keypair.signing_pk.hex(), keypair.encryption_pk.hex()]
    split = sync_core.call(
        "team_log_fork_split", local=copy, served=records, user_id=client._user_id, held_keys=held,
        withdrawn=sorted(team_log_withdrawn.withdrawn(db)),
    )
    if "refusal" in split:
        return None, split["refusal"]
    if "stand" in split:
        return None, None
    fork = split["fork"]
    try:
        state = teamlog.replay(records)
    except teamlog.TeamLogError:
        return None, None
    old = client._pending_old_keypair() if keypair is not None and split["relink"] else None
    try:
        old_pk = None if old is None else old.signing_pk.hex()
    finally:
        if old is not None:
            old.zeroize()
    take = sync_core.call(
        "team_log_fork_take", state=state.to_core(), head=server_head, lost=copy[fork:],
        missing=split["missing"], user_id=client._user_id, held_keys=held, old_signing_pk=old_pk,
    )
    if "stand" in take:
        return None, None
    # A rotation linked again is signed again on that head by the push
    # (add_identity_team_record), so nothing is lost by following.
    plan = take["follow"]
    batch = new_ulid()  # set aside together or not at all, as they were made
    requeued = [[body["type"], {**body["data"], "_batch": batch}] for body in plan["remake"]]
    with db.transaction(immediate=True):
        if client._local_head_seq() != local.head_seq:
            return None, None  # another process moved the copy meanwhile: the next pull compares again
        db.execute("DELETE FROM team_log WHERE seq >= ?", (fork,))
        # Capability finding 505: this account's records left behind are
        # withdrawn - a server serving them again later is not followed
        # (their changes go out again, or are set aside).
        team_log_withdrawn.withdraw(db, plan["abandoned"])
        client._store_team_log(records[fork:], state)
        if requeued:
            _set_queued_changes(db, requeued + queued_changes(db))
        # R17-N8, capability finding 691: a removal on the server's side
        # takes what waits here for the member (the lost changes made again
        # too), as on a plain pull; one this device lost it knew of already.
        known = {teamlog.change_key(teamlog.parse_body(row["body"])) for row in rows[fork:]}
        client._drop_access_removed_since([
            r for r in records[fork:] if teamlog.change_key(teamlog.parse_body(r["body"])) not in known])
    logger.warning("Followed the server's team log from record %s, which forks from this device's copy; "
                   "%s own change(s) queued again", fork, len(requeued))
    return state, None
