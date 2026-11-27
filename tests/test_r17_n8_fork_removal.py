"""Review c02cc47 R17-N8, capability finding 691: a removal takes the access
still waiting for the member also when it comes in a fork the device follows.

de2c278 applied the rule only on the linear catch-up. Another device of the
admin removed Bob on a server log that forks from this device's copy (the
server went back to a backup); this device followed it, stored the removal
and kept the access waiting here and the one it lost (made again). Bob,
added back later (a plain pull), looked as if never removed: the next push
gave him what the removal took.
"""

from __future__ import annotations

from sezam.vault.sync_rekey import RekeyMixin
from sezam.vault.team_log_state import _set_queued_changes, queued_changes
from tests import test_r16_fork_following as fork
from tests.team_log_fork_vectors import _base
from tests.team_log_vectors import A, B, F1, F2, K
from tests.test_r16_fork_following import _head


class _Admin(fork._Device, RekeyMixin):
    """The fork follower with the re-key batch, as in SyncClient."""

    _push_cache: dict = {}


def _device(tmp_path, user, held, served) -> _Admin:
    device = fork._device(tmp_path, user, held, served)
    device.__class__ = _Admin
    return device


def _bobs_access(device) -> list:
    return [c for c in queued_changes(device._db) if c[0] == "access.set" and c[1]["user_id"] == B.uid]


def test_a_removal_in_a_followed_fork_takes_the_access_waiting_and_lost(tmp_path):
    held = _base().key(F1, 0, K[1], None).access(F1, B, "write").records
    forked = _base().key(F2, 0, K[2], None).remove(B)
    device = _device(tmp_path, A, held, forked.records)
    try:
        _set_queued_changes(device._db, [["access.set", {"folder": F2, "user_id": B.uid, "level": "read"}]])
        device._sync_team_log(_head(forked.records))
        assert not _bobs_access(device)  # the waiting read and the lost write went with the removal
        assert [c[0] for c in queued_changes(device._db)] == ["folder.key"]  # F1's lost key goes out again
        device._served = forked.member(B).records  # Bob added back, pulled plainly
        assert device._sync_team_log(_head(device._served)).members[B.uid].active
        assert not _bobs_access(device)
    finally:
        device._db.close()


def test_access_queued_after_a_queued_removal_stays_in_a_fork(tmp_path):
    """A readmit queued here (removal, re-add, then access) was made knowing
    the removal; the fork's removal does not take what came after it."""
    held = _base().key(F1, 0, K[1], None).records
    forked = _base().key(F2, 0, K[2], None).remove(B)
    device = _device(tmp_path, A, held, forked.records)
    try:
        readmit = [["member.remove", {"user_id": B.uid}], ["member.add", {"user_id": B.uid}],
                   ["access.set", {"folder": F1, "user_id": B.uid, "level": "read"}]]
        _set_queued_changes(device._db, readmit)
        device._sync_team_log(_head(forked.records))
        assert queued_changes(device._db)[-3:] == readmit
    finally:
        device._db.close()
