"""INV-1 on the restore path (capability run 453 on 2c6b22e).

The server lost its whole team log, and its users rows are from a backup
older than the log's handover: ``users.is_admin`` still names the founder A,
while the signed log the device uploads made C the admin. A key rotation of
B the server lost comes back only from the team admin (review c78fd19 #2),
and the team admin is who the restored log says, not the stale cache.
"""

from __future__ import annotations

import copy

from tests.test_inv2_restore_within_append import (
    IDS, REFUSED, Honest, Keys, _db, _rotation, _set_keys, restore,
)


def _lost_log_with_a_stale_cache() -> tuple[list, dict]:
    honest = Honest(Keys())
    for name in ("B", "C"):
        assert honest._commit("A", [("member.add", "A", {
            "user_id": IDS[name], "signing_pk": honest.current(name).pk,
            "encryption_pk": honest.current(name).enc, "role": "member",
        })])
    assert honest._commit("A", [
        ("member.role", "A", {"user_id": IDS["C"], "role": "admin"}),
        ("member.role", "A", {"user_id": IDS["A"], "role": "member"}),
    ])
    old_b = honest.current("B")
    new_b = honest.keys.new()
    assert honest._commit("B", [_rotation(honest.state, "B", new_b)], rotate=new_b)
    storage = copy.deepcopy(honest.snapshots[-1][1])
    storage["team_log"] = []
    db = _db(storage)
    _set_keys(db, IDS["B"], old_b)  # the backup is from before B's rotation
    rows = {u["id"]: u for u in db._storage["users"]}
    rows[IDS["A"]]["is_admin"], rows[IDS["C"]]["is_admin"] = 1, 0  # and before the handover
    return honest.records, db._storage


def test_the_cached_admin_does_not_put_back_a_lost_rotation():
    records, storage = _lost_log_with_a_stale_cache()
    REFUSED.clear()
    assert not restore(_db(storage), records, IDS["A"]), "the stale users.is_admin decided"
    assert "only the team admin puts back the key rotation" in str(REFUSED[-1:]), REFUSED


def test_the_restored_logs_admin_puts_it_back():
    records, storage = _lost_log_with_a_stale_cache()
    REFUSED.clear()
    assert restore(_db(storage), records, IDS["C"]), REFUSED
