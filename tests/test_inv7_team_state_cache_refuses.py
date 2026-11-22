"""INV-7 (review e443cbc, goal #438): the cached team state never outlives a
refusal.

TeamLogMixin.team_state cached the replayed log under the head row's seq and
hash. Damage below the head, a broken signature at the head, keys naming
another genesis or an unreadable list of left logs changed neither, so every
team operation of the process went on with the state local_team_state now
refuses.
"""

from __future__ import annotations

import pytest

from sezam.vault.team_log_local import FORGOTTEN_GENESIS_META, TeamLogMismatch
from tests.test_integration_client_server import PASSWORD
from tests.test_inv7_unlock_never_blocked import OTHER_GENESIS, _device, _Server, _wrap_keys

DAMAGE = {
    "head_sig": ("UPDATE team_log SET sig = ? WHERE seq = (SELECT MAX(seq) FROM team_log)", "00" * 64),
    "genesis_sig": ("UPDATE team_log SET sig = ? WHERE seq = 0", "00" * 64),
    "genesis_hash": ("UPDATE team_log SET hash = ? WHERE seq = 0", "00" * 32),
    "middle_body": ("UPDATE team_log SET body = body || ' ' WHERE seq = 1", None),
}


@pytest.mark.parametrize("damage", [*DAMAGE, "anchor_names_other", "left_list_unreadable"])
def test_a_refusal_after_the_state_was_read_is_a_refusal(tmp_path, damage):
    vault, _entry = _device(tmp_path, "none")
    vault.unlock(PASSWORD)
    client = _Server(vault, "same")
    assert client.team_state() is not None  # read once: the state is cached
    with vault.db.transaction(immediate=True):
        if damage == "anchor_names_other":
            _wrap_keys(vault, OTHER_GENESIS)
        elif damage == "left_list_unreadable":
            vault.db.set_meta(FORGOTTEN_GENESIS_META, "not a list")
        else:
            sql, value = DAMAGE[damage]
            vault.db.execute(sql, (value,) if value is not None else ())
    if damage == "anchor_names_other":
        vault.lock()
        vault.unlock(PASSWORD)  # the unlock notes the genesis the keys name
    with pytest.raises(TeamLogMismatch):
        client.team_state()
