"""INV-7 (docs/ROOT_CAUSE_PLAN.md): a team log this desktop refuses holds back
the team's changes only, never the personal tree's.

On eba9493 every push stopped in require_trusted_team_log on the refusal, so a
change in the user's own folder never left the device until a risky
forget-pin (anchor_conflict) or a pull that fixed the copy. Now the personal
objects go out, the rest waits, and the push names the refusal and its way out.
A re-key or key change is one unit with the team's keys: it waits whole.
"""

from __future__ import annotations

import pytest

from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, TeamLogMismatch, local_team_state
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_inv7_unlock_never_blocked import OTHER_GENESIS, _wrap_keys
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401

STATES = ("anchor_names_other", "holds_damaged_hash")


def _on_server(db, obj_id: str) -> bool:
    return any(o["id"] == obj_id for o in db._storage["vault_objects"])


def _refused_member(team, state):  # noqa: F811
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    mine = bob.create_personal_folder("mine")
    bob_client.pull()
    bob.db.set_meta(CONFIRMED_GENESIS_META, admin_client.team_state().genesis_hash)
    assert [c for c in bob_client.push()["conflicts"] if c["error"] != "admin only"] == []
    with bob.db.transaction(immediate=True):
        if state == "anchor_names_other":
            _wrap_keys(bob, OTHER_GENESIS)
        else:
            bob.db.execute("UPDATE team_log SET hash = ? WHERE seq = (SELECT MAX(seq) FROM team_log)", ("00" * 32,))
    bob.lock()
    bob.unlock(PASSWORD)
    with pytest.raises(TeamLogMismatch) as refused:
        local_team_state(bob.db)
    return db, bob, _client(bob, bob.db.get_meta("server_url")), mine, str(refused.value)


@pytest.mark.parametrize("state", STATES)
def test_the_personal_tree_goes_out_while_the_log_is_refused(team, state):  # noqa: F811
    db, bob, client, mine, refusal = _refused_member(team, state)
    sub = bob.create_node("sub", parent_id=mine)
    entry = bob.create_entry(sub, "written", [{"key": "password", "value": "new"}])

    # No pull first: the copy is still refused. What is not the personal tree's
    # (the audit records, the member's root) waits, so the push names the refusal.
    with pytest.raises(TeamLogMismatch) as waits:
        client.push()
    result = waits.value.pushed
    assert [c for c in result["conflicts"] if c["error"] != "admin only"] == [], result
    assert _on_server(db, sub) and _on_server(db, entry), result
    assert "personal change(s) went out" in str(waits.value) and str(waits.value).endswith(refusal), waits.value
    assert waits.value.cause == ("anchor_conflict" if state == "anchor_names_other" else "local_damaged")
    assert ("forget-pin" in str(waits.value)) is (state == "anchor_names_other"), waits.value
    assert not bob.db.fetchone("SELECT 1 FROM outbox WHERE kind = 'write' AND object_id IN (?, ?)", (sub, entry))


@pytest.mark.parametrize("state", STATES)
def test_a_key_change_waits_whole_while_the_log_is_refused(team, state):  # noqa: F811
    db, bob, client, mine, _ = _refused_member(team, state)
    entry = bob.create_entry(mine, "written", [{"key": "password", "value": "new"}])
    bob.change_password(PASSWORD, PASSWORD + "-2")
    with pytest.raises(TeamLogMismatch):
        client.push()
    assert not _on_server(db, entry)
