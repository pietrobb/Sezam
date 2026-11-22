"""INV-5/INV-7 precedence for the team's admin (review e443cbc, #436): "with a
refused log the admin's whole vault is read-only".

The member's case is tests/test_inv7_personal_push_while_refused.py and
tests/test_inv7_unlock_never_blocked.py (a device outside the log). Here the
device is the log's founder and admin: its personal folder is written and goes
out to the server while the copy is refused, and the organisation's tree, which
the log owns, waits (rule 2 of the precedence in docs/ROOT_CAUSE_PLAN.md).
"""

from __future__ import annotations

import pytest

from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, TeamLogMismatch, local_team_state
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_inv7_personal_push_while_refused import STATES, _on_server
from tests.test_inv7_unlock_never_blocked import OTHER_GENESIS, _personal_mutations, _wrap_keys
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401


def _refused_admin(team, state):  # noqa: F811
    db, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    org_entry = admin.create_entry(admin.db.get_meta("root_node_id"), "org", [{"key": "password", "value": "o"}])
    mine = admin.create_personal_folder("mine")
    admin_client.push()
    admin.db.set_meta(CONFIRMED_GENESIS_META, admin_client.team_state().genesis_hash)
    assert local_team_state(admin.db).members[admin.db.get_meta("user_id")].role == "admin"
    with admin.db.transaction(immediate=True):
        if state == "anchor_names_other":
            _wrap_keys(admin, OTHER_GENESIS)
        else:
            admin.db.execute("UPDATE team_log SET hash = ? WHERE seq = (SELECT MAX(seq) FROM team_log)", ("00" * 32,))
    admin.lock()
    admin.unlock(PASSWORD)
    with pytest.raises(TeamLogMismatch):
        local_team_state(admin.db)
    return db, admin, _client(admin, admin.db.get_meta("server_url")), mine, org_entry


@pytest.mark.parametrize("state", STATES)
def test_the_admin_writes_its_personal_tree_and_it_goes_out(team, state):  # noqa: F811
    db, admin, client, mine, _ = _refused_admin(team, state)
    refused = {}
    for name, op in _personal_mutations(admin).items():
        try:
            op()
        except Exception as exc:  # noqa: BLE001 - every refusal is the finding
            refused[name] = f"{type(exc).__name__}: {getattr(exc, 'cause', '')} {exc}"[:160]
    assert refused == {}, sorted(refused)
    entry = admin.create_entry(mine, "written", [{"key": "password", "value": "new"}])
    with pytest.raises(TeamLogMismatch) as waits:
        client.push()
    assert _on_server(db, entry), waits.value.pushed
    assert "personal change(s) went out" in str(waits.value), waits.value
    assert not admin.db.fetchone("SELECT 1 FROM outbox WHERE kind = 'write' AND object_id = ?", (entry,))


@pytest.mark.parametrize("state", STATES)
def test_the_organisation_waits_for_the_admin_too(team, state):  # noqa: F811
    db, admin, client, _, org_entry = _refused_admin(team, state)
    root = admin.db.get_meta("root_node_id")
    for op in (
        lambda: admin.update_entry(org_entry, fields=[{"key": "password", "value": "w"}]),
        lambda: admin.create_entry(root, "team", [{"key": "password", "value": "v"}]),
        lambda: admin.create_node("f", parent_id=root),
        lambda: admin.delete_entry(org_entry),
    ):
        with pytest.raises(TeamLogMismatch):
            op()
    assert admin.get_field_value(org_entry, "password") == "o"  # still readable
