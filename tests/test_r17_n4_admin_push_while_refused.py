"""Review c02cc47 R17-N4 (INV-7 rule 1): with a refused team log an admin who
shares a folder sent nothing on 'sezam push' or the GUI push.

Both start with the revocation queue (revocation.queue_revoked_holders). For an
account that sealed an envelope for another member it reads the server's team
log first, and the refused copy raised TeamLogMismatch before client.push(),
which on its own sends the personal tree and holds back only the team's part.
The R15-P4 tests pushed from a member, who holds no envelope for anyone.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault.revocation import grant_member, push_with_queued_revocations
from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, TeamLogMismatch, local_team_state
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_inv7_personal_push_while_refused import STATES, _on_server
from tests.test_inv7_unlock_never_blocked import OTHER_GENESIS, _wrap_keys
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401


def _refused_granting_admin(team, state):  # noqa: F811
    db, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    shared = admin.create_node("Shared", parent_id=admin.db.get_meta("root_node_id"))
    admin_client.push()
    bob_id = bob.db.get_meta("user_id")
    grant_member(admin, admin_client, bob_id, shared, confirm_fingerprint=lambda _fp: True)
    mine = admin.create_personal_folder("mine")
    admin_client.push()
    assert admin.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE created_by = ? AND user_id = ?",
        (admin.db.get_meta("user_id"), bob_id),
    ), "the admin holds no open grant"
    admin.db.set_meta(CONFIRMED_GENESIS_META, admin_client.team_state().genesis_hash)
    with admin.db.transaction(immediate=True):
        if state == "anchor_names_other":
            _wrap_keys(admin, OTHER_GENESIS)
        else:
            admin.db.execute("UPDATE team_log SET hash = ? WHERE seq = (SELECT MAX(seq) FROM team_log)", ("00" * 32,))
    admin.lock()
    admin.unlock(PASSWORD)
    with pytest.raises(TeamLogMismatch):
        local_team_state(admin.db)
    entry = admin.create_entry(mine, "written", [{"key": "password", "value": "new"}])
    return db, admin, _client(admin, admin.db.get_meta("server_url")), entry


@pytest.mark.parametrize("state", STATES)
def test_the_gui_push_of_a_granting_admin_sends_the_personal_tree(team, state):  # noqa: F811
    db, admin, client, entry = _refused_granting_admin(team, state)
    try:
        result = push_with_queued_revocations(admin, client)
    except TeamLogMismatch as waits:
        result = waits.pushed
    assert _on_server(db, entry), result
    assert not admin.db.fetchone("SELECT 1 FROM outbox WHERE kind = 'write' AND object_id = ?", (entry,))


@pytest.mark.parametrize("state", STATES)
def test_sezam_push_of_a_granting_admin_sends_the_personal_tree(team, state, monkeypatch):  # noqa: F811
    db, admin, _, entry = _refused_granting_admin(team, state)
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)
    result = CliRunner().invoke(cli.main, ["push"])
    assert _on_server(db, entry), result.output
    # The refusal and its way out are named; the queue's part waits.
    assert "team log" in result.output.lower(), result.output
