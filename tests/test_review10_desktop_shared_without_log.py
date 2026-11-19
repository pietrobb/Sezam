"""Review 8595ec1 (low): a desktop member of an organisation without a team log
did not read the folders shared with them.

The desktop takes another account's key only through the team log
(docs/DESIGN_TEAM_LOG.md §9), and never opened envelopes before it existed. The
member got a bare "Decryption failed" and nothing said why or what to do. Now
the key is refused with the way out (an admin founds the log, the member
confirms the founder), 'sezam status' lists the folders waiting, and that way
out opens them without the admin sharing again.
"""

from __future__ import annotations

import pytest

from sezam.vault import revocation, team_migration
from sezam.vault.dek import TeamKeyRefused
from sezam.vault.pending_states import pending_states
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


def test_folder_shared_before_the_log_says_how_and_opens_once_the_log_exists(team):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    ops = _ops(admin)
    entry = admin.create_entry(ops, "db", [{"key": "password", "value": "s3cret", "sensitive": True}])
    admin_client.push()
    revocation.grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, "read",
                            confirm_fingerprint=lambda _fp: True)
    bob_client.pull()

    with pytest.raises(TeamKeyRefused, match="team-log init.*confirm-founder"):
        bob.list_entries(ops)
    waiting = {s.key: s for s in pending_states(bob)}
    assert "shared_before_team_log" in waiting
    assert "1 folder" in waiting["shared_before_team_log"].summary
    assert "team-log init" in waiting["shared_before_team_log"].resolve

    team_migration.found_team_log(admin, admin_client, confirm_fingerprint=lambda _u, _fp: True)
    _confirm_founder(admin, bob)
    bob_client.pull()

    assert [e["id"] for e in bob.list_entries(ops)] == [entry]
    assert "shared_before_team_log" not in {s.key for s in pending_states(bob)}


def test_own_folders_without_a_log_are_not_reported(team):  # noqa: F811
    _db, admin, _admin_client, _bob, _bob_client = team
    assert "shared_before_team_log" not in {s.key for s in pending_states(admin)}
    assert admin.list_entries(_ops(admin)) == []
