"""A grant whose level changed goes out again at the level the log gives (R15, goal #441).

Found by the default stateful run of TeamLogMachine on 4ee7d65: the admin
shared a folder 'read', then changed it to 'write'. A level change is only
the log's access.set (the member keeps the envelope), so the envelope here
still said 'read'. The server was restored from a backup from before the
grant; the full resync kept the envelope and put the log records back, and
every push sent the envelope at 'read' while the log said 'write': refused
as 'envelope access differs from the team log', the device never settled.
An envelope's level is not signed and the log decides it: it goes out at
the log's level.
"""

from __future__ import annotations

import copy

from sezam.vault import revocation
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob, team  # noqa: F401


def test_a_level_changed_grant_is_resent_at_the_logs_level(team, server):  # noqa: F811
    db, admin, admin_client, bob, _bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_id = bob.db.get_meta("user_id")
    side = admin.create_node("Side")
    assert admin_client.push()["conflicts"] == []
    backup = copy.deepcopy(db._storage)

    sealed_read = revocation.grant_member(admin, admin_client, bob_id, side, "read")
    # R16-N5: a level change re-seals the envelope at the new level (the read one is withdrawn).
    envelope = revocation.grant_member(admin, admin_client, bob_id, side, "write")
    assert envelope != sealed_read
    assert not any(o["id"] == sealed_read for o in db._storage["vault_objects"] if not o.get("is_deleted"))

    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))  # restored from a backup from before the grant
    _forget_server_cache()
    admin_client.full_resync(confirmed=True)
    result = admin_client.push()
    assert result["conflicts"] == [], result["conflicts"]
    assert admin_client.push()["conflicts"] == []
    stored = next(o for o in db._storage["vault_objects"] if o["id"] == envelope)
    assert stored["access_level"] == "write"
