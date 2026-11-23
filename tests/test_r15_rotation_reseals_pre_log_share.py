"""An identity rotation re-seals a share the team log has no key for (R15, goal #441).

Found by the stateful run (TeamLogMachine, mutant R8 regeneration on
005074b): the server lost its team log, and meanwhile the admin's second
device, holding no copy of it, shared a folder; the envelope landed. The
first device put the log back, without that folder's key. The second device
then rotated its identity: the rotation re-seals the member's envelope in its
atomic batch, but the push took the new envelope for a grant made before the
log (005074b) and held it back until the key change landed. The batch missed
it, so every push failed with "Atomic re-key batch is missing 1 local
object(s)", for good.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob, team  # noqa: F401


def test_a_rotation_resends_a_share_the_log_has_no_key_for(team, server, tmp_path):  # noqa: F811
    url = server[0]
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    db._storage["team_log"] = []
    _forget_server_cache()

    other = _vault(tmp_path / "admin2", "admin")
    cli._server_connect_flow(url, other, PASSWORD)
    other_client = _client(other, url)
    try:
        other_client.pull()
        side = other.create_node("Side")
        other.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
        revocation.grant_member(other, other_client, bob_id, side, "read", confirm_fingerprint=lambda fp: True)
        admin_client.pull()  # puts the log back
        other_client.pull()
        side_key = other.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (side,))["dek_id"]
        assert side_key not in other_client.team_state().dek_index

        other_client.prepare_key_change()
        proof = other.change_password(PASSWORD, PASSWORD, rotate_identity=True)
        proof[:] = b"\x00" * len(proof)
        other_client = _client(other, url)
        assert other_client.push()["conflicts"] == []
        assert other_client.push()["conflicts"] == []  # sync settles
        assert not other_client.has_pending_key_change()
    finally:
        other.lock()
