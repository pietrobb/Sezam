"""The new admin's waiting re-key batch in another process (R16-Z SM4).

Deep stateful run on c287969 (TeamLogMachine, the same on 18c300f): a member
who holds a team folder's key only through an envelope became admin and
re-keyed the folder after the handover. Making the batch withdraws the old
key's envelopes here, this member's own too, until the batch lands. The
server refused the batch (an item in the folder had changed) and the rebase
had to open the old key again: the process that made the batch held it in
memory, any other did not, and every push raised "No authorized team
envelope opens this key". Invariant: while this device's own re-key batch
waits, a key it opened through an envelope opens as before; the envelope the
batch withdrew is still this account's authority to it, under the same log
checks. The stateful counterexample is in property_seeds.txt.
"""

from __future__ import annotations

from sezam import teamlog
from sezam.vault import pending_states, revocation
from sezam.vault.crud import Vault
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _client, _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)


def test_another_process_opens_the_key_the_waiting_batch_retires(team, server, tmp_path):  # noqa: F811
    _db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    folder = admin.create_node("Shared")
    revocation.grant_member(admin, admin_client, bob_id, folder, "read")
    item = admin.create_entry(folder, "db", [{"key": "password", "value": "db-pw"}])
    assert admin_client.push()["conflicts"] == []
    bob_client.pull()
    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)
    bob_client.pull()
    old_key = teamlog.current_key(bob_client.team_state(), folder)

    assert bob.rekey_after_handover(admin_id) > 0  # the batch waits here
    assert pending_states.rekey_batch(bob.db)

    # Another process of Bob's (the desktop app, or the CLI after a restart).
    other = Vault(tmp_path / "bob")
    other.unlock(PASSWORD)
    try:
        assert len(other.dek_mgr.unlock_dek(old_key)) == 32  # before: CryptoError
        other_client = _client(other, server[0])
        result = revocation.push_with_queued_revocations(other, other_client)
        assert result["conflicts"] == []
        assert not pending_states.rekey_batch(other.db)
        other_client.pull()
        assert teamlog.current_key(other_client.team_state(), folder) != old_key
        assert other.get_field_value(item, "password") == "db-pw"
    finally:
        other.lock()
