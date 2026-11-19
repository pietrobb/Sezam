"""Review c78fd19 high #2: POST /api/team-log/restore went around the append rules.

Any signed-in account put back records of any author. A thief of a member's
identity key (no password) signed member.keys from the member's key to keys
of its own and uploaded it as a "restore": the server took it because the
account still signed in with the key the record had just retired (the
capability run 277 exception). The real member was then shut out and the
admin's devices sealed the member's folder keys to the thief.

Now only the team admin puts back a key rotation the server lost; a member's
device still puts back the rest (a lone admin's org.recovery, review 8595ec1 #4).
"""

from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.crypto.keys import generate_keypair
from sezam.vault import revocation
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import (  # noqa: F401
    _confirm_founder,
    _found_with_bob,
    team,
)
from tests.test_team_log_desktop_changes import _ops, _server_head


def _thief_member_keys(bob, bob_client) -> dict:
    """member.keys signed with bob's stolen identity key, to the thief's keys."""
    bob_client._refresh_team_log()
    state = bob_client.team_state()
    thief = generate_keypair()
    uid = bob_client._user_id
    spk, epk = thief.signing_pk.hex(), thief.encryption_pk.hex()
    data = {
        "user_id": uid, "signing_pk": spk, "encryption_pk": epk,
        "new_key_sig": thief.to_nacl_signing_key().sign(
            teamlog.new_key_message(state.head_hash, uid, spk, epk)
        ).signature.hex(),
    }
    return teamlog.sign_record(
        teamlog.next_body(state, "member.keys", uid, data), bob.keypair.to_nacl_signing_key(),
    )


def test_a_stolen_member_key_cannot_take_the_member_over_through_restore(team):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    revocation.grant_member(admin, client, bob.db.get_meta("user_id"), _ops(admin), "write")
    _confirm_founder(admin, bob)
    bob_client.pull()
    head = _server_head(db)
    forged = _thief_member_keys(bob, bob_client)

    with pytest.raises(RuntimeError, match="403.*only the team admin puts back the key rotation"):
        bob_client._request("POST", "/api/team-log/restore", {"records": [forged]}, auth=True)
    # Nor through a plain append: member.keys needs the password-checked rotation.
    with pytest.raises(RuntimeError, match="member.keys must carry the account's rotated keys"):
        bob_client._request("POST", "/api/team-log", {"records": [forged]}, auth=True)
    assert _server_head(db) == head
    user = next(u for u in db._storage["users"] if u["id"] == bob_client._user_id)
    assert bytes(user["signing_pk"]) == bytes(bob.keypair.signing_pk)
    client.pull()
    assert client.team_state().members[bob_client._user_id].signing_pk == bob.keypair.signing_pk.hex()
