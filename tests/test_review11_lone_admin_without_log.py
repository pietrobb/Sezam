"""Review 4acfdde R11 (medium): the only admin of an organisation without a
team log, whose password change the server refuses (no old password: a
Shamir recovery after the server lost the recovery registration).

'sezam status' and the refused push sent that admin to another admin's
'sezam allow-key-reset' - there is no other admin. The way out named now is
the one that works: found the team log, whose first push names the vault's
org recovery key, and the server takes the reset signed by it.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault import pending_states
from sezam.vault.crud import Vault
from sezam.vault.pending_states import key_reset_way_out
from sezam.vault.team_migration import found_team_log
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_lone_admin_org_recovery import _recover
from tests.test_rollback_commit_token_sm7 import _restore

RECOVERED = "recovered-r11-lone!"


def _recovered_after_restore(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    backup = copy.deepcopy(db._storage)
    shares = admin.setup_org_recovery(threshold=2, shares=3)
    admin_client.store_org_recovery(
        pending_states.org_recovery_registration(admin.db), admin.current_auth_proof(PASSWORD)
    )
    admin.lock()
    _restore(db, backup)  # from before the registration
    assert not db._storage.get("org_recovery_blobs")
    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(shares[:2], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)
    return recovered


def test_the_lone_admin_without_a_log_is_sent_where_the_reset_works(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    recovered = _recovered_after_restore(team, tmp_path)
    try:
        client = _client(recovered, url)
        with pytest.raises(RuntimeError, match="403|401"):
            client.push()
        assert client.has_pending_key_change()
        way_out = key_reset_way_out(recovered.db, admin_id)
        assert "only admin" in way_out and "team-log init" in way_out, way_out
        waiting = {s.key: s for s in pending_states.pending_states(recovered)}
        assert "team-log init" in str(waiting["key_change"]), waiting

        # Following it works: the log names the recovery key, the reset goes through.
        found_team_log(recovered, client, lambda user_id, fingerprint: True)
        assert client.push()["conflicts"] == []
        assert not client.has_pending_key_change()
        assert _recover(recovered, url, RECOVERED)["user_id"] == admin_id
    finally:
        recovered.lock()


def test_without_a_recovery_key_the_way_out_is_the_server_password(team):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    way_out = key_reset_way_out(admin.db, admin.db.get_meta("user_id"))
    assert "only admin" in way_out and "abandon-pending-change" in way_out, way_out
    assert "team-log init" not in way_out
