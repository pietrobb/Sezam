"""Review 8595ec1 #1 (critical), phone: a member with only a phone rejoins a
server restored from a backup older than the account (R10-B, goal #372).

The desktop way back is `sezam server rejoin` (test_review10_restore_before_member).
A member whose only device is a phone had none: every sync ended in a 401.
The phone now reports AccountLostOnServerException and rejoins with the
password (AuthService.rejoinServer), also when the rejoin's answer is lost.
"""

from __future__ import annotations

import copy

from sezam import cli
from sezam.crypto.envelope_crypto import compute_fingerprint
from sezam.vault import revocation
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD, _client, _entry_value, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob
from tests.test_team_log_desktop_changes import _ops

PHONE_TEST = "test/phone_rejoin_after_restore_test.dart"


def test_a_member_with_only_a_phone_rejoins_after_the_restore(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    admin.create_node("Ops")
    cli._server_connect_flow(url, admin, PASSWORD)
    client = _client(admin, url)
    backup = copy.deepcopy(db._storage)  # before bob registered
    invitation = client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")  # the device bob has lost by the restore
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    client.approve_user(bob_id)
    _client(bob, url).push()  # bob's root folder
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "read")
    _confirm_founder(admin, bob)
    bob.lock()

    def restore():
        db._storage.clear()
        db._storage.update(copy.deepcopy(backup))
        _forget_server_cache()
        # The admin's device puts the team log and its own objects back.
        client.pull()
        client.full_resync(confirmed=True)
        assert [c["error"] for c in client.push()["conflicts"]] == ["unknown target user"]

    def admin_sync():
        # The admin's next sync sends bob's envelope the server refused
        # while bob had no account.
        assert client.push()["conflicts"] == []
        client.pull()

    def check():
        user = next(u for u in db._storage["users"] if u["id"] == bob_id)
        assert user["encrypted_keypair"] and user["status"] == "active" and not user["is_admin"]
        # A new device of bob's signs in with the password and reads what
        # the phone wrote after the backup.
        fresh = _vault(tmp_path / "fresh", "bob")
        cli._server_connect_flow(url, fresh, PASSWORD)
        assert fresh.db.get_meta("user_id") == bob_id
        _confirm_founder(admin, fresh)
        _client(fresh, url).pull()
        assert _entry_value(fresh, "Phone", "phone-mine", "password") == "from-phone"
        fresh.lock()

    out = _phone(url, tmp_path, {
        "username": "bob", "password": PASSWORD,
        "fingerprint": compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk),
    }, {"restore": restore, "admin_sync": admin_sync, "check": check}, PHONE_TEST)
    assert "All tests passed!" in out, out
    admin.lock()
