"""Review d615826 (E8): a team member's password change never reached the server.

A member's folder under their own top-level root never goes up (its key has a
parent_ref, which the server refuses from a non-admin: 'invalid personal DEK
metadata'). The password change carried every local DEK atomically, that key
too, so the server refused the whole change on every sync and the new epoch
never arrived. Only the keys the server holds are part of the change now.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.crud import Vault
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_member_key_from_own_envelope_sm46 import _invite
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices

BOB_NEW = "bob-new-password-1"


def test_member_with_own_folder_finishes_the_epoch_push(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    admin_client = _client(laptop, url)
    shared = _folder(laptop)
    laptop.create_entry(shared, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    admin_client.push()
    bob_id = _invite(url, admin_client, tmp_path, monkeypatch, "bob")
    revocation.grant_member(laptop, admin_client, bob_id, shared, confirm_fingerprint=lambda _f: True)

    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    _client(bob, url).pull()
    mine = bob.create_node("Mine")
    bob.create_entry(mine, "bank", [{"key": "pin", "value": "1234", "sensitive": True}])
    _client(bob, url).push()
    try:
        bob.change_password(PASSWORD, BOB_NEW)
        _client(bob, url).push()

        epoch = next(s for s in db._storage["sync_state"] if s["user_id"] == bob_id)["key_epoch"]
        account = next(u for u in db._storage["users"] if u["id"] == bob_id)
        assert epoch == 1
        assert bytes(account["encrypted_keypair"]).hex() == bob.db.get_meta("encrypted_keypair")
        assert bob.db.get_meta("last_pushed_key_epoch") == "1"
        assert (pending_states.key_change_journal(bob.db) or None) is None
    finally:
        bob.lock()

    # The own folder stays readable under the new password.
    reopened = Vault(tmp_path / "bob")
    reopened.unlock(BOB_NEW)
    try:
        entry = next(e for e in reopened.list_entries(mine) if e["name"] == "bank")
        assert reopened.get_field_value(entry["id"], "pin") == "1234"
    finally:
        reopened.lock()
        laptop.lock()
        phone.lock()
