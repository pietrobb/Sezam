"""INV-7 (review e443cbc, goal #438): a team log copy this device refuses never
keeps the vault locked, on the emergency paths either.

The unlock already opens with a damaged copy or keys naming another genesis
(tests/test_inv7_unlock_never_blocked.py). A Shamir org recovery and a
password change are the ways back in when the password is lost or leaked;
each must open the vault in the same states, the team alone waiting.
"""

from __future__ import annotations

import pytest

from sezam.vault.crud import Vault
from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, local_team_state
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_inv7_unlock_never_blocked import OTHER_GENESIS, STATES, _device, _Server, _wrap_keys
from tests.test_team_log_desktop import _client, _found_with_bob, team  # noqa: F401

NEW_PASSWORD = "a-new-recovered-passw0rd!"


def _damage(vault, state, pinned):
    """The damage _device makes, after the shares were handed out. Unpinned,
    the device trusts the log through the founder's own keys only (no
    confirm-genesis, account keys naming no genesis): publishable_anchor then
    reads the copy itself."""
    vault.unlock(PASSWORD)
    with vault.db.transaction(immediate=True):
        if not pinned:
            vault.db.execute("DELETE FROM vault_meta WHERE key = ?", (CONFIRMED_GENESIS_META,))
            _wrap_keys(vault, None)
        if state == "holds_damaged_sig":
            vault.db.execute("UPDATE team_log SET sig = ? WHERE seq = 2", ("00" * 64,))
        elif state == "holds_damaged_hash":
            vault.db.execute("UPDATE team_log SET hash = ? WHERE seq = 2", ("00" * 32,))
        elif state == "holds_damaged_genesis_sig":
            vault.db.execute("UPDATE team_log SET sig = ? WHERE seq = 0", ("00" * 64,))
        elif state == "holds_damaged_genesis_hash":
            vault.db.execute("UPDATE team_log SET hash = ? WHERE seq = 0", ("00" * 32,))
        elif state == "anchor_names_other":
            _wrap_keys(vault, OTHER_GENESIS)
    vault.lock()


@pytest.mark.parametrize("pinned", [True, False], ids=["pinned", "founder_lineage"])
@pytest.mark.parametrize("state", STATES)
def test_org_recovery_opens_the_vault(tmp_path, state, pinned):
    vault, entry = _device(tmp_path, "none")
    vault.unlock(PASSWORD)
    shares = vault.setup_org_recovery(threshold=2, shares=3)
    vault.lock()
    _damage(vault, state, pinned)

    recovered = Vault(vault.path)
    recovered.org_recovery(shares[:2], NEW_PASSWORD)
    assert recovered.get_field_value(entry, "password") == "keep-me"
    recovered.lock()
    recovered.unlock(NEW_PASSWORD)
    assert recovered.get_field_value(entry, "password") == "keep-me"
    assert _Server(recovered, "same").team_log_refusal() is None or state == "anchor_names_other"


@pytest.mark.parametrize("pinned", [True, False], ids=["pinned", "founder_lineage"])
def test_the_password_change_of_a_damaged_copy_reaches_the_server(team, pinned):  # noqa: F811
    """The way out of local_damaged is the next pull; after it the change
    goes out whole, and the server holds the new key material."""
    db, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    with admin.db.transaction(immediate=True):
        if not pinned:
            admin.db.execute("DELETE FROM vault_meta WHERE key = ?", (CONFIRMED_GENESIS_META,))
            _wrap_keys(admin, None)
        admin.db.execute("UPDATE team_log SET hash = ? WHERE seq = (SELECT MAX(seq) FROM team_log)", ("00" * 32,))
    admin.lock()
    admin.unlock(PASSWORD)
    admin.change_password(PASSWORD, NEW_PASSWORD)
    client = _client(admin, admin.db.get_meta("server_url"))
    client.pull()
    assert local_team_state(admin.db) is not None  # fetched again under its pins
    client.push()
    user_id = admin.db.get_meta("user_id")
    held = bytes(next(u for u in db._storage["users"] if u["id"] == user_id)["encrypted_keypair"]).hex()
    assert held == admin.db.get_meta("encrypted_keypair")


@pytest.mark.parametrize("pinned", [True, False], ids=["pinned", "founder_lineage"])
@pytest.mark.parametrize("state", STATES)
def test_a_password_change_opens_the_vault(tmp_path, state, pinned):
    vault, entry = _device(tmp_path, "none")
    _damage(vault, state, pinned)
    vault.unlock(PASSWORD)
    vault.change_password(PASSWORD, NEW_PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"
    vault.lock()
    vault.unlock(NEW_PASSWORD)
    assert vault.get_field_value(entry, "password") == "keep-me"
