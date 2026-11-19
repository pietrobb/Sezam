"""Review e4cd15a #2: a pending password change the server never takes.

Three ways left a device with a journal the server refused on every push,
while K2 refused any new change until it was pushed:
a) a journal from before K1 (no proof of the current password),
b) a journal proving a password the server no longer has: retries counted
   towards the 24 h name lock, and an admin's key-reset grant was never looked
   at because the wrong proof was refused first,
c) an offline change on A, a change on B, then org recovery on A: A is two
   epochs ahead, missed the rival rotation and got 409 "must include every
   active DEK" for good.
The server now takes a grant (or recovery proof) before refusing a wrong
proof, a rival rotation below the local epoch is detected, and
'sezam abandon-pending-change' drops the journal for the server's password.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault import sync_client as sync_client_module
from sezam.vault.crud import Vault
from sezam.vault.sync_client import KeyEpochStale, SyncClient
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _entry_value,
    _rotate_on_laptop,
    server,
)

BOB_NEW = "bob-new-password!"


def _user(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


def _real_conflicts(result: dict) -> list:
    # A member's own top-level root never goes up (review 2052248).
    return [c for c in result["conflicts"] if "top-level" not in str(c.get("error"))]


def _bob(team, tmp_path) -> tuple[Vault, SyncClient]:
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    client = SyncClient(bob.db, url, bob.keypair, bob_id)
    client.set_dek_manager(bob.dek_mgr)
    return bob, client


def test_a_journal_without_current_proof_is_abandoned_for_the_server_password(
    team, tmp_path, monkeypatch  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    bob, client = _bob(team, tmp_path)
    # A journal written before K1 carries no proof of the current password.
    monkeypatch.setattr(sync_client_module, "open_current_auth_proof", lambda *a: None, raising=False)
    try:
        bob.change_password(PASSWORD, BOB_NEW)
        with pytest.raises(RuntimeError, match="403"):
            client.push()
        with pytest.raises(ValueError, match="abandon-pending-change"):
            bob.change_password(BOB_NEW, "bob-third-password!")

        with pytest.raises(RuntimeError, match="Wrong current account password"):
            client.abandon_pending_change(bob, BOB_NEW)
        assert (pending_states.key_change_journal(bob.db) or None)

        assert client.abandon_pending_change(bob, PASSWORD) == 0
        assert (pending_states.key_change_journal(bob.db) or None) is None
        assert not client.has_pending_key_change()
        assert not _real_conflicts(client.push())
        # The vault opens with the password the server has.
        assert bob.verify_password(PASSWORD)
        assert not bob.verify_password(BOB_NEW)
        # And a new change goes through again.
        monkeypatch.undo()
        bob.change_password(PASSWORD, BOB_NEW)
        client.push()
        assert (pending_states.key_change_journal(bob.db) or None) is None
    finally:
        bob.lock()


def test_b_admin_grant_wins_over_a_wrong_current_proof_without_counting(
    team, tmp_path, monkeypatch  # noqa: F811
):
    url, db, admin, admin_client, bob_id, folders = team
    bob, client = _bob(team, tmp_path)
    # The proof of a password the server does not have (e.g. the new one).
    monkeypatch.setattr(
        sync_client_module, "open_current_auth_proof",
        lambda *a: bytearray(os.urandom(32)), raising=False,
    )
    try:
        bob.change_password(PASSWORD, BOB_NEW)
        with pytest.raises(RuntimeError, match="Wrong current account password"):
            client.push()
        assert _user(db, bob_id)["recovery_attempts"] == 1
        admin_client.allow_key_reset(bob_id)
        client.push()
        assert (pending_states.key_change_journal(bob.db) or None) is None
        assert _user(db, bob_id)["recovery_attempts"] == 1
        assert _user(db, bob_id)["key_reset_until"] is None
    finally:
        bob.lock()


def test_b_missing_journal_points_to_abandon_not_change_password(team, tmp_path):  # noqa: F811
    bob, client = _bob(team, tmp_path)
    try:
        bob.change_password(PASSWORD, BOB_NEW)
        pending_states.clear_key_change_journal(bob.db)
        with pytest.raises(RuntimeError, match="abandon-pending-change") as exc:
            client.push()
        assert "change-password" not in str(exc.value)
        assert client.abandon_pending_change(bob, PASSWORD) == 0
        assert not _real_conflicts(client.push())
    finally:
        bob.lock()


def test_c_org_recovery_on_top_of_a_lost_change_detects_the_rival(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, phone = _rotate_on_laptop(url, tmp_path)
    shares = phone.setup_org_recovery(threshold=2, shares=3)
    # The phone changed the password offline, the laptop's change (epoch 1)
    # won, and a new folder there brought a DEK the phone never saw.
    proof = phone.change_password(PASSWORD, "phone-offline-pw!")
    proof[:] = b"\x00" * len(proof)
    laptop_folder = laptop.create_node("Laptop only")
    laptop.create_entry(laptop_folder, "k", [{"key": "password", "value": "lp", "sensitive": True}])
    assert _client(laptop, url).push()["accepted"]
    phone.lock()

    recovered = Vault(tmp_path / "phone")
    recovered.org_recovery(shares[:2], "phone-recovered-pw!")
    try:
        assert recovered.db.get_meta("key_epoch") == "2"
        client = SyncClient(recovered.db, url, recovered.keypair, recovered.db.get_meta("user_id"))
        client.set_dek_manager(recovered.dek_mgr)
        with pytest.raises(KeyEpochStale):
            client.push()
        with pytest.raises(KeyEpochStale):
            client.pull()
        assert client.abandon_pending_change(recovered, NEW_PASSWORD) == 1
        client.pull()
        assert _entry_value(recovered, "Laptop only", "k", "password") == "lp"
        assert not client.push()["conflicts"]
    finally:
        recovered.lock()
        laptop.lock()


def test_cli_abandon_pending_change(team, tmp_path, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    bob, client = _bob(team, tmp_path)
    monkeypatch.setattr(
        sync_client_module, "open_current_auth_proof",
        lambda *a: bytearray(os.urandom(32)), raising=False,
    )
    bob.change_password(PASSWORD, BOB_NEW)
    bob.lock()
    local = {"password": BOB_NEW}

    def password_prompt(prompt: str = "", **_kwargs) -> str:
        return PASSWORD if "server has now" in prompt else local["password"]

    monkeypatch.setattr(cli, "_open_vault", lambda: bob)
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(cli, "_get_password", password_prompt)

    result = CliRunner().invoke(cli.main, ["push"])
    assert "abandon-pending-change" in result.output, result.output
    assert f"allow-key-reset {bob_id}" in result.output

    result = CliRunner().invoke(cli.main, ["abandon-pending-change"], input="y\n")
    assert result.exit_code == 0, result.output
    assert "server's account password" in result.output
    reopened = Vault(tmp_path / "bob")
    reopened.unlock(PASSWORD)
    try:
        assert (pending_states.key_change_journal(reopened.db) or None) is None
    finally:
        reopened.lock()

    local["password"] = PASSWORD
    result = CliRunner().invoke(cli.main, ["abandon-pending-change"])
    assert result.exit_code != 0
    assert "no password or key change waiting" in result.output
