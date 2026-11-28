"""Review 8595ec1 #1 (critical): a server restored from a backup older than a member's registration (R10-B, goal #372).

The devices put the lost team-log records back, but the server refused them:
the member they name has no account row any more. Every pull then ended in
TeamLogMismatch for the whole organisation, and the member could not come back
under the user_id the log names (the server assigns ids).
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from sezam.vault import revocation
from sezam.vault.reseed import ReseedError, rejoin_server
from sezam.vault.sync_common import AccountLostOnServer
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob
from tests.test_team_log_desktop_changes import _ops, _server_head


@pytest.fixture
def restored(server, tmp_path, monkeypatch):  # noqa: F811
    """Admin + member bob with a log; the server then goes back to a backup
    taken before bob registered (and before the log was founded)."""
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    admin.create_node("Ops")
    cli._server_connect_flow(url, admin, PASSWORD)
    client = _client(admin, url)
    backup = copy.deepcopy(db._storage)
    invitation = client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    client.approve_user(bob_id)
    bob_client = _client(bob, url)
    _found_with_bob(client, bob)
    ops = _ops(admin)
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.get_field_value(item, "password") == "ops-pw"
    head = client.team_state().head_seq

    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    _forget_server_cache()
    yield url, db, admin, client, bob, bob_client, item, head
    admin.lock()
    bob.lock()


def _resync(client) -> None:
    """What the user runs after the restore message: sezam pull --full-resync."""
    from sezam.vault.sync_common import SERVER_ROLLBACK_META

    client.pull()  # notices the restore
    assert client._db.get_meta(SERVER_ROLLBACK_META)
    client.full_resync(confirmed=True)


def test_the_admin_device_puts_the_log_back_and_keeps_pulling(restored):
    url, db, admin, client, bob, bob_client, item, head = restored

    _resync(client)
    client.pull()  # and every later pull

    assert _server_head(db) == head
    assert client.team_state().head_seq == head


def test_the_member_comes_back_under_the_id_the_log_names(restored, tmp_path):
    url, db, admin, client, bob, bob_client, item, head = restored
    bob_id = bob.db.get_meta("user_id")
    _resync(client)
    client.push()  # the admin's device re-sends its own objects and envelopes
    with pytest.raises(AccountLostOnServer, match="sezam server rejoin"):
        _client(bob, url).pull()

    assert rejoin_server(bob, url, PASSWORD)["conflicts"] == []
    _client(bob, url).pull()

    user = next(u for u in db._storage["users"] if u["id"] == bob_id)
    assert user["encrypted_keypair"]  # a new device of bob's signs in with the password again
    assert user["status"] == "active" and not user["is_admin"]
    assert bytes(user["signing_pk"]) == bytes(bob.keypair.signing_pk)
    assert bob.get_field_value(item, "password") == "ops-pw"
    written = bob.create_entry(bob.db.get_meta("root_node_id"), "mine", [{"key": "k", "value": "v"}])
    _client(bob, url).push()
    assert any(o["id"] == written for o in db._storage["vault_objects"])

    # The admin's next sync sends bob's envelope the server refused while
    # bob had no account; a new device of bob's reads Ops and bob's items.
    assert client.push()["conflicts"] == []
    fresh = _vault(tmp_path / "fresh", "bob")
    cli._server_connect_flow(url, fresh, PASSWORD)
    _confirm_founder(admin, fresh)
    _client(fresh, url).pull()
    assert fresh.db.get_meta("user_id") == bob_id
    assert fresh.get_field_value(item, "password") == "ops-pw"
    assert fresh.get_field_value(written, "k") == "v"
    fresh.lock()


@pytest.mark.parametrize("forgery", ["own_keys", "named_keys_wrong_signer", "other_context"])
def test_nobody_else_can_take_the_named_id(restored, forgery):
    """Only the keys the log names for the account, proving themselves, bring it back."""
    from sezam.crypto.keys import generate_keypair
    from sezam.vault.reseed import reseed_message

    url, db, admin, client, bob, bob_client, item, head = restored
    bob_id = bob.db.get_meta("user_id")
    _resync(client)
    thief = generate_keypair()
    shown = thief if forgery == "own_keys" else bob.keypair
    challenge = bob_client._request("POST", "/api/auth/challenge", {"username": "bob"})["challenge"]
    message = reseed_message(
        bytes.fromhex(challenge), bob_id, "bob", shown.signing_pk, shown.encryption_pk, 0,
        rejoin=forgery != "other_context",
    )
    signer = bob.keypair if forgery == "other_context" else thief
    with pytest.raises(RuntimeError, match="401"):
        bob_client._request("POST", "/api/auth/rejoin", {
            "username": "bob", "user_id": bob_id,
            "signing_pk": shown.signing_pk.hex(), "encryption_pk": shown.encryption_pk.hex(),
            "key_epoch": 0, "challenge": challenge,
            "signature": signer.to_nacl_signing_key().sign(message).signature.hex(),
        })
    assert not any(u["id"] == bob_id for u in db._storage["users"])


def test_an_existing_account_is_not_rejoined(restored):
    url, db, admin, client, bob, bob_client, item, head = restored
    _resync(client)
    with pytest.raises(ReseedError, match="409"):
        rejoin_server(admin, url, PASSWORD)  # the backup has the admin's account
    assert rejoin_server(bob, url, PASSWORD)["conflicts"] == []
    rows = [u for u in db._storage["users"] if u["id"] == bob.db.get_meta("user_id")]
    with pytest.raises(ReseedError, match="409"):
        rejoin_server(bob, url, PASSWORD)  # a second time: the account exists
    assert [u for u in db._storage["users"] if u["id"] == bob.db.get_meta("user_id")] == rows


def test_a_rejoin_whose_answer_was_lost_finishes_on_the_next_run(restored, monkeypatch):
    from sezam.vault import sync_client as sync_module

    url, db, admin, client, bob, bob_client, item, head = restored
    _resync(client)
    client.push()
    original = sync_module.SyncClient._request

    def lose_answer(self, method, path, *args, **kwargs):
        answer = original(self, method, path, *args, **kwargs)
        if path == "/api/auth/rejoin":
            raise ConnectionError("answer lost")
        return answer

    monkeypatch.setattr(sync_module.SyncClient, "_request", lose_answer)
    with pytest.raises(ConnectionError):
        rejoin_server(bob, url, PASSWORD)
    monkeypatch.setattr(sync_module.SyncClient, "_request", original)
    rejoin_server(bob, url, PASSWORD)
    _client(bob, url).pull()
    assert bob.get_field_value(item, "password") == "ops-pw"
