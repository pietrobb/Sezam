"""Review 4acfdde R11 (low): a rejoin whose name another account took.

After a restore from a backup older than member bob, a new account may
register as "bob". The log names bob by id, but the rejoin only said 409 and
the old name could not be changed. The server now answers username_taken and
the desktop rejoins under another name ('sezam server rejoin --username').
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from sezam.crypto.envelope_crypto import compute_fingerprint
from sezam.vault import revocation
from sezam.vault.reseed import ReseedError, rejoin_server
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD, _client, _entry_value, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review10_restore_before_member import _resync, restored  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _forget_server_cache, _found_with_bob
from tests.test_team_log_desktop_changes import _ops


def _someone_registers_as_bob(url, client, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    other = _vault(tmp_path / "other-bob", "bob")
    invitation = client.create_invitation()
    cli._server_register_and_upload(
        url, other, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    other_id = other.db.get_meta("user_id")
    other.lock()
    return other_id


def test_a_member_whose_name_was_taken_rejoins_under_another(restored, tmp_path, monkeypatch):  # noqa: F811
    url, db, admin, client, bob, bob_client, item, head = restored
    bob_id = bob.db.get_meta("user_id")
    _resync(client)
    client.push()
    other_id = _someone_registers_as_bob(url, client, tmp_path, monkeypatch)

    with pytest.raises(ReseedError, match="--username NEW_NAME"):
        rejoin_server(bob, url, PASSWORD)
    assert bob.db.get_meta("username") == "bob"
    assert not any(u["id"] == bob_id for u in db._storage["users"])

    assert rejoin_server(bob, url, PASSWORD, "bob-again")["conflicts"] == []
    assert bob.db.get_meta("username") == "bob-again"
    names = {u["id"]: u["username"] for u in db._storage["users"]}
    assert names[bob_id] == "bob-again" and names[other_id] == "bob"
    _client(bob, url).pull()  # signs in under the new name
    assert bob.get_field_value(item, "password") == "ops-pw"


def test_the_cli_names_the_way_out(restored, tmp_path, monkeypatch):  # noqa: F811
    from click.testing import CliRunner

    url, db, admin, client, bob, bob_client, item, head = restored
    _resync(client)
    client.push()
    _someone_registers_as_bob(url, client, tmp_path, monkeypatch)
    vault_dir = bob.db.path.parent
    bob.lock()
    monkeypatch.setenv("SEZAM_VAULT", str(vault_dir))
    monkeypatch.setattr(cli, "_attempt_tracker_path", lambda: tmp_path / "attempts.json")
    taken = CliRunner().invoke(cli.main, ["server", "rejoin", url], input=PASSWORD + "\n")
    assert taken.exit_code != 0 and "sezam server rejoin --username NEW_NAME" in taken.output
    back = CliRunner().invoke(cli.main, ["server", "rejoin", url, "--username", "bob2"], input=PASSWORD + "\n")
    assert back.exit_code == 0, back.output
    assert any(u["username"] == "bob2" for u in db._storage["users"])


PHONE_TEST = "test/review11_phone_rejoin_name_taken_test.dart"


def test_a_phone_member_whose_name_was_taken_rejoins_under_another(server, tmp_path, monkeypatch):  # noqa: F811
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
    _client(bob, url).push()
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "read")
    _confirm_founder(admin, bob)
    bob.lock()
    taken_by = {}

    def restore():
        db._storage.clear()
        db._storage.update(copy.deepcopy(backup))
        _forget_server_cache()
        client.pull()
        client.full_resync(confirmed=True)
        assert [c["error"] for c in client.push()["conflicts"]] == ["unknown target user"]
        taken_by["id"] = _someone_registers_as_bob(url, client, tmp_path, monkeypatch)

    def admin_sync():
        assert client.push()["conflicts"] == []
        client.pull()

    def check():
        names = {u["id"]: u["username"] for u in db._storage["users"]}
        assert names[bob_id] == "bob2" and names[taken_by["id"]] == "bob"
        fresh = _vault(tmp_path / "fresh", "bob2")
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
