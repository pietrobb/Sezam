"""Review 688edcb K2: a second key change before the first reached the server.

The journal of a change the server has not taken holds what the server still
knows: the proof of its password and, after rotate-identity, the old identity
keypair the login needs. change_password / rotate-identity overwrote it, so
after an offline rotation and a password change every login of the device
failed with 401 for good. A second change is now refused until the first is
pushed; org recovery (no password to wait for) carries the journal over.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault.crud import Vault
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)


def _user(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


def _hex(value) -> str:
    return value if isinstance(value, str) else bytes(value).hex()


def _rotate_offline(admin: Vault) -> None:
    """rotate-identity whose push did not get through: only the local half."""
    admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    assert "identity" in (pending_states.key_change_journal(admin.db) or None)


def test_password_change_waits_for_a_pending_offline_rotation(team):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    old_signing_pk = admin.keypair.signing_pk
    _rotate_offline(admin)
    journal = (pending_states.key_change_journal(admin.db) or None)

    with pytest.raises(ValueError, match="has not reached the server"):
        admin.change_password(PASSWORD, "another-password!")
    with pytest.raises(ValueError, match="has not reached the server"):
        admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    assert (pending_states.key_change_journal(admin.db) or None) == journal

    # The device still logs in with the old key and lands the rotation.
    _client(admin, url).push()
    assert _hex(_user(db, admin_id)["signing_pk"]) == admin.keypair.signing_pk.hex()
    assert admin.keypair.signing_pk != old_signing_pk
    assert _client(admin, url).token
    # Afterwards the password change goes through.
    admin.change_password(PASSWORD, "another-password!")
    _client(admin, url).push()
    assert (pending_states.key_change_journal(admin.db) or None) is None


def test_cli_change_password_reports_the_pending_change(team, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    _rotate_offline(admin)
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_get_password", lambda *a, **k: PASSWORD)
    monkeypatch.setattr(cli, "_get_new_password", lambda vault: "another-password!")
    result = CliRunner().invoke(cli.main, ["change-password"])
    assert result.exit_code == 1, result.output
    assert "sezam push" in result.output
    assert "password was not changed" in result.output


def test_org_recovery_keeps_a_pending_rotation(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    shares = admin.setup_org_recovery(threshold=2, shares=3)
    _rotate_offline(admin)
    new_signing_pk = admin.keypair.signing_pk
    admin.lock()

    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(shares[:2], "recovered-pw!")
    recovered.lock()
    recovered.unlock("recovered-pw!")
    try:
        journal = (pending_states.key_change_journal(recovered.db) or None)
        assert "identity" in journal and "current_auth_proof" in journal
        # The server still knows the old key and the old password: the push
        # logs in with the first and proves the second, no key-reset grant.
        _client(recovered, url).push()
        user = _user(db, admin_id)
        assert _hex(user["signing_pk"]) == new_signing_pk.hex()
        assert (pending_states.key_change_journal(recovered.db) or None) is None
        assert _client(recovered, url).token
    finally:
        recovered.lock()
