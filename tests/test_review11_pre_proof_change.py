"""Review 4acfdde R11 (medium): a password change left unsent by a version
from before the server asked for the old password's proof (688edcb K1).

The server refuses it for good. The only way out, 'sezam abandon-pending-change',
silently dropped the new password, and nothing said the change was an older
version's. Status and push now say so, and 'sezam finish-pending-change' adds
the proof of the server's password, so the new password goes through.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault import oplock, pending_states
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_stuck_key_change_escape import _bob

BOB_NEW = "bob-new-r11-password!"


def _older_versions_change(bob) -> None:
    """change_password, with the journal an older version wrote: no proof."""
    bob.change_password(PASSWORD, BOB_NEW)
    journal = pending_states.key_change_journal(bob.db)
    journal.pop("current_auth_proof")
    with oplock.exclusive(bob.db.path):  # INV-6
        pending_states.set_key_change_journal(bob.db, journal)


def _server_takes(url, via, password) -> bool:
    """The server's /auth/recover takes ``password`` for bob (asked from the unlocked ``via``)."""
    from sezam.crypto.kdf import derive_kek_and_proof
    from sezam.vault.crud import server_account_kdf
    from sezam.vault.sync_client import SyncClient

    client = SyncClient(via.db, url, via.keypair, via.db.get_meta("user_id"))
    meta = client._request("GET", "/api/meta?username=bob")
    _, proof = derive_kek_and_proof(
        password, bytes.fromhex(meta["argon2_salt"]), server_account_kdf(meta, via.db))
    try:
        client._request("POST", "/api/auth/recover", {"username": "bob", "auth_proof": proof.hex()})
        return True
    except RuntimeError:
        return False


def test_the_new_password_of_an_older_versions_change_goes_through(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    bob, client = _bob(team, tmp_path)
    try:
        _older_versions_change(bob)
        with pytest.raises(RuntimeError, match="403"):
            client.push()
        [waiting] = [s for s in pending_states.pending_states(bob) if s.key == "key_change"]
        assert "older Sezam version" in waiting.summary
        assert "finish-pending-change" in waiting.resolve

        with pytest.raises(RuntimeError, match="Wrong current account password"):
            client.finish_pending_change(bob, BOB_NEW)
        assert pending_states.change_lacks_server_proof(bob.db)

        client.finish_pending_change(bob, PASSWORD)
        assert not pending_states.change_lacks_server_proof(bob.db)
        client.push()
        assert not client.has_pending_key_change()
        assert _server_takes(url, bob, BOB_NEW) and not _server_takes(url, bob, PASSWORD)
        assert bob.verify_password(BOB_NEW)
    finally:
        bob.lock()


def test_cli_names_the_older_version_and_finishes_the_change(team, tmp_path, monkeypatch):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    bob, client = _bob(team, tmp_path)
    _older_versions_change(bob)
    bob.lock()

    def password_prompt(prompt: str = "", **_kwargs) -> str:
        return PASSWORD if "server has now" in prompt else BOB_NEW

    monkeypatch.setattr(cli, "_open_vault", lambda: bob)
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(cli, "_get_password", password_prompt)

    result = CliRunner().invoke(cli.main, ["push"])
    assert "older Sezam version" in result.output, result.output
    assert "finish-pending-change" in result.output

    result = CliRunner().invoke(cli.main, ["finish-pending-change"])
    assert result.exit_code == 0, result.output
    assert "new password was sent" in result.output
    assert _server_takes(url, admin, BOB_NEW)

    result = CliRunner().invoke(cli.main, ["finish-pending-change"])
    assert result.exit_code != 0 and "lacks the server's password" in result.output


def test_a_current_change_is_not_taken_for_an_older_versions(team, tmp_path):  # noqa: F811
    url, db, admin, admin_client, bob_id, folders = team
    bob, client = _bob(team, tmp_path)
    try:
        bob.change_password(PASSWORD, BOB_NEW)
        assert not pending_states.change_lacks_server_proof(bob.db)
        [waiting] = [s for s in pending_states.pending_states(bob) if s.key == "key_change"]
        assert "older Sezam version" not in waiting.summary
    finally:
        bob.lock()
