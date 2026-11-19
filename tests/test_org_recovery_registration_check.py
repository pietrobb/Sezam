"""Review 526419e V5: a lone admin whose org recovery the server never learned.

A recovery set up before f7f43cc (or whose registration failed) was noticed
only after the password was forgotten: after 'sezam org-recovery' the server
refused the new password (403) and there was no other admin to allow a reset.
Unlock and push now check the server while the password is known, and
'org-recovery-setup --replace' neither sends the proof of a password the
server lacks nor voids the working shares when the server refuses.
"""

from __future__ import annotations

from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)

NEW = "a-new-password-1!"


def _connected(url, path, *, recovery: bool = True, registered: bool = False) -> Vault:
    vault = _vault(path, "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    if recovery:
        vault.setup_org_recovery(threshold=2, shares=3)
        if registered:
            assert SyncClient.register_org_recovery(vault, PASSWORD)
    return vault


def _user(db, vault_user_id):
    return next(u for u in db._storage["users"] if u["id"] == vault_user_id)


def _meta(path, password, keys):
    vault = Vault(path)
    vault.unlock(password)
    try:
        return {
            k: pending_states.org_recovery_registration(vault.db)
            if k == "registration" else vault.db.get_meta(k)
            for k in keys
        }
    finally:
        vault.lock()


def _cli(path, monkeypatch, args, password=PASSWORD):
    _cli_env(path, monkeypatch)
    return CliRunner().invoke(cli.main, args, input=f"{password}\n")


def test_push_warns_about_a_recovery_set_up_before_the_server_knew_keys(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    vault = _connected(url, tmp_path / "laptop")
    # What a setup before f7f43cc left: no registration body, nothing on the server.
    vault._drop_pending_org_recovery_registration()
    vault.lock()

    result = _cli(tmp_path / "laptop", monkeypatch, ["push"])
    assert result.exit_code == 0, result.output
    assert "does not know this vault's org recovery" in result.output
    assert "--replace" in result.output


def test_unlock_registers_a_recovery_the_server_did_not_take(server, tmp_path):  # noqa: F811
    from sezam.vault.org_recovery_server import REGISTERED_NOTICE, register_while_password_known

    url, db = server
    vault = _connected(url, tmp_path / "laptop")  # registration never reached the server
    user_id = vault.db.get_meta("user_id")
    try:
        assert not db._storage.get("org_recovery_blobs")
        assert register_while_password_known(vault, PASSWORD) == REGISTERED_NOTICE
        assert db._storage["org_recovery_blobs"][0]["created_by"] == user_id
        # Known now: no further notice and no further server round trip.
        assert register_while_password_known(vault, PASSWORD) is None
    finally:
        vault.lock()


def test_push_without_a_terminal_says_the_registration_waits(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    _connected(url, tmp_path / "laptop").lock()

    result = _cli(tmp_path / "laptop", monkeypatch, ["push"])
    assert result.exit_code == 0, result.output
    assert "not registered on the server yet" in result.output


def test_replace_is_refused_while_a_password_change_is_unsent(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    vault = _connected(url, tmp_path / "laptop", registered=True)
    user_id = vault.db.get_meta("user_id")
    old_pk = vault.db.get_meta("org_recovery_pk")
    vault.change_password(PASSWORD, NEW)  # not pushed: the server has PASSWORD
    vault.lock()

    result = _cli(
        tmp_path / "laptop", monkeypatch,
        ["org-recovery-setup", "-t", "2", "-n", "3", "--replace"], password=NEW,
    )
    assert result.exit_code == 1, result.output
    assert "Share 1:" not in result.output
    assert not _user(db, user_id).get("recovery_attempts")
    assert _meta(tmp_path / "laptop", NEW, ["org_recovery_pk"]) == {"org_recovery_pk": old_pk}


def test_a_replacement_the_server_refuses_keeps_the_old_shares(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    vault = _connected(url, tmp_path / "laptop", registered=True)
    before = {
        k: vault.db.get_meta(k)
        for k in ("org_recovery_pk", "org_recovery_wrapped_kek")
    }
    vault.lock()

    def refuse(self, body, proof):
        raise RuntimeError("Server error 409: another admin's recovery key")

    monkeypatch.setattr(SyncClient, "store_org_recovery", refuse)
    result = _cli(
        tmp_path / "laptop", monkeypatch, ["org-recovery-setup", "-t", "2", "-n", "3", "--replace"]
    )
    assert result.exit_code == 1, result.output
    assert "Share 1:" not in result.output
    assert "stay valid" in result.output
    keys = [*before, "registration"]
    assert _meta(tmp_path / "laptop", PASSWORD, keys) == {
        **before, "registration": None,
    }
