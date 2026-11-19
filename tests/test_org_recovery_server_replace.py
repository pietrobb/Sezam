"""Review 526419e S2+S3: the org recovery the server already holds.

S2: 'sezam org-recovery-setup' on a device without a local setup replaced,
without a word, the recovery the account set up on the web or another device:
those shares stopped working. S3: with several admins the server keeps one
recovery; '--replace' over another admin's got a 409 and the CLI kept advising
the same '--replace'. Both now say what is on the server and replace it only
when asked; another admin's recovery is not a dead end (allow-key-reset).
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import org_recovery_server
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_org_recovery_registration_check import _cli, _connected

SETUP = ["org-recovery-setup", "-t", "2", "-n", "3"]


def _blob(db) -> dict:
    (blob,) = db._storage["org_recovery_blobs"]
    return dict(blob)


def test_setup_does_not_silently_replace_the_recovery_from_elsewhere(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    _connected(url, tmp_path / "laptop", registered=True).lock()  # e.g. the web
    before = _blob(db)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone.lock()

    result = _cli(tmp_path / "phone", monkeypatch, SETUP)
    assert result.exit_code == 1, result.output
    assert "already on the server" in result.output and "--replace" in result.output
    assert "Share 1:" not in result.output
    assert _blob(db) == before

    result = _cli(tmp_path / "phone", monkeypatch, [*SETUP, "--replace"])
    assert result.exit_code == 0, result.output
    assert "Share 1:" in result.output
    assert _blob(db)["recovery_signing_pk"] != before["recovery_signing_pk"]


def _second_admin(url, db, admin, path, monkeypatch):
    invitation = _client(admin, url).create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(path, "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    _client(admin, url).approve_user(bob_id)
    next(u for u in db._storage["users"] if u["id"] == bob_id)["is_admin"] = 1
    _client(bob, url).pull()
    return bob


def test_replace_over_another_admin_names_the_way_out(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    admin = _connected(url, tmp_path / "admin", registered=True)
    admin_id = admin.db.get_meta("user_id")
    bob = _second_admin(url, db, admin, tmp_path / "bob", monkeypatch)
    admin.lock()
    bob.lock()

    result = _cli(tmp_path / "bob", monkeypatch, [*SETUP, "--replace"])
    assert result.exit_code == 1, result.output
    assert "--replace-other-admin" in result.output and "allow-key-reset" in result.output
    assert "409" not in result.output
    assert _blob(db)["created_by"] == admin_id

    result = _cli(tmp_path / "bob", monkeypatch, [*SETUP, "--replace-other-admin"])
    assert result.exit_code == 0, result.output
    assert "Share 1:" in result.output
    assert _blob(db)["created_by"] != admin_id


def test_unlock_does_not_advise_replace_over_another_admin(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    admin = _connected(url, tmp_path / "admin", registered=True)
    bob = _second_admin(url, db, admin, tmp_path / "bob", monkeypatch)
    try:
        bob.setup_org_recovery(threshold=2, shares=3)  # its registration would get a 409
        stored = []
        monkeypatch.setattr(SyncClient, "store_org_recovery", lambda *a: stored.append(a))
        note = org_recovery_server.register_while_password_known(bob, PASSWORD)
        assert note and "allow-key-reset" in note
        assert "'sezam org-recovery-setup --replace'" not in note
        assert stored == []
        assert org_recovery_server.register_while_password_known(bob, PASSWORD) is None
    finally:
        admin.lock()
        bob.lock()
