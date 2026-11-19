"""Lockout review 2026-11-08, finding 8 (K8b): revocation waited for the re-key.

``sezam revoke-user`` (and the team dialog) told the server to revoke the
member only after the folder re-key had been pushed. Whenever that push
failed — a concurrent edit, a network error — the member stayed active on the
server with full sync access. The server revocation now comes first; a re-key
that could not be sent stays pending and goes with the next push.
"""

from __future__ import annotations

import os

from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.models import new_ulid
from sezam.vault.sync_client import SyncClient
from sezam.vault import outbox
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


def _admin_with_member(url, db, tmp_path, monkeypatch):
    admin = _vault(tmp_path / "admin", "admin")
    folder = admin.create_node("Ops")
    admin.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw"}])
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()

    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    bob.lock()

    dek_id = admin.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    admin.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (new_ulid(), dek_id, bob_id, admin.db.get_meta("user_id"), os.urandom(72)),
    )
    outbox.queue_write(admin.db, folder)
    assert admin_client.push()["conflicts"] == []
    return admin, bob_id


def _status(db, user_id):
    return next(u for u in db._storage["users"] if u["id"] == user_id)["status"]


def _bob_envelopes_live(db, bob_id):
    return [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == bob_id
        and not o["is_deleted"]
    ]


def test_cli_revokes_on_the_server_even_when_the_rekey_push_fails(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, bob_id = _admin_with_member(url, db, tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)

    real_push = SyncClient.push

    def offline_push(self):
        raise RuntimeError("Network error: connection refused")

    monkeypatch.setattr(SyncClient, "push", offline_push)
    result = CliRunner().invoke(cli.main, ["revoke-user", bob_id])

    # The member is cut off by the server right away...
    assert _status(db, bob_id) == "revoked"
    assert result.exit_code != 0
    assert "revoked on the server" in result.output
    assert "sezam push" in result.output
    # ...and the re-key waits locally for the next push.
    pending = (pending_states.rekey_batch(admin.db) or None)
    assert pending and pending["revoked_user_id"] == bob_id
    assert _bob_envelopes_live(db, bob_id)

    monkeypatch.setattr(SyncClient, "push", real_push)
    _client(admin, url).push()
    assert pending_states.rekey_batch(admin.db) == {}
    assert not _bob_envelopes_live(db, bob_id)


def test_cli_revoke_retry_finishes_the_pending_rekey(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    admin, bob_id = _admin_with_member(url, db, tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)
    assert admin.rekey_after_revocation(bob_id) == 1

    result = CliRunner().invoke(cli.main, ["revoke-user", bob_id])

    assert result.exit_code == 0, result.output
    assert "Re-keyed 1 folder(s)" in result.output
    assert _status(db, bob_id) == "revoked"
    assert pending_states.rekey_batch(admin.db) == {}
    assert not _bob_envelopes_live(db, bob_id)
