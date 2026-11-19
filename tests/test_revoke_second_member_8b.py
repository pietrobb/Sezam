"""Review 688edcb #8b: a second member revoked while a re-key waits.

Only one re-key batch can be pending. When an admin revoked a second member
while the first member's re-key had not reached the server, the second
member was revoked on the server but their folders were never re-keyed - and
the CLI/GUI said the re-key "stays pending and is sent with the next push".
The second member is now queued and re-keyed as soon as the first batch lands.
"""

from __future__ import annotations

import os

from click.testing import CliRunner

from sezam.vault import pending_states
from sezam import cli
from sezam.models import new_ulid
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_revoke_member_review8 import _status
from sezam.vault import outbox


def _admin_with_two_members(url, db, tmp_path, monkeypatch):
    admin = _vault(tmp_path / "admin", "admin")
    folders = {}
    for name in ("Ops", "Finance"):
        folders[name] = admin.create_node(name)
        admin.create_entry(folders[name], f"{name}-secret", [{"key": "password", "value": "pw"}])
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)

    member_ids = {}
    for name, folder in (("bob", folders["Ops"]), ("carol", folders["Finance"])):
        invitation = admin_client.create_invitation()
        member = _vault(tmp_path / name, name)
        cli._server_register_and_upload(
            url, member, PASSWORD, is_bootstrap=False,
            invitation_token=invitation["invitation_token"],
        )
        member_id = member.db.get_meta("user_id")
        admin_client.approve_user(member_id)
        member.lock()
        dek_id = admin.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
        admin.db.execute(
            "INSERT INTO access_envelopes "
            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
            "VALUES (?, ?, ?, ?, 'read', ?)",
            (new_ulid(), dek_id, member_id, admin.db.get_meta("user_id"), os.urandom(72)),
        )
        outbox.queue_write(admin.db, folder)
        member_ids[name] = member_id
    assert admin_client.push()["conflicts"] == []

    monkeypatch.setattr(cli, "_open_vault", lambda: admin)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault, *a, **k: PASSWORD)
    monkeypatch.setattr(admin, "lock", lambda: None)
    return admin, member_ids["bob"], member_ids["carol"]


def _queue(vault):
    return pending_states.revocation_queue(vault.db)


def _envelopes_live(db, user_id):
    return [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == user_id
        and not o["is_deleted"]
    ]


def test_second_member_revoked_offline_is_rekeyed_by_the_next_push(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, bob_id, carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    real_push = SyncClient.push

    def offline_push(self):
        raise RuntimeError("Network error: connection refused")

    monkeypatch.setattr(SyncClient, "push", offline_push)
    assert CliRunner().invoke(cli.main, ["revoke-user", bob_id]).exit_code != 0
    result = CliRunner().invoke(cli.main, ["revoke-user", carol_id])

    assert _status(db, carol_id) == "revoked"
    assert result.exit_code != 0
    # The message no longer claims carol's re-key is pending: it is not made yet.
    assert "not re-keyed" in result.output
    assert _queue(admin) == [carol_id]
    assert (pending_states.rekey_batch(admin.db) or None)["revoked_user_id"] == bob_id

    monkeypatch.setattr(SyncClient, "push", real_push)
    result = CliRunner().invoke(cli.main, ["push"])

    assert result.exit_code == 0, result.output
    assert f"Re-keyed 1 folder(s) after revoking user {carol_id}" in result.output
    # Before the fix carol's folder kept its old DEK and her envelope.
    assert not _envelopes_live(db, bob_id)
    assert not _envelopes_live(db, carol_id)
    assert _queue(admin) == []
    assert pending_states.rekey_batch(admin.db) == {}


def test_second_member_revoked_online_is_rekeyed_right_after_the_first(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, bob_id, carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    _client(admin, url).revoke_user(bob_id)
    assert admin.rekey_after_revocation(bob_id) == 1  # pending, not pushed

    result = CliRunner().invoke(cli.main, ["revoke-user", carol_id])

    assert result.exit_code == 0, result.output
    assert "Re-keyed 1 folder(s)" in result.output
    assert not _envelopes_live(db, bob_id)
    assert not _envelopes_live(db, carol_id)
    assert _queue(admin) == []


def test_a_failed_queued_rekey_stays_queued_and_is_retried(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, bob_id, carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    _client(admin, url).revoke_user(bob_id)
    assert admin.rekey_after_revocation(bob_id) == 1
    real_push = SyncClient.push
    calls = []

    def push_then_fail(self):
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("Network error: connection reset")
        return real_push(self)

    monkeypatch.setattr(SyncClient, "push", push_then_fail)
    result = CliRunner().invoke(cli.main, ["revoke-user", carol_id])

    # Bob's batch landed; carol's re-key is made and pending, she stays queued.
    assert result.exit_code != 0
    assert not _envelopes_live(db, bob_id)
    assert _envelopes_live(db, carol_id)
    assert _queue(admin) == [carol_id]
    assert (pending_states.rekey_batch(admin.db) or None)["revoked_user_id"] == carol_id

    monkeypatch.setattr(SyncClient, "push", real_push)
    result = CliRunner().invoke(cli.main, ["push"])

    assert result.exit_code == 0, result.output
    assert f"Re-keyed 1 folder(s) after revoking user {carol_id}" in result.output
    assert not _envelopes_live(db, carol_id)
    assert _queue(admin) == []
