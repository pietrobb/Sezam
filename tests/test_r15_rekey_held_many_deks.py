"""Capability run 439 (goal #429): a member re-key with more DEKs than the lookup cap.

ab915bc asks POST /api/objects/held whether a re-key batch landed, and sent
every new DEK id of the batch in one request. The server takes at most
MAX_HELD_IDS ids, so revoking a member with access to more folders than that
made every push (and abandon-rekey) raise 422 before the batch went out. The
batch is atomic and its new DEK ids are sent nowhere else, so one id answers.
"""

from __future__ import annotations

import os

import pytest

from sezam import cli
from sezam.models import new_ulid
from sezam.vault import outbox, pending_states
from sezam.vault.rekey_abandon import abandon_pending_rekey
from server.app.routers.sync_held import MAX_HELD_IDS
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_revoke_second_member_8b import _envelopes_live


def _admin_with_member_on(url, tmp_path, monkeypatch, folders: int):
    admin = _vault(tmp_path / "admin", "admin")
    ids = [admin.create_node(f"F{i:03d}") for i in range(folders)]
    cli._server_connect_flow(url, admin, PASSWORD)
    client = _client(admin, url)
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    invitation = client.create_invitation()
    member = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, member, PASSWORD, is_bootstrap=False,
        invitation_token=invitation["invitation_token"],
    )
    bob_id = member.db.get_meta("user_id")
    client.approve_user(bob_id)
    member.lock()
    admin_id = admin.db.get_meta("user_id")
    for folder in ids:
        dek_id = admin.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
        admin.db.execute(
            "INSERT INTO access_envelopes "
            "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
            "VALUES (?, ?, ?, ?, 'read', ?)",
            (new_ulid(), dek_id, bob_id, admin_id, os.urandom(72)),
        )
        outbox.queue_write(admin.db, folder)
    assert client.push()["conflicts"] == []
    return admin, client, bob_id


def test_the_client_chunks_at_the_server_cap():
    from sezam.vault.sync_rekey import HELD_IDS_PER_REQUEST

    assert HELD_IDS_PER_REQUEST == MAX_HELD_IDS


def _server_deks(db) -> set[str]:
    return {
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "dek" and not o["is_deleted"]
    }


@pytest.mark.parametrize("folders", [3, MAX_HELD_IDS + 1])
def test_a_rekey_over_the_lookup_cap_goes_out(server, tmp_path, monkeypatch, folders):  # noqa: F811
    url, db = server
    admin, client, bob_id = _admin_with_member_on(url, tmp_path, monkeypatch, folders)
    client.revoke_user(bob_id)
    assert admin.rekey_after_revocation(bob_id) == folders
    pending = pending_states.rekey_batch(admin.db)
    new_deks = set(pending["dek_map"].values())
    assert len(new_deks) == folders

    assert client.rekey_batch_on_server(pending) is False  # not sent yet
    client.push()

    assert new_deks <= _server_deks(db)
    assert pending_states.rekey_batch(admin.db) == {}
    assert client.rekey_batch_on_server(pending) is True  # as if its reply was lost
    assert not _envelopes_live(db, bob_id)


@pytest.mark.parametrize("folders", [3, MAX_HELD_IDS + 1])
def test_abandon_over_the_lookup_cap_asks_the_server(server, tmp_path, monkeypatch, folders):  # noqa: F811
    url, db = server
    admin, client, bob_id = _admin_with_member_on(url, tmp_path, monkeypatch, folders)
    client.revoke_user(bob_id)
    assert admin.rekey_after_revocation(bob_id) == folders
    new_deks = set(pending_states.rekey_batch(admin.db)["dek_map"].values())

    abandon_pending_rekey(client)

    assert pending_states.rekey_batch(admin.db) == {}
    assert not new_deks & _server_deks(db)
