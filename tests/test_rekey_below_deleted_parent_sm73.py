"""Stateful test finding SM73: a re-key of a folder deleted elsewhere with its parent.

The phone deleted a shared folder and the folder above it. The laptop, which
had not seen that, added an entry to the shared folder, renamed it and removed the member
it was shared with. The refused re-key was rebased: the pull brought both
deletes, the push brought both folders back for the unsent entry (SM34), but
the atomic unit took only the re-keyed folder. Its parent waited for the
normal push after the unit, so the server refused the unit ('parent folder is
deleted') on every sync. The revived folders above the unit now go with it.

Then the rename, held by the rebase, came back as a
conflict whose server side was the delete the rebase had seen, not the live
folder the unit had sent: 'Use server' deleted the folder on the laptop only.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _live(vault, node_id) -> bool:
    return bool(vault.db.fetchone(
        "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (node_id,)
    ))


def test_rekey_of_a_folder_deleted_with_its_parent_elsewhere_lands(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    parent = _folder(laptop)
    sub = laptop.create_node("Sub", parent_id=parent)
    laptop_client.push()
    phone_client.pull()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, sub, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    phone.delete_node(sub)
    phone.delete_node(parent)
    assert not phone_client.push()["conflicts"]

    entry = laptop.create_entry(sub, "vpn", [{"key": "password", "value": "pw", "sensitive": True}])
    laptop.rename_node(sub, "Renamed")
    revocation.revoke_member(laptop, laptop_client, bob_id)
    for _ in range(3):
        revocation.push_with_queued_revocations(laptop, laptop_client)
        laptop_client.pull()
    assert not (pending_states.rekey_batch(laptop.db) or None)

    conflicts = {c["id"]: c for c in laptop_client.get_pull_conflicts()}
    assert conflicts[sub]["server_is_deleted"] == 0  # the unit sent the folder back live
    laptop_client.resolve_conflict(sub, "server")
    laptop_client.push()
    laptop_client.pull()
    phone_client.pull()
    store = {o["id"]: o for o in db._storage["vault_objects"]}
    for node_id in (parent, sub):
        assert not store[node_id]["is_deleted"]
        assert _live(laptop, node_id) and _live(phone, node_id)
    assert not store[entry]["is_deleted"]
    assert phone.read_entry(entry)["node_id"] == sub
    laptop.lock()
    phone.lock()
