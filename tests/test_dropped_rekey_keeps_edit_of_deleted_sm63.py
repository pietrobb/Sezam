"""Stateful test finding SM63: a dropped re-key lost an edit of an entry deleted elsewhere.

The laptop shared a folder with Bob and edited an entry in it without pushing.
The phone (same admin account) deleted that entry, removed Bob and re-keyed the
folder first. The laptop's own re-key for Bob was refused and dropped as
superseded: the entry took the server's copy (the delete) and the held edit,
taken for a delete made here, went to the entry's history with no conflict.
It now comes back as a conflict with the server's delete, as SM41 does for a
folder.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_edit_of_an_entry_deleted_elsewhere_survives_a_dropped_rekey(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "old-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    laptop.update_entry(entry, fields=[{"key": "password", "value": "new-pw", "sensitive": True}])
    phone.delete_entry(entry)
    assert revocation.revoke_member(phone, phone_client, bob_id) == 1

    revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    conflicts = {c["id"]: c for c in laptop_client.get_pull_conflicts()}
    assert entry in conflicts, "the edit went to the history without a conflict"
    assert "new-pw" in str(laptop.read_entry(entry))
    laptop_client.resolve_conflict(entry, "local")
    laptop_client.push()
    phone_client.pull()
    assert "new-pw" in str(phone.read_entry(entry))
    laptop.lock()
    phone.lock()


def test_rename_of_a_folder_deleted_elsewhere_survives_a_dropped_rekey(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    parent = _folder(laptop)
    sub = laptop.create_node("Sub", parent_id=parent)
    laptop.create_entry(parent, "vpn", [{"key": "password", "value": "pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, parent, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    laptop.rename_node(sub, "Renamed")
    phone.delete_node(sub)
    assert revocation.revoke_member(phone, phone_client, bob_id) == 1

    revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert sub in {c["id"] for c in laptop_client.get_pull_conflicts()}
    laptop_client.resolve_conflict(sub, "local")
    laptop_client.push()
    phone_client.pull()
    assert phone.db.fetchone("SELECT is_deleted FROM nodes WHERE id = ?", (sub,))["is_deleted"] == 0
    laptop.lock()
    phone.lock()
