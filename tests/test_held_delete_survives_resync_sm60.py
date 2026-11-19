"""Stateful test finding SM60: a held delete a full resync keeps stays a conflict.

A member re-key the laptop dropped held its delete of a folder another device
had changed; the delete came back as a conflict at the server copy's version,
with that copy's blobs (and so its payload hash). The full resync dropped the
conflict and kept the delete as an unsent change of the server's copy: sent at
the version the server holds live, it was refused on every push and nothing
was left to settle it. It stays a conflict now, and settles.
"""

from __future__ import annotations

from sezam.vault import outbox
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_held_delete_kept_by_full_resync_stays_a_conflict(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop_client.push()
    phone_client.pull()
    phone.rename_node(folder, "renamed on the phone")
    phone_client.push()
    laptop_client.pull()
    parent = laptop.db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (folder,))["parent_id"]

    # What a dropped re-key brings back of the laptop's delete of the folder.
    laptop.db.begin()
    laptop_client._restore_held_edits({folder: {"kind": "node", "deleted": True, "parent": parent}}, {})
    laptop.db.commit()
    assert [c["id"] for c in laptop_client.get_pull_conflicts()] == [folder]

    assert laptop_client.full_resync(confirmed=True)["full_resync"]
    assert [c["id"] for c in laptop_client.get_pull_conflicts()] == [folder]

    laptop_client.resolve_conflict(folder, "server")
    laptop_client.push()
    laptop_client.pull()
    row = laptop.db.fetchone("SELECT is_deleted FROM nodes WHERE id = ?", (folder,))
    assert (outbox.has_write(laptop.db, folder), row["is_deleted"]) == (False, 0)
    assert not laptop_client.get_pull_conflicts()
    laptop.lock()
    phone.lock()
