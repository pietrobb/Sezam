"""Stateful test finding SM13: an edit the restored server lost was overwritten silently.

The phone edited an entry and pushed it; the server was then restored from a
backup made before. The laptop, which never saw the edit, deleted the entry
and pushed. The phone noticed the rollback and ran the full resync, which took
the server's copy (the laptop's delete) over its own edit without a word,
although the delete was made without knowing the edit. The edit is now kept
as a conflict the user decides.
"""

from __future__ import annotations

import copy

from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices, sees_rollback


def _entry(vault, name: str) -> str:
    return next(e["id"] for e in vault.list_entries(_folder(vault)) if e["name"] == name)


def test_edit_lost_by_restore_meets_a_delete(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop.create_entry(_folder(laptop), "e", [{"key": "password", "value": "v1", "sensitive": True}])
    laptop_client = _client(laptop, url)
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()
    entry = _entry(phone, "e")
    backup = copy.deepcopy(db._storage)

    phone.update_entry(entry, name="edited")
    assert phone_client.push()["accepted"]
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    laptop.delete_entry(entry)
    assert laptop_client.push()["accepted"]

    assert sees_rollback(phone_client)
    phone_client.full_resync(confirmed=True)
    conflicts = {c["id"] for c in phone_client.get_pull_conflicts()}
    assert entry in conflicts, "the lost edit was settled without the user"
    phone.lock()
    laptop.lock()
