"""Stateful test finding SM22: a change kept in a conflict sat below the device's own writes.

The phone edited an entry twice and pushed both (versions 2 and 3); the
laptop pulled them. The server was then restored from a backup holding
version 1. The phone deleted the entry, ran the full resync and kept its
delete in the conflict: resealed at server version + 1 = 2. The laptop's full
resync sent its copy, version 3, again - the phone's own write. The phone's
push was refused, rebased on that own write and sent version 2 once more, on
every sync: it never settled. A kept change now goes above every version the
device already sent, too.
"""

from __future__ import annotations

import copy

from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices, sees_rollback


def test_kept_change_goes_above_own_writes_a_restore_lost(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    entry = laptop.create_entry(
        _folder(laptop), "e", [{"key": "password", "value": "v1", "sensitive": True}]
    )
    laptop_client = _client(laptop, url)
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()
    backup = copy.deepcopy(db._storage)

    for name in ("e2", "e3"):
        phone.update_entry(entry, name=name)
        assert phone_client.push()["accepted"]
    laptop_client.pull()
    _restore(db, backup)

    phone.delete_entry(entry)
    assert sees_rollback(phone_client)
    phone_client.full_resync(confirmed=True)
    assert entry in {c["id"] for c in phone_client.get_pull_conflicts()}
    phone_client.resolve_conflict(entry, "local")

    assert sees_rollback(laptop_client)
    laptop_client.full_resync(confirmed=True)
    assert not laptop_client.push()["conflicts"]

    for _ in range(2):
        result = phone_client.push()
    assert not result["conflicts"], result
    server_copy = next(o for o in db._storage["vault_objects"] if o["id"] == entry)
    assert server_copy["is_deleted"]
    phone.lock()
    laptop.lock()
