"""Stateful test finding SM45: an edit lost by a restore was replaced unseen.

The phone changed an entry once and pushed; the server was then restored from
a backup made before. The laptop, which never saw the phone's change, changed
the entry twice on top of the backup (a version above the phone's) and pushed.
The phone's full resync took the laptop's copy as the next version of its own
write and dropped the phone's change without a conflict. SM13 caught only the
same version and SM17 only a server copy below the phone's.
"""

from __future__ import annotations

import copy

import pytest

from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices, sees_rollback
from tests.test_rollback_lost_edit_conflict_sm13 import _entry


@pytest.mark.parametrize("then", ["edit", "delete"])
def test_edit_lost_by_restore_meets_a_higher_rival(server, tmp_path, then):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop.create_entry(_folder(laptop), "e", [{"key": "password", "value": "v1", "sensitive": True}])
    laptop_client = _client(laptop, url)
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()
    entry = _entry(phone, "e")
    backup = copy.deepcopy(db._storage)

    phone.update_entry(entry, name="phone")
    assert phone_client.push()["accepted"]
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    laptop.update_entry(entry, name="laptop")
    if then == "edit":
        laptop.update_entry(entry, name="laptop 2")
    else:
        laptop.delete_entry(entry)
    assert laptop_client.push()["accepted"]

    assert sees_rollback(phone_client)
    phone_client.full_resync(confirmed=True)
    conflicts = {c["id"] for c in phone_client.get_pull_conflicts()}
    assert entry in conflicts, "the phone's edit was dropped without the user"
    phone.lock()
    laptop.lock()
