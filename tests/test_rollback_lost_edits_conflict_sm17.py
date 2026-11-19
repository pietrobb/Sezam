"""Stateful test finding SM17: another device's edit was overwritten after a restore.

The phone changed an entry twice (two versions up) and pushed; the server was
then restored from a backup made before. The laptop, which never saw the
phone's change, edited the entry on top of the backup (one version up) and
pushed. The phone's full resync saw a server copy below its own version and
took it for one it had already superseded: its next push overwrote the
laptop's edit without a conflict. SM13 caught only the same version.
"""

from __future__ import annotations

import copy

import pytest

from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices, sees_rollback
from tests.test_rollback_lost_edit_conflict_sm13 import _entry


@pytest.mark.parametrize("push_between", [True, False], ids=["two-pushes", "one-push"])
def test_edits_lost_by_restore_meet_a_newer_edit(server, tmp_path, push_between):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop.create_entry(_folder(laptop), "e", [{"key": "password", "value": "v1", "sensitive": True}])
    laptop_client = _client(laptop, url)
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()
    entry = _entry(phone, "e")
    backup = copy.deepcopy(db._storage)

    phone.update_entry(entry, name="phone 1")
    if push_between:
        assert phone_client.push()["accepted"]
    phone.update_entry(entry, name="phone 2")
    assert phone_client.push()["accepted"]
    assert phone.db.fetchone("SELECT version FROM entries WHERE id = ?", (entry,))["version"] == 3
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    laptop.update_entry(entry, name="laptop")
    assert laptop_client.push()["accepted"]

    assert sees_rollback(phone_client)
    phone_client.full_resync(confirmed=True)
    conflicts = {c["id"] for c in phone_client.get_pull_conflicts()}
    assert entry in conflicts, "the laptop's edit would be overwritten without the user"
    phone.lock()
    laptop.lock()
