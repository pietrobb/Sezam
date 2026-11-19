"""Stateful test finding SM2: a restore from trash brought back an older version.

A pulled tombstone only marked the local row deleted and kept the content
this device last had. When another device edited the entry and then deleted
it, this device's trash showed the entry before that edit, and restoring it
there sent the old content back as the newest version: the edit was gone
without a conflict. A pulled tombstone now carries its content into the
local row, so every device's trash holds what was deleted.
"""

from __future__ import annotations

from sezam.vault import trash
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_lost_update_base_version_sm1 import _set, _two_devices


def test_restore_on_another_device_keeps_the_last_edit_before_delete(server, tmp_path):
    url, _db = server
    laptop, phone, entry_id = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)

    _set(laptop, entry_id, "edited-before-delete")
    laptop.delete_entry(entry_id)
    assert laptop_client.push()["accepted"]

    phone_client.pull()
    assert entry_id in {item["id"] for item in trash.list_trash(phone)}
    trash.restore_entry(phone, entry_id)
    assert phone.get_field_value(entry_id, "password") == "edited-before-delete"

    assert phone_client.push()["accepted"]
    laptop_client.pull()
    assert laptop.get_field_value(entry_id, "password") == "edited-before-delete"
    laptop.lock()
    phone.lock()
