"""Stateful test finding SM4: after a full resync an unsent edit could never leave.

A full resync keeps what this device changed and never sent (review d150605
#6). When the server copy had moved on meanwhile, that change was kept as a
plain unsent edit: the server refused it on every push, and as the resync
had already brought the server's copy, no pull ever showed a conflict. The
edit stayed on the device with no way to send or settle it. It is now a
conflict to resolve like any other.
"""

from __future__ import annotations

from tests.test_integration_client_server import _client, _entry_value, server  # noqa: F401
from tests.test_lost_update_base_version_sm1 import _set, _two_devices, _vault_reader


def test_an_unsent_edit_kept_by_full_resync_can_be_settled(server, tmp_path):
    url, _db = server
    laptop, phone, entry_id = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)

    _set(laptop, entry_id, "laptop-1")
    assert laptop_client.push()["accepted"]
    _set(laptop, entry_id, "laptop-2")
    assert laptop_client.push()["accepted"]
    _set(phone, entry_id, "phone-offline")

    assert phone_client.full_resync_blocker() is None
    phone_client.full_resync(confirmed=True)
    assert [c["id"] for c in phone_client.get_pull_conflicts()] == [entry_id]
    assert phone.get_field_value(entry_id, "password") == "phone-offline"

    phone_client.resolve_conflict(entry_id, "local")
    pushed = phone_client.push()
    assert pushed["accepted"] and not pushed["conflicts"]
    assert phone_client.dirty_object_count() == 0
    assert _entry_value(_vault_reader(url, tmp_path), "Servers", "db01", "password") == "phone-offline"
    laptop.lock()
    phone.lock()
