"""Stateful test finding SM1: an edit on one device silently overwrote another's.

The server took any change whose version was higher than the stored one.
Every local edit raises the version by one, so a device that edited an
entry twice offline (version +2) overwrote an edit another device had sent
in the meantime (version +1) without any conflict. Now changes carry the
server version they were made on (base_version) and the server takes them
only over that copy.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import PASSWORD, _client, _entry_value, _vault, server  # noqa: F401


def _two_devices(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "v0", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    entry_id = next(
        e["id"] for n in laptop.list_nodes() if n["name"] == "Servers"
        for e in laptop.list_entries(n["id"])
    )
    return laptop, phone, entry_id


def _set(vault, entry_id, value):
    vault.update_entry(entry_id, fields=[{"key": "password", "value": value, "sensitive": True}])


def test_two_offline_edits_do_not_overwrite_an_edit_sent_meanwhile(server, tmp_path):
    url, _db = server
    laptop, phone, entry_id = _two_devices(url, tmp_path)

    _set(laptop, entry_id, "laptop-new")
    _set(phone, entry_id, "phone-1")
    _set(phone, entry_id, "phone-2")  # a second offline edit: version +2

    assert _client(laptop, url).push()["accepted"]
    phone_client = _client(phone, url)
    pushed = phone_client.push()
    assert [c["id"] for c in pushed["conflicts"]] == [entry_id]

    # The laptop's edit is still what the server holds ...
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert laptop.get_field_value(entry_id, "password") == "laptop-new"
    # ... and the phone is shown the conflict instead of losing either side.
    phone_client.pull()
    assert [c["id"] for c in phone_client.get_pull_conflicts()] == [entry_id]
    assert phone.get_field_value(entry_id, "password") == "phone-2"

    phone_client.resolve_conflict(entry_id, "local")
    assert phone_client.push()["accepted"]
    laptop_client.pull()
    assert laptop.get_field_value(entry_id, "password") == "phone-2"
    laptop.lock()
    phone.lock()


def test_an_edit_after_a_lost_reply_is_not_a_conflict_with_itself(server, tmp_path):
    url, _db = server
    laptop, _phone, entry_id = _two_devices(url, tmp_path)
    client = _client(laptop, url)

    _set(laptop, entry_id, "sent-but-reply-lost")
    real = SyncClient._request

    def lose_reply(self, method, path, *args, **kwargs):
        result = real(self, method, path, *args, **kwargs)
        if method == "POST" and path == "/api/sync":
            raise RuntimeError("reply lost")
        return result

    client._request = lose_reply.__get__(client)
    with pytest.raises(RuntimeError, match="reply lost"):
        client.push()
    client._request = real.__get__(client)

    _set(laptop, entry_id, "edited-again")
    pushed = client.push()
    assert pushed["accepted"] and not pushed["conflicts"]
    client.pull()
    assert not client.get_pull_conflicts()
    assert _entry_value(_vault_reader(url, tmp_path), "Servers", "db01", "password") == "edited-again"
    laptop.lock()


def _vault_reader(url, tmp_path):
    reader = _vault(tmp_path / "reader", "admin")
    cli._server_connect_flow(url, reader, PASSWORD)
    return reader
