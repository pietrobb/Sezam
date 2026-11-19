"""Stateful test finding SM10: a session ended by a key change elsewhere was a dead end.

A password change or identity rotation bumps the account's token epoch, so
every open session of the account's other devices is revoked. Their next
request failed with a bare '401 Token revoked' however often it was retried,
instead of reaching the check that tells the device to take the change over
with the current password (KeyEpochStale). The client now logs in again once
and repeats the request.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)

NEW = "changed-elsewhere-pw!"


def test_open_session_learns_of_a_password_change_elsewhere(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_client = _client(phone, url)
    phone_client.pull()

    laptop.change_password(PASSWORD, NEW)
    assert not _client(laptop, url).push()["conflicts"]

    with pytest.raises(KeyEpochStale):
        phone_client.pull()
    phone_client.adopt_rotated_key_material(phone, NEW)
    phone_client.pull()
    assert not phone_client.push()["conflicts"]
    phone.lock()
    phone.unlock(NEW)
    phone.lock()
    laptop.lock()
