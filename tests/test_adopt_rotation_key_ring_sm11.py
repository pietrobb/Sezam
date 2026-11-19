"""Stateful test finding SM11: after taking over a rotated identity, every push failed.

Another device of the account rotated the identity key. This device took the
new keypair over (adopt_rotated_key_material), which re-signs its unsent
audit records with the new key. The client still held the signing key ring
it loaded before, with only the old key in it, so it refused those records as
forged on every push for the rest of the session ("Invalid audit signature").
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


def test_push_after_taking_over_a_rotated_identity(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_client = _client(phone, url)
    phone.create_node("before")
    assert not phone_client.push()["conflicts"]  # loads the key ring

    _client(laptop, url).pull()
    laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    assert not _client(laptop, url).push()["conflicts"]

    phone.create_node("after")  # an audit record signed with the old key
    phone_client._token = None  # a new login, as after the session ended
    with pytest.raises(KeyEpochStale):
        phone_client.push()
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    assert phone.keypair.signing_pk == laptop.keypair.signing_pk
    assert not phone_client.push()["conflicts"]
    assert not phone_client.dirty_object_count()
    phone.lock()
    laptop.lock()
