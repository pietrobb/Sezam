"""Stateful test finding SM44: an org recovery on DEKs another device moved on.

The laptop rotated the account keys twice; the phone took the key change over
without pulling, so its folder keys stayed at the versions before. The phone's
password was then forgotten and reset with an org recovery (Shamir), which
pulls nothing first and re-wrapped those old versions. The server held newer
ones and refused the change on every push ('Atomic batch conflict'). The pull
now re-wraps the server's copies into the change, which goes out again.
"""

from __future__ import annotations

import pytest

from sezam.vault import org_recovery_server
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices

RECOVERED = "phone-rec-sm44!"


@pytest.mark.parametrize("rotations", [1, 2])
def test_org_recovery_goes_out_over_dek_versions_it_never_pulled(
    server, tmp_path, rotations  # noqa: F811
):
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    shares = org_recovery_server.setup_and_register(phone, PASSWORD, 2, 3).shares
    phone_client.push()
    laptop_client.pull()

    for _ in range(rotations):
        laptop_client.prepare_key_change()
        proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
        proof[:] = b"\x00" * len(proof)
        laptop_client = _client(laptop, url)
        laptop_client.push()
        assert not laptop_client.has_pending_key_change()

    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    phone.lock()
    phone.org_recovery(shares[:2], RECOVERED)
    phone_client = _client(phone, url)
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    phone_client.pull()
    phone.lock()
    phone.unlock(RECOVERED)
    assert "ops-pw" in str(phone.read_entry(entry))
    laptop_client.adopt_rotated_key_material(laptop, RECOVERED)
    laptop_client.pull()
    assert "ops-pw" in str(laptop.read_entry(entry))
    phone.lock()
    laptop.lock()
