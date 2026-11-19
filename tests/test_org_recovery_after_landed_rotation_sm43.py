"""Stateful test finding SM43: an org recovery on top of a rotation that landed.

The phone rotated its identity; the server took the push, but the reply never
came, so the change still looked pending. The phone's password was then
forgotten and reset with an org recovery (Shamir), which carries the waiting
change, rotation included, into its own. The server already had the rotated
keys and refused every push of it: 'An identity rotation needs new keys'. The
change now goes out again without the rotation part.
"""

from __future__ import annotations

from sezam.vault import org_recovery_server
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once

RECOVERED = "phone-rec-sm43!"


def test_org_recovery_goes_out_after_a_rotation_whose_reply_was_lost(
    server, tmp_path  # noqa: F811
):
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    shares = org_recovery_server.setup_and_register(phone, PASSWORD, 2, 3).shares

    phone_client.prepare_key_change()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    phone_client = _client(phone, url)
    undo = _fail_once(phone_client, "POST", "/api/sync", "after")
    try:
        phone_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert phone_client.has_pending_key_change()  # landed, but the reply was lost

    phone.lock()
    phone.org_recovery(shares[:2], RECOVERED)
    phone_client = _client(phone, url)
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    phone_client.pull()
    phone.lock()
    phone.unlock(RECOVERED)
    assert "ops-pw" in str(phone.read_entry(entry))
    phone.lock()
    laptop.lock()
