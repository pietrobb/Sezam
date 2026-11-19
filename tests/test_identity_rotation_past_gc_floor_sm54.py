"""Stateful test finding SM54: an identity rotation waiting while the server compacted.

Like SM40, but the phone's password change also rotated its identity key.
The change has to carry the laptop's new folder DEK, the pull for it was a
410, and the full resync stayed refused for a change with an identity
rotation, so the phone could never sync again. The journal keeps the old
KEK and the old keypair, so the resync re-wraps the new DEK into the change
like a plain password change, and the rotation goes out.
"""

from __future__ import annotations

from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once
from tests.test_tombstone_gc_orphans_r5k1 import _gc

import pytest


def test_identity_rotation_goes_out_after_the_server_compacted_past_the_device(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    doomed = laptop.create_entry(folder, "old", [{"key": "k", "value": "v"}])
    laptop_client.push()
    phone_client.pull()

    phone_client.prepare_key_change()
    phone.change_password(PASSWORD, "phone-pw-sm54!", rotate_identity=True)
    new_signing_pk = phone._keypair.signing_pk.hex()
    phone_client = _client(phone, url)
    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        phone_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert phone_client.has_pending_key_change()

    new_folder = laptop.create_node("G", parent_id=folder)
    entry = laptop.create_entry(new_folder, "vpn", [{"key": "password", "value": "g-pw", "sensitive": True}])
    laptop.delete_entry(doomed)
    laptop_client.push()
    _gc(db)

    with pytest.raises(RuntimeError, match="full resync"):
        phone_client.push()
    assert phone_client.full_resync_blocker() is None
    assert phone_client.full_resync(confirmed=True)["full_resync"]
    assert "g-pw" in str(phone.read_entry(entry))
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    user_id = phone._db.get_meta("user_id")
    keys = phone_client._request("GET", f"/api/users/{user_id}/keys", auth=True)
    assert keys["signing_pk"] == new_signing_pk

    with pytest.raises(KeyEpochStale):
        laptop_client.pull()
    laptop_client.adopt_rotated_key_material(laptop, "phone-pw-sm54!")
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert "g-pw" in str(laptop.read_entry(entry))
    laptop.lock()
    phone.lock()
