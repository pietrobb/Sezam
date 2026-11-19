"""Stateful test finding SM40: a password change waiting while the server compacted.

The phone changed the password, but the push failed. The laptop meanwhile
made a folder (a new DEK) and deleted an entry, and the server collected that
tombstone past the phone's checkpoint. The phone's change must carry every
active DEK, so the server refused it until the phone pulled the new one; that
pull was a 410 (full resync required), and the full resync was refused while
the change waited. The phone could never sync again. The new DEK now comes
from the server's snapshot, joins the change, and the change goes out.
"""

from __future__ import annotations

from sezam.vault import org_recovery_server
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once
from tests.test_tombstone_gc_orphans_r5k1 import _gc

import pytest


def test_password_change_goes_out_after_the_server_compacted_past_the_device(
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
    phone.change_password(PASSWORD, "phone-pw-sm40!")
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

    with pytest.raises(KeyEpochStale):
        laptop_client.pull()
    laptop_client.adopt_rotated_key_material(laptop, "phone-pw-sm40!")
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert "g-pw" in str(laptop.read_entry(entry))
    laptop.lock()
    phone.lock()


def test_org_recovery_takes_in_a_folder_key_made_elsewhere(server, tmp_path):  # noqa: F811
    """Its push was refused for the new folder's DEK; the named way out
    ('sezam abandon-pending-change') needs the password the user forgot."""
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    shares = org_recovery_server.setup_and_register(phone, PASSWORD, 2, 3).shares
    new_folder = laptop.create_node("G", parent_id=_folder(laptop))
    entry = laptop.create_entry(new_folder, "vpn", [{"key": "password", "value": "g-pw", "sensitive": True}])
    laptop_client.push()

    phone.lock()
    phone.org_recovery(shares[:2], "phone-rec-sm40!")
    phone_client = _client(phone, url)
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    assert "g-pw" in str(phone.read_entry(entry))
    with pytest.raises(KeyEpochStale):
        laptop_client.pull()
    laptop_client.adopt_rotated_key_material(laptop, "phone-rec-sm40!")
    _client(laptop, url).pull()
    assert "g-pw" in str(laptop.read_entry(entry))
    laptop.lock()
    phone.lock()


def test_org_recovery_goes_out_after_the_server_compacted_past_the_device(
    server, tmp_path  # noqa: F811
):
    """The same after a Shamir recovery: its journal had no old KEK at all."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    doomed = laptop.create_entry(folder, "old", [{"key": "k", "value": "v"}])
    laptop_client.push()
    phone_client.pull()
    shares = org_recovery_server.setup_and_register(phone, PASSWORD, 2, 3).shares

    phone.lock()
    phone.org_recovery(shares[:2], "phone-rec-sm40!")
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
    phone.lock()
    phone.unlock("phone-rec-sm40!")
    assert "g-pw" in str(phone.read_entry(entry))
    laptop.lock()
    phone.lock()
