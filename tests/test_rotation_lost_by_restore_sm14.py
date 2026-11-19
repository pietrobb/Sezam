"""Stateful test finding SM14: an identity rotation the restored server lost locked the device out.

The phone rotated its identity key and the server took it; then the server was
restored from a backup made before. The server knew only the key from before,
so every login of the phone failed with a bare 401 and nothing told the way
out. Now the device is told to take over the key material the server holds
(with the account password, through /auth/recover), and the full resync that
follows signs the records the server lost again with the key it knows.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault.sync_client import KeyEpochStale, SyncClient
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import (
    _add,
    _names,
    _restore,
    _two_devices,
    sees_rollback,
)

NEW = "new-pw-sm14!"


def test_rotation_lost_by_restore_has_a_way_out(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    _client(phone, url).authenticate()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    _add(phone, "after-rotation")
    assert _client(phone, url).push()["accepted"]
    _restore(db, backup)

    phone_client = SyncClient(phone.db, url, phone.keypair, phone.db.get_meta("user_id"))
    phone_client.set_dek_manager(phone.dek_mgr)
    with pytest.raises(KeyEpochStale):
        phone_client.authenticate()
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    phone_client.full_resync(confirmed=True)
    # The audit records the server lost go out again, signed with a key it knows.
    phone_client.push()
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert "after-rotation" in _names(laptop)
    phone.lock()
    phone.unlock(PASSWORD)
    phone.lock()
    laptop.lock()


def test_rotation_lost_by_restore_seen_with_a_live_session(server, tmp_path):  # noqa: F811
    """The phone's session outlived the restore and another device moved the epoch on."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    _client(phone, url).authenticate()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    phone_client = _client(phone, url)
    phone_client.push()
    _restore(db, backup)
    # The laptop's password change takes the epoch the lost rotation had.
    laptop.change_password(PASSWORD, NEW)
    _client(laptop, url).push()

    assert sees_rollback(phone_client)
    with pytest.raises(KeyEpochStale):
        phone_client.full_resync(confirmed=True)
    phone_client.adopt_rotated_key_material(phone, NEW)
    phone_client.full_resync(confirmed=True)
    phone_client.push()
    phone.lock()
    phone.unlock(NEW)
    phone.lock()
    laptop.lock()
