"""Stateful test finding SM12: a key change the restored server lost went unnoticed.

The laptop changed the password and the server took it; then the server was
restored from a backup made before. The server's DEKs are wrapped under the
KEK of the password it has now, while the laptop went on syncing and wrapping
new DEKs under its newer KEK, which no other device could ever open. A server
key epoch below the one this device last pushed now stops the sync until the
device takes over the server's key material with the password it has now.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _restore, _two_devices, sees_rollback


def test_key_change_lost_by_restore_stops_sync(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    laptop.change_password(PASSWORD, "new-pw-sm12!")
    laptop_client = _client(laptop, url)
    laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    _restore(db, backup)

    assert sees_rollback(laptop_client)
    with pytest.raises(KeyEpochStale):
        laptop_client.full_resync(confirmed=True)

    # The way out: the key material the server has, with its password.
    laptop_client.adopt_rotated_key_material(laptop, PASSWORD)
    laptop.lock()
    laptop.unlock(PASSWORD)
    laptop.lock()
    phone.lock()
