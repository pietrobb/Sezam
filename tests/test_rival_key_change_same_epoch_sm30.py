"""Stateful test finding SM30: a rival key change took the epoch a restore lost.

The laptop changed the password and the server took it as key epoch 2; the
server was then restored from a backup made before. Before the laptop synced
again, the phone changed the password too, and the server took that as epoch
2 as well. The laptop's epochs all matched the server's (SM12 saw only a
server below them), so it went on with key material the server no longer
has and could not open the DEKs the phone wrapped since. The laptop now
remembers which key material its push sent and stops when the server holds
other material at that epoch.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _restore, _two_devices


def test_rival_key_change_at_the_epoch_a_restore_lost_stops_sync(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    laptop.change_password(PASSWORD, "laptop-pw-sm30!")
    laptop_client = _client(laptop, url)
    laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    _restore(db, backup)

    phone_client = _client(phone, url)
    phone_client.prepare_key_change()
    phone.change_password(PASSWORD, "phone-pw-sm30!")
    phone_client = _client(phone, url)
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    assert laptop.db.get_meta("key_epoch") == phone.db.get_meta("key_epoch")

    with pytest.raises(KeyEpochStale):
        laptop_client.full_resync(confirmed=True)

    laptop_client.adopt_rotated_key_material(laptop, "phone-pw-sm30!")
    laptop.lock()
    laptop.unlock("phone-pw-sm30!")
    laptop.lock()
    phone.lock()


def test_change_taken_over_then_lost_and_replaced_at_its_epoch_stops_sync(
    server, tmp_path  # noqa: F811
):
    """The phone took the laptop's change over; the server lost it, and the
    laptop's next change took the same epoch with other key material."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    laptop.change_password(PASSWORD, "first-pw-sm30!")
    laptop_client = _client(laptop, url)
    laptop_client.push()
    phone_client = _client(phone, url)
    with pytest.raises(KeyEpochStale):
        phone_client.pull()
    phone_client.adopt_rotated_key_material(phone, "first-pw-sm30!")
    _restore(db, backup)

    with pytest.raises(KeyEpochStale):
        laptop_client.full_resync(confirmed=True)
    laptop_client.adopt_rotated_key_material(laptop, PASSWORD)
    laptop_client = _client(laptop, url)
    laptop_client.full_resync(confirmed=True)
    laptop.change_password(PASSWORD, "second-pw-sm30!")
    laptop_client = _client(laptop, url)
    laptop_client.push()
    assert laptop.db.get_meta("key_epoch") == phone.db.get_meta("key_epoch")

    phone_client = _client(phone, url)
    with pytest.raises(KeyEpochStale):
        phone_client.full_resync(confirmed=True)
    phone_client.adopt_rotated_key_material(phone, "second-pw-sm30!")
    laptop.lock()
    phone.lock()
