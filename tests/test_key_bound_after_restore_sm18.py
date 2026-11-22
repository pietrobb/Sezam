"""Stateful test finding SM18: a key bound from a lost rotation refused real objects.

Goal #443 replaced the bound by voucher lists of the current key; the case
stays: the old key's later writes must still count once the laptop rotated it
away (its rotation vouches for them).

The phone rotated the account's identity key and learned the old key's bound:
it vouches only for objects committed before that rotation. The server was then
restored from a backup made before the rotation, so the old key was the
account's key again; the laptop wrote with it and later rotated it away
itself. The phone took the new key over, but the bound it had pinned from the
lost rotation still retired the old key too early: every full resync refused
the laptop's object as forged ("invalid signature") and nothing got it out.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault.sync_client import KeyEpochStale, SyncClient
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _add, _names, _restore, _two_devices, sees_rollback


def _rotate(vault, url) -> None:
    _client(vault, url).authenticate()
    proof = vault.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    assert not _client(vault, url).push()["conflicts"]


def test_full_resync_after_a_lost_rotation_takes_the_old_keys_writes(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    _rotate(phone, url)
    user_id = phone.db.get_meta("user_id")
    _client(phone, url)._get_signing_pks(user_id)  # learns the old key is retired

    _restore(db, backup)
    _add(laptop, "written with the old key")
    assert _client(laptop, url).push()["accepted"]
    _rotate(laptop, url)

    phone_client = SyncClient(phone.db, url, phone.keypair, user_id)
    phone_client.set_dek_manager(phone.dek_mgr)
    with pytest.raises(KeyEpochStale):
        phone_client.authenticate()
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    assert sees_rollback(phone_client)
    phone_client.full_resync(confirmed=True)
    assert "written with the old key" in _names(phone)
    phone.lock()
    laptop.lock()
