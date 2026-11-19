"""Stateful test finding SM16: a re-signed audit record stopped the full resync for good.

The phone rotated its identity key and pushed a change; the laptop took the
rotation over and pulled the change with its audit record, signed with the new
key. Then the server was restored from a backup made before the rotation. The
phone took the old key back and its full resync sent the lost records again,
signed with the key the server knows (SM14). The laptop still held the copy
signed with the lost key; its full resync refused the server's copy as a
"Conflicting append-only audit record" on every attempt, and nothing else got
it out. The same record with a signature that verifies is now taken over.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault.sync_client import KeyEpochStale, SyncClient
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _add, _names, _restore, _two_devices


def _fresh_client(vault, url) -> SyncClient:
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    return client


def _take_back_old_key(vault, url) -> SyncClient:
    client = _fresh_client(vault, url)
    with pytest.raises(KeyEpochStale):
        client.authenticate()
    client.adopt_rotated_key_material(vault, PASSWORD)
    client.full_resync(confirmed=True)
    client.push()
    return client


def test_full_resync_takes_a_record_re_signed_after_a_restore(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    backup = copy.deepcopy(db._storage)
    _client(phone, url).authenticate()
    proof = phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    _add(phone, "after-rotation")
    assert _client(phone, url).push()["accepted"]

    laptop_client = _fresh_client(laptop, url)
    with pytest.raises(KeyEpochStale):
        laptop_client.pull()
    laptop_client.adopt_rotated_key_material(laptop, PASSWORD)
    laptop_client.pull()
    assert "after-rotation" in _names(laptop)

    _restore(db, backup)
    _take_back_old_key(phone, url)
    _take_back_old_key(laptop, url)
    assert "after-rotation" in _names(laptop)
    phone.lock()
    laptop.lock()
