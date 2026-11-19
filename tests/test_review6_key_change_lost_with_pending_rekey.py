"""Stateful test (second admin, bg238): a key change the restored server lost, met by a pending re-key.

The laptop changed the password and the server took it; the server was then
restored from a backup made before. The laptop removed Bob and the re-key
failed to go out. Its push met the restore, ran the full-resync read that
resends what the server lost (SM39) and sent the re-key again without the
rollback check, at the key epoch the server no longer had: the server refused
it on every push ("Key epoch advance must include every active DEK"), since
this device counted the epoch as sent. That read now checks the key epoch as
every pull does (SM12): the device takes over the server's key material with
the password the server has, and the re-key then lands.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_push_after_a_restore_lost_the_key_change_takes_over_the_server_keys(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    backup = copy.deepcopy(db._storage)

    laptop.change_password(PASSWORD, "new-pw-r6-bg238!")
    laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    _restore(db, backup)
    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(laptop, laptop_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(laptop.db) or None)

    with pytest.raises(KeyEpochStale):
        laptop_client.push()

    # The way out (SM12): the key material the server has, with its password.
    laptop_client.adopt_rotated_key_material(laptop, PASSWORD)
    laptop_client.push()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    laptop.lock()
    phone.lock()
