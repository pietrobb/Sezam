"""Stateful test finding SM50: a re-key the server lost to a restore broke the full resync.

The laptop shared a folder with Bob and then removed him: the re-key gave the
folder a new DEK and re-sealed its entries, but left the folder itself at its
version. The server was then restored from a backup taken before the re-key.
The laptop's full resync kept the re-sealed entries (newer than the server's)
but dropped the new DEK, which neither a kept folder nor the entries' own key
named: the folder still pointed to it and the commit failed on its foreign key.
The DEK now stays with the entries and goes out again with its archive, so the
phone reads them too.
"""

from __future__ import annotations

import copy

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices


def test_full_resync_after_a_restore_keeps_the_dek_of_a_lost_rekey(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    backup = copy.deepcopy(db._storage)

    revocation.revoke_member(laptop, laptop_client, bob_id)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    _restore(db, backup)

    assert laptop_client.pull().get("rollback_warning")
    laptop_client.full_resync(confirmed=True)
    assert laptop.read_entry(entry)["name"] == "vpn"
    assert not laptop_client.push()["conflicts"]

    phone_client.full_resync(confirmed=True)
    phone_client.pull()
    assert phone.read_entry(entry)["name"] == "vpn"
    laptop.lock()
    phone.lock()
