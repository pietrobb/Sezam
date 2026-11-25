"""Stateful test finding SM23b: a lost rotation sent again split the account's KEK.

The laptop rotated the account's identity key and its second device (the
desktop) took the new key material over. The server was then restored from a
backup made before the rotation. The laptop sends the rotation again
(capability run 277), but it did so under a NEW salt, so a new KEK at the same
key epoch the desktop already held. The desktop's folder keys, wrapped under
the lost rotation's KEK, were accepted at that epoch, and no other device could
open them: every pull of the laptop asked for a full resync ("keys of this
account in a copy from before a password change") and nothing settled. The
rotation sent again is the same one: same password and salt, so the same KEK.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from sezam.vault.sync_client import KeyEpochStale, SyncClient
from sezam.vault.sync_common import STALE_OWN_WRAPS_META
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_review9_team_identity import _rotate
from tests.test_review9_team_log_restore import _pull_confirming
from tests.test_team_log_desktop import _forget_server_cache, _found_with_bob, team  # noqa: F401


def _taken_over(vault, url) -> SyncClient:
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    with pytest.raises(KeyEpochStale):
        client.authenticate()
    client.adopt_rotated_key_material(vault, PASSWORD)  # the user types the password
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    return client


def test_a_lost_rotation_goes_out_again_under_the_kek_the_other_device_holds(
    team, server, tmp_path  # noqa: F811
):
    url, _ = server
    db, laptop, laptop_client, bob, _bob_client = team
    _found_with_bob(laptop_client, bob)
    desktop = _vault(tmp_path / "desktop", "admin")
    cli._server_connect_flow(url, desktop, PASSWORD)
    _pull_confirming(_client(desktop, url))
    backup = copy.deepcopy(db._storage)

    _rotate(laptop, laptop_client, url).push()
    desktop_client = _taken_over(desktop, url)
    lost_salt = desktop.db.get_meta("argon2_salt")
    assert lost_salt == laptop.db.get_meta("argon2_salt")

    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    _forget_server_cache()
    # Written under the lost rotation's KEK while the server lacks it.
    folder = desktop.create_node("Written on the desktop")

    laptop_client = _taken_over(laptop, url)  # the rotation goes out again
    laptop_client.full_resync(confirmed=True)
    laptop_client.push()
    assert laptop.db.get_meta("argon2_salt") == lost_salt
    user = next(u for u in db._storage["users"] if u["id"] == laptop.db.get_meta("user_id"))
    assert bytes(user["argon2_salt"]).hex() == lost_salt

    desktop_client.push()  # as the stateful test did: before its pull
    try:
        _pull_confirming(desktop_client)
    except KeyEpochStale:
        desktop_client.adopt_rotated_key_material(desktop, PASSWORD)
    assert any(o["id"] == folder for o in db._storage["vault_objects"])
    laptop_client = _client(laptop, url)
    _pull_confirming(laptop_client)
    assert not laptop.db.get_meta_json(STALE_OWN_WRAPS_META)
    assert "Written on the desktop" in {n["name"] for n in laptop.list_nodes()}
    desktop.lock()
