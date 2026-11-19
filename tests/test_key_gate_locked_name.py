"""Review e4cd15a (low): the K1 gate had no attempt limit on a locked name.

A wrong current-password proof on a key material change counts like a wrong
/recover proof, but once the name was locked the gate went on verifying every
proof: the holder of a stolen identity key guessed the password at push rate
while /recover allowed one checked guess per window. A locked name now gets
one checked proof per window on the gate too.
"""

from __future__ import annotations

import os

import pytest

from sezam.vault import sync_client as sync_client_module
from sezam.vault.sync_client import SyncClient
from tests.test_grant_folder_access import team  # noqa: F401  (fixture)
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    server,
)
from tests.test_key_material_needs_password import _thief, _user


def test_locked_name_gets_one_checked_proof_per_window_on_the_gate(
    team, tmp_path, monkeypatch  # noqa: F811
):
    url, db, admin, _, _, _ = team
    admin_id = admin.db.get_meta("user_id")
    thief = _thief(admin, tmp_path)
    try:
        thief.change_password(PASSWORD, "thief-password!")
        monkeypatch.setattr(
            sync_client_module, "open_current_auth_proof",
            lambda *a: bytearray(os.urandom(32)), raising=False,
        )
        client = SyncClient(thief.db, url, thief.keypair, admin_id)
        client.set_dek_manager(thief.dek_mgr)
        _user(db, admin_id)["recovery_attempts"] = 19  # recovery_max_total=20
        with pytest.raises(RuntimeError, match="423"):
            client.push()  # the guess that locks the name is checked ...
        attempts = _user(db, admin_id)["recovery_attempts"]
        for _ in range(3):  # ... the next ones in the window are not
            with pytest.raises(RuntimeError, match="429"):
                client.push()
        assert _user(db, admin_id)["recovery_attempts"] == attempts

        for slot in db._storage.get("recovery_probe_slots", []):
            slot["probe_at"] -= 300_001  # the window passes
        with pytest.raises(RuntimeError, match="423"):
            client.push()  # one more checked guess
        with pytest.raises(RuntimeError, match="429"):
            client.push()
    finally:
        thief.lock()

