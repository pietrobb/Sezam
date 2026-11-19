"""Stateful test finding SM66: a password change pushed after a restore hid it.

The laptop renamed a folder and pushed it; its password change then failed to
go out, and the server was restored from a backup taken before the rename. A
pending change blocks the full resync, so its push goes out without the
rollback check (SM39). That push moved the laptop's commit anchor onto the
restored server's history, the pull after it saw no restore, and the rename
the server lost never went out again: the phone's later rename replaced it
without a conflict. The push now reports the rollback once the change landed,
and the full resync then sends the rename again.
"""

from __future__ import annotations

import copy

from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices
from tests.test_sync_state_machine import _fail_once

NEW_PASSWORD = "laptop-pw-sm66!"


def test_key_change_after_a_restore_still_resends_what_the_server_lost(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop_client.push()
    phone_client.pull()
    backup = copy.deepcopy(db._storage)

    laptop.rename_node(folder, "renamed")
    laptop_client.push()
    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop_client = _client(laptop, url)
    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        laptop_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert laptop_client.has_pending_key_change()

    _restore(db, backup)
    result = laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    assert result.get("rollback_warning")

    laptop_client.full_resync(confirmed=True)
    assert not laptop_client.push()["conflicts"]
    phone_client.adopt_rotated_key_material(phone, NEW_PASSWORD)
    phone_client = _client(phone, url)
    phone_client.pull()
    assert {n["id"]: n["name"] for n in phone.list_nodes()}[folder] == "renamed"
    laptop.lock()
    phone.lock()
