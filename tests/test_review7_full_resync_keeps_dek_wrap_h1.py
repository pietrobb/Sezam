"""Review 7c10379 H1: a full resync took an old DEK wrap the server sent back.

The full resync set every local DEK to version 0, so any server copy of a
DEK replaced the local wrap. A server that kept the wraps from before a
password change (under the old KEK, at the old version, signed back then)
sent them in the snapshot - after a fake rollback or a 410 that made the
device run the full resync - and the device took them: the vault no longer
opened, neither with the current password nor with the old one. A DEK
version never goes down, and a wrap this device's KEK opens is never
replaced by one it does not open; the server gets the device's copy back.
"""

from __future__ import annotations

import copy

import pytest

from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,  # noqa: F401  (fixture)
)
from sezam import cli

NEW_PASSWORD = "laptop-pw-r7h1!"


def _dek_objects(db):
    return [o for o in db._storage["vault_objects"] if o["object_type"] == "dek"]


@pytest.mark.parametrize("withhold", [False, True])
def test_full_resync_never_takes_an_older_wrap_of_an_own_dek(server, tmp_path, withhold):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Ops")
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "v1", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    client = _client(laptop, url)
    old_wraps = {o["id"]: copy.deepcopy(o) for o in _dek_objects(db)}
    assert old_wraps

    client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    client = _client(laptop, url)
    assert client.push()["conflicts"] == []
    assert not client.has_pending_key_change()

    # The server goes back to the wraps from before the password change
    # (or leaves the DEKs out) and the device runs a full resync.
    storage = db._storage["vault_objects"]
    for index, obj in enumerate(storage):
        if obj["id"] in old_wraps:
            storage[index] = copy.deepcopy(old_wraps[obj["id"]])
    if withhold:
        storage[:] = [o for o in storage if o["id"] not in old_wraps]
    client.full_resync(confirmed=True)

    laptop.lock()
    laptop.unlock(NEW_PASSWORD)
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v1"
    # The server gets the device's wraps back.
    assert _client(laptop, url).push()["conflicts"] == []
    held = {o["id"]: o for o in _dek_objects(db)}
    for dek_id, old in old_wraps.items():
        assert held[dek_id]["version"] > old["version"]
    laptop.lock()
