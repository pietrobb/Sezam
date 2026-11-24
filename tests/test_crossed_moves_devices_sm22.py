"""R16-Z SM22 (gate 16, team_log) on two devices: crossed folder moves.

The laptop moved X below Y and pushed; the phone, not having pulled that,
moved Y below X. The server took both, every device then held X and Y as each
other's parent, and unlock (search index: every entry's folder path) walked
that cycle forever. Now the server refuses the second move
(tests/test_crossed_moves_sm22.py) and names where it keeps the folder; the
phone puts the folder back there and sends that, so both devices end on the
server's tree with nothing waiting, and open again.
"""

from __future__ import annotations

import threading

import pytest

from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _parents(vault) -> dict[str, str]:
    return {r["id"]: r["parent_id"] for r in vault.db.fetchall("SELECT id, parent_id FROM nodes")}


def _opens(vault) -> None:
    """lock + unlock ends (on a parent cycle it never did)."""
    vault.lock()
    done = threading.Event()
    failure = []

    def unlock():
        try:
            vault.unlock(PASSWORD)
        except Exception as exc:  # noqa: BLE001
            failure.append(exc)
        done.set()

    threading.Thread(target=unlock, daemon=True).start()
    assert done.wait(60), "unlock did not end"
    assert not failure, failure


@pytest.mark.parametrize("phone_pulls_first", [False, True])
def test_crossed_moves_end_on_the_servers_tree(server, tmp_path, phone_pulls_first):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    top = _folder(laptop)
    x = laptop.create_node("X", top)
    y = laptop.create_node("Y", top)
    laptop.create_entry(x, "in-x", [{"key": "password", "value": "x", "sensitive": True}])
    laptop.create_entry(y, "in-y", [{"key": "password", "value": "y", "sensitive": True}])
    laptop_client.push()
    phone_client = _client(phone, url)
    phone_client.pull()

    laptop.move_node(x, y)
    laptop_client.push()
    phone.move_node(y, x)
    if phone_pulls_first:
        # The pulled move closes a cycle with the unsent one until it is refused.
        phone_client.pull()
        _opens(phone)
        phone_client = _client(phone, url)
    for _ in range(2):
        phone_client.push()
        phone_client.pull()
    laptop_client.pull()

    for vault in (laptop, phone):
        assert _parents(vault)[x] == y and _parents(vault)[y] == top
    assert phone_client.dirty_object_count() == 0
    assert not phone_client.get_pull_conflicts()
    for vault in (laptop, phone):
        _opens(vault)
        names = {e["name"] for e in vault.list_entries(x)} | {e["name"] for e in vault.list_entries(y)}
        assert names == {"in-x", "in-y"}
    laptop.lock()
    phone.lock()
