"""Review a159e97 (desktop sync, state machine): two devices of one account
re-keyed the same folder.

Both archives wrap the folder's old key, each under its own new key. Which
one successor_of() named was the first archive row in table order, i.e. the
order the device pulled them in: devices disagreed, and a member's grant
made again on a successor (_grant_again_on_successors) could land on the key
no folder uses, cutting the member off. The successor whose chain reaches the
key the folder uses now wins, whatever the order.
"""

from __future__ import annotations

import pytest

from tests.test_integration_client_server import _vault


@pytest.mark.parametrize("current", ["first", "second"])
def test_the_successor_is_the_key_the_folder_uses_whatever_the_archive_order(tmp_path, current):
    vault = _vault(tmp_path / "v", "admin")
    folder = vault.create_node("Ops")
    mgr = vault._dek_mgr
    old = vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    first, _ = mgr.rekey_folder(old, folder)
    second, _ = mgr.rekey_folder(old, folder)
    used, dead = (first, second) if current == "first" else (second, first)
    vault.db.execute("UPDATE deks SET node_id = NULL WHERE id = ?", (dead,))
    vault.db.execute("UPDATE nodes SET dek_id = ? WHERE id = ?", (used, folder))

    # On 2860952 the first archive row won: 'second' named the dead key.
    assert mgr.successor_of(old) == used

    # A dead key re-keyed on still leads to the folder's key: that chain wins.
    later, _ = mgr.rekey_folder(used, folder)
    vault.db.execute("UPDATE deks SET node_id = NULL WHERE id = ?", (used,))
    vault.db.execute("UPDATE nodes SET dek_id = ? WHERE id = ?", (later, folder))
    assert mgr.successor_of(old) == used
    vault.lock()
