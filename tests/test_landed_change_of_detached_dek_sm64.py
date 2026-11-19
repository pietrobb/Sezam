"""Stateful test finding SM64: a landed key change resends a detached DEK as it is.

The laptop deleted a folder and changed its password; the server took the
change, but the reply never came. The server then collected the folder's
tombstone, and the laptop's full resync kept the folder's DEK unbound (the
server still names the folder as its parent_ref, SM59). Resending the change,
the laptop built that DEK with no parent_ref: no identical retry, so the
server refused the whole atomic batch on every sync. The DEK now goes out
under the folder it remembers.
"""

from __future__ import annotations

from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once
from tests.test_tombstone_gc_orphans_r5k1 import _gc

NEW_PASSWORD = "pw-2-Sezam!-landed"


def test_landed_change_resends_a_detached_dek_under_its_folder(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "old", [{"key": "k", "value": "v"}])
    laptop_client.push()
    dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    laptop.delete_node(folder)
    laptop_client.push()

    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop_client = _client(laptop, url)
    undo = _fail_once(laptop_client, "POST", "/api/sync", "after")
    try:
        laptop_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert laptop_client.has_pending_key_change()

    _gc(db)
    assert laptop_client.full_resync(confirmed=True)["full_resync"]
    assert laptop.db.fetchone("SELECT node_id FROM deks WHERE id = ?", (dek,))["node_id"] is None

    laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    server_dek = next(o for o in db._storage["vault_objects"] if o["id"] == dek)
    assert server_dek["parent_ref"] == folder
    laptop.lock()
    phone.lock()
