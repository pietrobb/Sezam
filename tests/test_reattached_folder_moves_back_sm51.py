"""Stateful test finding SM51: a copy shown below the root went out as another write.

The phone deleted subfolder S of F while the laptop deleted F; tombstone GC
then collected both. The phone sent its S tombstone again, below F the server
no longer had, and the laptop pulled it with F gone and showed it below the
root - a local move at the same version. After a restore from a backup both
full resyncs kept S (newer than the server's) and the laptop sent its copy
first, with the root as parent. The server then refused the phone's own write
at that version on every push, and the phone took it for its own (the blob
hash is the same) and sent it again: the sync never settled. Once F is back,
S moves back below it while its version is unchanged. Since S1 the phone's
tombstone over the collected identical one is done at the collected version.
"""

from __future__ import annotations

import copy

from sezam import cli
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _restore, sees_rollback
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _dirty(vault) -> list[str]:
    return [r["id"] for t in ("nodes", "entries")
            for r in vault.db.fetchall(f"SELECT id FROM {t} WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")]


def test_folder_shown_below_the_root_goes_out_below_its_own_folder(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    sub = laptop.create_node("S", parent_id=folder)
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    backup = copy.deepcopy(db._storage)

    phone.delete_node(sub)
    laptop.delete_node(folder)
    laptop_client.push()
    _gc(db)
    laptop_client.full_resync(confirmed=True)
    phone_client.push()
    laptop_client.pull()
    # Since S1 the server takes no write at a collected version: the phone's
    # tombstone is the collected one (same blob), so it is done, not resent,
    # and the laptop never sees S below the root.
    assert not _dirty(phone)
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (sub,)) is None

    _restore(db, backup)
    for client in (laptop_client, phone_client):
        assert sees_rollback(client)
        client.full_resync(confirmed=True)
    for _ in range(3):
        for client in (laptop_client, phone_client):
            client.push()
            client.pull()
    assert not _dirty(laptop) and not _dirty(phone)
    assert laptop.db.fetchone("SELECT parent_id FROM nodes WHERE id = ?", (sub,))["parent_id"] == folder
    laptop.lock()
    phone.lock()
