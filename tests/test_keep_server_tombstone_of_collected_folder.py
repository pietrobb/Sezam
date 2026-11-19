"""Nightly stateful run on c78fd19 (second admin): keeping a server delete crashed.

A moved an entry into a folder that B then deleted; the server collected the
folder's tombstone but still held the entry's tombstone below it. B, after a
full resync that no longer brings the folder, kept the server copy of its
conflict on that entry: the tombstone named a folder this vault does not have
and resolve_conflict failed on the foreign key (sqlite3.IntegrityError) every
time, so the conflict could not be settled. It now settles as a pull does: the
deleted entry hangs below the root until its folder comes back.
"""

from __future__ import annotations

import hashlib
import struct
import time

from ulid import ULID

from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_lost_update_base_version_sm1 import _two_devices


def test_keeping_a_delete_below_a_collected_folder_settles_the_conflict(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, _phone, entry_id = _two_devices(url, tmp_path)
    client = _client(laptop, url)
    row = laptop.db.fetchone(
        "SELECT version, encrypted_meta, encrypted_data FROM entries WHERE id = ?", (entry_id,)
    )
    meta, data = bytes(row["encrypted_meta"]), bytes(row["encrypted_data"])
    payload = struct.pack(">I", len(meta)) + meta + data
    gone = str(ULID())  # the folder the server collected
    laptop.db.execute(
        "INSERT INTO sync_conflicts (object_id, object_type, local_version, server_version, "
        "server_payload, server_parent_ref, server_is_deleted, server_payload_hash, detected_at) "
        "VALUES (?, 'entry', ?, ?, ?, ?, 1, ?, ?)",
        (entry_id, row["version"], row["version"] + 1, payload, gone,
         hashlib.sha256(payload).hexdigest(), int(time.time() * 1000)),
    )

    client.resolve_conflict(entry_id, "server")

    assert client.get_pull_conflicts() == []
    kept = laptop.db.fetchone(
        "SELECT node_id, version, is_deleted FROM entries WHERE id = ?", (entry_id,)
    )
    assert kept["is_deleted"] == 1 and kept["version"] == row["version"] + 1
    assert laptop.db.fetchone("SELECT 1 FROM nodes WHERE id = ?", (kept["node_id"],))
    client.pull()  # the vault stays consistent for the next sync
    laptop.lock()
