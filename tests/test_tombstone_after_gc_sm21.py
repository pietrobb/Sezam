"""Stateful test finding SM21: two tombstones under one version after tombstone GC.

The laptop renamed a folder and deleted it (version 3) and pushed. The phone,
offline, renamed it differently and deleted it too, also version 3. Tombstone
GC collected the laptop's delete, so the server took the phone's push as a new
object. The laptop pulled it, saw its own version 3 with another payload,
reported equivocation and kept its own copy. Now the server keeps the
collected tombstone's (version, hash) and the phone's push is a conflict.
"""

from __future__ import annotations

import asyncio
import hashlib

from sezam import cli
from server.app.main import _cleanup_tombstones
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


def _meta_hash(vault, node_id: str) -> str:
    row = vault.db.fetchone("SELECT encrypted_meta FROM nodes WHERE id = ?", (node_id,))
    return hashlib.sha256(bytes(row["encrypted_meta"])).hexdigest()


def test_tombstone_sent_after_gc_replaces_the_collected_one(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F1")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    laptop.rename_node(folder, "laptop-name")
    laptop.delete_node(folder)
    laptop_client = _client(laptop, url)
    assert not laptop_client.push()["conflicts"]
    phone.rename_node(folder, "phone-name")
    phone.delete_node(folder)

    for obj in db._storage["vault_objects"]:
        if obj.get("is_deleted"):
            obj["modified_at"] = 0
    asyncio.run(_cleanup_tombstones(db, 0))
    assert all(o["id"] != folder for o in db._storage["vault_objects"])

    # docs/SYNC_SINGLE_SOURCE.md point 1: GC kept the laptop's tombstone as
    # (version, hash). The phone's delete was made on version 1: refused as
    # collected_object, it is rebuilt on that tombstone and goes up above
    # version 3, so (id, 3) keeps naming the laptop's copy.
    laptop_version = laptop.db.fetchone(
        "SELECT version FROM nodes WHERE id = ?", (folder,)
    )["version"]
    collected = next(o for o in db._storage["collected_objects"] if o["id"] == folder)
    assert (collected["version"], collected["payload_hash"]) == (
        laptop_version, _meta_hash(laptop, folder)
    )
    result = _client(phone, url).push()
    assert folder not in {c["id"] for c in result["conflicts"]}, result
    after = next(o for o in db._storage["vault_objects"] if o["id"] == folder)
    assert after["version"] > laptop_version and after["is_deleted"]

    result = laptop_client.pull()
    assert not result.get("equivocations"), result
    laptop.lock()
    phone.lock()
