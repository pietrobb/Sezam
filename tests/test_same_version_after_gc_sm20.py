"""Stateful test finding SM20: two writes under one version after tombstone GC.

The laptop renamed a folder offline. The phone deleted it (version 2) and
pushed, then restored and renamed it, still offline. Tombstone GC collected
the delete, so the laptop's rename came back as a new object - also at
version 2 - and the server compared the phone's base only by number.

docs/SYNC_SINGLE_SOURCE.md point 1: GC keeps the collected copy's (version,
hash). The laptop's rename was made on version 1, not on the delete: it is a
conflict naming the delete. The phone's change builds on its own delete and
is taken at a higher version; (id, 2) never names two contents.
"""

from __future__ import annotations

import asyncio

from sezam import cli
from sezam.vault import trash
from server.app.main import _cleanup_tombstones
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


def test_rename_on_an_old_copy_conflicts_with_the_collected_delete(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F1")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    laptop.rename_node(folder, "laptop-name")
    phone.delete_node(folder)
    phone_client = _client(phone, url)
    assert not phone_client.push()["conflicts"]
    deleted = next(o for o in db._storage["vault_objects"] if o["id"] == folder)
    trash.restore_node(phone, folder)
    phone.rename_node(folder, "phone-name")

    for obj in db._storage["vault_objects"]:
        if obj.get("is_deleted"):
            obj["modified_at"] = 0
    asyncio.run(_cleanup_tombstones(db, 0))
    assert all(o["id"] != folder for o in db._storage["vault_objects"])

    # The server refuses the rename as built on version 1 (code
    # collected_object); with no copy left to choose, the laptop rebuilds it on
    # the collected delete and it comes back above that version.
    result = _client(laptop, url).push()
    assert folder not in {c["id"] for c in result["conflicts"]}, result
    revived = next(o for o in db._storage["vault_objects"] if o["id"] == folder)
    assert revived["version"] > deleted["version"] and not revived["is_deleted"]
    assert all(o["id"] != folder for o in db._storage["collected_objects"])

    # The phone built on its own delete, which the laptop's write now
    # supersedes: a conflict naming the laptop's copy, never a second
    # content under one version.
    conflict = next(c for c in phone_client.push()["conflicts"] if c["id"] == folder)
    assert (conflict["server_version"], conflict["server_payload_hash"]) == (
        revived["version"], revived["payload_hash"]
    )
    laptop.lock()
    phone.lock()
