"""Deep stateful run on 6d4aa8a, finding R16-Z SM18: a revived folder reused a version sent.

The laptop renamed a folder and queued an entry in it; the phone deleted the
folder and tombstone GC collected the delete. The laptop's push was refused
on the collected copy, rebuilt one version above it and sent again; the
server took it, but the reply was lost. The conflict the laptop's pull had
recorded with the phone's delete stayed. Settled with the server's copy, the
folder was deleted again, and the queued entry brought it back one version
above that delete: the version the laptop had sent already, with another
content. The server's copy no longer read as the laptop's own write; the
folder was refused on every push, and no conflict was left to settle it.

A sent version is never reused: the folder comes back above every version
this device sent (as _rebase_local does, SM22).
"""

from __future__ import annotations

import asyncio

from sezam import cli
from server.app.main import _cleanup_tombstones
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_sync_state_machine import Injected


def _lose_reply_of_call(client, n: int):
    """The reply to the n-th POST /api/sync is lost (the server took it)."""
    real = client._request
    calls = {"n": 0}

    def request(m, path, *args, **kwargs):
        if m == "POST" and path.startswith("/api/sync"):
            calls["n"] += 1
            if calls["n"] == n:
                real(m, path, *args, **kwargs)
                raise Injected("reply lost (injected)")
        return real(m, path, *args, **kwargs)

    client._request = request
    return lambda: setattr(client, "_request", real)


def test_revived_folder_goes_above_the_version_whose_reply_was_lost(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F1")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)

    laptop.rename_node(folder, "laptop-name")
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "pw", "sensitive": False}])
    phone.delete_node(folder)
    assert not phone_client.push()["conflicts"]
    laptop_client.pull()
    assert folder in {c["id"] for c in laptop_client.get_pull_conflicts()}

    for obj in db._storage["vault_objects"]:
        if obj.get("is_deleted"):
            obj["modified_at"] = 0
    asyncio.run(_cleanup_tombstones(db, 0))

    # Refused on the collected delete, rebuilt above it, sent again: the
    # server takes it and the reply is lost.
    undo = _lose_reply_of_call(laptop_client, 2)
    try:
        laptop_client.push()
    except Injected:
        pass
    finally:
        undo()
    taken = next(o for o in db._storage["vault_objects"] if o["id"] == folder)
    assert not taken["is_deleted"]

    laptop_client.resolve_conflict(folder, "server")
    for _ in range(3):
        laptop_client.push()
        laptop_client.pull()
    queued = laptop.db.fetchone("SELECT COUNT(*) AS n FROM outbox WHERE kind = 'write'")["n"]
    assert queued == 0 and not laptop_client.get_pull_conflicts(), (
        queued, laptop_client.get_pull_conflicts()
    )
    server_folder = next(o for o in db._storage["vault_objects"] if o["id"] == folder)
    assert not server_folder["is_deleted"]
    assert any(o["id"] == entry and not o["is_deleted"] for o in db._storage["vault_objects"])
    laptop.lock()
    phone.lock()
