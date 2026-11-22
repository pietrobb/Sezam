"""INV-3 (docs/ROOT_CAUSE_PLAN.md: the server may withhold, not forge) for
the unsigned gc_floor_seq.

A device that deleted an entry holds its tombstone. The shared core's
against_held (core/src/pull.rs) let any pulled copy replace a tombstone at or
below the GC floor the server states, so a server that kept the entry's old,
validly signed version served it again with a floor above the tombstone (or
after really collecting it) and the deleted password was back on the device.
SM8 and SM21 need a copy over a collected tombstone to come in; those are
writes at the tombstone's version, which a device cannot tell from a
concurrent write and which the server orders anyway. An older version is a
replay whatever the floor says.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _live_entries(vault) -> dict[str, dict]:
    root = vault.db.get_meta("root_node_id")
    return {e["id"]: e for e in vault.list_entries(root)}


def _capture(client, object_id: str) -> dict:
    """The entry as the server serves it to a device pulling from scratch."""
    reply = client._fetch_pull_pages(0, check=(0, None))
    return next(copy.deepcopy(o) for o in reply["objects"] if o["id"] == object_id)


def _serve_again(client, old: dict, floor_lie: bool):
    real = client._request

    def request(m, path, *args, **kwargs):
        reply = real(m, path, *args, **kwargs)
        if m == "GET" and path.startswith("/api/sync") and isinstance(reply, dict) \
                and not reply.get("has_more"):
            # Served as a new commit, so the checkpoint sees a later state.
            reply = copy.deepcopy(reply)
            seq = max(reply.get("max_commit_seq") or 0, reply.get("head_commit_seq") or 0) + 1
            reply["objects"] = [*(reply.get("objects") or []), {**copy.deepcopy(old), "commit_seq": seq}]
            reply["max_commit_seq"] = reply["head_commit_seq"] = seq
            if floor_lie:
                reply["gc_floor_seq"] = seq - 1
        return reply

    client._request = request


@pytest.mark.parametrize("collected", [False, True], ids=["floor lie", "really collected"])
def test_an_old_version_never_replaces_a_held_tombstone(server, tmp_path, collected):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    entry = laptop.create_entry(
        laptop.db.get_meta("root_node_id"), "E", [{"key": "password", "value": "old secret", "sensitive": True}]
    )
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    laptop_client = _client(laptop, url)
    old = _capture(_client(phone, url), entry)
    assert old["version"] == 1 and not old["is_deleted"]

    laptop.delete_entry(entry)
    assert laptop_client.push()["accepted"]
    laptop_client.pull()
    assert entry not in _live_entries(laptop)
    if collected:
        _gc(db)

    _serve_again(laptop_client, old, floor_lie=not collected)
    assert laptop_client.pull().get("rollback_warning") is None
    assert entry not in _live_entries(laptop), "a replayed old version brought a deleted entry back"
    laptop.lock()
    phone.lock()
