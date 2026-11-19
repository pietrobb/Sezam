"""Review main@a159e97 (state machine, desktop sync): 410 for good after a full snapshot.

When the newest commits on the server were tombstones its GC collected, a
snapshot (full resync, or a new device's first pull) ends below the GC floor:
its max_commit_seq is the newest object left. The device saved that as its
checkpoint, and every delta pull from there was refused with 410 (data too
old, full resync required) - the full resync it asked for ended the same way.
The checkpoint after a complete snapshot is now at least the GC floor.
"""

from __future__ import annotations

from sezam import cli
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _newest_commits_collected(url, tmp_path, db):
    laptop = _vault(tmp_path / "laptop", "admin")
    keep = laptop.create_node("Keep")
    laptop.create_entry(keep, "web", [{"key": "password", "value": "w", "sensitive": True}])
    gone = laptop.create_node("Gone")
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.delete_node(gone)
    assert _client(laptop, url).push()["accepted"]
    _gc(db)
    # The newest commits were tombstones as well (another device's deletes,
    # their audit records sent before them), collected with the floor past them.
    counter = db._storage["commit_counter"][0]
    counter["gc_floor_seq"] = counter["next_seq"] + 2
    counter["next_seq"] += 3
    newest = max(o["commit_seq"] for o in db._storage["vault_objects"] if o["object_type"] != "key_archive")
    assert counter["gc_floor_seq"] > newest
    return laptop


def test_pulls_after_a_full_resync_below_the_gc_floor(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _newest_commits_collected(url, tmp_path, db)
    client = _client(laptop, url)
    assert client.full_resync(confirmed=True)["full_resync"]
    assert int(laptop.db.get_meta("last_known_commit_seq")) >= db._storage["commit_counter"][0]["gc_floor_seq"]
    assert "rollback_warning" not in client.pull()
    laptop.lock()


def test_pulls_of_a_new_device_whose_first_pull_ends_below_the_gc_floor(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _newest_commits_collected(url, tmp_path, db)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    _client(phone, url).pull()
    laptop.create_node("After")
    assert _client(laptop, url).push()["accepted"]
    assert _client(phone, url).pull()["pulled"] >= 1
    assert any(n["name"] == "After" for n in phone.list_nodes())
    laptop.lock()
    phone.lock()
