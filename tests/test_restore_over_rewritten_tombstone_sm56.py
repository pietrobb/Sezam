"""Stateful test finding SM56: a restore built on a tombstone GC let be rewritten.

The laptop deleted folder F and pushed; the phone renamed F before it pulled
the delete. Tombstone GC collected F, and the laptop restored it from the
trash, a write on top of the tombstone (version 2). The phone's rename then
went out as F version 2 (the server no longer had F), another copy at the
tombstone's version. The server refused the laptop's restore against it, and
the laptop's pull skipped that copy as one its edit already builds on (same
version), so the restore stayed unsent on every round without a conflict.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import trash
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _dirty(vault) -> list[str]:
    return [r["id"] for t in ("nodes", "entries")
            for r in vault.db.fetchall(f"SELECT id FROM {t} WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")]


def test_restore_over_a_rewritten_tombstone_conflicts(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)

    laptop.delete_node(folder)
    laptop_client.push()
    laptop_client.pull()
    phone.rename_node(folder, "Renamed")
    _gc(db)
    trash.restore_node(laptop, folder)
    phone_client.push()

    for _ in range(3):
        laptop_client.push()
        laptop_client.pull()
    conflicts = [c["id"] for c in laptop_client.get_pull_conflicts()]
    assert folder in conflicts or not _dirty(laptop), (
        "the laptop's restore stays unsent without a conflict"
    )
    laptop.lock()
    phone.lock()
