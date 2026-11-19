"""Stateful test finding SM53: a full resync dropped a delete that held an unsent edit.

The phone edited an entry and then deleted it, both offline. The laptop deleted
the same entry, pushed, and restored it from the trash; tombstone GC then
collected the server's tombstone. The phone's full resync took its delete for
moot (the server had the entry and no longer has it) and dropped the row with
the edit inside: the restore came back with the old content and the phone's
edit was gone everywhere, without a conflict. A delete more than one version
above its base holds such an edit; it is kept and meets the restore as a
conflict.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import trash
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _password_field(value: str) -> list[dict]:
    return [{"key": "password", "value": value, "sensitive": True}]


def test_full_resync_keeps_a_delete_over_an_unsent_edit(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    entry = laptop.create_entry(folder, "vpn", _password_field("old"))
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)

    phone.update_entry(entry, fields=_password_field("phone-edit"))
    phone.delete_entry(entry)
    laptop.delete_entry(entry)
    assert laptop_client.push()["conflicts"] == []
    trash.restore_entry(laptop, entry)
    _gc(db)
    assert entry not in {o["id"] for o in db._storage["vault_objects"]}

    assert phone_client.full_resync(confirmed=True)["full_resync"]
    assert phone.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry,)) is not None
    laptop_client.push()
    phone_client.push()
    phone_client.pull()
    laptop_client.pull()

    conflicts = {
        row["object_id"]
        for vault in (laptop, phone)
        for row in vault.db.fetchall("SELECT object_id FROM sync_conflicts")
    }
    assert entry in conflicts
    laptop.lock()
    phone.lock()
