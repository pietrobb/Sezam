"""Stateful test finding SM42: an object kept by a full resync overwrote a newer copy.

The phone deleted an entry and restored it from the trash without syncing;
the server collected the tombstone. The phone's full resync kept its restored
copy (the server had none) and forgot what it was built on. The laptop, which
had edited the entry meanwhile, then sent it, and the server took it as a new
object. The phone's push, sent without a base, replaced the laptop's edit
without a conflict. A copy kept over a server that has none now builds on
"no copy" (base version 0), so such a push is a conflict.
"""

from __future__ import annotations

from sezam.vault import trash
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def test_copy_kept_over_a_collected_tombstone_does_not_overwrite_a_newer_one(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    entry = laptop.create_entry(_folder(laptop), "vpn", [{"key": "password", "value": "v1"}])
    laptop_client.push()
    phone_client.pull()

    phone.delete_entry(entry)
    phone_client.push()
    laptop.update_entry(entry, fields=[{"key": "password", "value": "laptop-edit"}])
    trash.restore_entry(phone, entry)
    _gc(db)
    assert phone_client.full_resync(confirmed=True)["full_resync"]

    laptop_client.push()
    result = phone_client.push()
    assert entry in {c["id"] for c in result["conflicts"]}, result
    server_copy = next(o for o in db._storage["vault_objects"] if o["id"] == entry)
    assert not server_copy["is_deleted"]
    laptop_client.full_resync(confirmed=True)
    assert "laptop-edit" in str(laptop.read_entry(entry))
    laptop.lock()
    phone.lock()
