"""R16-Z SM16: two devices of one admin re-key a folder, GC collects its items.

The phone re-keyed the folder after the revocation, deleted it and pushed; GC
collected the folder and its item. The laptop's own re-key of the same folder
then built on the collected copies and landed as well: two live keys of one
folder, and the devices kept different ones (a member granted one of them
could not read what was sealed under the other).
"""

from __future__ import annotations

from sezam.vault import pending_states
from tests.test_integration_client_server import (
    _client,
    _gc_tombstones,
    server,  # noqa: F401  (fixture)
)
from tests.test_rekey_rebase_review8 import _folder_shared_with_member


def _live_folder_keys(db, folder):
    return sorted(
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "dek" and not o["is_deleted"] and o.get("parent_ref") == folder
    )


def test_a_sibling_rekey_on_a_collected_folder_does_not_land(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)

    assert phone.rekey_after_revocation(member_id) == 1
    assert laptop.rekey_after_revocation(member_id) == 1
    phone.delete_node(folder)
    assert _client(phone, url).push()["conflicts"] == []
    phone_key = phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert phone_key != old_dek_id
    _gc_tombstones(db)

    # Refused as a sibling (folder_key_moved); the pull drops the laptop's
    # superseded batch. The laptop never saw the deletion (its tombstone was
    # collected): its item comes back refused, with the way out named.
    conflicts = _client(laptop, url).push()["conflicts"]
    assert [(c["id"], c["error"]) for c in conflicts] == [(
        entry, "parent folder is deleted or missing; restore the folder or move the item",
    )]
    assert pending_states.rekey_batch(laptop.db) == {}
    # The old key stays (archived wraps); one new key only, the phone's.
    new_keys = [k for k in _live_folder_keys(db, folder) if k != old_dek_id]
    assert new_keys == [phone_key], new_keys
    laptop.lock()
    phone.lock()
