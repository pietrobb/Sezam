"""Stateful test finding SM78: 'sezam abandon-rekey' after the batch had landed.

The re-key batch reached the server and its reply was lost, so it stayed
pending here, and the user dropped it. The drop sealed the folder's items back
under the old key at the version the batch had sent. The server already held
that version (under the new key), so the item was refused as a conflict on
every push and never synced; nothing showed a conflict to resolve either. The
re-sealed copy now goes out one version above.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault.rekey_abandon import abandon_pending_rekey
from tests.test_integration_client_server import _client, server  # noqa: F401  (fixture)
from tests.test_rekey_rebase_review8 import _folder_shared_with_member
from tests.test_sync_state_machine import _fail_once


def _dirty(vault) -> list[str]:
    return [
        row["id"] for row in vault.db.fetchall(
            "SELECT id FROM entries WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write') UNION ALL SELECT id FROM nodes WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')"
        )
    ]


def test_dropping_a_rekey_that_had_landed_still_syncs(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, _old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    client = _client(laptop, url)
    assert laptop.rekey_after_revocation(member_id) == 1
    undo = _fail_once(client, "POST", "/api/sync", "after")
    try:
        client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(laptop.db) or None)

    abandon_pending_rekey(client)
    for _ in range(3):
        client.push()
        client.pull()
    assert _dirty(laptop) == []

    phone_client = _client(phone, url)
    phone_client.pull()
    assert phone.read_entry(entry)["name"] == laptop.read_entry(entry)["name"]
    assert [e["id"] for e in phone.list_entries(folder)] == [entry]
    laptop.lock()
    phone.lock()
