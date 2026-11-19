"""Stateful test finding SM76: a Shamir recovery dropped a re-key that had landed.

The laptop re-keyed a folder after removing a member; the batch reached the
server but its reply was lost, and no pull followed. A Shamir recovery then
dropped the pending re-key (review 526419e V4). The drop sealed the folder's
items back under the old key at the version the batch had sent, which the
server already held under the new key, so one item was refused as a conflict
on every push and the device never settled. Fixed together with SM78
(c825b47): the re-sealed copy goes out one version above.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault.crud import Vault
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_rekey_rebase_review8 import _folder_shared_with_member
from tests.test_review6_abandon_landed_rekey_sm78 import _dirty
from tests.test_sync_state_machine import _fail_once

NEW = "a-new-password-1!"


def test_shamir_recovery_after_a_landed_rekey_without_a_pull_settles(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, _old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    shares = laptop.setup_org_recovery(threshold=2, shares=3)
    client = _client(laptop, url)
    client.store_org_recovery(
        pending_states.org_recovery_registration(laptop.db), laptop.current_auth_proof(PASSWORD)
    )
    assert laptop.rekey_after_revocation(member_id) == 1
    undo = _fail_once(client, "POST", "/api/sync", "after")
    try:
        client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(laptop.db) or None)
    laptop.lock()

    recovered = Vault(tmp_path / "laptop")
    recovered.org_recovery(shares[:2], NEW)
    recovered.lock()
    recovered.unlock(NEW)
    try:
        client = _client(recovered, url)
        # In SM76 a tombstone GC had passed the device's checkpoint, so the
        # next sync was a full resync, which keeps the dirty copy as it is.
        client.full_resync(confirmed=True)
        for _ in range(3):
            pushed = client.push()
            client.pull()
        assert pushed["conflicts"] == []
        assert _dirty(recovered) == []
        assert not (pending_states.rekey_batch(recovered.db) or None)
        local = recovered.db.fetchone("SELECT version FROM entries WHERE id = ?", (entry,))["version"]
        on_server = next(o for o in db._storage["vault_objects"] if o["id"] == entry)
        assert on_server["version"] == local
        assert [e["id"] for e in recovered.list_entries(folder)] == [entry]
    finally:
        recovered.lock()
        phone.lock()
