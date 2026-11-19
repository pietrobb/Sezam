"""Stateful test finding SM85: a queued re-key pushed to a server restored from a backup.

A member was revoked and the folder re-keyed on top of copies the restored
server no longer holds. 'sezam push' sends the queued re-key first; the server
refused it (history changed, or an atomic batch conflict whose pull saw the
restore) and the push reported the rollback, but the queue raised 'The re-key
batch was not accepted' instead, on every sync, so the full resync the
warning names was never offered. The batch now waits for that resync, and the
named way out (drop the re-key, full resync, push) cuts the member off.
"""

from __future__ import annotations

import copy

from sezam.vault import pending_states, revocation
from sezam.vault.rekey_abandon import abandon_pending_rekey
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member
from tests.test_rollback_commit_token_sm7 import _restore


def test_queued_rekey_after_a_restore_waits_for_the_full_resync(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    client = _client(laptop, url)
    backup = copy.deepcopy(db._storage)
    laptop.update_entry(entry, fields=[{"key": "password", "value": "v2", "sensitive": True}])
    assert client.push()["conflicts"] == []

    assert laptop.rekey_after_revocation(member_id) == 1
    pending_states.set_revocation_queue(laptop.db, [member_id])
    _restore(db, backup)

    result = revocation.push_with_queued_revocations(laptop, client)
    assert result.get("rollback_warning")
    assert pending_states.rekey_batch(laptop.db)
    assert member_id in revocation.queued_revocations(laptop)

    abandon_pending_rekey(client)
    client.full_resync(confirmed=True)
    result = revocation.push_with_queued_revocations(laptop, client)
    assert result["rekeyed"] == {member_id: 1}
    _assert_member_cut_off(db, laptop, folder, old_dek, member_id)
    laptop.lock()
    phone.lock()
