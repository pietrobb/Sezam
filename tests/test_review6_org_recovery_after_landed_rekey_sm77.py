"""Stateful test finding SM77: a Shamir recovery dropped a re-key the server held.

The laptop re-keyed a folder after removing a member; the batch landed but its
reply was lost, so it stayed pending, and a pull brought the batch's new folder
key back. A Shamir recovery then dropped the pending re-key as never sent
(review 526419e V4) and deleted that key here. The server still held it, so the
recovery's password change - which must re-wrap every key the server holds -
was refused on every sync, and the only way out named needs the forgotten
password. A re-key whose new key a pull brought back is closed as sent instead.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.crud import Vault
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member
from tests.test_sync_state_machine import _fail_once

NEW = "a-new-password-1!"


def test_shamir_recovery_after_a_rekey_whose_reply_was_lost(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
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
    client.pull()
    laptop.lock()

    recovered = Vault(tmp_path / "laptop")
    recovered.org_recovery(shares[:2], NEW)
    recovered.lock()
    recovered.unlock(NEW)
    try:
        client = _client(recovered, url)
        assert client.push()["conflicts"] == []
        assert recovered.db.get_meta("last_pushed_key_epoch") == recovered.db.get_meta("key_epoch")
        assert not (pending_states.rekey_batch(recovered.db) or None)
        assert revocation.queued_revocations(recovered) == []
        _assert_member_cut_off(db, recovered, folder, old_dek, member_id)
    finally:
        recovered.lock()
        phone.lock()
