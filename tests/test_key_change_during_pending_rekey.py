"""Review 526419e V4: a password change made while a member re-key was pending.

change_password checked for a pending re-key only when rotating the identity,
org_recovery not at all. The next push sent both in one batch and the server
refused it with 409 on every sync; the re-key rebase was skipped. The way out
('sezam abandon-pending-change') dropped the new password - and after a Shamir
recovery it needs the forgotten one: locked out for good. Now the password
change waits for the re-key, a Shamir recovery drops the re-key and queues the
member, and a re-key waits for an unsent password change.
"""

from __future__ import annotations

import pytest

from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.crud import Vault
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member

NEW = "a-new-password-1!"


def test_password_change_waits_for_the_pending_rekey(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    assert laptop.rekey_after_revocation(member_id) == 1

    with pytest.raises(ValueError, match="abandon-rekey"):
        laptop.change_password(PASSWORD, NEW)

    client = _client(laptop, url)
    assert client.push()["conflicts"] == []
    _assert_member_cut_off(db, laptop, folder, old_dek, member_id)
    laptop.change_password(PASSWORD, NEW)
    assert client.push()["conflicts"] == []
    assert laptop.db.get_meta("last_pushed_key_epoch") == laptop.db.get_meta("key_epoch")
    laptop.lock()
    phone.lock()


def test_rekey_waits_for_an_unsent_password_change(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    laptop.change_password(PASSWORD, NEW)

    with pytest.raises(RuntimeError, match="password change has not reached"):
        laptop.rekey_after_revocation(member_id)
    client = _client(laptop, url)
    # (The member exists only as an envelope here, so no server revocation.)
    with pytest.raises(revocation.RekeyPending, match="password change"):
        revocation.revoke_member(laptop, None, member_id)
    assert revocation.queued_revocations(laptop) == [member_id]

    # What 'sezam push' does: the password change lands, then the re-key.
    assert client.push()["conflicts"] == []
    assert revocation.finish_queued_revocations(laptop, client) == {member_id: 1}
    _assert_member_cut_off(db, laptop, folder, old_dek, member_id)
    assert revocation.queued_revocations(laptop) == []
    laptop.lock()
    phone.lock()


def test_shamir_recovery_with_a_pending_rekey_still_syncs(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    shares = laptop.setup_org_recovery(threshold=2, shares=3)
    _client(laptop, url).store_org_recovery(
        pending_states.org_recovery_registration(laptop.db), laptop.current_auth_proof(PASSWORD)
    )
    assert laptop.rekey_after_revocation(member_id) == 1
    laptop.lock()

    recovered = Vault(tmp_path / "laptop")
    recovered.org_recovery(shares[:2], NEW)
    recovered.lock()
    recovered.unlock(NEW)
    try:
        client = _client(recovered, url)
        assert client.push()["conflicts"] == []
        assert (pending_states.key_change_journal(recovered.db) or None) is None
        # The dropped re-key is queued and made afresh under the new password.
        assert revocation.queued_revocations(recovered) == [member_id]
        assert revocation.finish_queued_revocations(recovered, client) == {member_id: 1}
        _assert_member_cut_off(db, recovered, folder, old_dek, member_id)
    finally:
        recovered.lock()
        phone.lock()
