"""Review d150605 #2: something deleted while a member re-key was pending.

abandon_pending_rekey opened every blob it resealed at the row version. A
delete only bumps the row version and leaves the blobs sealed one version
below, so dropping the re-key died on CryptoError - and with it 'sezam
abandon-rekey' (the way out 'sezam status' offers) and a Shamir recovery
(which drops the re-key): the vault rolled back, the new password did not
open it and the old one was forgotten.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation, trash
from sezam.vault.crud import Vault
from sezam.vault.rekey_abandon import abandon_pending_rekey
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member

NEW = "a-new-password-1!"


def test_abandon_rekey_with_a_deleted_entry_and_folder(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    sub = laptop.create_node("Sub", parent_id=folder)
    assert _client(laptop, url).push()["conflicts"] == []
    assert laptop.rekey_after_revocation(member_id) == 1
    laptop.delete_entry(entry)
    laptop.delete_node(sub)

    client = _client(laptop, url)
    result = abandon_pending_rekey(client)
    assert result["requeued"]
    # The deletes stand and the deleted items still open (trash restore).
    names = {item["name"] for item in trash.list_trash(laptop)}
    assert "(unreadable here)" not in names
    trash.restore_entry(laptop, entry)
    assert client.push()["conflicts"] == []
    assert revocation.finish_queued_revocations(laptop, client) == {member_id: 1}
    _assert_member_cut_off(db, laptop, folder, old_dek, member_id)
    laptop.lock()
    phone.lock()


def test_shamir_recovery_with_a_delete_during_the_pending_rekey(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    shares = laptop.setup_org_recovery(threshold=2, shares=3)
    _client(laptop, url).store_org_recovery(
        pending_states.org_recovery_registration(laptop.db), laptop.current_auth_proof(PASSWORD)
    )
    assert laptop.rekey_after_revocation(member_id) == 1
    laptop.delete_entry(entry)
    laptop.lock()

    recovered = Vault(tmp_path / "laptop")
    recovered.org_recovery(shares[:2], NEW)
    recovered.lock()
    recovered.unlock(NEW)
    try:
        client = _client(recovered, url)
        assert client.push()["conflicts"] == []
        assert revocation.finish_queued_revocations(recovered, client) == {member_id: 1}
        _assert_member_cut_off(db, recovered, folder, old_dek, member_id)
    finally:
        recovered.lock()
        phone.lock()
