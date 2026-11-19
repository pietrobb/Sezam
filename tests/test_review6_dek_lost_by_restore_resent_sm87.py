"""Stateful test finding SM87: a push past a restore sent items without the DEK they are sealed with.

The laptop re-keyed a shared folder after removing a member; the batch landed,
then the server was restored from a backup that predates it and lost the new
DEK. The laptop deleted an entry (its trash copy stays sealed with that DEK)
and removed a second member. With that re-key pending, the push goes out
unchecked past the restore (SM39) and resent the lost audit records, but not
the lost DEK: the laptop counted it as held by the server. The deleted entry
landed under a key no other device could get, and the phone could not open
it in the trash. The DEKs the restored server lost now go out again too.
"""

from __future__ import annotations

import copy

from sezam.vault import trash
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rebase_review8 import _folder_shared_with_member
from tests.test_review6_abandon_rekey_keeps_grants import _pinned_member
from tests.test_rollback_commit_token_sm7 import _restore


def test_push_past_a_restore_sends_the_lost_dek_again(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    client = _client(laptop, url)
    second, keys = _pinned_member(db, laptop)
    laptop.grant_folder_access(folder, second, keys.encryption_pk, "read")
    assert client.push()["conflicts"] == []
    backup = copy.deepcopy(db._storage)

    assert laptop.rekey_after_revocation(member_id) == 1
    assert client.push()["conflicts"] == []
    lost_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    _restore(db, backup)
    assert not any(o["id"] == lost_dek for o in db._storage["vault_objects"])

    laptop.delete_entry(entry)
    assert laptop.rekey_after_revocation(second) == 1
    client.push()
    assert any(o["id"] == lost_dek for o in db._storage["vault_objects"])

    _client(phone, url).pull()
    trash.restore_entry(phone, entry)
    assert phone.read_entry(entry)["name"] == "vpn"
    laptop.lock()
    phone.lock()
