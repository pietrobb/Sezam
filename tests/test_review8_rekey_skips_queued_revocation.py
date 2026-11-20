"""Review a159e97 (desktop sync): c494af0 sealed the new key to a member
waiting for their own removal re-key.

Two members hold the same folder. The admin revokes both; the first one's
re-key goes first and carol waits in queued_revocations. c494af0 dropped the
skip of queued members, so the first re-key sealed the folder's new key to
carol and only the server's 'envelope for a revoked user' refusal kept it from
her. A server that accepts it handed her the key she was being removed from.
A member in the queue is now never sealed a new key, whatever the server says.
"""

from __future__ import annotations

from sezam.models import new_ulid
from sezam.vault import oplock, pending_states
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_rekey_rebase_review8 import _folder_shared_with_member
from tests.test_review7_rekey_seals_only_trusted_holders_h2 import _grant, _pin


def test_a_rekey_does_not_seal_the_new_key_to_a_member_queued_for_removal(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    own = laptop.db.get_meta("user_id")
    carol, dave = new_ulid(), new_ulid()
    for user_id in (carol, dave):
        _pin(laptop, user_id)
        _grant(laptop, old_dek, user_id, own)
    with oplock.exclusive(laptop.db.path):  # INV-6
        pending_states.set_revocation_queue(laptop.db, [carol])

    assert laptop.rekey_after_revocation(member_id) == 1

    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek != old_dek
    holders = {
        row["user_id"] for row in laptop.db.fetchall(
            "SELECT user_id FROM access_envelopes WHERE dek_id = ?", (new_dek,)
        )
    }
    # On c494af0 carol, queued for her own removal, held the new key.
    assert carol not in holders
    assert dave in holders and member_id not in holders
    assert pending_states.revocation_queue(laptop.db) == [carol]
    laptop.lock()
    phone.lock()
