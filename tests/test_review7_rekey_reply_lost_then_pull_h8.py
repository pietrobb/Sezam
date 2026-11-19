"""Review 7c10379 H8: a re-key whose reply was lost, then a pull, blocked every push.

The re-key batch reached the server and its reply was lost. The pull brought
the batch's own copies back; since 956656b a pulled own copy is clean, so the
batch's objects were no longer dirty and every push stopped with 'Atomic
re-key batch is missing N local object(s)'. One of the batch's keys on the
server proves the atomic batch is there: it is closed as sent and the push
goes on.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import outbox
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member
from tests.test_sync_state_machine import _fail_once


def test_push_after_a_lost_rekey_reply_and_a_pull_is_not_blocked(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    client = _client(laptop, url)
    assert laptop.rekey_after_revocation(member_id) == 1
    undo = _fail_once(client, "POST", "/api/sync", "after")
    try:
        client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    client.pull()

    other = laptop.create_node("After", parent_id=folder)
    assert client.push()["conflicts"] == []
    assert (pending_states.rekey_batch(laptop.db) or None) in (None, {})
    assert not outbox.has_write(laptop.db, other)
    _assert_member_cut_off(db, laptop, folder, old_dek, member_id)
    laptop.lock()
    phone.lock()
