"""Stateful test finding SM84: 'sezam abandon-rekey' after a pull brought the batch back.

The re-key batch reached the server and its reply was lost; a pull then
brought its new folder key back, and the user dropped the re-key. The drop
took the folder back under the old key here and deleted the new one, while
the server and the other devices kept the folder under the new key. The next
envelope another device sealed to that key named a key this device no longer
had: every pull failed with 'FOREIGN KEY constraint failed'. One of the
batch's keys on the server proves the atomic batch is there, so it is closed
as sent: the member stays removed.
"""

from __future__ import annotations

import os

from sezam.vault import pending_states
from sezam.models import new_ulid
from sezam.vault.rekey_abandon import abandon_pending_rekey
from tests.test_integration_client_server import _client, _server_member, server  # noqa: F401
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member
from tests.test_sync_state_machine import _fail_once
from sezam.vault import outbox


def test_dropping_a_rekey_a_pull_brought_back_closes_it_as_sent(server, tmp_path):  # noqa: F811
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
    assert (pending_states.rekey_batch(laptop.db) or None)

    result = abandon_pending_rekey(client)
    assert result["requeued"] is False
    new_dek = _assert_member_cut_off(db, laptop, folder, old_dek, member_id)

    # The phone shares the folder, now under the new key, with someone else.
    phone_client = _client(phone, url)
    phone_client.pull()
    assert phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == new_dek
    phone.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (new_ulid(), new_dek, _server_member(db), phone.db.get_meta("user_id"), os.urandom(72)),
    )
    outbox.queue_write(phone.db, folder)
    assert phone_client.push()["conflicts"] == []

    client.pull()
    assert client.push()["conflicts"] == []
    laptop.lock()
    phone.lock()
