"""R16-Z (SecondAdminMachine deep run on b20ece6, also on 18c300f).

Two devices of one admin re-key a folder for the same removed member. The
batch made second must meet the server before it is sent (review 4acfdde
R11 #3): the pull binds the folder to the landed key and the superseded
batch is dropped. That pull ran once, in the revocation queue; when it failed
the next push sent the batch unchecked. For a folder deleted on that device
the batch re-seals none of its items, nothing in it clashed, and it landed
beside the other re-key: two successors of one key, and a member granted on
the other one lost the folder.
"""

from __future__ import annotations

import pytest

from sezam.vault import oplock, pending_states
from sezam.vault.revocation import push_with_queued_revocations
from sezam.vault.sync_common import ServerError
from tests.test_integration_client_server import _client, server  # noqa: F401  (fixture)
from tests.test_rekey_rebase_review8 import _folder_shared_with_member


def _folder_keys(db, folder):
    return sorted(
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "dek" and o.get("parent_ref") == folder and not o["is_deleted"]
    )


def test_a_rekey_whose_pull_failed_is_not_sent_beside_another(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    laptop.delete_node(folder)  # here only: the laptop's batch re-seals none of its items

    assert phone.rekey_after_revocation(member_id) == 1
    assert _client(phone, url).push()["conflicts"] == []
    phone_dek = phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert _folder_keys(db, folder) == sorted([old_dek_id, phone_dek])

    with oplock.exclusive(laptop.db.path):  # INV-6
        pending_states.set_revocation_queue(laptop.db, [member_id])
    client = _client(laptop, url)
    real_pull = client.pull

    def unavailable(*args, **kwargs):
        raise ServerError(503, "unavailable")

    client.pull = unavailable
    with pytest.raises(ServerError):
        push_with_queued_revocations(laptop, client)
    assert pending_states.rekey_batch(laptop.db).get("dek_map")  # made, not sent
    assert _folder_keys(db, folder) == sorted([old_dek_id, phone_dek])

    client.pull = real_pull
    client.push()
    assert _folder_keys(db, folder) == sorted([old_dek_id, phone_dek])
    assert pending_states.rekey_batch(laptop.db) == {}
    laptop.lock()
    phone.lock()
