"""Review e4cd15a S1: the second rebase of a re-key lost the edit made after the first.

The first rebase holds the laptop's edit (it comes back as a conflict, V1)
and puts the server copy in the row. The phone pushes again before the batch
lands, so the batch is rebased a second time. An edit the user made in
between was skipped (`entry_id not in held`) and replaced by the server copy:
lost, not even in the history. A held item the user deleted in between lost
the held edit without a word. Now the newer edit is the one held (the earlier
goes to the entry's history), and a deleted item keeps the held edit in its
history (trash restore brings it back).
"""

from __future__ import annotations

import pytest

from sezam.vault import pending_states
from sezam.vault.sync_client import SyncClient
from sezam.vault.trash import list_history, read_history, restore_entry
from tests.test_integration_client_server import (
    _client,
    _entry_value,
    server,  # noqa: F401  (fixture)
)
from tests.test_rekey_rebase_keeps_local_edit import _laptop_value
from tests.test_rekey_rebase_review8 import _folder_shared_with_member


def _history_values(vault, entry) -> list[str]:
    return [
        next(f["value"] for f in read_history(vault, entry, h["id"]) if f["key"] == "password")
        for h in list_history(vault, entry)
    ]


@pytest.mark.parametrize("then", ["edit", "delete"])
def test_second_rebase_keeps_the_newer_edit(server, tmp_path, monkeypatch, then):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    phone_client = _client(phone, url)
    phone.update_entry(entry, fields=_laptop_value("v2-phone-draft"))
    phone.update_entry(entry, fields=_laptop_value("v2-phone"))
    assert phone_client.push()["conflicts"] == []

    laptop.update_entry(entry, fields=_laptop_value("v2-laptop"))
    assert laptop.rekey_after_revocation(member_id) == 1
    client = _client(laptop, url)

    # The phone gets in again right after the first rebase (twice, so its copy
    # is as new as the laptop's next edit): the batch is refused a second time.
    original = SyncClient._rebase_pending_rekey
    rounds = []

    def rebase_then_phone_pushes(self):
        original(self)
        rounds.append(1)
        if len(rounds) == 1:
            phone_client.pull()
            phone.update_entry(entry, fields=_laptop_value("v3-phone-draft"))
            phone.update_entry(entry, fields=_laptop_value("v3-phone"))
            assert phone_client.push()["conflicts"] == []

    monkeypatch.setattr(SyncClient, "_rebase_pending_rekey", rebase_then_phone_pushes)
    with pytest.raises(RuntimeError, match="stays pending"):
        client.push()
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v2-phone"

    # The user works on what they see before the batch lands.
    if then == "edit":
        laptop.update_entry(entry, fields=_laptop_value("v3-laptop"))
    else:
        laptop.delete_entry(entry)
    client.push()
    assert len(rounds) == 2
    assert pending_states.rekey_batch(laptop.db) == {}

    if then == "edit":
        # The newer edit is the local copy of the conflict with the phone's.
        assert _entry_value(laptop, "Ops", "vpn", "password") == "v3-laptop"
        assert [c["id"] for c in client.get_pull_conflicts()] == [entry]
        assert "v2-laptop" in _history_values(laptop, entry)
        client.resolve_conflict(entry, "local")
        assert client.push()["conflicts"] == []
        phone_client.pull()
        assert _entry_value(phone, "Ops", "vpn", "password") == "v3-laptop"
    else:
        # The delete is the local copy of a conflict with the phone's edit,
        # and the held edit is not gone without a trace.
        assert [c["id"] for c in client.get_pull_conflicts()] == [entry]
        assert laptop.db.fetchone(
            "SELECT is_deleted FROM entries WHERE id = ?", (entry,)
        )["is_deleted"] == 1
        client.resolve_conflict(entry, "local")
        assert client.push()["conflicts"] == []
        phone_client.pull()
        assert phone.db.fetchone(
            "SELECT is_deleted FROM entries WHERE id = ?", (entry,)
        )["is_deleted"] == 1
        restore_entry(laptop, entry)
        assert "v2-laptop" in _history_values(laptop, entry)
    laptop.lock()
    phone.lock()
