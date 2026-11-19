"""Review 526419e V3: two devices of one admin re-key for the same member.

The phone's re-key lands first. On the laptop's pull the folder binds to the
phone's new DEK, the rebase finds no folder on the laptop's own new DEK and
sent the batch again unchanged: a 409 on every sync, and since the atomic
batch always goes first, the laptop synced nothing at all any more. Conflict
resolution, a full resync, another re-key and an identity rotation all refused
while it was pending, and there was no command to drop it.
"""

from __future__ import annotations

import pytest

from sezam.vault import pending_states
from tests.test_integration_client_server import (
    _client,
    _entry_value,
    server,  # noqa: F401  (fixture)
)
from tests.test_rekey_rebase_review8 import (
    _assert_member_cut_off,
    _folder_shared_with_member,
    _server_entry_dek,
)


def test_a_rekey_another_device_already_landed_is_dropped(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)

    assert phone.rekey_after_revocation(member_id) == 1
    assert laptop.rekey_after_revocation(member_id) == 1
    assert _client(phone, url).push()["conflicts"] == []
    phone_dek = _assert_member_cut_off(db, phone, folder, old_dek_id, member_id)

    # Something unrelated the laptop made meanwhile.
    other = laptop.create_node("Unrelated")
    client = _client(laptop, url)
    client.push()

    assert pending_states.rekey_batch(laptop.db) == {}
    assert _server_entry_dek(db, entry) == phone_dek
    assert laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == phone_dek
    assert any(o["id"] == other for o in db._storage["vault_objects"])
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v1"
    assert client.get_pull_conflicts() == []
    assert client.push()["conflicts"] == []
    laptop.lock()
    phone.lock()


@pytest.mark.parametrize("phone_edits", [False, True])
def test_a_local_edit_on_a_superseded_rekey_is_kept(server, tmp_path, phone_edits):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    assert phone.rekey_after_revocation(member_id) == 1
    if phone_edits:
        phone.update_entry(entry, fields=[{"key": "password", "value": "v2-phone", "sensitive": True}])
    assert laptop.rekey_after_revocation(member_id) == 1
    laptop.update_entry(entry, fields=[{"key": "password", "value": "v2-laptop", "sensitive": True}])
    assert _client(phone, url).push()["conflicts"] == []
    phone_dek = _assert_member_cut_off(db, phone, folder, old_dek_id, member_id)

    client = _client(laptop, url)
    client.push()
    assert pending_states.rekey_batch(laptop.db) == {}
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v2-laptop"
    if phone_edits:
        # The phone's copy is newer: the laptop's batch is dropped and its
        # edit comes back as a conflict the user settles.
        assert [c["id"] for c in client.get_pull_conflicts()] == [entry]
        client.resolve_conflict(entry, "local")
        assert client.push()["conflicts"] == []
        assert _server_entry_dek(db, entry) == phone_dek
    else:
        # The phone only re-keyed: the laptop's batch is dropped and its edit
        # lands on top of the phone's re-key, under its key, with no conflict
        # (stateful test SM1: a change goes out over the copy the server holds).
        assert client.get_pull_conflicts() == []
        _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
        assert _server_entry_dek(db, entry) == phone_dek
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == "v2-laptop"
    laptop.lock()
    phone.lock()


def test_abandon_rekey_undoes_a_stuck_batch_and_requeues_the_member(server, tmp_path):  # noqa: F811
    from sezam.vault.rekey_abandon import abandon_pending_rekey
    from sezam.vault.revocation import finish_queued_revocations, queued_revocations

    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    assert laptop.rekey_after_revocation(member_id) == 1
    added = laptop.create_entry(folder, "db", [{"key": "password", "value": "db-pw"}])

    client = _client(laptop, url)
    result = abandon_pending_rekey(client)
    assert result == {"member": member_id, "conflicts": 0, "requeued": True}
    assert pending_states.rekey_batch(laptop.db) == {}
    assert laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"] == old_dek_id
    assert laptop.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE user_id = ? AND dek_id = ?", (member_id, old_dek_id)
    )
    assert queued_revocations(laptop) == [member_id]
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v1"
    assert _entry_value(laptop, "Ops", "db", "password") == "db-pw"

    # Everything syncs again, and the next run re-keys from the current state.
    assert client.push()["conflicts"] == []
    assert _server_entry_dek(db, added) == old_dek_id
    assert finish_queued_revocations(laptop, client) == {member_id: 1}
    new_dek = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert _server_entry_dek(db, entry) == _server_entry_dek(db, added) == new_dek
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "db", "password") == "db-pw"
    laptop.lock()
    phone.lock()


def test_abandon_rekey_command(server, tmp_path, monkeypatch):  # noqa: F811
    from click.testing import CliRunner

    from sezam import cli

    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    assert laptop.rekey_after_revocation(member_id) == 1
    monkeypatch.setattr(cli, "_open_vault", lambda: laptop)
    monkeypatch.setattr(cli, "_unlock_vault_fresh", lambda vault, *a, **k: None)
    monkeypatch.setattr(laptop, "lock", lambda: None)
    out = CliRunner().invoke(cli.main, ["abandon-rekey", "--yes"])
    assert out.exit_code == 0, out.output
    assert "Dropped the unsent re-key" in out.output
    assert "re-keys them again" in out.output
    assert pending_states.rekey_batch(laptop.db) == {}
    out = CliRunner().invoke(cli.main, ["abandon-rekey", "--yes"])
    assert out.exit_code != 0 and "no member re-key" in out.output
    monkeypatch.undo()
    laptop.lock()
    phone.lock()
