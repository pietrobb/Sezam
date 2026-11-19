"""Lockout review 2026-11-08, finding 8 (K8a): a member re-key that lost a race.

The re-key after revoking a member is one atomic batch. When another device
of the account changed one of its objects first, the server refused the whole
batch with 409, and every later sync sent the very same batch again: the
member kept the folder's key for good and the re-key journal could not be
left (a full resync is refused while it is pending). Now the refused batch
is pulled, carried over the other device's changes and sent once more.
"""

from __future__ import annotations

import os

from sezam.vault import pending_states
from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid, new_ulid
from sezam.vault import outbox
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _entry_value,
    _server_member,
    _vault,
    server,  # noqa: F401  (fixture)
)


def _folder_shared_with_member(url, tmp_path, db):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Ops")
    entry = laptop.create_entry(
        folder, "vpn", [{"key": "password", "value": "v1", "sensitive": True}]
    )
    cli._server_connect_flow(url, laptop, PASSWORD)
    dek_id = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    member_id = _server_member(db)
    laptop.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (new_ulid(), dek_id, member_id, laptop.db.get_meta("user_id"), os.urandom(72)),
    )
    outbox.queue_write(laptop.db, folder)
    assert _client(laptop, url).push()["conflicts"] == []

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert _entry_value(phone, "Ops", "vpn", "password") == "v1"
    return laptop, phone, folder, entry, dek_id, member_id


def _server_object(db, object_id):
    return next(o for o in db._storage["vault_objects"] if o["id"] == object_id)


def _server_entry_dek(db, entry_id):
    payload = bytes(_server_object(db, entry_id)["payload"])
    meta_len = int.from_bytes(payload[:4], "big")
    return bytes_to_ulid(parse_envelope(payload[4:4 + meta_len]).dek_id)


def _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id):
    new_dek_id = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek_id != old_dek_id
    assert pending_states.rekey_batch(laptop.db) == {}
    member_envelopes = [
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == member_id
    ]
    assert member_envelopes and all(o["is_deleted"] for o in member_envelopes)
    return new_dek_id


def test_rekey_carries_over_an_edit_pushed_by_another_device(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)

    phone.update_entry(entry, fields=[{"key": "password", "value": "v2-phone", "sensitive": True}])
    added = phone.create_entry(folder, "db", [{"key": "password", "value": "db-pw"}])
    assert _client(phone, url).push()["conflicts"] == []

    # The laptop re-keys before it has seen the phone's changes.
    assert laptop.rekey_after_revocation(member_id) == 1
    _client(laptop, url).push()

    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    # Both the edited and the newly added entry are sealed with the new DEK
    # on the server: the member's old key opens neither.
    assert _server_entry_dek(db, entry) == new_dek_id
    assert _server_entry_dek(db, added) == new_dek_id
    # The phone's edit is kept, not overwritten by the laptop's older copy.
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v2-phone"
    assert laptop.db.fetchall("SELECT object_id FROM sync_conflicts") == []
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == "v2-phone"
    assert _entry_value(phone, "Ops", "db", "password") == "db-pw"
    laptop.lock()
    phone.lock()


def test_rekey_takes_over_an_entry_deleted_by_another_device(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    kept = laptop.create_entry(folder, "kept", [{"key": "password", "value": "k"}])
    _client(laptop, url).push()
    _client(phone, url).pull()

    phone.delete_entry(entry)
    assert _client(phone, url).push()["conflicts"] == []

    assert laptop.rekey_after_revocation(member_id) == 1
    _client(laptop, url).push()

    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert _server_object(db, entry)["is_deleted"]
    assert laptop.db.fetchone("SELECT is_deleted FROM entries WHERE id = ?", (entry,))[0] == 1
    assert _server_entry_dek(db, kept) == new_dek_id
    laptop.lock()
    phone.lock()


def test_rekey_takes_over_a_folder_renamed_by_another_device(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)

    phone.rename_node(folder, "Ops-renamed")
    assert _client(phone, url).push()["conflicts"] == []

    assert laptop.rekey_after_revocation(member_id) == 1
    _client(laptop, url).push()

    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert _server_entry_dek(db, entry) == new_dek_id
    assert _entry_value(laptop, "Ops-renamed", "vpn", "password") == "v1"
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops-renamed", "vpn", "password") == "v1"
    laptop.lock()
    phone.lock()


def test_unrelated_conflicting_edit_does_not_sink_the_rekey(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    other_folder = laptop.create_node("Private")
    other = laptop.create_entry(other_folder, "note", [{"key": "text", "value": "base"}])
    _client(laptop, url).push()
    _client(phone, url).pull()

    # Both devices edit an entry outside the re-keyed folder.
    phone.update_entry(other, fields=[{"key": "text", "value": "phone"}])
    assert _client(phone, url).push()["conflicts"] == []
    laptop.update_entry(other, fields=[{"key": "text", "value": "laptop"}])

    assert laptop.rekey_after_revocation(member_id) == 1
    result = _client(laptop, url).push()

    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert _server_entry_dek(db, entry) == new_dek_id
    # The unrelated edit is an ordinary conflict, reported after the batch.
    assert [c["id"] for c in result["conflicts"]] == [other]
    laptop.lock()
    phone.lock()
