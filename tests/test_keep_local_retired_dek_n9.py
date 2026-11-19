"""Review 526419e N9: 'keep local' could send a copy the removed member opens.

A held edit (re-key rebase) and 'keep local' on a conflict were resealed
under the DEK the local copy was written with. When that is the folder DEK a
member re-key retired, the kept copy went to the server under the revoked
member's key. Both now reseal under the folder's current DEK.
"""

from __future__ import annotations

from sezam.crypto.aead import BlobKind, decrypt, encrypt, parse_envelope
from sezam.models import bytes_to_ulid, ulid_to_bytes
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


def _password(value: str) -> list[dict]:
    return [{"key": "password", "value": value, "sensitive": True}]


def _local_entry_deks(vault, entry_id) -> set[str]:
    row = vault.db.fetchone(
        "SELECT encrypted_meta, encrypted_data FROM entries WHERE id = ?", (entry_id,)
    )
    return {
        bytes_to_ulid(parse_envelope(bytes(row[col])).dek_id)
        for col in ("encrypted_meta", "encrypted_data")
    }


def _seal_local_under(vault, entry_id, dek_id) -> None:
    """The local copy as a writer still on ``dek_id`` left it."""
    row = vault.db.fetchone(
        "SELECT encrypted_meta, encrypted_data, version FROM entries WHERE id = ?", (entry_id,)
    )
    mgr = vault.dek_mgr
    sealed = []
    for col, kind in (("encrypted_meta", BlobKind.ENTRY_META),
                      ("encrypted_data", BlobKind.ENTRY_DATA)):
        blob = bytes(row[col])
        current = bytes_to_ulid(parse_envelope(blob).dek_id)
        plain = decrypt(
            blob, mgr.unlock_dek(current), ulid_to_bytes(entry_id), row["version"],
            expected_blob_kind=kind,
        )
        sealed.append(encrypt(
            plaintext=plain, dek=mgr.unlock_dek(dek_id), dek_id=ulid_to_bytes(dek_id),
            object_id=ulid_to_bytes(entry_id), version=row["version"], blob_kind=kind,
        ))
    vault.db.execute(
        "UPDATE entries SET encrypted_meta = ?, encrypted_data = ? WHERE id = ?",
        (*sealed, entry_id),
    )


def _laptop_edit_held_by_rebase(url, db, tmp_path, *, retired_dek_edit: bool):
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    phone.update_entry(entry, fields=_password("v2-phone-draft"))
    phone.update_entry(entry, fields=_password("v2-phone"))
    assert _client(phone, url).push()["conflicts"] == []

    assert laptop.rekey_after_revocation(member_id) == 1
    laptop.update_entry(entry, fields=_password("v2-laptop"))
    if retired_dek_edit:
        _seal_local_under(laptop, entry, old_dek_id)
    client = _client(laptop, url)
    client.push()
    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)
    assert [c["id"] for c in client.get_pull_conflicts()] == [entry]
    return laptop, phone, client, entry, old_dek_id, new_dek_id


def test_a_held_edit_under_the_retired_dek_comes_back_under_the_new_one(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, phone, client, entry, old_dek_id, new_dek_id = _laptop_edit_held_by_rebase(
        url, db, tmp_path, retired_dek_edit=True
    )
    assert _local_entry_deks(laptop, entry) == {new_dek_id}
    assert _entry_value(laptop, "Ops", "vpn", "password") == "v2-laptop"

    client.resolve_conflict(entry, "local")
    assert client.push()["conflicts"] == []
    assert _server_entry_dek(db, entry) == new_dek_id
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == "v2-laptop"
    laptop.lock()
    phone.lock()


def test_keep_local_of_a_copy_under_the_retired_dek_seals_it_with_the_new_one(
    server, tmp_path  # noqa: F811
):
    url, db = server
    laptop, phone, client, entry, old_dek_id, new_dek_id = _laptop_edit_held_by_rebase(
        url, db, tmp_path, retired_dek_edit=False
    )
    _seal_local_under(laptop, entry, old_dek_id)

    client.resolve_conflict(entry, "local")
    assert _local_entry_deks(laptop, entry) == {new_dek_id}
    assert client.push()["conflicts"] == []
    assert _server_entry_dek(db, entry) == new_dek_id
    _client(phone, url).pull()
    assert _entry_value(phone, "Ops", "vpn", "password") == "v2-laptop"
    laptop.lock()
    phone.lock()
