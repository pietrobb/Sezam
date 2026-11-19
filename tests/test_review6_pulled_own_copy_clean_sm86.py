"""Stateful test finding SM86: a pull brought back this device's own copy of a dirty row.

The laptop renamed a subfolder; the push landed and its reply was lost, so
the row stayed dirty. The pull then brought that very copy back, together with
the phone's re-key of the folder above: the base moved to the copy's version,
but the row stayed dirty at that version. Sealed again under the new key in
place (an unsent change keeps its version), it went out as a change of the
version the server already holds and was refused on every sync. The row the
server holds as it is here is now clean, so the reseal goes one version up.
"""

from __future__ import annotations

from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rebase_review8 import _folder_shared_with_member, _server_object
from sezam.vault import outbox


def test_own_copy_pulled_back_with_a_rekey_is_resealed_one_version_up(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone, folder, _entry, old_dek, member_id = _folder_shared_with_member(url, tmp_path, db)
    client = _client(laptop, url)
    sub = laptop.create_node("Sub", parent_id=folder)
    assert client.push()["conflicts"] == []
    seq = laptop.db.get_meta("last_known_commit_seq")
    base = client._base(sub)
    laptop.rename_node(sub, "Renamed")
    assert client.push()["conflicts"] == []
    # The reply was lost: the row is still dirty on the old base.
    outbox.queue_write(laptop.db, sub)
    client._set_base(sub, *base)
    laptop.db.set_meta("last_known_commit_seq", seq)

    # The phone never saw the subfolder; its re-key leaves it under the old key.
    assert phone.rekey_after_revocation(member_id) == 1
    assert _client(phone, url).push()["conflicts"] == []
    new_dek = phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek != old_dek

    client.pull()
    assert client.push()["conflicts"] == []
    sealed = bytes_to_ulid(parse_envelope(bytes(_server_object(db, sub)["payload"])).dek_id)
    assert sealed == new_dek
    laptop.lock()
    phone.lock()
