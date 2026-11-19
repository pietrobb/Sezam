"""Review main@d615826 capability run 157: a withheld re-key archive.

After a member was removed, the folder's new key K1 and its retired key K0
both name the folder by their signed parent_ref. Only the dek_archive row
(``K0 replaced_by K1``) said which one is current; a server that left it out
of a fresh device's pull made the earlier id, the retired key the removed
member still holds, the folder's key there. The folder's entries, sealed
under K1 in their signed headers, decide it now.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_rekey_rebase_review8 import _assert_member_cut_off, _folder_shared_with_member


def _node_dek(vault, node_id):
    return vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))["dek_id"]


@pytest.mark.parametrize("variant", ["live_entry", "deleted_entry", "shared_subfolder"])
@pytest.mark.parametrize("lie", ["honest", "no_archive", "no_archive_reversed"])
def test_a_withheld_rekey_archive_does_not_bring_the_retired_key_back(
        server, tmp_path, monkeypatch, lie, variant):  # noqa: F811
    """deleted_entry (state machine, second admin): a re-key reseals only live
    children, so the retired key still sealed a deleted entry's tombstone and
    that alone made it the folder's key again.

    shared_subfolder (state machine, second admin): a subfolder without a key
    of its own (as the web client makes them) took the folder's key when it
    was applied, before the keys were bound; without the archive only the
    folder moved to the new key and the subfolder kept the retired one."""
    url, db = server
    laptop, phone, folder, entry, old_dek_id, member_id = _folder_shared_with_member(url, tmp_path, db)
    phone.lock()
    emptied = variant == "deleted_entry"
    sub = None
    if emptied:
        laptop.delete_entry(entry)
        _client(laptop, url).push()
    if variant == "shared_subfolder":
        sub = laptop.create_node("Sub", parent_id=folder, create_dek=False)
        _client(laptop, url).push()
    assert laptop.rekey_after_revocation(member_id) == 1
    _client(laptop, url).push()
    new_dek_id = _assert_member_cut_off(db, laptop, folder, old_dek_id, member_id)

    order = SyncClient._order_pulled_objects

    def lying_order(objects):
        ordered = order(objects)
        if lie != "honest":
            ordered = [o for o in ordered if o.get("object_type") != "dek_archive"]
        if lie == "no_archive_reversed":
            deks = [o for o in ordered if o.get("object_type") == "dek"]
            ordered = deks[::-1] + [o for o in ordered if o.get("object_type") != "dek"]
        return ordered

    monkeypatch.setattr(SyncClient, "_order_pulled_objects", staticmethod(lying_order))
    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert _node_dek(tablet, folder) == new_dek_id
    if sub:
        assert _node_dek(tablet, sub) == new_dek_id, "the subfolder kept the retired key"
    new_entry = tablet.create_entry(folder, "fresh", [{"key": "pin", "value": "2"}])
    meta = bytes(tablet.db.fetchone("SELECT encrypted_meta FROM entries WHERE id = ?", (new_entry,))[0])
    assert bytes_to_ulid(parse_envelope(meta).dek_id) == new_dek_id
    if not emptied:
        assert tablet.get_field_value(entry, "password") == "v1"
    laptop.lock()
    tablet.lock()
