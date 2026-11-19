"""Review 1141a20 (R9-G), phone: an own item moved to the personal root vanished.

Bob kept an item of his own key (his personal root's) in the team folder Ops
while he could write there. With read access only, he moves it back to his
personal root - the server takes it (move_refusal own_personal, TL7). His
phone judged the same move without ownPersonal and dropped the item: it was
gone from the phone until a resync, and a resync did not bring it back either.
"""

from __future__ import annotations

import struct

from sezam.crypto import aead
from sezam.models import ulid_to_bytes
from sezam.vault import revocation
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_forged_root_folder_desktop_h4 import _login, _push
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops

PHONE_TEST = "test/phone_personal_move_test.dart"


def _stored(db, obj_id: str) -> dict:
    return next(o for o in db._storage["vault_objects"] if o["id"] == obj_id)


def _resealed(vault, db, item: str, home: str, version: int) -> bytes:
    """The stored entry sealed again for ``version``, still with Bob's own key."""
    row = _stored(db, item)
    payload = bytes(row["payload"])
    (meta_len,) = struct.unpack(">I", payload[:4])
    blobs = (payload[4:4 + meta_len], payload[4 + meta_len:])
    dek_id, dek = vault.dek_mgr.get_dek_for_node(home)
    oid = ulid_to_bytes(item)
    meta, data = (
        aead.encrypt(aead.decrypt(b, dek, oid, row["version"]), dek, ulid_to_bytes(dek_id), oid, version, kind)
        for b, kind in zip(blobs, (aead.BlobKind.ENTRY_META, aead.BlobKind.ENTRY_DATA))
    )
    return struct.pack(">I", len(meta)) + meta + data


def _move(url, token, sk, db, item: str, parent: str, payload: bytes) -> None:
    row = _stored(db, item)
    _push(url, token, sk, item, "entry", parent, payload, version=row["version"] + 1)


def test_the_phone_keeps_an_own_item_moved_to_the_personal_root(team, server, tmp_path):  # noqa: F811
    url, db = server
    _, admin, admin_client, bob, _bob_client = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")

    _confirm_founder(admin, bob)
    bob_client = _client(bob, url)
    bob_client.pull()
    home = bob.create_personal_folder("Moje")
    item = bob.create_entry(home, "own-item", [{"key": "password", "value": "mine"}])
    assert [c for c in bob_client.push()["conflicts"] if c["error"] != "admin only"] == []
    sk = bob.keypair.to_nacl_signing_key()
    token = _login(url, sk, "bob")
    # Kept in Ops while Bob could write there (an older device put it there).
    # Every move seals the item again for its next version, with his own key.
    v = _stored(db, item)["version"]
    to_ops = _resealed(bob, db, item, home, v + 1)
    _move(url, token, sk, db, item, ops, to_ops)
    back = _resealed(bob, db, item, home, v + 2)
    bob.lock()

    def moved():
        admin_client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": "read"})])
        _move(url, token, sk, db, item, home, back)  # the server takes it: his own, to his root

    out = _phone(url, tmp_path, {
        "username": "bob", "password": PASSWORD, "item": item, "ops": ops, "home": home,
    }, {"moved": moved}, PHONE_TEST)
    assert "All tests passed!" in out, out
    assert _stored(db, item)["parent_ref"] == home
