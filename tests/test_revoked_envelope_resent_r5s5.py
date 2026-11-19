"""Review d150605 S5 (security): a removed member's grant came back.

Tombstone GC collected the tombstone of a revoked member's envelope. An
outdated admin device (upgraded to d150605, which resends this account's own
envelopes once) then sent that envelope live again; the server took it as a
new object and restored the member's write_acl. Now the server takes no live
envelope for a revoked user, GC keeps envelope tombstones, and the
device does not resend the refused grant on every push.
"""

from __future__ import annotations

from sezam.vault import outbox

from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    server,
)
from tests.test_revoke_second_member_8b import _admin_with_two_members, _envelopes_live
from tests.test_tombstone_gc_orphans_r5k1 import _gc


def _bob_envelope(db, bob_id):
    return next(
        o for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o.get("target_user_id") == bob_id
    )


def test_server_refuses_a_revoked_members_envelope_after_its_tombstone_is_gone(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin, bob_id, _carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    client = _client(admin, url)
    client.revoke_user(bob_id)
    envelope_id = _bob_envelope(db, bob_id)["id"]
    # What GC of its tombstone left: the envelope is gone from the server.
    db._storage["vault_objects"] = [
        o for o in db._storage["vault_objects"] if o["id"] != envelope_id
    ]
    # The outdated device still holds the grant (with write access) and resends it.
    admin.db.execute(
        "UPDATE access_envelopes SET access_level = 'write' WHERE id = ?", (envelope_id,)
    )
    outbox.requeue(admin.db, outbox.ENVELOPE, envelope_id)

    result = client.push()

    assert {c["id"]: c["error"] for c in result["conflicts"]} == {
        envelope_id: "envelope for a revoked user"
    }
    assert not _envelopes_live(db, bob_id)
    assert not [a for a in db._storage.get("write_acl", []) if a["user_id"] == bob_id]
    # Not resent on every push; the local copy stays for the re-key.
    assert client.push()["conflicts"] == []
    assert admin.db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (envelope_id,))


def test_gc_keeps_envelope_tombstones(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    admin, bob_id, _carol_id = _admin_with_two_members(url, db, tmp_path, monkeypatch)
    envelope = _bob_envelope(db, bob_id)
    envelope["is_deleted"] = 1
    folder = admin.create_node("Gone")
    _client(admin, url).push()
    gone = next(o for o in db._storage["vault_objects"] if o["id"] == folder)
    gone["is_deleted"] = 1

    _gc(db)

    ids = {o["id"] for o in db._storage["vault_objects"]}
    assert envelope["id"] in ids
    assert folder not in ids
