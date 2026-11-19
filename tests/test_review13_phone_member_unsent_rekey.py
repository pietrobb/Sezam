"""Review c78fd19 (medium), phone: a member's unsent writes after a re-key.

Bob's phone holds a new item in the team folder Ops, not yet sent, sealed with
Ops' key, which Bob holds through the admin's access envelope. The admin
removes Carol on the desktop, which re-keys Ops. The phone could seal the item
again only with a key wrapped under its own KEK (the admin's case), so the
member's write was refused on every push and never left the phone
(mobile/test/review13_phone_member_unsent_rekey_test.dart).
"""

from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.crypto.aead import encrypt_dek_wrap
from sezam.crypto.envelope_crypto import compute_fingerprint
from sezam.models import ulid_to_bytes
from sezam.vault import revocation
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops

PHONE_TEST = "test/review13_phone_member_unsent_rekey_test.dart"


@pytest.mark.parametrize("in_deleted_folder", [False, True])
def test_a_members_phone_sends_unsent_writes_after_a_re_key(
    team, server, tmp_path, monkeypatch, in_deleted_folder,  # noqa: F811
):
    """With in_deleted_folder the item waits in Ops/Sub, Bob's own folder, which
    the admin deletes before the re-key: the phone brings Sub back from a
    tombstone sealed with the replaced key. It threw on that after the pull's
    checkpoint, on every pull."""
    url, db = server
    _, admin, admin_client, bob, _bob_client = team
    carol = _carol(url, admin_client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    admin_client.append_team_log([("member.add", _member(carol))])
    carol.lock()
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    revocation.grant_member(admin, admin_client, carol_id, ops, "read")
    # The phone walks a folder's parents up to the root to pick the write key
    # (resolveWriteDekId): Bob reads the root's name too, as in
    # test_phone_unconfirmed_team_writes_preserve_queue.
    root_key, raw_key = admin.dek_mgr.get_dek_for_node(admin.db.get_meta("root_node_id"))
    root_row = next(o for o in db._storage["vault_objects"] if o["id"] == root_key)
    payload = encrypt_dek_wrap(raw_key, bob.dek_mgr._kek, ulid_to_bytes(bob.dek_mgr.kek_dek_id),
                               ulid_to_bytes(root_key), version=root_row["version"])
    signed = admin_client._make_sync_object(root_key, "dek", payload, version=root_row["version"])
    root_row.update(payload=payload, payload_hash=signed["payload_hash"],
                    client_signature=bytes.fromhex(signed["signature"]))
    bob.lock()
    old_key = teamlog.current_key(admin_client.team_state(), ops)

    def rekeyed():
        if in_deleted_folder:
            admin_client.pull()
            sub = (tmp_path / "phone" / "sub.txt").read_text(encoding="utf-8")
            admin.delete_node(sub)
            assert admin_client.push()["conflicts"] == []
        assert revocation.revoke_member(admin, admin_client, carol_id) == 1
        assert teamlog.current_key(admin_client.team_state(), ops) != old_key

    out = _phone(url, tmp_path, {
        "username": "bob", "password": PASSWORD, "ops": ops, "in_sub": in_deleted_folder,
        "fingerprint": compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk),
    }, {"rekeyed": rekeyed}, PHONE_TEST)
    assert "All tests passed!" in out, out

    added = (tmp_path / "phone" / "added.txt").read_text(encoding="utf-8")
    admin_client.pull()
    parent = ((tmp_path / "phone" / "sub.txt").read_text(encoding="utf-8")
              if in_deleted_folder else ops)
    [item] = [e for e in admin.list_entries(parent) if e["id"] == added]
    assert item["name"] == "member-offline"
    row = admin.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (added,))
    assert (row["dek_id"] or admin.dek_mgr.get_dek_for_node(parent)[0]) == teamlog.current_key(
        admin_client.team_state(), ops)
