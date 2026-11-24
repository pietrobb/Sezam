"""Stateful test finding R16-Z SM20 (gate 16, SecondAdminMachine): an unsent
identity rotation carries a grant under a key a re-key has since replaced.

Device B of the admin account rotated its identity, but the push did not go
through: the rotation, with the account's grants re-sealed under the new
identity, stayed queued as one atomic unit. Device A then removed the member
and its re-key replaced the folder's key. B pulled the re-key, yet the unit
still held the member's envelope under the retired key. The server takes no
live envelope under a key that names no folder ('envelope references unknown
DEK') and refused the whole rotation on every push.

Invariant (INV-7, docs/SYNC_SINGLE_SOURCE.md point 1): nothing waits forever
for a push the server can never take. As for a grant outside a rotation
(SM19c), a rotation's envelope under a retired folder key leaves the unit; a
member the re-key withdrew gets nothing, one it kept gets the current key.
"""

from __future__ import annotations

from sezam.vault import pending_states, revocation
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once, _injected


def test_an_unsent_rotation_drops_a_grant_a_later_rekey_replaced(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    retired = phone.db.fetchone("SELECT id FROM deks WHERE node_id = ? AND scope = 'folder'", (folder,))["id"]

    # The phone rotates its identity; the push does not go through.
    phone_client.prepare_key_change()
    phone.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    phone_client = _client(phone, url)
    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        phone_client.push()
    except Exception as exc:  # noqa: BLE001
        assert _injected(exc), exc
    finally:
        undo()
    batch = pending_states.rekey_batch(phone.db)
    assert batch.get("identity_rotation")
    assert phone.db.fetchone(
        f"SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ? "
        f"AND id IN ({','.join('?' * len(batch['object_ids']))})",
        (retired, bob_id, *batch["object_ids"]),
    ), "the rotation re-sealed Bob's grant"

    # The laptop removes Bob: its re-key replaces the folder's key.
    revocation.revoke_member(laptop, laptop_client, bob_id)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    # The phone pulls the re-key; its rotation re-wraps the retired key, now
    # without its folder, in the same unit as Bob's envelope under it. Like
    # the CLI, every command builds its own client (no push cache carries over).
    _client(phone, url).pull()
    phone_client = _client(phone, url)
    assert phone.db.fetchone("SELECT node_id FROM deks WHERE id = ?", (retired,))["node_id"] is None

    for _ in range(2):
        phone_client.push()
        phone_client.pull()
    assert not phone_client.has_pending_key_change()
    assert not (pending_states.rekey_batch(phone.db) or None)
    assert phone_client.dirty_object_count() == 0
    assert not _bob_envelopes_live(db, bob_id)
    laptop.lock()
    phone.lock()
