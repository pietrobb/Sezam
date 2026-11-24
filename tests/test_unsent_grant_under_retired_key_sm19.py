"""Stateful test finding R16-Z SM19c: an unsent grant under a key a re-key replaced.

Device B of the admin account shared a folder with a member, but the push
did not go through: the envelope stayed queued. Device C then removed
another member and its re-key replaced the folder's key. B pulled the
re-key and sealed its grant again on the new key (SM62), yet the queued
copy under the retired key stayed in the outbox. The server refuses a live
envelope under a key that names no folder ('envelope references unknown
DEK'), so B pushed it on every round and never got clean ("1 local
change(s) not on the server yet").

Invariant (INV-7, docs/SYNC_SINGLE_SOURCE.md point 1): nothing waits
forever for a push the server can never take. A grant that never reached
the server under a retired folder key lives on as its copy on the folder's
current key; the retired copy is not sent.
"""

from __future__ import annotations

from sezam.vault import outbox, pending_states, revocation
from tests.test_grant_under_rekeyed_key_sm62 import _invite_carol
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once

NEW_PASSWORD = "laptop-pw-sm19c!"

def _queued_envelopes(vault) -> list[str]:
    return [
        r["object_id"] for r in vault.db.fetchall(
            "SELECT object_id FROM outbox WHERE kind = ? AND state = 'queued'", (outbox.ENVELOPE,)
        )
    ]


def test_an_unsent_grant_under_a_replaced_key_does_not_wait_forever(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    carol_id = _invite_carol(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        revocation.grant_member(phone, phone_client, carol_id, folder, confirm_fingerprint=lambda _fp: True)
    except RuntimeError:
        pass
    finally:
        undo()
    assert _queued_envelopes(phone), "the grant to Carol stays queued"
    assert not _bob_envelopes_live(db, carol_id)

    revocation.revoke_member(laptop, laptop_client, bob_id)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    # The laptop's password change wraps the retired key again, now without
    # its folder: the server takes no live envelope under it any more.
    laptop_client.prepare_key_change()
    laptop.change_password(PASSWORD, NEW_PASSWORD)
    laptop_client = _client(laptop, url)
    laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    # The phone takes the new keys over before it pulls the re-key: its queued
    # grant is sealed again, still under the key the re-key replaced.
    phone_client.adopt_rotated_key_material(phone, NEW_PASSWORD)
    phone_client = _client(phone, url)
    assert _queued_envelopes(phone)

    for _ in range(3):
        phone_client.pull()
        phone_client.push()
        laptop_client.pull()
    assert not _queued_envelopes(phone), _queued_envelopes(phone)
    assert phone_client.dirty_object_count() == 0
    assert not [s for s in pending_states.pending_states(phone) if s.key == "unpushed"]
    current = phone.db.fetchone(
        "SELECT id FROM deks WHERE node_id = ? AND scope = 'folder'", (folder,)
    )["id"]
    assert current in {o["parent_ref"] for o in _bob_envelopes_live(db, carol_id)}
    assert not _bob_envelopes_live(db, bob_id)
    laptop.lock()
    phone.lock()
