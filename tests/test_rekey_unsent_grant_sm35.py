"""Stateful test finding SM35: a re-key that withdraws a grant the server never had.

The laptop shared a new folder with Bob while its push failed, so neither the
folder's key nor Bob's envelope reached the server. The phone revoked Bob. The
laptop's push re-keyed the folder and sent the tombstone of Bob's envelope,
sealed with a key the server never had: 'envelope references unknown DEK', and
the whole atomic batch was refused on every sync. A tombstone of an envelope the
server holds no live copy of takes no access away, so the server takes it.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_of_a_grant_that_never_reached_the_server_lands(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    laptop_client.pull()

    folder = laptop.create_node("Ops")
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    except RuntimeError:
        pass
    finally:
        undo()
    assert not _bob_envelopes_live(db, bob_id)

    assert revocation.revoke_member(phone, phone_client, bob_id) == 0

    result = revocation.push_with_queued_revocations(laptop, laptop_client)
    assert result["rekeyed"] == {bob_id: 1}, result
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert not _bob_envelopes_live(db, bob_id)
    phone_client.pull()
    assert {e["name"] for e in phone.list_entries(folder)} == {"vpn"}
    laptop.lock()
    phone.lock()
