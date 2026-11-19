"""Stateful test finding SM58: a re-key another device already did for one of its folders.

The laptop shared two folders with Bob; the phone saw only the first grant.
The phone removed Bob and re-keyed the first folder. The laptop then queued
its own re-key of Bob (it sealed his envelopes, SM23) over both folders and
the server refused it: the first folder's items were re-keyed by the phone.
The pull bound that folder to the phone's DEK, but the batch still carried the
folder's items sealed with its own new key and went out unchanged on every
sync ('Atomic re-key batch conflict'). Only a batch none of whose folders was
left counted as superseded. One such folder is enough now: the batch is
dropped and Bob queued for a fresh re-key of what he can still open.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live, _status
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_of_two_folders_after_another_device_rekeyed_one(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    first = _folder(laptop)
    second = laptop.create_node("Second", parent_id=laptop.db.get_meta("root_node_id"))
    laptop.create_entry(first, "vpn", [{"key": "password", "value": "one-pw", "sensitive": True}])
    laptop.create_entry(second, "db", [{"key": "password", "value": "two-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, first, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    revocation.grant_member(laptop, laptop_client, bob_id, second, confirm_fingerprint=lambda _fp: True)

    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(phone, phone_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert _status(db, bob_id) == "revoked"
    # The laptop re-keys both folders before it sees the phone's re-key.
    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        revocation.push_with_queued_revocations(laptop, laptop_client)
    except RuntimeError:
        pass
    finally:
        undo()
    assert len((pending_states.rekey_batch(laptop.db) or None)["dek_map"]) == 2
    phone_client.push()
    assert not (pending_states.rekey_batch(phone.db) or None)

    for _ in range(3):
        revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert not revocation.queued_revocations(laptop)
    assert not _bob_envelopes_live(db, bob_id)
    phone_client.pull()
    assert {e["name"] for e in phone.list_entries(second)} == {"db"}
    laptop.lock()
    phone.lock()
