"""Stateful test finding SM27: a re-key's audit record went out without its parents.

The phone edited an entry without syncing, then removed Bob. The re-key's
audit record names the phone's earlier audit records as parents, but the
atomic batch held only the re-key objects; the rest was to follow in the next
push. The reply was lost, the next push never came, and the server held a
record whose parents it did not have: the laptop's full resync refused the
audit DAG. Unsent audit records now go with the atomic batch.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_batch_carries_the_audit_records_it_builds_on(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    phone.update_entry(entry, name="vpn2")
    undo = _fail_once(phone_client, "POST", "/api/sync", "after")
    try:
        revocation.revoke_member(phone, phone_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()

    assert (pending_states.rekey_batch(phone.db) or None)
    laptop_client.full_resync(confirmed=True)
    phone_client.push()
    laptop.lock()
    phone.lock()
