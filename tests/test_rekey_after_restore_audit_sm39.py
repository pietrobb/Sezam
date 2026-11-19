"""Stateful test finding SM39: a re-key pushed after a restore left holes in the audit DAG.

The laptop edited a private entry and pushed it; the server was then restored from a
backup taken before that push. The laptop removed Bob, and the re-key failed
to go out. A pending re-key blocks the full resync, so its push went out
without the rollback check: its audit record landed on a parent the restore
lost, and the phone's full resync refused the audit DAG until the laptop ran
one too. That push now still sends the check; when the server went back, the
account's records it no longer holds go out again with the re-key.
"""

from __future__ import annotations

import copy

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _restore, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_push_after_restore_resends_the_audit_records_it_builds_on(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    private = laptop.create_node("private")
    entry = laptop.create_entry(private, "bank", [{"key": "pin", "value": "1234", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()
    backup = copy.deepcopy(db._storage)

    laptop.update_entry(entry, name="bank2")
    laptop_client.push()
    _restore(db, backup)
    undo = _fail_once(laptop_client, "POST", "/api/sync", "before")
    try:
        revocation.revoke_member(laptop, laptop_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(laptop.db) or None)

    laptop_client.push()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    # The phone saw nothing the restore took; it only pulls what came since.
    assert not phone_client.pull().get("rollback_warning")
    phone_client.full_resync(confirmed=True)
    assert not phone_client.push()["conflicts"]
    laptop.lock()
    phone.lock()
