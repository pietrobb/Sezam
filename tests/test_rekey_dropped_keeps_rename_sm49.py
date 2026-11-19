"""Stateful test finding SM49: a dropped re-key took a rename with it.

The laptop shared a folder with Bob and renamed its subfolder without pushing.
The phone (same admin account) removed Bob and re-keyed the folder first. The
laptop's next push re-keyed again for Bob's envelope it still held; the server
refused the batch, the pull bound the folder to the phone's key and the
superseded batch was dropped. The subfolder took the server's copy and the
rename was gone without a conflict. The rename is now held like any other
local edit and comes back as a conflict with the server's copy.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rekey_rename_deleted_elsewhere_sm41 import _names
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_rename_made_before_a_superseded_rekey_survives(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    parent = _folder(laptop)
    sub = laptop.create_node("Sub", parent_id=parent)
    laptop.create_entry(sub, "vpn", [{"key": "password", "value": "pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, parent, confirm_fingerprint=lambda _fp: True)
    phone_client.pull()

    laptop.rename_node(sub, "Renamed")
    assert revocation.revoke_member(phone, phone_client, bob_id) == 1

    revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert "Renamed" in _names(laptop, parent), "the rename was dropped without the user"
    conflicts = {c["id"] for c in laptop_client.get_pull_conflicts()}
    if sub in conflicts:
        laptop_client.resolve_conflict(sub, "local")
    laptop_client.push()
    phone_client.pull()
    assert "Renamed" in _names(phone, parent)
    laptop.lock()
    phone.lock()
