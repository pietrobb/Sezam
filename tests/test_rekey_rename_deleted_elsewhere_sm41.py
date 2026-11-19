"""Stateful test finding SM41: a folder rename lost to its own re-key.

The phone deleted a shared folder; the laptop, which had not seen it, renamed
the folder and then removed the member it was shared with. The re-key was
refused for the delete and rebased on the server's copy: the folder rode in
the batch as the server had it (deleted) and the rename was gone without a
conflict. The rename is now held and comes back as a conflict with the
server's delete, as an entry edit does (SM37).
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _names(vault, parent) -> set[str]:
    return {n["name"] for n in vault.list_nodes(parent)}


def test_rename_of_a_folder_deleted_elsewhere_survives_its_rekey(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    parent = _folder(laptop)
    sub = laptop.create_node("Sub", parent_id=parent)
    laptop.create_entry(sub, "vpn", [{"key": "password", "value": "pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)

    phone.delete_node(sub)
    phone_client.push()

    laptop.rename_node(sub, "Renamed")
    revocation.grant_member(laptop, laptop_client, bob_id, sub, confirm_fingerprint=lambda _fp: True)
    assert revocation.revoke_member(laptop, laptop_client, bob_id) == 1
    assert not (pending_states.rekey_batch(laptop.db) or None)

    conflicts = {c["id"]: c for c in laptop_client.get_pull_conflicts()}
    assert conflicts[sub]["server_is_deleted"] == 1
    assert "Renamed" in _names(laptop, parent)

    laptop_client.resolve_conflict(sub, "local")
    laptop_client.push()
    phone_client.pull()
    assert "Renamed" in _names(phone, parent)
    laptop.lock()
    phone.lock()
