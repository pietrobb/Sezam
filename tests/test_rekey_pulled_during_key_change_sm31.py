"""Stateful test finding SM31: a re-key pulled while a password change waits.

The laptop shared a folder with Bob; the phone removed him (it re-keyed
nothing, SM23) and changed the password, but that push failed. The laptop
then re-keyed the folder. Its new DEK is wrapped under the KEK the server
still has, which the phone had already replaced: the folder was unreadable on
the phone, and its change, which must carry every active DEK, was refused on
every push. The pending change now keeps the old KEK in its journal (sealed
under the new one): such a DEK is re-wrapped and joins the change.
"""

from __future__ import annotations

import pytest

from sezam.vault import revocation
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_pulled_while_own_password_change_waits_stays_readable(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)

    assert revocation.revoke_member(phone, phone_client, bob_id) == 0
    phone_client.prepare_key_change()
    phone.change_password(PASSWORD, "phone-pw-sm31!")
    phone_client = _client(phone, url)
    undo = _fail_once(phone_client, "POST", "/api/sync", "before")
    try:
        phone_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    assert phone_client.has_pending_key_change()

    result = revocation.push_with_queued_revocations(laptop, laptop_client)
    assert result["rekeyed"] == {bob_id: 1}, result
    phone_client.pull()
    assert "ops-pw" in str(phone.read_entry(entry))

    # The change goes out with the re-key's DEK in it, and the laptop takes it over.
    phone_client.push()
    assert not phone_client.has_pending_key_change()
    with pytest.raises(KeyEpochStale):
        laptop_client.pull()
    laptop_client.adopt_rotated_key_material(laptop, "phone-pw-sm31!")
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert "ops-pw" in str(laptop.read_entry(entry))
    laptop.lock()
    phone.lock()
