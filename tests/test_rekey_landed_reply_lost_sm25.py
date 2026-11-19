"""Stateful test finding SM25: a re-key the server took, with its reply lost.

The phone removed Bob; the re-key batch landed but the reply never came, so
the batch stayed pending. The laptop pulled the re-key and edited an entry of
the re-keyed folder. The phone's resent batch was refused; rebased, the
server copy was sealed with the batch's own new key and the rebase stopped
('sealed with another key') on every sync. A server copy sealed with one of
the batch's new DEKs proves the atomic batch is there: it is closed as sent.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once


def test_rekey_whose_reply_was_lost_is_closed_once_seen_on_the_server(
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
    old_dek = phone.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]

    undo = _fail_once(phone_client, "POST", "/api/sync", "after")
    try:
        revocation.revoke_member(phone, phone_client, bob_id)
    except RuntimeError:
        pass
    finally:
        undo()
    assert (pending_states.rekey_batch(phone.db) or None)

    laptop_client.pull()
    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    assert new_dek != old_dek
    laptop.update_entry(entry, name="vpn2")
    assert not laptop_client.push()["conflicts"]

    phone_client.push()
    assert not (pending_states.rekey_batch(phone.db) or None)
    phone_client.pull()
    assert {e["name"] for e in phone.list_entries(folder)} == {"vpn2"}
    server_copy = next(o for o in db._storage["vault_objects"] if o["id"] == entry)
    payload = bytes(server_copy["payload"])
    meta = payload[4:4 + int.from_bytes(payload[:4], "big")]
    assert bytes_to_ulid(parse_envelope(meta).dek_id) == new_dek
    laptop.lock()
    phone.lock()
