"""Stateful test finding SM32: a second grant of a folder survived the member's removal.

The phone and the laptop (same admin account) both shared a folder with Bob
before either saw the other's grant. The laptop removed Bob and re-keyed the
folder, withdrawing only the envelope it held. The phone's envelope, now for
the folder's retired key, stayed live; the phone queued Bob's re-key (SM23),
but with no folder bound to that key it re-keyed nothing and kept the
envelope. With no folder to re-key, the removed member's envelope still goes.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_envelope_of_a_second_grant_goes_when_the_member_is_removed(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    yes = lambda _fp: True  # noqa: E731
    revocation.grant_member(phone, phone_client, bob_id, folder, confirm_fingerprint=yes)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=yes)

    assert revocation.revoke_member(laptop, laptop_client, bob_id) == 1
    laptop_client.pull()  # the phone's envelope, for the key just retired
    phone_client.pull()
    revocation.push_with_queued_revocations(phone, phone_client)

    assert not _bob_envelopes_live(db, bob_id)
    assert not (pending_states.rekey_batch(phone.db) or None)
    assert not revocation.queued_revocations(phone)
    laptop.lock()
    phone.lock()
