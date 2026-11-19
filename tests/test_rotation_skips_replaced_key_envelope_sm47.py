"""Stateful test finding SM47: an identity rotation stuck on a revoked member's envelope.

As in SM48, the laptop removed Bob and then pulled the phone's envelope for
him, live under the folder key the re-key replaced. Rotating the laptop's
identity re-sealed every envelope the account sealed, that one included: a
new envelope for a removed member, under a key now re-wrapped without its
folder. The server refused the whole rotation for good. The rotation now
leaves envelopes under a replaced folder key alone; they open nothing current.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_withdraw_envelope_under_replaced_key_sm48 import (
    change_password,
    granted_twice_then_revoked,
)


def test_identity_rotation_after_pulling_a_revoked_members_envelope(server, tmp_path, monkeypatch):  # noqa: F811
    url, db, laptop, phone, _laptop_client, bob_id = granted_twice_then_revoked(
        server, tmp_path, monkeypatch
    )
    laptop_client = change_password(laptop, url, rotate=True)
    revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not laptop_client.has_pending_key_change()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert not _bob_envelopes_live(db, bob_id)
    laptop.lock()
    phone.lock()
