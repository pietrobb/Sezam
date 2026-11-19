"""Stateful test finding SM83: a member's key could not be proven after an identity take-over.

The laptop shared a folder with Bob and Carol, removed Bob (re-keying the
folder) and rotated the account identity. The phone had pulled the first
envelopes but nothing after. Taking the rotation over, it holds the new
keypair while its envelopes for Carol are still sealed under the old one, so
the server's key for Carol no longer opened any of them and was not pinned:
finishing Bob's re-key there failed on every push ('Missing verified
encryption key'). The phone now proves the keys with the identity it held
before it takes the new one.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_member_key_from_own_envelope_sm46 import _shared_with_two
from tests.test_revoke_member_review8 import _bob_envelopes_live


def _rotate_identity(vault, url):
    client = _client(vault, url)
    client.prepare_key_change()
    proof = vault.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    client = _client(vault, url)
    client.push()
    assert not client.has_pending_key_change()


def test_queued_rekey_after_taking_over_a_rotated_identity(server, tmp_path, monkeypatch):  # noqa: F811
    url, db, laptop, phone, phone_client, bob, carol = _shared_with_two(server, tmp_path, monkeypatch)
    laptop_client = _client(laptop, url)
    assert revocation.revoke_member(laptop, laptop_client, bob) == 1
    _rotate_identity(laptop, url)

    try:
        phone_client.pull()
    except KeyEpochStale:
        pass
    phone_client.adopt_rotated_key_material(phone, PASSWORD)

    revocation.push_with_queued_revocations(phone, phone_client)
    phone_client.pull()
    assert not revocation.queued_revocations(phone)
    assert not (pending_states.rekey_batch(phone.db) or None)
    assert not _bob_envelopes_live(db, bob)
    assert _bob_envelopes_live(db, carol)
    laptop.lock()
    phone.lock()
