"""Stateful test finding SM52: a re-key rebase stopped at a member revoked meanwhile.

The laptop shared a folder with Bob, the phone (same admin account) pulled it.
Then the laptop shared it with Carol too and edited an entry, Carol was revoked
on the server, and the phone - which never saw Carol's grant - revoked Bob.
The re-key was refused for the edit; the rebase pulled Carol's envelope on the
old key and wanted to seal the new key for her, but the phone had never pinned
her key: 'Missing verified encryption key', on every push. Pinned, the new
envelope would still be refused (she is revoked). A member revoked on the
server now gets no envelope on the new key (their own re-key would drop it).
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_member_key_from_own_envelope_sm46 import _invite
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def test_rebase_gives_no_new_key_to_a_member_revoked_meanwhile(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    entry = laptop.create_entry(
        folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}]
    )
    laptop_client.push()
    yes = lambda _fp: True  # noqa: E731
    bob = _invite(url, laptop_client, tmp_path, monkeypatch, "bob")
    revocation.grant_member(laptop, laptop_client, bob, folder, confirm_fingerprint=yes)
    phone_client.pull()

    carol = _invite(url, laptop_client, tmp_path, monkeypatch, "carol")
    revocation.grant_member(laptop, laptop_client, carol, folder, confirm_fingerprint=yes)
    laptop.update_entry(entry, fields=[{"key": "password", "value": "ops-pw-2", "sensitive": True}])
    laptop_client.push()
    laptop_client.revoke_user(carol)

    assert revocation.revoke_member(phone, phone_client, bob) == 1
    assert not (pending_states.rekey_batch(phone.db) or None)
    assert not _bob_envelopes_live(db, bob)
    assert not _bob_envelopes_live(db, carol)

    result = revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not result["blocked"] and not result["too_large"], result
    assert not revocation.queued_revocations(laptop)
    assert not _bob_envelopes_live(db, carol)
    laptop.lock()
    phone.lock()

