"""Stateful test finding SM48: a revoked member's envelope that could not be withdrawn.

The laptop and the phone (same admin account) both shared a folder with Bob,
neither seeing the other's envelope. The laptop removed Bob: its re-key moved
the folder to a new key and withdrew the envelope it knew. The phone's
envelope stayed live under the old key. The laptop pulled it and changed its
password, which re-wraps every key - the old one without its folder. The
push then queued a re-key for the envelope (SM23) that only withdraws it, and
the server refused that for good ("envelope references unknown DEK"): every
later push of the laptop failed. The server now takes
a withdrawal under such a key: it removes access, it grants none.
"""

from __future__ import annotations

from sezam.vault import pending_states
from sezam.vault import revocation
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def granted_twice_then_revoked(server, tmp_path, monkeypatch):  # noqa: F811
    """Both devices grant Bob unseen by each other; the laptop revokes and pulls."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    phone_client.pull()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    yes = lambda _fp: True  # noqa: E731
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=yes)
    revocation.grant_member(phone, phone_client, bob_id, folder, "write", confirm_fingerprint=yes)
    assert len(_bob_envelopes_live(db, bob_id)) == 2

    assert revocation.revoke_member(laptop, laptop_client, bob_id) == 1
    laptop_client.pull()
    assert laptop.db.fetchone("SELECT 1 FROM access_envelopes WHERE user_id = ?", (bob_id,))
    return url, db, laptop, phone, laptop_client, bob_id


def change_password(vault, url, rotate: bool):
    _client(vault, url).prepare_key_change()
    proof = vault.change_password(PASSWORD, PASSWORD + "-2", rotate_identity=rotate)
    proof[:] = b"\x00" * len(proof)
    return _client(vault, url)


def test_envelope_under_a_replaced_key_is_withdrawn(server, tmp_path, monkeypatch):  # noqa: F811
    url, db, laptop, phone, _laptop_client, bob_id = granted_twice_then_revoked(
        server, tmp_path, monkeypatch
    )
    # The password change re-wraps every key, the replaced one without its folder.
    laptop_client = change_password(laptop, url, rotate=False)
    revocation.push_with_queued_revocations(laptop, laptop_client)
    assert not laptop_client.has_pending_key_change()
    assert not (pending_states.rekey_batch(laptop.db) or None)
    assert not _bob_envelopes_live(db, bob_id)
    assert not revocation.queued_revocations(laptop)
    laptop.lock()
    phone.lock()
