"""Stateful test finding SM61: a landed identity rotation survives a key takeover.

The laptop rotated its identity, which re-seals Bob's envelope as a new one;
the server took the batch but the reply was lost, and the laptop's next pull
went past it. The phone took the rotation over and changed the password.
Taking that change over, the laptop dropped its rotation as one that never
reached the server: the re-sealed envelope went, the original came back. The
server held the re-sealed one live and no pull brought it again, so Bob's
grant was on no device and revoking Bob left it on the server. The server's
keypair is the laptop's own rotated one: the rotation landed and stays.
"""

from __future__ import annotations

from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices
from tests.test_sync_state_machine import _fail_once
from sezam.vault import pending_states
from sezam.vault import revocation
from sezam.vault.sync_client import KeyEpochStale

NEW_PASSWORD = "pw-11-Sezam!"


def _bob_envelopes_local(vault, bob_id) -> set[str]:
    return {r["id"] for r in vault.db.fetchall(
        "SELECT id FROM access_envelopes WHERE user_id = ?", (bob_id,))}


def test_landed_rotation_is_kept_when_the_next_key_change_is_taken_over(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)

    laptop_client.prepare_key_change()
    proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    laptop_client = _client(laptop, url)
    undo = _fail_once(laptop_client, "POST", "/api/sync", "after")
    try:
        laptop_client.push()
    except RuntimeError:
        pass
    finally:
        undo()
    resealed = {o["id"] for o in _bob_envelopes_live(db, bob_id)}
    assert resealed and (pending_states.rekey_batch(laptop.db) or None)
    laptop_client.pull()  # goes past the re-sealed envelope

    try:
        phone_client.pull()
    except KeyEpochStale:
        pass
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    phone_client = _client(phone, url)
    phone_client.prepare_key_change()
    proof = phone.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    phone_client = _client(phone, url)
    phone_client.push()
    assert {o["id"] for o in _bob_envelopes_live(db, bob_id)} == resealed

    laptop_client.adopt_rotated_key_material(laptop, NEW_PASSWORD)
    laptop_client = _client(laptop, url)
    assert _bob_envelopes_local(laptop, bob_id) == resealed
    assert not (pending_states.rekey_batch(laptop.db) or None)
    laptop_client.pull()
    laptop_client.push()
    assert _bob_envelopes_local(laptop, bob_id) == resealed
    assert {o["id"] for o in _bob_envelopes_live(db, bob_id)} == resealed
    laptop.lock()
    phone.lock()
