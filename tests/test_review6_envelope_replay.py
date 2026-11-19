"""Review main@d615826 H2: a server replayed a removed member's envelope.

A pulled envelope was stored with INSERT OR REPLACE and no version check, so
a server could hand back the old signed envelope of a member whose envelope
tombstone this device had already applied; the server also called the member
active again. The grant again (stateful test SM62) then sealed the folder's
new key to the removed member. created_by came from the unsigned owner_id.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault import revocation
from tests.test_grant_under_rekeyed_key_sm62 import _invite_carol
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_revoke_member_review8 import _bob_envelopes_live
from tests.test_revoke_unseen_grant_sm23 import invite_bob
from tests.test_rollback_commit_token_sm7 import _folder, _two_devices


def _next_seq(db) -> int:
    counter = db._storage["commit_counter"][0]
    seq = counter["next_seq"]
    counter["next_seq"] = seq + 1
    return seq


def _current_folder_dek(vault, folder) -> str:
    return vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]


@pytest.mark.parametrize("pull_tombstone", [True, False], ids=["pulled", "pushed"])
def test_a_replayed_envelope_of_a_removed_member_is_not_taken_back(
    server, tmp_path, monkeypatch, pull_tombstone  # noqa: F811
):
    """Withdrawn either by the tombstone pulled back or by the push the
    server accepted (the replay replaces the tombstone before any pull)."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    client = _client(laptop, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    client.push()
    bob_id = invite_bob(url, client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    signed_grant = copy.deepcopy(_bob_envelopes_live(db, bob_id)[0])

    revocation.revoke_member(laptop, client, bob_id)
    if pull_tombstone:
        client.pull()
    assert not _bob_envelopes_live(db, bob_id)
    new_dek = _current_folder_dek(laptop, folder)
    assert new_dek != signed_grant["parent_ref"]

    # The server puts the signed grant back and calls Bob active again.
    row = next(o for o in db._storage["vault_objects"] if o["id"] == signed_grant["id"])
    row.update(signed_grant, commit_seq=_next_seq(db))
    next(u for u in db._storage["users"] if u["id"] == bob_id)["status"] = "active"

    for _ in range(2):
        client.pull()
        client.push()
    assert not laptop.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE user_id = ?", (bob_id,)
    )
    assert new_dek not in {o["parent_ref"] for o in _bob_envelopes_live(db, bob_id)}

    # The phone never saw the tombstone: the grant came from the server, not
    # from this device, so it is not this device's to seal again.
    phone_client = _client(phone, url)
    for _ in range(2):
        phone_client.pull()
        phone_client.push()
    assert new_dek not in {o["parent_ref"] for o in _bob_envelopes_live(db, bob_id)}
    laptop.lock()
    phone.lock()


def test_a_grant_another_device_withdrew_is_not_sealed_again(
    server, tmp_path, monkeypatch  # noqa: F811
):
    """Capability review run 139: the laptop granted Bob, the phone removed
    him and re-keyed. The server never shows the laptop the tombstone (it
    replays Bob's signed version 1 instead) and calls Bob active. The
    laptop's own grant predates the re-key, which the re-key's signed key id
    proves, so the laptop does not seal the new key to Bob."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    folder = _folder(laptop)
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    laptop_client.push()
    bob_id = invite_bob(url, laptop_client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, laptop_client, bob_id, folder, confirm_fingerprint=lambda _fp: True)
    signed_grant = copy.deepcopy(_bob_envelopes_live(db, bob_id)[0])
    phone_client.pull()

    revocation.revoke_member(phone, phone_client, bob_id)
    assert not _bob_envelopes_live(db, bob_id)
    new_dek = _current_folder_dek(phone, folder)
    assert new_dek != signed_grant["parent_ref"]

    row = next(o for o in db._storage["vault_objects"] if o["id"] == signed_grant["id"])
    row.update(signed_grant, commit_seq=_next_seq(db))
    next(u for u in db._storage["users"] if u["id"] == bob_id)["status"] = "active"

    for _ in range(2):
        laptop_client.pull()
        laptop_client.push()
    assert _current_folder_dek(laptop, folder) == new_dek
    assert not laptop.db.fetchone(
        "SELECT 1 FROM access_envelopes WHERE user_id = ? AND dek_id = ?", (bob_id, new_dek)
    )
    assert new_dek not in {o["parent_ref"] for o in _bob_envelopes_live(db, bob_id)}
    laptop.lock()
    phone.lock()


def test_an_envelope_keeps_its_verified_signer_as_author(
    server, tmp_path, monkeypatch  # noqa: F811
):
    """The phone's grant to Carol, relabelled by the server as written by
    another account, still belongs to the account whose key signed it."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    client = _client(laptop, url)
    folder = _folder(laptop)
    client.push()
    carol_id = _invite_carol(url, client, tmp_path, monkeypatch)
    revocation.grant_member(laptop, client, carol_id, folder, confirm_fingerprint=lambda _fp: True)
    grant = _bob_envelopes_live(db, carol_id)[0]
    grant["owner_id"] = carol_id  # unsigned server metadata

    phone_client = _client(phone, url)
    phone_client.pull()
    row = phone.db.fetchone("SELECT created_by FROM access_envelopes WHERE id = ?", (grant["id"],))
    assert row["created_by"] == laptop.db.get_meta("user_id")
    laptop.lock()
    phone.lock()
