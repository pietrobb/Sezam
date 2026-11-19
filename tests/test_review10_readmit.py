"""Review 8595ec1 (low, R10-F step 6): a restore from before a member's identity
rotation cut off a member who has since lost the device with the rotated key.

The restored server knows only the key the log retired (K1); the log names K2,
which nobody holds any more. K1 may only read the log (capability run 300), and
member.keys needs K2's signature, so nothing let the member back in. Now an
admin's key-reset grant lets the K1 account send an identity rotation to fresh
keys (with the account password, as every rotation), and 'sezam team-log
readmit' (member.remove + member.add in one append, after the admin compared
the new fingerprint) re-keys the member's folders and grants them again.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from sezam.crypto.keys import compute_fingerprint
from sezam.vault import revocation, team_migration
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review9_team_identity import _rotate
from tests.test_review9_team_log_restore import _pull_confirming
from tests.test_team_log_desktop import (  # noqa: F401
    _confirm_founder,
    _forget_server_cache,
    _found_with_bob,
    team,
)
from tests.test_team_log_desktop_changes import _ops


def _confirming(call, client):
    from sezam.vault.sync_common import TofuKeyChangeError

    for _ in range(4):
        try:
            return call()
        except TofuKeyChangeError as change:
            client.confirm_tofu_key_change(change, change.new_fingerprint)
    raise AssertionError("kept asking to confirm keys")


def _fingerprint(vault) -> str:
    return compute_fingerprint(bytes(vault.keypair.signing_pk), bytes(vault.keypair.encryption_pk))


def _lost_rotated_device(team, url, tmp_path):  # noqa: F811
    """Bob rotated K1 -> K2, lost that device, the server went back to K1."""
    db, admin, client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(client, bob)
    ops = _ops(admin)
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob_id, ops, "write")
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.get_field_value(item, "password") == "ops-pw"
    own = bob.create_entry(bob.db.get_meta("root_node_id"), "mine", [{"key": "password", "value": "own"}])
    bob_client.push()
    backup = copy.deepcopy(db._storage)
    _rotate(bob, bob_client, url).push()
    rotated_pk = bytes(bob.keypair.signing_pk).hex()
    admin_client = _client(admin, url)
    _pull_confirming(admin_client)
    assert admin_client.team_state().members[bob_id].signing_pk == rotated_pk
    bob.lock()  # the device holding K2 is gone

    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    _forget_server_cache()
    _pull_confirming(admin_client)  # puts member.keys (K2) back

    laptop = _vault(tmp_path / "laptop", "bob")
    cli._server_connect_flow(url, laptop, PASSWORD)  # K1, the key the log retired
    assert laptop.db.get_meta("user_id") == bob_id
    assert bytes(laptop.keypair.signing_pk).hex() != rotated_pk
    _confirm_founder(admin, laptop)  # the user compares it on the new device
    return admin_client, laptop, ops, item, own


def test_a_member_who_lost_the_rotated_device_is_readmitted(team, server, tmp_path):  # noqa: F811
    url, _ = server
    db, admin, _, bob, _ = team
    bob_id = bob.db.get_meta("user_id")
    admin_client, laptop, ops, item, own = _lost_rotated_device(team, url, tmp_path)

    admin_client.allow_key_reset(bob_id)  # the admin knows the member lost the device
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    _rotate(laptop, laptop_client, url).push()  # fresh keys K3, with the password
    fresh = _fingerprint(laptop)
    _confirming(lambda: admin_client.full_resync(confirmed=True), admin_client)  # 'the server went back'

    with pytest.raises(ValueError, match="not confirmed"):
        team_migration.readmit_member(admin, admin_client, bob_id, confirm_fingerprint=lambda fp: False)
    team_migration.readmit_member(admin, admin_client, bob_id, confirm_fingerprint=lambda fp: fp == fresh)

    state = admin_client.team_state()
    member = state.members[bob_id]
    assert member.active and member.signing_pk == bytes(laptop.keypair.signing_pk).hex()
    assert state.access[ops][bob_id] == "write"
    laptop_client = _client(laptop, url)
    _pull_confirming(laptop_client)
    assert laptop.get_field_value(item, "password") == "ops-pw"
    assert laptop.get_field_value(own, "password") == "own"
    written = laptop.create_entry(ops, "back-in", [{"key": "password", "value": "k3"}])
    result = laptop_client.push()
    assert written in [a["id"] for a in result["accepted"]], result  # (a member's audit rows stay 'admin only')
    _pull_confirming(admin_client)
    assert admin.get_field_value(written, "password") == "k3"


def test_the_retired_key_alone_still_cannot_rotate(team, server, tmp_path):  # noqa: F811
    """Without an admin's grant the K1 holder (maybe the thief the rotation was
    for) still only reads the log: no rotation to keys of its own."""
    url, _ = server
    admin_client, laptop, *_ = _lost_rotated_device(team, url, tmp_path)
    laptop_client = _client(laptop, url)
    with pytest.raises(RuntimeError, match="identity_key_retired|retired"):
        laptop_client.pull()
    with pytest.raises(RuntimeError, match="identity_key_retired|retired"):
        _rotate(laptop, laptop_client, url).push()
