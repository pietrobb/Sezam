"""Goal #443 (review e443cbc R15, INV-3): a retired key vouches only for what
a list of the account's current key names, on the desktop.

Before, the server picked both numbers that bounded a retired key: the
archive's ``retired_seq`` and each object's ``commit_seq``. A device that had
not pinned a bound (a new device, a full resync) took any object the server
signed with a leaked retired key, given a high enough ``retired_seq``.
"""

from __future__ import annotations

import shutil

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam.vault.crud import Vault
from sezam.vault.revocation import grant_member
from sezam.vault.sync_common import TofuKeyChangeError
from tests.test_archived_key_bound_v4 import _bob_desktop, _forge_envelope, _rotated_team
from tests.test_grant_folder_access import _yes, team  # noqa: F401
from tests.test_identity_rotation import _rotate
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401


def _old_key_entries(db, folder_id: str) -> list[str]:
    return [
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "entry" and o["parent_ref"] == folder_id and not o["is_deleted"]
    ]


def _holds(vault, entry_ids) -> bool:
    return all(vault.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (i,)) for i in entry_ids)


def test_a_new_device_refuses_what_a_leaked_retired_key_signs_under_any_bound(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(team, monkeypatch)
    # The server stretches the bound before the member's new desktop saw one.
    [archive] = db._storage["user_key_archives"]
    archive["retired_seq"] = 10**9
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    bob, client = _bob_desktop(tmp_path, url)
    try:
        with pytest.raises(RuntimeError, match=forged):
            client.pull()
    finally:
        bob.lock()


def test_what_the_old_key_signed_before_its_rotation_is_vouched_for(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, *_ = _rotated_team(team, monkeypatch)
    old_key_signed = _old_key_entries(db, team[5]["Ops"])
    assert old_key_signed and db._storage["key_vouchers"]
    bob, client = _bob_desktop(tmp_path, url)
    try:
        assert client.pull()["pulled"] > 0
        assert _holds(bob, old_key_signed)
    finally:
        bob.lock()


def test_a_rotation_from_before_vouchers_gets_its_list_from_the_device_holding_the_key(
    team, monkeypatch, tmp_path  # noqa: F811
):
    admin = team[2]
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(team, monkeypatch)
    db._storage["key_vouchers"] = []  # a rotation pushed by a client from before #443
    admin.db.set_meta("key_vouchers_checked", "")
    old_key_signed = _old_key_entries(db, team[5]["Ops"])

    bob, client = _bob_desktop(tmp_path, url)
    try:
        with pytest.raises(RuntimeError, match="invalid or unverifiable signature"):
            client.pull()  # nothing vouches for the old key's objects yet
        _client(admin, url).pull()  # the admin's desktop holds them and posts the list
        assert db._storage["key_vouchers"]
        fresh = _client(bob, url)
        assert fresh.pull()["pulled"] > 0
        assert _holds(bob, old_key_signed)
        # What the server signs with the leaked key later is still refused.
        forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
        with pytest.raises(RuntimeError, match=forged):
            _client(bob, url).pull()
    finally:
        bob.lock()


def test_an_inactive_admin_s_rotation_from_before_vouchers_leaves_members_their_items(
    team, monkeypatch, tmp_path  # noqa: F811
):
    """Capability review run 480: only the rotated account's own updated
    desktop could vouch for what its retired key signed. The admin rotated
    with a client from before #443 and never syncs again; the member's devices
    still read the folder, and what the leaked key signs later is refused."""
    url, db, admin, admin_client, bob_id, folders = team
    admin_id = admin.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    ops_dek_id, _ = admin.dek_mgr.get_dek_for_node(folders["Ops"])
    shutil.copytree(tmp_path / "bob", tmp_path / "bob-next")  # Bob's next device
    bob = Vault(tmp_path / "bob")
    bob.unlock(PASSWORD)
    try:
        _client(bob, url).pull()
    finally:
        bob.lock()
    old_signer = SigningKey(bytes(admin.keypair.to_nacl_signing_key()))
    old_box_sk = bytes(PrivateKey(bytes(admin.keypair.encryption_sk)))
    assert _rotate(admin, monkeypatch).exit_code == 0
    db._storage["key_vouchers"] = []  # a rotation from before #443; the admin is gone
    old_key_signed = _old_key_entries(db, folders["Ops"])

    bob.unlock(PASSWORD)
    try:
        assert _holds(bob, old_key_signed)
        client = _client(bob, url)
        with pytest.raises(TofuKeyChangeError) as raised:
            client.pull()
        client.confirm_tofu_key_change(raised.value, raised.value.new_fingerprint)
        client.full_resync(confirmed=True)  # keeps the copies it verified
        assert _holds(bob, old_key_signed)
        _client(bob, url).pull()  # and vouches for them for Bob's other devices
    finally:
        bob.lock()
    assert {v["user_id"] for v in db._storage["key_vouchers"]} == {bob_id}

    nxt = Vault(tmp_path / "bob-next")
    nxt.unlock(PASSWORD)
    try:
        assert _client(nxt, url).pull()["pulled"] > 0  # vouched by Bob's own list
        assert _holds(nxt, old_key_signed)
        forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
        with pytest.raises(RuntimeError, match=forged + ".*a retired key of " + admin_id):
            _client(nxt, url).full_resync(confirmed=True)
    finally:
        nxt.lock()
