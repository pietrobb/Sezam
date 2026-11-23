"""Goal #443 (review e443cbc R15, INV-3) on the phone: a retired key vouches
only for what a voucher list names: of the account's current key, of the
phone's own account (its desktop or phone holds the versions) or of a team
admin.

A phone that had not pinned a bound (every new phone) took the bound the
server served (retired_seq) and with it any object the server signed with a
leaked retired key.
"""

from __future__ import annotations

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from sezam.vault.revocation import grant_member
from tests.test_archived_key_bound_v4 import _bob_desktop, _forge_envelope, _rotated_team
from tests.test_cross_client_password_change import _phone, _web_login
from tests.test_grant_folder_access import _readable_passwords, _yes, team  # noqa: F401
from tests.test_identity_rotation import _rotate
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401

PHONE_TEST = "test/phone_key_vouchers_test.dart"


def test_a_new_phone_refuses_what_a_leaked_retired_key_signs_under_any_bound(
    team, monkeypatch, tmp_path  # noqa: F811
):
    url, db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk = _rotated_team(team, monkeypatch)
    bob, client = _bob_desktop(tmp_path, url)  # Bob's vault root reaches the server
    try:
        client.pull()
        client.push()
        # Capability review run 480: the admin rotated with a client from
        # before #443 and never syncs again. Bob's desktop holds the folder
        # and vouches for it; his new phone takes it from that list.
        db._storage["key_vouchers"] = []
        client.pull()
        # R16-M4: what Bob writes after his list; his new phone's first
        # pull brings it and must not vouch for it (the desktop's rule: a
        # list names only what the device held before the pull).
        bob.create_entry(bob.db.get_meta("root_node_id"), "wifi", [{"key": "password", "value": "w", "sensitive": True}])
        client.push()
    finally:
        bob.lock()
    assert {v["user_id"] for v in db._storage["key_vouchers"]} == {bob_id}
    lists = list(db._storage["key_vouchers"])
    vouched = [
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "entry" and o["parent_ref"] == team[5]["Ops"]
    ]
    honest = _phone(url, tmp_path / "honest", {
        "username": "bob", "password": PASSWORD, "forged": [], "vouched": vouched,
    }, {}, PHONE_TEST)
    assert "All tests passed!" in honest, honest
    assert db._storage["key_vouchers"] == lists

    [archive] = db._storage["user_key_archives"]
    archive["retired_seq"] = 10**9
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    out = _phone(url, tmp_path / "forged", {
        "username": "bob", "password": PASSWORD, "forged": [forged], "vouched": [],
    }, {}, PHONE_TEST)
    assert "All tests passed!" in out, out


def test_a_member_with_only_a_phone_keeps_what_the_sole_inactive_admin_s_retired_key_signed(
    team, monkeypatch, tmp_path  # noqa: F811
):
    """Capability review run 482: the sole admin rotated with a client from
    before #443 and never syncs again; Bob has no desktop. His phone holds
    the folder and vouches for it, so his new phone and web sessions read it."""
    # The vault Bob registered with sends its root once, before Ops is
    # shared; it never syncs again (the phone needs a root to sign in).
    url, db, admin, admin_client, bob_id, folders = team
    admin_client.approve_user(bob_id)
    bob, client = _bob_desktop(tmp_path, url)
    try:
        client.push()
    finally:
        bob.lock()
    assert not db._storage["key_vouchers"]
    admin_id = admin.db.get_meta("user_id")
    grant_member(admin, admin_client, bob_id, folders["Ops"], confirm_fingerprint=_yes)
    ops_dek_id, _ = admin.dek_mgr.get_dek_for_node(folders["Ops"])
    old_signer = SigningKey(bytes(admin.keypair.to_nacl_signing_key()))
    old_box_sk = bytes(PrivateKey(bytes(admin.keypair.encryption_sk)))
    vouched = [
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "entry" and o["parent_ref"] == folders["Ops"]
    ]

    def rotate_before_443():
        # The admin's rotation carries no list (a client from before #443),
        # and nothing posted before it is left either.
        assert _rotate(admin, monkeypatch).exit_code == 0
        db._storage["key_vouchers"] = []

    # Bob's phone holds Ops; after the rotation it pulls again.
    held = _phone(url, tmp_path / "held", {
        "username": "bob", "password": PASSWORD, "forged": [], "vouched": vouched,
        "post_after": "rotated",
    }, {"rotated": rotate_before_443}, PHONE_TEST)
    assert "All tests passed!" in held, held
    assert {v["user_id"] for v in db._storage["key_vouchers"]} == {bob_id}

    fresh = _phone(url, tmp_path / "fresh", {
        "username": "bob", "password": PASSWORD, "forged": [], "vouched": vouched,
    }, {}, PHONE_TEST)
    assert "All tests passed!" in fresh, fresh
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    assert _readable_passwords(member) == {"vpn": "ops-pw"}
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is not None and forged in str(member["error"]), member
