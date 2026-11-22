"""Goal #443 (review e443cbc R15, INV-3) on the phone: a retired key vouches
only for what a voucher list names: of the account's current key, of the
phone's own account (its desktop holds the versions) or of a team admin.

A phone that had not pinned a bound (every new phone) took the bound the
server served (retired_seq) and with it any object the server signed with a
leaked retired key.
"""

from __future__ import annotations

from tests.test_archived_key_bound_v4 import _bob_desktop, _forge_envelope, _rotated_team
from tests.test_cross_client_password_change import _phone
from tests.test_grant_folder_access import team  # noqa: F401
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
    finally:
        bob.lock()
    assert {v["user_id"] for v in db._storage["key_vouchers"]} == {bob_id}
    vouched = [
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "entry" and o["parent_ref"] == team[5]["Ops"]
    ]
    honest = _phone(url, tmp_path / "honest", {
        "username": "bob", "password": PASSWORD, "forged": [], "vouched": vouched,
    }, {}, PHONE_TEST)
    assert "All tests passed!" in honest, honest

    [archive] = db._storage["user_key_archives"]
    archive["retired_seq"] = 10**9
    forged = _forge_envelope(db, admin_id, bob_id, ops_dek_id, old_signer, old_box_sk)
    out = _phone(url, tmp_path / "forged", {
        "username": "bob", "password": PASSWORD, "forged": [forged], "vouched": [],
    }, {}, PHONE_TEST)
    assert "All tests passed!" in out, out
