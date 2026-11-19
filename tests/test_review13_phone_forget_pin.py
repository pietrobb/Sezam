"""Review c78fd19 (medium), phone: a team log the server lost for good left the
phone on TEAM LOG MISMATCH with no way out; forgetting the pin lets it follow
the new log (mobile/test/review13_phone_forget_pin_test.dart).
"""
from __future__ import annotations

from tests.test_integration_client_server import server  # noqa: F401
from tests.test_review13_forget_pin import _reseed_server
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401


def test_a_phone_leaves_a_lost_team_log(team, server, tmp_path):  # noqa: F811
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    old = client.team_state().genesis_hash
    admin_id = admin.db.get_meta("user_id")

    def anchor(genesis):
        # The account bundle on the server names [genesis] (another device anchored it).
        from sezam.crypto.aead import encrypt_account_keypair
        user = next(u for u in db._storage["users"] if u["id"] == admin_id)
        keys, saved = admin.keypair, (admin.keypair.confirmed_genesis, admin.keypair.pre_anchor)
        keys.confirmed_genesis, keys.pre_anchor = None, b""
        try:
            raw = keys.serialize_private()
        finally:
            keys.confirmed_genesis, keys.pre_anchor = saved
        user["encrypted_keypair"] = encrypt_account_keypair(
            raw, genesis,
            admin.current_kek, admin.db.get_meta("kek_dek_id").encode(), admin_id.encode())

    def reseed():
        new = _reseed_server(db, client)
        (tmp_path / "phone" / "new_genesis.txt").write_text(new, encoding="utf-8")

    def anchor_new():
        # The desktop changes the password and anchors the account to the new log:
        # the phone takes the server's bundle and checks it against its own.
        from tests.test_integration_client_server import NEW_PASSWORD, _client
        new = client.team_state().genesis_hash
        proof = admin.change_password(PASSWORD, NEW_PASSWORD)
        proof[:] = bytes(len(proof))
        admin.unlock(NEW_PASSWORD)
        assert _client(admin, url).push()["conflicts"] == []
        anchor(new)

    anchor(old)  # capability #374: the phone's stored keypair carries the old anchor
    out = _phone(url, tmp_path, {
        "username": "admin", "user_id": admin_id,
        "password": PASSWORD, "new_password": "integration-new-pw!", "genesis": old,
    }, {"reseed": reseed, "anchor_new": anchor_new}, "test/review13_phone_forget_pin_test.dart")
    assert "All tests passed!" in out, out
