"""INV-7, phone against a real server (mobile/test/inv7_phone_way_out_test.dart):
a team log the phone refuses never keeps the vault locked, and each cause has
a way out that runs on the unlocked vault. A damaged cached copy is fetched
again by the next sync (held to its pins) and the personal change made
meanwhile goes out; account keys naming another log are left together with
the phone's own pin. Before, both stopped the unlock ("Wrong password" offline
for the account keys) and the phone had no way out but wiping the app.
"""
from __future__ import annotations

from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401


def test_a_phone_refusing_its_team_log_unlocks_and_finds_the_way_out(team, server, tmp_path):  # noqa: F811
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PASSWORD

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    admin_id = admin.db.get_meta("user_id")
    work = tmp_path / "phone"

    def pushed():
        # The personal entry made while the copy was damaged reached the server.
        entry_id = (work / "pushed_id.txt").read_text(encoding="utf-8").strip()
        assert any(o["id"] == entry_id for o in db._storage["vault_objects"]), entry_id

    out = _phone(url, tmp_path, {
        "username": "admin", "user_id": admin_id, "password": PASSWORD, "genesis": genesis,
    }, {"pushed": pushed}, "test/inv7_phone_way_out_test.dart")
    assert "All tests passed!" in out, out
