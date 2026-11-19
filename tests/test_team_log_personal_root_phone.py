"""TL7 on the phone: a member's personal folder is a personal root.

docs/DESIGN_TEAM_LOG.md §10. Real server, real phone (flutter test): Carol's
phone makes her personal folder top-level, the server takes it, the phone keeps
the account's root and lists the personal root among its folders; her desktop
reads what the phone wrote there.
"""

from __future__ import annotations

from sezam.vault.team_migration import found_team_log
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, team  # noqa: F401  (fixture)
from tests.test_team_log_migration import org  # noqa: F401  (fixture)

PHONE_TEST = "test/phone_personal_root_test.dart"


def test_the_phones_personal_folder_is_a_personal_root(org, server, tmp_path):  # noqa: F811
    db, admin, admin_client, _bob, _bob_client, carol, _ids, _ops, _dan = org
    found_team_log(admin, admin_client, lambda _uid, _fp: True)
    _confirm_founder(admin, carol)
    carol_client = _client(carol, server[0])
    carol_client.pull()
    carol_client.push()  # her account's root is on the server

    out = _phone(server[0], tmp_path, {"username": "carol", "password": PASSWORD}, {}, PHONE_TEST)
    assert "All tests passed!" in out, out

    [row] = [o for o in db._storage["vault_objects"]
             if o["object_type"] == "node" and o["parent_ref"] is None
             and o["owner_id"] == carol.db.get_meta("user_id")
             and o["id"] != carol.db.get_meta("root_node_id")]
    carol_client.pull()
    assert carol.db.get_meta("root_node_id") != row["id"]
    assert carol.find_entry_by_path("Z telefonu/pin")["fields"][0]["value"] == "7"
