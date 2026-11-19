"""TL7 on the phone: a tier-2 item in a team folder is neither shown nor edited.

docs/DESIGN_TEAM_LOG.md §10. The admin's tier-2 item in Ops is from before the
log (an older organisation). Its key is not in the log, so the phone does not
take it - an edit there would be sealed under the folder's key, readable by Bob
and Carol. A plain item there is edited and taken by the server; the desktop
still reads the tier-2 item (its way out is a move to a personal root).
"""

from __future__ import annotations

from sezam.vault.team_migration import found_team_log
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import team  # noqa: F401  (fixture)
from tests.test_team_log_migration import org  # noqa: F401  (fixture)

PHONE_TEST = "test/phone_tier2_team_folder_test.dart"


def test_the_phone_does_not_edit_a_tier2_item_in_a_team_folder(org, server, tmp_path):  # noqa: F811
    db, admin, admin_client, _bob, _bob_client, _carol, _ids, ops, _dan = org
    tier2 = admin.create_entry(ops, "trezor", [{"key": "pin", "value": "1"}], tier=2)
    plain = admin.create_entry(ops, "bezne", [{"key": "pin", "value": "4"}])
    assert [c for c in admin_client.push()["conflicts"] if c["error"] != "admin only"] == []
    found_team_log(admin, admin_client, lambda _uid, _fp: True)

    out = _phone(server[0], tmp_path, {"username": "admin", "password": PASSWORD,
                                       "tier2": tier2, "plain": plain, "ops": ops}, {}, PHONE_TEST)
    assert "All tests passed!" in out, out

    admin_client.pull()
    assert admin.read_entry(tier2)["fields"][0]["value"] == "1"
    assert admin.read_entry(plain)["fields"][0]["value"] == "8"
