"""Review 1141a20 (R9-G), phone: unsent writes and a folder re-key.

The admin's phone holds a new item and an edit in the team folder Ops, not yet
sent, sealed with Ops' key. On the desktop the admin removes Carol, which
re-keys Ops (and seals its items again). The log refuses an old key
generation, so the phone refused its whole push, again on every sync: the
writes never left the phone. Sealed again with the folder's current key they
are sent, and the desktop reads them.
"""

from __future__ import annotations

from sezam import teamlog
from sezam.vault import revocation
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _carol, _member, _ops

PHONE_TEST = "test/phone_unsent_rekey_test.dart"


def test_the_phone_sends_unsent_writes_after_a_folder_re_key(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    _, admin, admin_client, bob, _bob_client = team
    carol = _carol(url, admin_client, tmp_path, monkeypatch)
    carol_id = carol.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    admin_client.append_team_log([("member.add", _member(carol))])
    carol.lock()
    ops = _ops(admin)
    vpn = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, carol_id, ops, "read")
    old_key = teamlog.current_key(admin_client.team_state(), ops)

    def rekeyed():
        assert revocation.revoke_member(admin, admin_client, carol_id) == 1
        assert teamlog.current_key(admin_client.team_state(), ops) != old_key

    out = _phone(url, tmp_path, {
        "username": "admin", "password": PASSWORD, "ops": ops, "vpn": vpn,
    }, {"rekeyed": rekeyed}, PHONE_TEST)
    assert "All tests passed!" in out, out

    admin_client.pull()
    new_key = teamlog.current_key(admin_client.team_state(), ops)
    for name in ("offline-new", "vpn-edited"):
        [item] = [e for e in admin.list_entries(ops) if e["name"] == name]
        row = admin.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (item["id"],))
        assert (row["dek_id"] or admin.dek_mgr.get_dek_for_node(ops)[0]) == new_key
    assert admin.get_field_value(vpn, "password") == "ops-pw"
