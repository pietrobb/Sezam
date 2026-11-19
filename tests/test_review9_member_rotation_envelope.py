"""Review 1141a20 H1 / goal #369: a member's own identity rotation.

The member cannot seal team keys, so after bob rotates only the envelope on
his retired encryption key existed; bob's next unlock failed with
"No authorized team envelope opens this key". The admin's device, on pulling
the signed member.keys, seals the team keys bob holds to his new key.
"""

from __future__ import annotations

import pytest

from sezam.vault import revocation
from sezam.vault.sync_rekey import ROTATION_SEALED_META
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_review9_team_identity import _rotate
from tests.test_review9_team_log_restore import _pull_confirming
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401
from tests.test_team_log_desktop_changes import _ops


def _granted(team, url):  # noqa: F811
    db, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    revocation.grant_member(admin, client, bob.db.get_meta("user_id"), ops, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.get_field_value(item, "password") == "ops-pw"
    return ops, item


def _sealed_to_bob(admin, bob, ops) -> int:
    dek_id = admin.dek_mgr.get_dek_for_node(ops)[0]
    return len(admin.db.fetchall(
        "SELECT 1 FROM access_envelopes WHERE dek_id = ? AND user_id = ?",
        (dek_id, bob.db.get_meta("user_id")),
    ))


def _bob_reads(bob, url, item, value="ops-pw"):
    bob.lock()
    bob.unlock(PASSWORD)
    _pull_confirming(_client(bob, url))
    assert bob.get_field_value(item, "password") == value


def test_member_rotation_keeps_the_member_reading(team, server):  # noqa: F811
    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)

    _rotate(bob, bob_client, url).push()
    # Before any admin acts the member unlocks; only the team key is missing.
    bob.lock()
    bob.unlock(PASSWORD)
    admin_client = _client(admin, url)
    _pull_confirming(admin_client)  # the admin sees member.keys
    admin_client.push()

    _bob_reads(bob, url, item)
    # The admin writes after the rotation; bob still reads it.
    later = admin.create_entry(ops, "later", [{"key": "password", "value": "later-pw"}])
    _client(admin, url).push()
    _pull_confirming(_client(bob, url))
    assert bob.get_field_value(later, "password") == "later-pw"


def test_the_rotated_member_reads_in_the_browser(team, server, tmp_path):  # noqa: F811
    from tests.web_tab import WebTab

    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)
    _rotate(bob, bob_client, url).push()
    admin_client = _client(admin, url)
    _pull_confirming(admin_client)
    admin_client.push()

    tab = WebTab(url, tmp_path / "member-rotation-tab.log")
    try:
        seen = tab.do("login", username="bob", password=PASSWORD)
        assert seen["error"] is None, seen
        [entry] = [e for e in seen["view"]["entries"] if e["id"] == item]
        assert not entry["undecryptable"] and entry["password"] == "ops-pw", entry
    finally:
        tab.kill()


def test_a_browser_admin_seals_to_the_rotated_member(team, server, tmp_path):  # noqa: F811
    """Capability run 286: the founder administers from the browser only."""
    from tests.web_tab import WebTab

    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)
    _rotate(bob, bob_client, url).push()
    # The founder's desktop never pulls the member.keys.

    tab = WebTab(url, tmp_path / "browser-admin.log")
    try:
        seen = tab.do("login", username="admin", password=PASSWORD)
        assert seen["error"] is None, seen
        seen = tab.do("refresh")
        assert seen["error"] is None, seen
        assert not seen["view"]["dirty"], seen["view"]
    finally:
        tab.kill()
    _bob_reads(bob, url, item)


def _server_envelopes(db, dek_id: str, user_id: str) -> int:
    return sum(
        1 for o in db._storage["vault_objects"]
        if o["object_type"] == "envelope" and o["parent_ref"] == dek_id
        and o.get("target_user_id") == user_id and not o.get("is_deleted")
    )


@pytest.mark.parametrize("mode", ["before", "after"])
def test_a_browser_seal_whose_push_fails_is_sent_once(team, server, tmp_path, mode):  # noqa: F811
    """The push never arrives, or arrives and its answer is lost; a later sync
    (another tab, then the desktop of the same account) seals exactly once."""
    from tests.web_tab import WebTab

    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)
    dek_id = admin.dek_mgr.get_dek_for_node(ops)[0]
    bob_id = bob.db.get_meta("user_id")
    before = _server_envelopes(db, dek_id, bob_id)
    _rotate(bob, bob_client, url).push()

    tab = WebTab(url, tmp_path / f"browser-admin-{mode}.log")
    try:
        seen = tab.do("login", username="admin", password=PASSWORD,
                      fail={"method": "POST", "path": "/api/sync", "mode": mode})
        assert seen["error"] is None, seen
        assert _server_envelopes(db, dek_id, bob_id) == before + (mode == "after")
        assert tab.do("refresh")["error"] is None
        assert _server_envelopes(db, dek_id, bob_id) == before + 1
    finally:
        tab.kill()
    tab = WebTab(url, tmp_path / f"browser-admin-{mode}-fresh.log")  # no marker in this browser
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
    finally:
        tab.kill()
    admin_client = _client(admin, url)
    _pull_confirming(admin_client)
    admin_client.push()
    assert _server_envelopes(db, dek_id, bob_id) == before + 1
    _bob_reads(bob, url, item)


def test_a_seal_lost_before_the_push_is_sent_once(team, server):  # noqa: F811
    """The device stops after sealing: the next run neither repeats nor loses it."""
    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)
    before = _sealed_to_bob(admin, bob, ops)
    _rotate(bob, bob_client, url).push()

    _pull_confirming(_client(admin, url))  # sealed locally, never pushed
    assert _sealed_to_bob(admin, bob, ops) == before + 1
    admin_client = _client(admin, url)  # restarted
    _pull_confirming(admin_client)
    assert _sealed_to_bob(admin, bob, ops) == before + 1
    admin_client.push()
    _bob_reads(bob, url, item)


def test_a_failed_seal_is_retried_on_the_next_pull(team, server, monkeypatch):  # noqa: F811
    from sezam.crypto import envelope_crypto

    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)
    before = _sealed_to_bob(admin, bob, ops)
    _rotate(bob, bob_client, url).push()
    marker = admin.db.get_meta(ROTATION_SEALED_META)

    real = envelope_crypto.create_envelope

    def broken(*args):
        raise OSError("disk full")

    monkeypatch.setattr(envelope_crypto, "create_envelope", broken)
    with pytest.raises(OSError, match="disk full"):
        _pull_confirming(_client(admin, url))
    assert _sealed_to_bob(admin, bob, ops) == before
    assert admin.db.get_meta(ROTATION_SEALED_META) == marker

    monkeypatch.setattr(envelope_crypto, "create_envelope", real)
    admin_client = _client(admin, url)
    _pull_confirming(admin_client)
    admin_client.push()
    _bob_reads(bob, url, item)


def test_two_rotations_before_the_admin_pulls_seal_to_the_last_key(team, server):  # noqa: F811
    url, _ = server
    db, admin, client, bob, bob_client = team
    ops, item = _granted(team, url)
    before = _sealed_to_bob(admin, bob, ops)
    _rotate(bob, bob_client, url).push()
    _rotate(bob, _client(bob, url), url).push()

    admin_client = _client(admin, url)
    _pull_confirming(admin_client)
    admin_client.push()
    assert _sealed_to_bob(admin, bob, ops) == before + 1
    _bob_reads(bob, url, item)
