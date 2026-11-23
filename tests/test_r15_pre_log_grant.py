"""A grant sealed before this device knew the team log (R15, goal #441).

Found by the stateful run on 4ee7d65: the admin's second device shared a
folder while no team log existed, and the push failed ("goes with the next
push"). Meanwhile the first device founded the log. From then on the server
takes another account's envelope only with an ``access.set``, so the queued
envelope was refused on every push of the second device, for good, and sync
never settled. Now the push puts it into the log as founding would have (the
folder's key and the access, one atomic request), or, where the log does not
allow it, withdraws it once like any refused grant.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault import revocation
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
from sezam.vault.team_migration import found_team_log
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import team  # noqa: F401  (fixture)
from tests.test_team_log_migration import _yes, org  # noqa: F401  (fixture)


def _offline(client):
    def push():
        raise OSError("Server unreachable")

    client.push = push


def _second_device_shares(org, server, tmp_path, user_id):  # noqa: F811
    url, _ = server
    _db, admin, admin_client, *_rest = org
    other = _vault(tmp_path / "admin2", "admin")
    cli._server_connect_flow(url, other, PASSWORD)
    other_client = _client(other, url)
    other_client.pull()
    side = other.create_node("Side")
    entry = other.create_entry(side, "db", [{"key": "password", "value": "side-pw"}])
    _offline(other_client)
    with pytest.raises(RuntimeError, match="next push"):
        revocation.grant_member(other, other_client, user_id, side, "read", confirm_fingerprint=_yes)
    del other_client.push
    found_team_log(admin, admin_client, lambda uid, fp: False)
    other_client.pull()
    return other, other_client, side, entry


def test_a_grant_from_before_the_log_goes_into_it(org, server, tmp_path):  # noqa: F811
    _db, admin, admin_client, bob, bob_client, _carol, ids, _ops, _dan = org
    other, other_client, side, entry = _second_device_shares(org, server, tmp_path, ids["bob"])
    try:
        assert other_client.push()["conflicts"] == []
        assert other_client.push()["conflicts"] == []  # sync settles
        admin_client.pull()
        assert admin_client.team_state().access[side] == {ids["bob"]: "read"}
        bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
            admin.db.get_meta("user_id"): admin.keypair.fingerprint,
        })
        bob_client.pull()
        assert bob.read_entry(entry)["fields"][0]["value"] == "side-pw"
    finally:
        other.lock()


def test_a_grant_the_log_does_not_allow_is_withdrawn_once(org, server, tmp_path):  # noqa: F811
    """Dan was left out at founding (key never confirmed): no access for him."""
    _db, _admin, admin_client, *_rest, ids, _ops, _dan = org
    other, other_client, side, _entry = _second_device_shares(org, server, tmp_path, ids["dan"])
    try:
        refused = other_client.push()["conflicts"]
        assert [c["id"] for c in refused if "withdrawn" in str(c.get("error"))]
        assert other_client.push()["conflicts"] == []  # not refused again on every push
        assert not other.db.fetchone("SELECT 1 FROM access_envelopes WHERE user_id = ?", (ids["dan"],))
        admin_client.pull()
        assert ids["dan"] not in admin_client.team_state().access.get(side, {})
    finally:
        other.lock()
