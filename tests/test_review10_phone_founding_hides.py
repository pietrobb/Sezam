"""Review 8595ec1 (R10-C, goal #373), phone: an item founding the log hid
comes back once the log gives its author write access.

Before the log, Bob wrote an item into Ops with a write grant; the admin's
grant then said read. Founded from that state, the log gives Bob no write
access to Ops: every client hides his item. The way out 'sezam team-log init'
names is a write grant in the log. The desktop and the web judge the item
again on their next pull; the phone dropped the refused copy for good, and
only a full resync (a new device) brought it back. It now keeps the copy the
log refused for want of write access and judges it again on every pull.
"""

from __future__ import annotations

from sezam.crypto.envelope_crypto import compute_fingerprint
from sezam.vault import revocation
from sezam.vault.team_migration import found_team_log
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review10_founding_hides import _bob_wrote_then_lowered
from tests.test_team_log_desktop import team  # noqa: F401  (fixture)

PHONE_TEST = "test/phone_founding_hides_test.dart"


def test_the_phone_shows_a_hidden_item_once_its_author_may_write(team, server, tmp_path, monkeypatch):  # noqa: F811
    url, _ = server
    admin, admin_client, carol, ids, ops, entry = _bob_wrote_then_lowered(team, server, tmp_path, monkeypatch)
    _client(carol, url).push()  # her root folder, as her first device's sync
    carol.lock()
    result = found_team_log(admin, admin_client, lambda uid, fp: True)
    assert [(h.item, h.reason) for h in result.hidden] == [(entry, "read")]

    def granted():
        revocation.grant_member(admin, admin_client, ids["bob"], ops, "write")
        assert admin_client.team_state().access[ops][ids["bob"]] == "write"

    out = _phone(url, tmp_path, {
        "username": "carol", "password": PASSWORD, "entry": entry,
        "fingerprint": compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk),
    }, {"granted": granted}, PHONE_TEST)
    assert "All tests passed!" in out, out
