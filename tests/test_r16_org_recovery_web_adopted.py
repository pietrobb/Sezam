"""Review 18c300f R16-L4: a version 2 recovery set up on the web, adopted by
the desktop (team_log_local.adopt_org_recovery), still recovers the desktop.

The log names only the recovery's Ed25519 key, so the desktop seals its local
KEK wrap to that key's X25519 form; the rebuilt secret derives the version 2
key and opens it (tests/test_r16_org_recovery_key_separation.py: the rest).
"""

from __future__ import annotations

from nacl.signing import SigningKey

from sezam.crypto.shamir import split_secret
from sezam.vault import pending_states
from sezam.vault.crud import Vault
from tests.test_integration_client_server import _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_r16_org_recovery_key_separation import _hkdf
from tests.test_review11_org_recovery_current import _store
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)

RECOVERED = "recovered-password!"


def test_a_web_setup_the_desktop_adopted_recovers_the_desktop(team, server, tmp_path):  # noqa: F811
    url, _ = server
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    web = _store(admin, admin_client, anchor=True)  # the page's version 2 setup
    admin_client.push()
    web_pk = bytes(SigningKey(_hkdf(web, "ed25519")).verify_key).hex()
    assert admin.db.get_meta("org_recovery_signing_pk") == web_pk  # adopted
    admin.lock()

    recovered = Vault(tmp_path / "admin")
    recovered.org_recovery(split_secret(web, 2, 3)[:2], RECOVERED)
    recovered.lock()
    recovered.unlock(RECOVERED)
    try:
        assert "recovery_secret" in (pending_states.key_change_journal(recovered.db) or {})
        assert _client(recovered, url).push()["conflicts"] == []  # the version 2 key proved it
        assert (pending_states.key_change_journal(recovered.db) or None) is None
    finally:
        recovered.lock()
