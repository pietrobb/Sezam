"""Review 4acfdde R11 (low): the web's Shamir recovery left the team log's
org.recovery.wrap on the old KEK.

The recovery stores a fresh blob (the new KEK, the next key epoch) on the
server, but only the desktop also logged the new wrap. The log kept the wrap
of the forgotten password, which a server restored from a backup serves the
shares. The browser now logs the new wrap after the recovery's pull.
"""

from __future__ import annotations

import json

from sezam.crypto import aead
from tests.node_support import requires_node
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)

pytestmark = requires_node


def _logged_wraps(db, user_id: str) -> list[dict]:
    bodies = [json.loads(row["body"]) for row in db._storage["team_log"]]
    return [b["data"] for b in bodies if b["type"] == "org.recovery.wrap" and b["author"] == user_id]


def test_web_recovery_logs_the_wrap_of_the_new_password(team, server, tmp_path):  # noqa: F811
    from tests.web_tab import WebTab

    url, db = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    genesis = admin_client.team_state().genesis_hash
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    user["encrypted_keypair"] = aead.encrypt_account_keypair(
        admin.keypair.serialize_private(), genesis, admin.current_kek,
        admin.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    _confirm_founder(admin, bob)

    tab = WebTab(url, tmp_path / "setup.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
        assert setup["error"] is None, setup
    finally:
        tab.kill()
    before = _logged_wraps(db, user["id"])
    assert len(before) == 1

    tab = WebTab(url, tmp_path / "recover.log")
    try:
        result = tab.do("org_recovery", shares=setup["shares"][:2], total_shares=3,
                        password="Web-Recovery-Wrap-2026!")
        assert result["error"] is None, result
    finally:
        tab.kill()

    blob = next(iter(db._storage["org_recovery_blobs"]))
    epoch = int(next(s for s in db._storage["sync_state"] if s.get("user_id", user["id"]) == user["id"])["key_epoch"])
    assert int(blob["key_epoch"]) == epoch > before[0]["key_epoch"]
    wraps = _logged_wraps(db, user["id"])
    assert wraps[-1]["key_epoch"] == epoch  # was the setup's epoch
    assert bytes.fromhex(wraps[-1]["wrapped_kek"]) == bytes(blob["wrapped_kek"])
