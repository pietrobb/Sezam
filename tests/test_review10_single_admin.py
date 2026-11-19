"""Review 8595ec1 (R10-D, goal #374): the lone admin of a team log.

#4: a server restored from a backup older than the org recovery registration
no longer knows the recovery key. The lone admin who then forgot the password
reset it with the shares locally, and every push got 403
key_change_needs_proof: no old password, no recovery key on the server, and
no other admin for 'allow-key-reset' (a log has one admin). The recovery key
is now anchored in the team log (record org.recovery, signed by the admin):
the devices put the log back on the restored server, and the server checks
the recovery proof against the key the log names.

#3: losing the lone admin froze the organisation without a word. The admin
can hand the role over (member.role in one append), and status names a lone
admin with no recovery anchored in the log.
"""

from __future__ import annotations

import copy
import json
import os

import pytest
from nacl.signing import SigningKey

from sezam import teamlog
from sezam.vault import org_recovery_server
from sezam.crypto.shamir import split_secret
from sezam.vault.key_rotation import (
    org_recovery_rewrap_message,
    org_recovery_server_wrap,
    org_recovery_signing_key,
)
from sezam.vault.pending_states import key_reset_way_out, pending_states
from sezam.vault.team_migration import hand_over_admin
from tests.test_integration_client_server import PASSWORD, _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.node_support import requires_node
from tests.test_lone_admin_org_recovery import _recover
from tests.test_rollback_commit_token_sm7 import _restore
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401  (fixture)

RECOVERED = "recovered-r10d!"


def _logged_recovery(db) -> list:
    """The recovery keys named by the server's stored team log."""
    bodies = [json.loads(row["body"]) for row in (db._storage.get("team_log") or [])]
    return [b["data"]["recovery_pk"] for b in bodies if b["type"] == "org.recovery"]


def test_lone_admin_recovers_after_the_server_lost_the_recovery_key(team, server):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    backup = copy.deepcopy(db._storage)
    shares = org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3).shares
    admin_client.push()
    assert db._storage.get("org_recovery_blobs")
    assert _logged_recovery(db) == [admin.db.get_meta("org_recovery_signing_pk")]

    _restore(db, backup)  # from before the registration
    assert not db._storage.get("org_recovery_blobs")
    admin.lock()
    admin.org_recovery(shares[:2], RECOVERED)
    admin.lock()
    admin.unlock(RECOVERED)
    client = _client(admin, url)
    client.pull()  # puts the log back on the server
    assert _logged_recovery(db) == [admin.db.get_meta("org_recovery_signing_pk")]
    assert client.push()["conflicts"] == []  # 8595ec1: 403 key_change_needs_proof
    assert not client.has_pending_key_change()
    assert _recover(admin, url, RECOVERED)["user_id"] == admin.db.get_meta("user_id")
    # The shares work on the server again (web): the blob is back.
    assert client._request("GET", "/api/org-recovery/status")["configured"]


def _web_setup(admin, admin_client) -> tuple[str, list]:
    """What the web's Shamir setup does (app.js handleShamirGenerate): a fresh
    32-byte secret wraps the KEK in the web format, the server registers its
    Ed25519 key on proof of the password, and anchorWebOrgRecovery appends
    the org.recovery record. The blob exists only on the server."""
    secret = os.urandom(32)
    signing_pk = bytes(org_recovery_signing_key(secret).verify_key).hex()
    epoch = int(admin.db.get_meta("key_epoch") or "0")
    admin_client.store_org_recovery({
        "wrapped_kek": org_recovery_server_wrap(admin.dek_mgr._kek, secret).hex(),
        "recovery_signing_pk": signing_pk, "threshold": 2, "total_shares": 3, "key_epoch": epoch,
    }, admin.current_auth_proof(PASSWORD))
    admin_client.append_team_log([("org.recovery", {"recovery_pk": signing_pk})])
    return signing_pk, split_secret(secret, 2, 3)


def test_a_web_setup_survives_a_server_restore(team, server):  # noqa: F811
    """Capability run 314: a recovery set up on the web (here replacing a
    desktop one) had no KEK wrap outside the server; after a restore from
    before it the shares opened nothing. The admin's desktop now keeps a wrap
    of the key the log names, and a push no longer names its older key over it."""
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    admin_client.push()
    admin_client.pull()
    backup = copy.deepcopy(db._storage)
    web_pk, shares = _web_setup(admin, admin_client)
    admin_client.push()  # the desktop sees the log name the web's key
    assert _logged_recovery(db)[-1] == web_pk  # not named over by the desktop's
    assert admin.db.get_meta("org_recovery_signing_pk") == web_pk

    _restore(db, backup)  # holds the desktop's old blob, not the web's
    admin.lock()
    admin.org_recovery(shares[:2], RECOVERED)
    admin.lock()
    admin.unlock(RECOVERED)
    client = _client(admin, url)
    client.pull()  # puts the log back
    assert _logged_recovery(db)[-1] == web_pk
    assert client.push()["conflicts"] == []
    assert not client.has_pending_key_change()
    assert _recover(admin, url, RECOVERED)["user_id"] == admin.db.get_meta("user_id")
    blob = client._request("GET", "/api/org-recovery/status")
    assert blob["configured"] and blob["recovery_signing_pk"] == web_pk and not blob["stale"]


@requires_node
@pytest.mark.parametrize("setup_on", ["web", "desktop"])
def test_the_browser_recovers_a_lone_admin_after_a_server_restore(team, server, tmp_path, setup_on):  # noqa: F811
    """Capability run 316: the KEK wrap the shares open lived only in the
    server's blob table. With no desktop of the admin syncing between the
    setup and a restore from before it, /api/org-recovery/blob was empty and
    the shares opened nothing in the browser. The wrap is now in the log
    (org.recovery.wrap), which any member's device puts back, and the server
    serves it from there."""
    from sezam.crypto import aead
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, db = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin.create_entry(_ops(admin), "lone-admin-secret", [{"key": "password", "value": "kept-across-restore"}])
    assert admin_client.push()["conflicts"] == []
    genesis = admin_client.team_state().genesis_hash
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    user["encrypted_keypair"] = aead.encrypt_account_keypair(
        admin.keypair.serialize_private(), genesis, admin.current_kek,
        admin.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    _confirm_founder(admin, bob)
    bob_client.pull()
    backup = copy.deepcopy(db._storage)

    if setup_on == "web":
        tab = WebTab(url, tmp_path / "setup.log")
        try:
            assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
            setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
            assert setup["error"] is None, setup
        finally:
            tab.kill()
        shares = setup["shares"]
    else:
        result = org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
        shares = [f"{index}:{bytes(share).hex()}" for index, share in result.shares]
        assert admin_client.push()["conflicts"] == []
    logged_pk = _logged_recovery(db)[-1]
    bodies = [json.loads(row["body"]) for row in db._storage["team_log"]]
    assert any(b["type"] == "org.recovery.wrap" and b["author"] == user["id"] for b in bodies)
    bob_client.pull()  # a member's device holds the log; the admin's desktop never syncs again

    _restore(db, backup)
    assert not db._storage.get("org_recovery_blobs")
    bob_client.pull()  # puts the log back
    assert _logged_recovery(db)[-1] == logged_pk
    tab = WebTab(url, tmp_path / "recover.log")
    try:
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password="Lone-Admin-Recovery-2026!")
        assert result["error"] is None, result
        assert any(e["password"] == "kept-across-restore" for e in result["view"]["entries"]), result
    finally:
        tab.kill()


def test_a_desktop_takes_no_recovery_key_the_log_does_not_name(team):  # noqa: F811
    """The server's word alone plants no recovery key in the desktop vault."""
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    secret = os.urandom(32)
    signing_pk = bytes(org_recovery_signing_key(secret).verify_key).hex()
    admin_client.store_org_recovery({
        "wrapped_kek": org_recovery_server_wrap(admin.dek_mgr._kek, secret).hex(),
        "recovery_signing_pk": signing_pk, "threshold": 2, "total_shares": 3,
        "key_epoch": int(admin.db.get_meta("key_epoch") or "0"),
    }, admin.current_auth_proof(PASSWORD))
    admin_client.push()
    assert not admin.org_recovery_configured()


def _server_admin(db, user_id: str) -> bool:
    return bool(next(u for u in db._storage["users"] if u["id"] == user_id)["is_admin"])


def test_the_lone_admin_hands_the_role_over(team):  # noqa: F811
    """#3: the role moves to a confirmed member in one append (the head never
    has two admins), and the new admin can change the team."""
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    with pytest.raises(ValueError, match="not confirmed"):
        hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: False)
    with pytest.raises(ValueError, match="not another active member"):
        hand_over_admin(admin, admin_client, admin_id, lambda fingerprint: True)
    assert teamlog.is_admin(admin_client.team_state(), admin_id)

    hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: fingerprint == bob.keypair.fingerprint)
    state = admin_client.team_state()
    assert teamlog.is_admin(state, bob_id) and not teamlog.is_admin(state, admin_id)
    assert teamlog.admin_policy_refusal(state) is None
    assert _server_admin(db, bob_id) and not _server_admin(db, admin_id)
    with pytest.raises(RuntimeError, match="Only the team log's admin"):
        hand_over_admin(admin, admin_client, bob_id, lambda fingerprint: True)

    # The new admin's own device changes the team (here: hands it back).
    _confirm_founder(admin, bob)
    hand_over_admin(bob, bob_client, admin_id, lambda fingerprint: True)
    admin_client.pull()
    assert teamlog.is_admin(admin_client.team_state(), admin_id)


def test_status_names_a_lone_admin_without_recovery_and_no_impossible_reset(team):  # noqa: F811
    """#3/#4: 'sezam status' says when losing the lone admin would freeze the
    organisation, and never sends that admin to another admin's allow-key-reset."""
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin_id, bob_id = admin.db.get_meta("user_id"), bob.db.get_meta("user_id")
    assert "lone_admin_without_recovery" in {s.key for s in pending_states(admin)}
    assert "allow-key-reset" not in key_reset_way_out(admin.db, admin_id)
    assert "no org recovery key" in key_reset_way_out(admin.db, admin_id)
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert "allow-key-reset" in key_reset_way_out(bob.db, bob_id)  # a member has an admin

    org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    admin_client.push()
    assert "lone_admin_without_recovery" not in {s.key for s in pending_states(admin)}
    way_out = key_reset_way_out(admin.db, admin_id)
    assert "allow-key-reset" not in way_out and "recovery key the team log names" in way_out


def test_a_restored_server_takes_only_the_recovery_key_the_log_names(team, server):  # noqa: F811
    """The holder of the identity key alone (a JWT, no password) plants no
    recovery key of their own on a server that lost the registration."""
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin_client.pull()
    backup = copy.deepcopy(db._storage)
    org_recovery_server.setup_and_register(admin, PASSWORD, 2, 3)
    admin_client.push()
    _restore(db, backup)
    admin_client.pull()  # puts the log back
    assert _logged_recovery(db)
    admin_id = admin.db.get_meta("user_id")
    epoch = int(admin.db.get_meta("key_epoch") or "0")
    thief = SigningKey.generate()
    wrapped = os.urandom(72)
    body = {
        "wrapped_kek": wrapped.hex(), "recovery_signing_pk": bytes(thief.verify_key).hex(),
        "threshold": 2, "total_shares": 3, "key_epoch": epoch,
        "recovery_signature": thief.sign(
            org_recovery_rewrap_message(admin_id, epoch, 2, 3, wrapped)).signature.hex(),
    }
    with pytest.raises(RuntimeError, match="403"):
        admin_client._request("POST", "/api/org-recovery/store", body, auth=True)
    assert not db._storage.get("org_recovery_blobs")
    # Nor does a challenge signed by a key the log does not name count.
    challenge = admin_client._request("POST", "/api/org-recovery/challenge", {})["challenge"]
    with pytest.raises(RuntimeError, match="401"):
        admin_client._request("POST", "/api/org-recovery/keypair", {
            "challenge": challenge, "signature": thief.sign(bytes.fromhex(challenge)).signature.hex(),
        })
