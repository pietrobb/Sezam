"""Review e443cbc, goal #439 (INV-3): a browser's org recovery records the
forgotten password with the salt + params that password was seen to open,
never the server's unsigned OrgRecoveryKeypairResponse.argon2_salt and
MetaResponse.argon2_params.

A recovered bundle without the anchor is recorded in the pre-anchor so no
client returns to that password (capability runs 269, 273). Under a salt the
server made up (the same in both answers: equal is no check) the entry names
no password at all: passwordReopensPreAnchor never sees the old one chosen
again, and the server keeping the old bundle without the anchor can serve it
to a new device.
"""
from __future__ import annotations

import json

from sezam.crypto import aead
from tests.node_support import requires_node
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401

FAKE_SALT = bytes(range(100, 116))
NEW_PASSWORD = "Bound-Recovery-2026!"


def _recover_under_a_lying_salt(team, server, tmp_path, forget_states: bool):  # noqa: F811
    from sezam.crypto.kdf import Argon2Params, derive_kek, derive_kek_and_proof
    from tests.test_integration_client_server import PASSWORD
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    legacy = user["encrypted_keypair"]
    user["encrypted_keypair"] = aead.encrypt_account_keypair(
        admin.keypair.serialize_private(), genesis, admin.current_kek,
        admin.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    tab = WebTab(url, tmp_path / "pin.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
        assert setup["error"] is None, setup
        profile = tab.close()
    finally:
        tab.kill()
    if forget_states:
        profile = {name: [row for row in rows if not str(next(iter(row.values()))).startswith("kdf_states:")]
                   for name, rows in profile.items()}
    user["encrypted_keypair"] = legacy  # the server holds the bundle without the anchor
    real_salt, params = bytes(user["argon2_salt"]), Argon2Params.from_dict(json.loads(user["argon2_params"]))
    user["argon2_salt"] = FAKE_SALT  # both the keypair answer and /api/meta say so
    tab = WebTab(url, tmp_path / "recover.log", idb=profile)
    try:
        result = tab.do("org_recovery", shares=setup["shares"][:2], total_shares=3, password=NEW_PASSWORD)
        assert result["error"] is None, result
    finally:
        tab.kill()
    old_kek = derive_kek(PASSWORD, real_salt, params)
    old_check = aead.pre_anchor_check(old_kek)
    old_kek[:] = bytes(len(old_kek))
    kek, proof = derive_kek_and_proof(NEW_PASSWORD, user["argon2_salt"], Argon2Params.from_dict(
        json.loads(user["argon2_params"])))
    try:
        keys, anchor, kept = aead.decrypt_account_bundle(user["encrypted_keypair"], kek, user["id"].encode())
        keys[:] = bytes(len(keys))
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))
    return genesis, real_salt, old_check, anchor, kept


@requires_node
def test_recovery_records_the_salt_the_forgotten_password_opened(team, server, tmp_path):  # noqa: F811
    genesis, real_salt, old_check, anchor, kept = _recover_under_a_lying_salt(
        team, server, tmp_path, forget_states=False)
    assert anchor == genesis
    entries = aead.parse_pre_anchor(kept)
    assert [(e[0], e[4]) for e in entries] == [(real_salt, old_check)]


@requires_node
def test_recovery_with_no_known_state_publishes_no_anchor(team, server, tmp_path):  # noqa: F811
    genesis, _, _, anchor, kept = _recover_under_a_lying_salt(team, server, tmp_path, forget_states=True)
    assert anchor is None and not kept
