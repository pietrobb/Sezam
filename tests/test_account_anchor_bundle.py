"""R9-B: portable anchor is authenticated inside the account's keypair wrap.

This codec gate intentionally precedes enabling bundle uploads: legacy clients
must not be locked out before all login/rotation paths retain the metadata.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from nacl.exceptions import CryptoError

from sezam.crypto import aead
from tests.node_support import node_cmd, requires_node
from tests.test_integration_client_server import server  # noqa: F401
from tests.test_team_log_desktop import team, _found_with_bob  # noqa: F401
from tests.test_cross_client_vectors import _web_constant, _web_function

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests/vectors/cross_client.json").read_text(encoding="utf-8"))["keypair_wrap"]
RAW = bytes.fromhex(V["envelopes"][0]["payload_hex"])
FULL = bytes.fromhex(V["keypair_hex"])
GENESIS = "ab" * 32
PAYLOAD = b"SZACCT01" + RAW + bytes.fromhex(GENESIS)
KEK = bytes.fromhex(V["kek_hex"])
UID = V["user_id"].encode()
KID = V["kek_id"].encode()


def _cases():
    cases = [
        ("anchored", PAYLOAD, GENESIS),
        ("legacy-desktop", RAW, None),
        ("legacy-web", FULL, None),
    ]
    bad = {
        "unknown-version": b"SZACCT02" + PAYLOAD[8:],
        "bad-magic": b"XZACCT01" + PAYLOAD[8:],
        "truncated-anchor": PAYLOAD[:-1],
        "trailing-bytes": PAYLOAD + b"x",
        "only-anchor": bytes.fromhex(GENESIS),
        "empty": b"",
        "inconsistent-public-key": FULL[:32] + bytes(32) + FULL[64:],
    }
    for name, payload, genesis in cases:
        yield {"name": name, "payload": payload.hex(), "ok": True, "genesis": genesis}
    for name, payload in bad.items():
        yield {"name": name, "payload": payload.hex(), "ok": False}


def test_account_bundle_preserves_keys_and_explicit_anchor():
    for raw in (RAW, FULL):
        assert aead.encode_account_keypair(raw, GENESIS) == PAYLOAD
    for case in _cases():
        if case["ok"]:
            keys, anchor = aead.decode_account_keypair(bytes.fromhex(case["payload"]))
            assert keys == RAW and anchor == case["genesis"], case["name"]
        else:
            with pytest.raises(ValueError, match="account keypair"):
                aead.decode_account_keypair(bytes.fromhex(case["payload"]))
    for invalid in (None, "", "AB" * 32, "ab" * 31, "gg" * 32, GENESIS + "\n"):
        with pytest.raises(ValueError):
            aead.encode_account_keypair(RAW, invalid)


def test_account_bundle_real_server_recovery_transport(server):  # noqa: F811
    from sezam import cli
    from sezam.crypto.kdf import derive_kek_and_proof
    from sezam.crypto.keys import KeyPair
    from tests.test_integration_client_server import PARAMS, PASSWORD

    url, _ = server
    keys = KeyPair.from_private_only(RAW)
    registered = cli._server_request(url, "POST", "/api/bootstrap", {
        "username": "anchor-owner", "signing_pk": keys.signing_pk.hex(),
        "encryption_pk": keys.encryption_pk.hex(),
    })
    user = registered["user_id"].encode()
    salt = bytes(range(16))
    kek, proof = derive_kek_and_proof(PASSWORD, salt, PARAMS)
    try:
        envelope = aead.encrypt_account_keypair(RAW, GENESIS, kek, KID, user)
        cli._server_request(url, "PUT", "/api/me/keypair", {
            "encrypted_keypair": envelope.hex(), "argon2_salt": salt.hex(),
            "auth_salt": bytes(range(16, 32)).hex(), "auth_proof": proof.hex(),
            "argon2_params": PARAMS.account_dict(),
        }, token=registered["token"])
        for _ in range(2):
            recovered = cli._server_request(url, "POST", "/api/auth/recover", {
                "username": "anchor-owner", "auth_proof": proof.hex(),
                "argon2_params": PARAMS.account_dict(),
            })
            assert recovered["encrypted_keypair"] == envelope.hex()
            assert aead.decrypt_account_keypair(bytes.fromhex(recovered["encrypted_keypair"]),
                                               kek, recovered["user_id"].encode()) == (RAW, GENESIS)
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))
        keys.zeroize()


@pytest.mark.parametrize("payload, genesis", [(RAW, None), (FULL, None), (PAYLOAD, GENESIS)])
def test_desktop_keypair_retains_authenticated_metadata(payload, genesis, tmp_path):
    from sezam.crypto.keys import KeyPair, export_sezam_key, import_sezam_key
    from sezam.crypto.kdf import derive_kek
    from sezam.vault.crud import open_server_keypair
    from tests.test_integration_client_server import PARAMS, PASSWORD

    envelope = aead.encrypt_keypair_wrap(payload, KEK, KID, UID)
    keys = open_server_keypair({"encrypted_keypair": envelope.hex(), "user_id": UID.decode()}, KEK)
    assert keys.confirmed_genesis == genesis
    decoded = KeyPair.from_private_only(keys.serialize_private())
    assert decoded.confirmed_genesis == genesis
    assert decoded.signing_pk == keys.signing_pk
    assert decoded.encryption_pk == keys.encryption_pk
    salt = bytes(range(16))
    kek = derive_kek(PASSWORD, salt, PARAMS)
    path = tmp_path / "anchor.sezam-key"
    try:
        export_sezam_key(keys, kek, path, salt, PARAMS)
        imported = import_sezam_key(path, PASSWORD)
        assert imported.confirmed_genesis == genesis
        assert imported.serialize_private() == keys.serialize_private()
        imported.zeroize()
    finally:
        keys.zeroize()
        decoded.zeroize()
        kek[:] = bytes(len(kek))


@pytest.mark.parametrize("case", ["anchored", "legacy", "foreign", "founder"])
def test_desktop_fresh_account_uses_bundle_before_team_pull(team, server, tmp_path, case):  # noqa: F811
    from sezam import cli
    from sezam.vault.revocation import grant_member
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
    from tests.test_integration_client_server import PASSWORD, _vault, _client
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "portable-secret", [{"key": "password", "value": "actual-shared-secret"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    client.push()
    genesis = client.team_state().genesis_hash
    owner = admin if case == "founder" else bob
    user = next(u for u in db._storage["users"] if u["id"] == owner.db.get_meta("user_id"))
    if case != "legacy":
        # Fixture enrollment only: production publishing is not enabled yet.
        user["encrypted_keypair"] = aead.encrypt_account_keypair(
            owner.keypair.serialize_private(), GENESIS if case == "foreign" else genesis,
            owner.current_kek, owner.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    fresh = _vault(tmp_path / "fresh", "admin" if case == "founder" else "bob")
    try:
        cli._server_connect_flow(url, fresh, PASSWORD)
        assert fresh.db.get_meta("user_id") == user["id"]
        expected = None if case == "legacy" else GENESIS if case == "foreign" else genesis
        assert fresh.keypair.confirmed_genesis == expected
        assert fresh.db.get_meta(CONFIRMED_GENESIS_META) == expected
        if case in ("anchored", "founder"):
            # A successful pull must actually open the shared secret.
            assert fresh.get_field_value(item, "password") == "actual-shared-secret"
            assert _client(fresh, url).team_log_trusted()
            fresh.lock()
            fresh.unlock(PASSWORD)
            assert fresh.keypair.confirmed_genesis == genesis
            assert fresh.get_field_value(item, "password") == "actual-shared-secret"
        else:
            assert fresh.db.fetchone("SELECT id FROM entries WHERE id = ?", (item,)) is None
            assert not _client(fresh, url).team_log_trusted()
    finally:
        fresh.lock()


@requires_node
@pytest.mark.parametrize("case", ["anchored", "legacy", "foreign", "founder", "stale-cache", "backup", "storage"])
def test_web_fresh_account_uses_bundle_before_team_pull(team, server, tmp_path, case):  # noqa: F811
    from sezam.vault.revocation import grant_member
    from tests.test_integration_client_server import PASSWORD
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    admin.create_entry(folder, "portable-secret", [{"key": "password", "value": "actual-shared-secret"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    assert client.push()["conflicts"] == []
    genesis = client.team_state().genesis_hash
    owner = admin if case == "founder" else bob
    user = next(u for u in db._storage["users"] if u["id"] == owner.db.get_meta("user_id"))
    profile = None
    if case == "stale-cache":
        tab = WebTab(url, tmp_path / "before-enrollment.log")
        try:
            result = tab.do("login", username="bob", password=PASSWORD)
            assert result["error"] is None, result
            assert not any(e["password"] for e in result["view"]["entries"]), result
            profile = tab.close()
        finally:
            tab.kill()
    if case != "legacy":
        user["encrypted_keypair"] = aead.encrypt_account_keypair(
            owner.keypair.serialize_private(), GENESIS if case == "foreign" else genesis,
            owner.current_kek, owner.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    backup = None
    if case == "backup":
        from sezam.crypto.keys import KeyPair, export_sezam_key
        from tests.test_integration_client_server import PARAMS
        keys = KeyPair.from_private_only(aead.encode_account_keypair(owner.keypair.serialize_private(), genesis))
        backup_path = tmp_path / "account.sezam-key"
        export_sezam_key(keys, owner.current_kek, backup_path, user["argon2_salt"], PARAMS)
        backup = backup_path.read_bytes().hex()
        keys.zeroize()
    for attempt in range(2):
        tab = WebTab(url, tmp_path / f"bundle-{case}-{attempt}.log", idb=profile)
        try:
            action = "login_anchor_write_failure" if case == "storage" and attempt == 0 else (
                "login_backup" if backup and attempt == 0 else "login")
            result = tab.do(action, username="admin" if case == "founder" else "bob", password=PASSWORD, backup=backup)
            if case == "storage" and attempt == 0:
                assert "injected anchor disk full" in (result["error"] or ""), result
                assert not result["view"]["unlocked"] and not result["view"]["entries"], result
                assert not any(c["path"].startswith("/api/sync") for c in result["calls"]), result
                profile = tab.close()
                continue
            if case == "foreign":
                # INV-7: the refused log refuses the team, not the sign-in.
                assert result["error"] is None and result["view"]["unlocked"], result
                assert any(a.startswith("TEAM LOG MISMATCH") for a in result["alerts"]), result
            else:
                assert result["error"] is None, result
            readable = any(e["password"] == "actual-shared-secret" for e in result["view"]["entries"])
            assert readable == (case not in ("legacy", "foreign")), result
            profile = tab.close()
        finally:
            tab.kill()


@requires_node
@pytest.mark.parametrize("replacement", ["legacy", "foreign"])
def test_web_server_downgrade_signs_in_and_keeps_the_pin(team, server, tmp_path, replacement):  # noqa: F811
    from tests.test_integration_client_server import PASSWORD
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    user = next(u for u in db._storage["users"] if u["id"] == bob.db.get_meta("user_id"))
    raw = bob.keypair.serialize_private()
    legacy = user["encrypted_keypair"]
    user["encrypted_keypair"] = aead.encrypt_account_keypair(
        raw, genesis, bob.current_kek, bob.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    honest = user["encrypted_keypair"]
    tab = WebTab(url, tmp_path / "honest-cache.log")
    try:
        assert tab.do("login", username="bob", password=PASSWORD)["error"] is None
        profile = tab.close()
    finally:
        tab.kill()
    user["encrypted_keypair"] = legacy if replacement == "legacy" else aead.encrypt_account_keypair(
        raw, GENESIS, bob.current_kek, bob.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    tab = WebTab(url, tmp_path / "changed-cache.log", idb=profile)
    try:
        result = tab.do("login", username="bob", password=PASSWORD)
        # INV-7 (capability run 416): the server copy naming another or no
        # genesis never fails the sign-in; the pin it never moves decides.
        assert result["error"] is None and result["view"]["unlocked"], result
        mismatch = any(a.startswith("TEAM LOG MISMATCH") for a in result["alerts"])
        assert mismatch == (replacement == "foreign"), result
        after = tab.close()
        before_keys = {r["id"]: r for r in profile["keys"]}
        after_keys = {r["id"]: r for r in after["keys"]}
        pin = f"confirmed_team_genesis:{user['id']}"
        assert after_keys[pin] == before_keys[pin]
    finally:
        tab.kill()
    user["encrypted_keypair"] = honest
    tab = WebTab(url, tmp_path / "retry-cache.log", idb=after)
    try:
        assert tab.do("login", username="bob", password=PASSWORD)["error"] is None
    finally:
        tab.kill()


@requires_node
@pytest.mark.parametrize("failure", [None, "before", "after"])
def test_web_recovery_preserves_account_anchor_and_retry(team, server, tmp_path, failure):  # noqa: F811
    from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
    from tests.test_integration_client_server import PASSWORD
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    admin.create_entry(_ops(admin), "portable-secret", [{"key": "password", "value": "actual-shared-secret"}])
    assert client.push()["conflicts"] == []
    genesis = client.team_state().genesis_hash
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    user["encrypted_keypair"] = aead.encrypt_account_keypair(
        admin.keypair.serialize_private(), genesis, admin.current_kek,
        admin.db.get_meta("kek_dek_id").encode(), user["id"].encode())
    tab = WebTab(url, tmp_path / "setup.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
        assert setup["error"] is None, setup
        shares = setup["shares"]
    finally:
        tab.kill()
    new_password = "Portable-Recovery-2026!"
    tab = WebTab(url, tmp_path / "recover.log")
    try:
        kwargs = {"fail": {"method": "POST", "path": "/api/sync", "mode": failure}} if failure else {}
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password=new_password, **kwargs)
        if failure:
            assert result["failure"]["fired"] and result["error"], result
        else:
            assert result["error"] is None, result
            assert any(e["password"] == "actual-shared-secret" for e in result["view"]["entries"]), result
        profile = tab.close()
    finally:
        tab.kill()
    tab = WebTab(url, tmp_path / "resume.log", idb=profile)
    try:
        result = tab.do("login", username="admin", password=new_password)
        assert result["error"] is None, result
        assert any(e["password"] == "actual-shared-secret" for e in result["view"]["entries"]), result
    finally:
        tab.kill()
    params = Argon2Params.from_dict(json.loads(user["argon2_params"]))
    kek, proof = derive_kek_and_proof(new_password, user["argon2_salt"], params)
    try:
        _, anchor = aead.decrypt_account_keypair(user["encrypted_keypair"], kek, user["id"].encode())
        assert anchor == genesis
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))


@requires_node
def test_web_recovery_never_returns_to_a_pre_anchor_password(team, server, tmp_path):  # noqa: F811
    """Capability run 269: a browser's org recovery refuses a recorded pre-anchor
    password and keeps every recorded state in the bundle it publishes."""
    import copy
    from sezam.crypto.kdf import Argon2Params, derive_kek, derive_kek_and_proof
    from tests.test_integration_client_server import PASSWORD
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    admin.create_entry(_ops(admin), "portable-secret", [{"key": "password", "value": "actual-shared-secret"}])
    assert client.push()["conflicts"] == []
    genesis = client.team_state().genesis_hash
    old_password, salt = "Pre-Anchor-Password-0!", bytes(range(16))
    old_kek = derive_kek(old_password, salt, Argon2Params(time_cost=2, memory_cost=65_536, parallelism=1))
    states = aead.add_pre_anchor(b"", salt, 2, 65_536, 1, old_kek)
    old_kek[:] = bytes(len(old_kek))
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    user["encrypted_keypair"] = aead.encrypt_account_keypair(
        admin.keypair.serialize_private(), genesis, admin.current_kek,
        admin.db.get_meta("kek_dek_id").encode(), user["id"].encode(), states)
    tab = WebTab(url, tmp_path / "setup.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
        assert setup["error"] is None, setup
        shares = setup["shares"]
    finally:
        tab.kill()
    before = copy.deepcopy(user)
    tab = WebTab(url, tmp_path / "refused.log")
    try:
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password=old_password)
        assert result["error"] and "team.publish_pre_anchor_password" in result["error"], result
    finally:
        tab.kill()
    assert user == before
    new_password = "Portable-Recovery-2026!"
    tab = WebTab(url, tmp_path / "recover.log")
    try:
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password=new_password)
        assert result["error"] is None, result
    finally:
        tab.kill()
    params = Argon2Params.from_dict(json.loads(user["argon2_params"]))
    kek, proof = derive_kek_and_proof(new_password, user["argon2_salt"], params)
    try:
        keys, anchor, kept = aead.decrypt_account_bundle(user["encrypted_keypair"], kek, user["id"].encode())
        keys[:] = bytes(len(keys))
        assert (anchor, kept) == (genesis, states)
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))


@requires_node
def test_web_never_returns_to_an_older_pre_anchor_password(team, server, tmp_path):  # noqa: F811
    """Capability run 273: A -> B by a browser's recovery without the anchor, the
    same browser publishes B -> C, then no browser may go back to A (or B)."""
    import copy
    from sezam.crypto.keys import compute_fingerprint
    from sezam.crypto.kdf import Argon2Params, derive_kek, derive_kek_and_proof
    from tests.test_integration_client_server import PASSWORD
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    states_of = {}

    def remember(password):
        params = Argon2Params.from_dict(json.loads(user["argon2_params"]))
        kek = derive_kek(password, bytes(user["argon2_salt"]), params)
        states_of[password] = aead.pre_anchor_check(kek)
        kek[:] = bytes(len(kek))

    a, b, c = "Older-Pre-Anchor-A-2026!", "Older-Pre-Anchor-B-2026!", "Older-Pre-Anchor-C-2026!"
    tab = WebTab(url, tmp_path / "setup.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
        assert setup["error"] is None, setup
        shares = setup["shares"]
        profile = tab.close()
    finally:
        tab.kill()
    tab = WebTab(url, tmp_path / "to-b.log", idb=profile)
    try:
        for password in (a, b):  # (fixture ->) A -> B, still without the anchor
            result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password=password)
            assert result["error"] is None, result
            remember(password)
        confirmed = tab.do("founder", open=True, fingerprint=fingerprint)  # this browser's pin only
        assert confirmed["error"] is None, confirmed
        profile = tab.close()
    finally:
        tab.kill()
    tab = WebTab(url, tmp_path / "to-c.log", idb=profile)
    try:
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password=c)  # the publication
        assert result["error"] is None, result
    finally:
        tab.kill()
    params = Argon2Params.from_dict(json.loads(user["argon2_params"]))
    kek, proof = derive_kek_and_proof(c, user["argon2_salt"], params)
    try:
        keys, anchor, kept = aead.decrypt_account_bundle(user["encrypted_keypair"], kek, user["id"].encode())
        keys[:] = bytes(len(keys))
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))
    assert anchor == genesis
    assert {states_of[a], states_of[b]} <= {e[4] for e in aead.parse_pre_anchor(kept)}
    before = copy.deepcopy(user)
    # The server allows five recovery keypair fetches an hour: A, B, C, this, D.
    tab = WebTab(url, tmp_path / "refused.log")  # a fresh browser: only the bundle knows A
    try:
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password=a)
        assert result["error"] and "team.publish_pre_anchor_password" in result["error"], result
    finally:
        tab.kill()
    assert user == before
    tab = WebTab(url, tmp_path / "fresh.log")
    try:  # a password never used is still taken
        result = tab.do("org_recovery", shares=shares[:2], total_shares=3, password="Never-Used-2026-D!")
        assert result["error"] is None, result
    finally:
        tab.kill()


@requires_node
def test_web_recovery_publishes_browser_pin_into_legacy_bundle(team, server, tmp_path):  # noqa: F811
    """Review 1141a20 H2: the browser's own pin reaches new devices through the rewrapped bundle."""
    from sezam import cli
    from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
    from tests.test_integration_client_server import PASSWORD, _client, _vault
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    item = admin.create_entry(_ops(admin), "pin-secret", [{"key": "password", "value": "actual-shared-secret"}])
    assert client.push()["conflicts"] == []
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
    user["encrypted_keypair"] = legacy  # server still holds the pre-anchor bundle
    new_password = "Portable-Recovery-2026!"
    tab = WebTab(url, tmp_path / "recover.log", idb=profile)
    try:
        result = tab.do("org_recovery", shares=setup["shares"][:2], total_shares=3, password=new_password)
        assert result["error"] is None, result
    finally:
        tab.kill()
    params = Argon2Params.from_dict(json.loads(user["argon2_params"]))
    kek, proof = derive_kek_and_proof(new_password, user["argon2_salt"], params)
    try:
        _, anchor = aead.decrypt_account_keypair(user["encrypted_keypair"], kek, user["id"].encode())
        assert anchor == genesis
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))
    fresh = _vault(tmp_path / "fresh", "admin")
    try:
        cli._server_connect_flow(url, fresh, new_password)
        assert fresh.keypair.confirmed_genesis == genesis
        assert _client(fresh, url).team_log_trusted()
        assert fresh.get_field_value(item, "password") == "actual-shared-secret"
    finally:
        fresh.lock()


@pytest.mark.parametrize("mode", ["password", "identity", "recovery"])
def test_desktop_anchor_survives_key_changes_and_restart(tmp_path, mode):
    from sezam.crypto.keys import KeyPair
    from sezam.vault import pending_states
    from sezam.vault.key_rotation import open_old_keypair
    from tests.test_integration_client_server import PASSWORD, _vault

    vault = _vault(tmp_path / "changes", "owner")
    try:
        keys = KeyPair.from_private_only(aead.encode_account_keypair(vault.keypair.serialize_private(), GENESIS))
        item = vault.create_entry(vault.db.get_meta("root_node_id"), "private", [{"key": "password", "value": "keep-me"}])
        vault.rebind_server_identity(vault.db.get_meta("user_id"), keys)
        new_password = PASSWORD + "-new"
        if mode == "recovery":
            shares = vault.setup_org_recovery(threshold=2, shares=3)
            vault.lock()
            vault.org_recovery(shares[:2], new_password)
        else:
            proof = vault.change_password(PASSWORD, new_password, rotate_identity=mode == "identity")
            proof[:] = bytes(len(proof))
        assert vault.keypair.confirmed_genesis == GENESIS
        if mode == "identity":
            old = open_old_keypair(pending_states.key_change_journal(vault.db), vault.current_kek, vault.db.get_meta("user_id"))
            previous = KeyPair.from_private_only(old)
            assert previous.confirmed_genesis == GENESIS
            assert previous.signing_pk != vault.keypair.signing_pk
            previous.zeroize()
            old[:] = bytes(len(old))
        vault.lock()
        vault.unlock(new_password)
        assert vault.keypair.confirmed_genesis == GENESIS
        assert vault.get_field_value(item, "password") == "keep-me"
    finally:
        vault.lock()


@pytest.mark.parametrize("path", ["password", "identity", "recovery", "later-change"])
def test_desktop_never_returns_to_a_pre_anchor_password(tmp_path, path):
    """Capability run 269: the anchored bundle records the password state it left.

    Publishing moved P0 -> P1; the server may keep the P0 bundle without the
    anchor. No later change on any path may make P0 the password again.
    """
    from sezam.crypto.kdf import Argon2Params, derive_kek
    from sezam.vault.crud import PRE_ANCHOR_PASSWORD_REFUSED
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
    from tests.test_integration_client_server import PASSWORD, _vault

    vault = _vault(tmp_path / "pre-anchor", "owner")
    try:
        s0 = bytes.fromhex(vault.db.get_meta("argon2_salt"))
        p0_params = Argon2Params.from_dict(vault.db.get_meta_json("argon2_params"))
        vault.db.set_meta(CONFIRMED_GENESIS_META, GENESIS)
        p1 = PASSWORD + "-anchored"
        proof = vault.change_password(PASSWORD, p1)  # the publication
        proof[:] = bytes(len(proof))
        keys, genesis, states = aead.decrypt_account_bundle(
            bytes.fromhex(vault.db.get_meta("encrypted_keypair")), vault.current_kek,
            vault.db.get_meta("user_id").encode())
        keys[:] = bytes(len(keys))
        assert genesis == GENESIS
        kek0 = derive_kek(PASSWORD, s0, p0_params)
        assert aead.parse_pre_anchor(states) == [
            (s0, p0_params.time_cost, p0_params.memory_cost, p0_params.parallelism, aead.pre_anchor_check(kek0))]
        kek0[:] = bytes(len(kek0))
        vault.lock()
        vault.unlock(p1)  # survives a restart
        assert vault.keypair.pre_anchor == states
        current = p1
        if path == "later-change":
            current = PASSWORD + "-third"
            proof = vault.change_password(p1, current)
            proof[:] = bytes(len(proof))
            proof = vault.change_password(current, current, Argon2Params(time_cost=1, memory_cost=8192, parallelism=1))
            proof[:] = bytes(len(proof))  # keeping the password (a KDF upgrade) is no return
            vault.lock()
            vault.unlock(current)
            assert vault.keypair.pre_anchor == states
        before = [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")]
        with pytest.raises(ValueError, match="before the team anchor"):
            if path == "recovery":
                shares = vault.setup_org_recovery(threshold=2, shares=3)
                before = [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")]
                vault.lock()
                vault.org_recovery(shares[:2], PASSWORD)
            else:
                vault.change_password(current, PASSWORD, rotate_identity=path == "identity")
        assert str(PRE_ANCHOR_PASSWORD_REFUSED).startswith("This password opened")
        if not vault.is_unlocked:
            vault.unlock(current)
        assert [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")] == before
        assert vault.keypair.pre_anchor == states and vault.keypair.confirmed_genesis == GENESIS
    finally:
        vault.lock()


@pytest.mark.parametrize("path", ["password", "recovery"])
def test_desktop_never_returns_to_an_older_pre_anchor_password(tmp_path, path):
    """Capability run 273: A -> B before the anchor, publish B -> C, then C -> A.

    The server may keep the A bundle as well as the B one; both lack the anchor.
    """
    from sezam.crypto.kdf import Argon2Params, derive_kek
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
    from tests.test_integration_client_server import PASSWORD, _vault

    vault = _vault(tmp_path / "older", "owner")
    try:
        s_a = bytes.fromhex(vault.db.get_meta("argon2_salt"))
        params = Argon2Params.from_dict(vault.db.get_meta_json("argon2_params"))
        b, c = PASSWORD + "-b", PASSWORD + "-c"
        if path == "recovery":
            shares = vault.setup_org_recovery(threshold=2, shares=3)
            vault.lock()
            vault.org_recovery(shares[:2], b)  # A -> B, still without the anchor
        else:
            proof = vault.change_password(PASSWORD, b)
            proof[:] = bytes(len(proof))
        assert vault.keypair.confirmed_genesis is None
        vault.lock()
        vault.unlock(b)  # the recorded A state survives a restart
        vault.db.set_meta(CONFIRMED_GENESIS_META, GENESIS)
        proof = vault.change_password(b, c)  # the publication
        proof[:] = bytes(len(proof))
        kek_a = derive_kek(PASSWORD, s_a, params)
        assert aead.pre_anchor_check(kek_a) in [e[4] for e in aead.parse_pre_anchor(vault.keypair.pre_anchor)]
        kek_a[:] = bytes(len(kek_a))
        assert len(aead.parse_pre_anchor(vault.keypair.pre_anchor)) == 2  # A and B travel in the bundle
        vault.lock()
        vault.unlock(c)
        before = [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")]
        for target in (PASSWORD, b):
            with pytest.raises(ValueError, match="before the team anchor"):
                if path == "recovery":
                    vault.lock()
                    vault.org_recovery(shares[:2], target)
                else:
                    vault.change_password(c, target)
            if not vault.is_unlocked:
                vault.unlock(c)
            assert [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")] == before
        assert vault.keypair.confirmed_genesis == GENESIS
    finally:
        vault.lock()


def test_pre_anchor_states_codec():
    kek = bytes(range(32))
    one = aead.add_pre_anchor(b"", bytes(16), 3, 65536, 4, kek)
    assert len(one) == 1 + aead.PRE_ANCHOR_ENTRY_LEN and aead.add_pre_anchor(one, bytes(16), 3, 65536, 4, kek) == one
    payload = aead.encode_account_keypair(RAW, GENESIS, one)
    assert payload[:8] == b"SZACCT02" and len(payload) == 104 + len(one)
    assert aead.decode_account_bundle(payload) == (RAW, GENESIS, one)
    assert aead.encode_account_keypair(RAW, GENESIS) == PAYLOAD  # no states: unchanged SZACCT01
    many = b""
    for i in range(aead.PRE_ANCHOR_MAX + 2):
        many = aead.add_pre_anchor(many, bytes([i]) * 16, 3, 65536, 4, kek)
    assert [e[0][0] for e in aead.parse_pre_anchor(many)] == list(range(2, aead.PRE_ANCHOR_MAX + 2))
    for bad in (b"SZACCT02" + RAW + bytes.fromhex(GENESIS),  # v2 without states
                b"SZACCT02" + RAW + bytes.fromhex(GENESIS) + b"\x02" + one[1:],  # count lies
                b"SZACCT02" + RAW + bytes.fromhex(GENESIS) + one[:-1],  # truncated
                b"SZACCT01" + RAW + bytes.fromhex(GENESIS) + one,  # v1 with a tail
                b"SZACCT02" + RAW + bytes.fromhex(GENESIS) + one[:17] + bytes(4) + one[21:]):  # time 0
        with pytest.raises(ValueError):
            aead.decode_account_bundle(bad)


@pytest.mark.parametrize("pin", ["team_log_confirmed_genesis_hash", "team_log_genesis_hash"])
def test_desktop_conflicting_anchor_rebind_is_atomic(tmp_path, pin):
    from sezam.crypto.keys import KeyPair
    from sezam.vault.team_log_local import TeamLogMismatch
    from tests.test_integration_client_server import _vault

    vault = _vault(tmp_path / "conflict", "owner")
    keys = KeyPair.from_private_only(PAYLOAD)
    try:
        vault.db.set_meta(pin, "cd" * 32)
        before = [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")]
        own_pk = vault.keypair.signing_pk
        with pytest.raises(TeamLogMismatch, match="conflicts"):
            vault.rebind_server_identity(UID.decode(), keys)
        assert [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")] == before
        assert vault.keypair.signing_pk == own_pk
    finally:
        keys.zeroize()
        vault.lock()


@pytest.mark.parametrize("mode", ["password", "identity", "response-lost"])
def test_desktop_anchor_survives_atomic_server_rotation(team, server, tmp_path, monkeypatch, mode):  # noqa: F811
    from sezam import cli
    from sezam.crypto.keys import KeyPair
    from sezam.vault import pending_states
    from tests.test_integration_client_server import PASSWORD, _client, _vault
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    anchored = KeyPair.from_private_only(aead.encode_account_keypair(admin.keypair.serialize_private(), genesis))
    admin.rebind_server_identity(admin.db.get_meta("user_id"), anchored)
    item = admin.create_entry(_ops(admin), "after-anchor", [{"key": "password", "value": "still-readable"}])
    client = _client(admin, url)
    client.push()
    client.prepare_key_change()
    proof = admin.change_password(PASSWORD, PASSWORD, rotate_identity=mode != "password")
    proof[:] = bytes(len(proof))
    client = _client(admin, url)
    if mode == "response-lost":
        real = client._request
        def lose(method, path, data=None, *args, **kwargs):
            result = real(method, path, data, *args, **kwargs)
            if method == "POST" and path == "/api/sync":
                raise RuntimeError("Network error: response lost")
            return result
        with monkeypatch.context() as m:
            m.setattr(client, "_request", lose)
            with pytest.raises(RuntimeError, match="response lost"):
                client.push()
        assert pending_states.key_change_journal(admin.db)
        admin.lock()
        admin.unlock(PASSWORD)
        client = _client(admin, url)
    client.push()
    assert not pending_states.key_change_journal(admin.db)
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    _, actual = aead.decrypt_account_keypair(bytes(user["encrypted_keypair"]), admin.current_kek, user["id"].encode())
    assert actual == genesis
    fresh = _vault(tmp_path / "rotated-device", "admin")
    try:
        cli._server_connect_flow(url, fresh, PASSWORD)
        assert fresh.keypair.confirmed_genesis == genesis
        assert fresh.get_field_value(item, "password") == "still-readable"
    finally:
        fresh.lock()


@pytest.mark.parametrize(
    "case",
    ["founder", "member", "untrusted", "password-change", "response-lost", "same-password", "rollback",
     "return"],
)
def test_desktop_publishes_trusted_anchor_for_new_devices(team, server, tmp_path, monkeypatch, case):  # noqa: F811
    """Review 1141a20 H2: a trusted log reaches a brand-new device through the account bundle.

    Capability run 264: publication is a password change. Under the same
    password the server could serve a new device the pre-anchor salt + keys
    ('rollback'); the new password cannot open them.
    """
    import copy
    from click.testing import CliRunner
    from sezam import cli
    from sezam.vault.revocation import grant_member
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
    from sezam.vault.crud import Vault
    from tests.test_integration_client_server import PARAMS, PASSWORD, _client
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "published", [{"key": "password", "value": "actual-shared-secret"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    client.push()
    genesis = client.team_state().genesis_hash
    owner = admin if case in ("founder", "password-change", "response-lost") else bob
    new_password = PASSWORD if case == "same-password" else "published-anchor-pw-2!"
    if case in ("member", "same-password", "rollback", "return"):
        confirmed = dict(bob.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {})
        confirmed[admin.db.get_meta("user_id")] = admin.keypair.fingerprint
        bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
    user = next(u for u in db._storage["users"] if u["id"] == owner.db.get_meta("user_id"))
    before = bytes(user["encrypted_keypair"])
    pre_anchor_row = copy.deepcopy(user)
    assert aead.decrypt_account_keypair(before, owner.current_kek, user["id"].encode())[1] is None

    if case == "password-change":
        # An ordinary password change of a trusting device publishes it too.
        owner_client = _client(owner, url)
        owner_client.prepare_key_change()
        proof = owner.change_password(PASSWORD, new_password)
        proof[:] = bytes(len(proof))
        _client(owner, url).push()
    else:
        monkeypatch.setattr(cli, "_open_vault", lambda: owner)
        monkeypatch.setattr(
            cli, "_get_password",
            lambda prompt="", *a, **k: new_password if "new" in prompt.lower() else PASSWORD,
        )
        monkeypatch.setattr(cli, "_check_rate_limit", lambda: None)
        monkeypatch.setattr(cli, "_clear_failed_attempts", lambda: None)
        monkeypatch.setattr(cli, "_clear_session", lambda: None)
        if case == "response-lost":
            from sezam.vault.sync_client import SyncClient
            real = SyncClient._request
            def lose(self, method, path, data=None, *args, **kwargs):
                result = real(self, method, path, data, *args, **kwargs)
                if method == "POST" and path == "/api/sync":
                    raise RuntimeError("Network error: response lost")
                return result
            with monkeypatch.context() as m:
                m.setattr(SyncClient, "_request", lose)
                out = CliRunner().invoke(cli.main, ["team-log", "publish-anchor"])
            assert out.exit_code == 0, out.output
            assert "response lost" in out.output
            owner.unlock(new_password)
            _client(owner, url).push()  # the retry of the kept journal
        else:
            out = CliRunner().invoke(cli.main, ["team-log", "publish-anchor"])
            if case in ("untrusted", "same-password"):
                assert out.exit_code != 0 and "nothing was published" in out.output.lower(), out.output
            else:
                assert out.exit_code == 0, out.output
    unpublished = case in ("untrusted", "same-password")
    password = PASSWORD if unpublished else new_password
    owner.unlock(password)

    user = next(u for u in db._storage["users"] if u["id"] == owner.db.get_meta("user_id"))
    _, published = aead.decrypt_account_keypair(bytes(user["encrypted_keypair"]), owner.current_kek, user["id"].encode())
    if unpublished:
        assert bytes(user["encrypted_keypair"]) == before and published is None
        if case == "untrusted":
            assert owner.db.get_meta(CONFIRMED_GENESIS_META) is None
    else:
        assert published == genesis
        assert owner.db.get_meta(CONFIRMED_GENESIS_META) == genesis
    fresh = Vault.create(tmp_path / "fresh", password, PARAMS)
    fresh.db.set_meta("username", "admin" if owner is admin else "bob")
    if case == "rollback":
        # A malicious server serves the account's pre-anchor salt, keys and
        # verifier again: the new password does not open them.
        user.clear()
        user.update(pre_anchor_row)
        try:
            cli._server_connect_flow(url, fresh, password)
        except (Exception, SystemExit):
            pass  # refused loudly or quietly: either way nothing below may be taken
        assert fresh.db.get_meta("server_url") is None
        assert fresh.keypair.fingerprint != owner.keypair.fingerprint
        assert fresh.keypair is None or fresh.keypair.confirmed_genesis is None
        assert fresh.db.fetchone("SELECT id FROM entries WHERE id = ?", (item,)) is None
        fresh.lock()
        # Control: the served row is a working rollback; only the OLD password
        # opens it, and that yields no pin (why the same password is refused).
        old = Vault.create(tmp_path / "old", PASSWORD, PARAMS)
        old.db.set_meta("username", "bob")
        cli._server_connect_flow(url, old, PASSWORD)
        assert old.keypair.fingerprint == owner.keypair.fingerprint
        assert old.keypair.confirmed_genesis is None
        old.lock()
        return
    try:
        cli._server_connect_flow(url, fresh, password)
        assert fresh.keypair.confirmed_genesis == (None if unpublished else genesis)
        if case == "return":
            # Capability run 269: neither the publishing device nor a new one
            # that never knew P0 lets the account go back to it.
            assert fresh.keypair.pre_anchor == owner.keypair.pre_anchor != b""
            for device in (owner, fresh):
                with pytest.raises(ValueError, match="before the team anchor"):
                    device.change_password(password, PASSWORD)
        if unpublished:
            assert not _client(fresh, url).team_log_trusted()
            assert fresh.db.fetchone("SELECT id FROM entries WHERE id = ?", (item,)) is None
        else:
            assert _client(fresh, url).team_log_trusted()
            assert fresh.get_field_value(item, "password") == "actual-shared-secret"
            fresh.lock()
            fresh.unlock(password)
            assert fresh.get_field_value(item, "password") == "actual-shared-secret"
    finally:
        fresh.lock()


@pytest.mark.parametrize("case", ["publish", "lost", "adopted"])
def test_phone_founder_confirmation_publishes_anchor_with_new_password(team, server, tmp_path, case):  # noqa: F811
    """Review 1141a20 H2: the founder a phone confirmed reaches the account's next devices.

    Capability run 264: only with a NEW password (the same one, a wrong
    current one or an unconfirmed founder change nothing on the server).
    'lost': the server applied the change, its answer never came; the phone
    tells by the salt it serves and takes the change over. Then the server
    serves the pre-anchor salt + keys again: the new password opens them for
    no new device, the old one yields keys without the pin.
    """
    import copy
    from sezam import cli
    from sezam.crypto.envelope_crypto import compute_fingerprint
    from sezam.vault.crud import Vault
    from sezam.vault.revocation import grant_member
    from tests.test_cross_client_password_change import _phone
    from tests.test_integration_client_server import PARAMS, PASSWORD, _client
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "published", [{"key": "password", "value": "actual-shared-secret"}])
    assert client.push()["conflicts"] == []
    bob_id = bob.db.get_meta("user_id")
    grant_member(admin, client, bob_id, folder, "read")
    genesis = client.team_state().genesis_hash
    new_password = "phone-published-anchor-pw!"
    key_fields = ("encrypted_keypair", "argon2_salt", "auth_proof_hash", "argon2_params", "token_epoch")

    def row():
        return next(u for u in db._storage["users"] if u["id"] == bob_id)

    pre_anchor_row = copy.deepcopy(row())
    assert aead.decrypt_account_keypair(
        bytes(pre_anchor_row["encrypted_keypair"]), bob.current_kek, bob_id.encode())[1] is None
    baseline = [pre_anchor_row]
    between_password = "desktop-between-pw-2026!"

    def unchanged():
        assert {k: row()[k] for k in key_fields} == {k: baseline[0][k] for k in key_fields}

    def changed_elsewhere():
        # Capability run 273: 'adopted' - bob's desktop leaves A before any anchor.
        proof = bob.change_password(PASSWORD, between_password)
        proof[:] = bytes(len(proof))
        assert bob.keypair.confirmed_genesis is None
        assert _client(bob, url).push()["conflicts"] == []
        baseline[0] = copy.deepcopy(row())

    out = _phone(url, tmp_path, {
        "case": case, "user_id": bob_id, "password": PASSWORD, "new_password": new_password,
        "between_password": between_password,
        "fingerprint": compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk),
        "genesis": genesis,
    }, {**({"changed_elsewhere": changed_elsewhere} if case == "adopted" else {}),  # the phone's order
        "unchanged": unchanged, "published": lambda: None}, "test/phone_publish_anchor_test.dart")
    assert "All tests passed!" in out, out
    assert bytes(row()["argon2_salt"]) != bytes(pre_anchor_row["argon2_salt"])

    fresh = Vault.create(tmp_path / "fresh", new_password, PARAMS)
    fresh.db.set_meta("username", "bob")
    try:
        cli._server_connect_flow(url, fresh, new_password)
        assert fresh.keypair.confirmed_genesis == genesis
        assert _client(fresh, url).team_log_trusted()
        assert fresh.get_field_value(item, "password") == "actual-shared-secret"
        # Capability run 269: the phone recorded the password state it left.
        with pytest.raises(ValueError, match="before the team anchor"):
            fresh.change_password(new_password, PASSWORD)
    finally:
        fresh.lock()

    # A malicious server serves the pre-anchor salt, keys and verifier again.
    current = row()
    current.clear()
    current.update(copy.deepcopy(pre_anchor_row))
    rolled = Vault.create(tmp_path / "rolled", new_password, PARAMS)
    rolled.db.set_meta("username", "bob")
    try:
        cli._server_connect_flow(url, rolled, new_password)
    except (Exception, SystemExit):
        pass  # refused loudly or quietly: either way nothing below may be taken
    assert rolled.db.get_meta("server_url") is None
    assert rolled.keypair is None or rolled.keypair.confirmed_genesis is None
    assert rolled.db.fetchone("SELECT id FROM entries WHERE id = ?", (item,)) is None
    rolled.lock()
    old = Vault.create(tmp_path / "old", PASSWORD, PARAMS)
    old.db.set_meta("username", "bob")
    cli._server_connect_flow(url, old, PASSWORD)
    assert old.keypair.fingerprint == bob.keypair.fingerprint
    assert old.keypair.confirmed_genesis is None
    old.lock()


@requires_node
@pytest.mark.parametrize(
    "case", ["member", "wrong-password", "same-password", "response-lost", "recovery-admin", "rollback"]
)
def test_web_founder_confirmation_publishes_anchor_for_new_devices(team, server, tmp_path, case):  # noqa: F811
    """Review 1141a20 H2: a browser's founder confirmation reaches the account's next devices.

    Capability run 264: only with a NEW password. 'rollback': the server serves
    the pre-anchor salt + keys again; the new password does not open them, and
    the old one yields an unpinned login that takes no shared key.
    """
    import copy
    import urllib.request
    from sezam import cli
    from sezam.crypto.keys import compute_fingerprint
    from sezam.crypto.kdf import Argon2Params, derive_kek_and_proof
    from sezam.vault.crud import Vault
    from sezam.vault.revocation import grant_member
    from tests.test_integration_client_server import PARAMS, PASSWORD, _client
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "web-published", [{"key": "password", "value": "actual-shared-secret"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    assert client.push()["conflicts"] == []
    genesis = client.team_state().genesis_hash
    fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    owner = admin if case == "recovery-admin" else bob
    name = "admin" if owner is admin else "bob"
    user_id = owner.db.get_meta("user_id")
    user = next(u for u in db._storage["users"] if u["id"] == user_id)
    before = bytes(user["encrypted_keypair"])
    pre_anchor_row = copy.deepcopy(user)
    refused = {"wrong-password": "team.publish_wrong_password", "same-password": "team.publish_same_password",
               "recovery-admin": "team.publish_recovery"}.get(case)
    new_password = PASSWORD if case == "same-password" else "Web-Published-Anchor-2026!"
    password = "Wrong-Password-2026!" if case == "wrong-password" else PASSWORD
    tab = WebTab(url, tmp_path / f"{case}.log")
    try:
        assert tab.do("login", username=name, password=PASSWORD)["error"] is None
        if case == "recovery-admin":
            setup = tab.do("org_recovery_setup", threshold=2, total_shares=3, password=PASSWORD)
            assert setup["error"] is None, setup
        fail = {"method": "POST", "path": "/api/sync", "mode": "after"} if case == "response-lost" else None
        result = tab.do("founder", open=True, fingerprint=fingerprint, password=password,
                        new_password=new_password, fail=fail)
        if refused:
            assert refused in (result["error"] or ""), result
            assert not any(c["method"] == "POST" and c["path"] == "/api/sync" for c in result["calls"]), result
        elif case == "response-lost":
            assert "reply lost" in (result["error"] or ""), result
        else:
            assert result["error"] is None, result
        # The confirmation itself holds in this browser either way.
        assert any(e["password"] == "actual-shared-secret" for e in result["view"]["entries"]), result
        profile = tab.close()
    finally:
        tab.kill()
    login_password = PASSWORD if refused else new_password
    if case == "response-lost":
        tab = WebTab(url, tmp_path / "resume.log", idb=profile)
        try:
            login = tab.do("login", username=name, password=login_password)
            assert login["error"] is None, login
            profile = tab.close()
        finally:
            tab.kill()
        assert not any(row["id"].startswith("pending_kek_rotation:") for row in profile["keys"])

    user = next(u for u in db._storage["users"] if u["id"] == user_id)
    params = Argon2Params.from_dict(json.loads(user["argon2_params"]))
    kek, proof = derive_kek_and_proof(login_password, user["argon2_salt"], params)
    try:
        _, anchor = aead.decrypt_account_keypair(bytes(user["encrypted_keypair"]), kek, user["id"].encode())
    finally:
        kek[:] = bytes(len(kek))
        proof[:] = bytes(len(proof))
    if refused:
        assert bytes(user["encrypted_keypair"]) == before and anchor is None
        if case == "recovery-admin":
            with urllib.request.urlopen(url + "/api/org-recovery/status") as resp:
                assert json.loads(resp.read())["stale"] is False
        return
    assert anchor == genesis

    if case == "rollback":
        user.clear()
        user.update(pre_anchor_row)
        tab = WebTab(url, tmp_path / "rollback-new.log")
        try:
            login = tab.do("login", username=name, password=new_password)
            assert login["error"] is not None, login
            assert not any(e.get("password") == "actual-shared-secret"
                           for e in (login.get("view") or {}).get("entries", [])), login
        finally:
            tab.kill()
        fresh = Vault.create(tmp_path / "fresh", new_password, PARAMS)
        fresh.db.set_meta("username", name)
        try:
            cli._server_connect_flow(url, fresh, new_password)
        except (Exception, SystemExit):
            pass
        assert fresh.db.get_meta("server_url") is None
        fresh.lock()
        # Control: only the old password opens the rolled-back keys, and that
        # unpinned browser trusts no log, so it takes no shared key.
        tab = WebTab(url, tmp_path / "rollback-old.log")
        try:
            login = tab.do("login", username=name, password=PASSWORD)
            assert login["error"] is None, login
            assert not any(e["password"] == "actual-shared-secret" for e in login["view"]["entries"]), login
        finally:
            tab.kill()
        return

    fresh = Vault.create(tmp_path / "fresh", login_password, PARAMS)
    fresh.db.set_meta("username", name)
    try:
        cli._server_connect_flow(url, fresh, login_password)
        assert fresh.keypair.confirmed_genesis == genesis
        assert _client(fresh, url).team_log_trusted()
        assert fresh.get_field_value(item, "password") == "actual-shared-secret"
        if login_password != PASSWORD:  # capability run 269: the browser recorded the state it left
            with pytest.raises(ValueError, match="before the team anchor"):
                fresh.change_password(login_password, PASSWORD)
    finally:
        fresh.lock()
    tab = WebTab(url, tmp_path / "fresh-web.log")
    try:
        login = tab.do("login", username=name, password=login_password)
        assert login["error"] is None, login
        assert any(e["password"] == "actual-shared-secret" for e in login["view"]["entries"]), login
    finally:
        tab.kill()


def test_desktop_failed_anchor_publication_changes_nothing(team, server, monkeypatch):  # noqa: F811
    from sezam.vault import pending_states
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
    from tests.test_integration_client_server import PASSWORD, _client

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    encrypted = admin.db.get_meta("encrypted_keypair")
    _client(admin, url).prepare_key_change()

    def fail(*_a, **_k):
        raise OSError("disk full")
    with monkeypatch.context() as m:
        m.setattr(pending_states, "set_key_change_journal", fail)
        with pytest.raises(OSError, match="disk full"):
            admin.change_password(PASSWORD, PASSWORD)
    assert admin.keypair.confirmed_genesis is None
    assert admin.db.get_meta(CONFIRMED_GENESIS_META) is None
    assert admin.db.get_meta("encrypted_keypair") == encrypted
    proof = admin.change_password(PASSWORD, PASSWORD)  # honest retry
    proof[:] = bytes(len(proof))
    _client(admin, url).push()
    user = next(u for u in db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
    assert aead.decrypt_account_keypair(bytes(user["encrypted_keypair"]), admin.current_kek,
                                        user["id"].encode())[1] == genesis


def test_desktop_existing_bundle_cannot_downgrade_to_legacy(tmp_path):
    from sezam.crypto.keys import KeyPair
    from tests.test_integration_client_server import _vault

    vault = _vault(tmp_path / "downgrade", "owner")
    raw = vault.keypair.serialize_private()
    keys = KeyPair.from_private_only(aead.encode_account_keypair(raw, GENESIS))
    legacy = KeyPair.from_private_only(raw)
    try:
        vault.rebind_server_identity(vault.db.get_meta("user_id"), keys)
        before = [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")]
        with pytest.raises(RuntimeError, match="missing.*authenticated anchor"):
            vault.rebind_server_identity(vault.db.get_meta("user_id"), legacy)
        assert [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")] == before
        assert vault.keypair.confirmed_genesis == GENESIS
    finally:
        raw[:] = bytes(len(raw))
        legacy.zeroize()
        vault.lock()


def test_desktop_recovery_rejects_authenticated_unsupported_bundles():
    from sezam.vault.crud import open_server_keypair

    for case in _input(list(_cases()))["envelopes"]:
        if not case["ok"]:
            with pytest.raises((ValueError, RuntimeError)):
                open_server_keypair({"encrypted_keypair": case["envelope"], "user_id": case.get("user", UID.decode())}, KEK)


@pytest.mark.parametrize("failure", ["storage", "unlock-conflict", "recovery-conflict"])
def test_desktop_anchor_failure_preserves_data_and_retry(tmp_path, monkeypatch, failure):
    from sezam.crypto.keys import KeyPair
    from sezam.vault.team_log_local import CONFIRMED_GENESIS_META, TeamLogMismatch, local_team_state
    from tests.test_integration_client_server import PASSWORD, _vault

    vault = _vault(tmp_path / "failure", "owner")
    keys = KeyPair.from_private_only(aead.encode_account_keypair(vault.keypair.serialize_private(), GENESIS))
    item = vault.create_entry(vault.db.get_meta("root_node_id"), "private", [{"key": "password", "value": "keep-me"}])
    try:
        before = [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")]
        if failure == "storage":
            write = vault.db.set_meta
            def fail(key, value):
                if key == "encrypted_keypair":
                    raise OSError("injected disk full")
                return write(key, value)
            with monkeypatch.context() as m:
                m.setattr(vault.db, "set_meta", fail)
                with pytest.raises(OSError, match="disk full"):
                    vault.rebind_server_identity(vault.db.get_meta("user_id"), keys)
            assert [tuple(r) for r in vault.db.fetchall("SELECT * FROM vault_meta ORDER BY key")] == before
        vault.rebind_server_identity(vault.db.get_meta("user_id"), keys)
        password = PASSWORD
        if failure != "storage":
            shares = vault.setup_org_recovery(threshold=2, shares=3) if failure == "recovery-conflict" else None
            vault.db.set_meta(CONFIRMED_GENESIS_META, "cd" * 32)
            vault.lock()
            # INV-7 (capability run 397): the conflict refuses the team, never
            # the unlock; the independent pin is not replaced.
            if shares:
                password = PASSWORD + "-new"
                vault.org_recovery(shares[:2], password)
            else:
                vault.unlock(PASSWORD)
            assert vault.is_unlocked and vault.get_field_value(item, "password") == "keep-me"
            with pytest.raises(TeamLogMismatch, match="another team log") as refused:
                local_team_state(vault.db)
            assert refused.value.cause == "anchor_conflict"
            assert vault.db.get_meta(CONFIRMED_GENESIS_META) == "cd" * 32
            # Restore the fixture's independent pin, not an application auto-reset.
            vault.db.set_meta(CONFIRMED_GENESIS_META, GENESIS)
        vault.lock()
        vault.unlock(password)
        assert vault.keypair.confirmed_genesis == GENESIS
        assert vault.get_field_value(item, "password") == "keep-me"
    finally:
        keys.zeroize()
        vault.lock()


def test_account_bundle_authentication_and_rewrap():
    envelope = aead.encrypt_account_keypair(FULL, GENESIS, KEK, KID, UID)
    assert aead.decrypt_account_keypair(envelope, KEK, UID) == (RAW, GENESIS)
    assert aead.decrypt_keypair_wrap(envelope, KEK, UID) == PAYLOAD
    for mutation in ("account", "kek", "tag", "kind", "schema", "algorithm"):
        altered = bytearray(envelope)
        user = UID
        key = KEK
        if mutation == "account":
            user = b"01JACC0000000000000000000G"
        elif mutation == "kek":
            key = bytes(32)
        else:
            altered[{"tag": -1, "kind": 2, "schema": 1, "algorithm": 0}[mutation]] ^= 1
        with pytest.raises((ValueError, CryptoError)):
            aead.decrypt_account_keypair(bytes(altered), key, user)
    for case in _cases():
        blob = aead.encrypt_keypair_wrap(bytes.fromhex(case["payload"]), KEK, KID, UID)
        if case["ok"]:
            assert aead.decrypt_account_keypair(blob, KEK, UID) == (RAW, case["genesis"])
        else:
            with pytest.raises(ValueError):
                aead.decrypt_account_keypair(blob, KEK, UID)
    for case in _input(list(_cases()))["envelopes"]:
        if not case["ok"]:
            with pytest.raises((ValueError, CryptoError)):
                aead.decrypt_account_keypair(bytes.fromhex(case["envelope"]), KEK, case.get("user", UID.decode()).encode())
    keys, anchor = aead.decrypt_account_keypair(envelope, KEK, UID)
    rotated = aead.encrypt_account_keypair(keys, anchor, bytes(32), KID, UID)
    assert aead.decrypt_account_keypair(rotated, bytes(32), UID) == (RAW, GENESIS)


def _web(source, cases, incoming=()):
    functions = "\n".join(_web_function(source, name) for name in (
        "encodeAccountKeypair", "decodeAccountKeypair", "encryptAccountKeypair", "decryptAccountKeypair",
        "encryptKeypairWrap", "decryptKeypairWrap", "expandDesktopKeypair", "buildAAD",
        "padPlaintext", "unpadPlaintext", "bytesToHex", "hexToBytes", "parsePreAnchor",
    ))
    constants = "\n".join(_web_constant(source, n) for n in (
        "ENVELOPE_ALG", "SCHEMA_VERSION", "BLOB_KIND", "PRE_ANCHOR_ENTRY_LEN", "PRE_ANCHOR_MAX",
        "ACCOUNT_BUNDLE_LENGTHS"))
    body = r"""
async function run(V) {
  await sodium.ready; const s = sodium;
  const check = (v, name) => { if (!v) throw new Error(name); };
  const raw = hexToBytes(V.raw), full = hexToBytes(V.full), kek = hexToBytes(V.kek);
  for (const keys of [raw, full]) check(bytesToHex(encodeAccountKeypair(keys, V.genesis, s)) === V.payload, 'encode');
  for (const c of V.cases) {
    let result;
    try { result = decodeAccountKeypair(hexToBytes(c.payload), s); }
    catch (e) { if (c.ok) throw e; continue; }
    check(c.ok && bytesToHex(result.keypairData) === V.raw && result.confirmedGenesis === c.genesis, c.name);
  }
  for (const g of [null, '', 'AB'.repeat(32), 'ab'.repeat(31), 'gg'.repeat(32), V.genesis + '\n']) {
    let refused = false;
    try { encodeAccountKeypair(raw, g, s); } catch { refused = true; }
    check(refused, 'invalid anchor');
  }
  for (const c of V.envelopes) {
    let result;
    try { result = decryptAccountKeypair(hexToBytes(c.envelope), kek, c.user || V.user, s); }
    catch (e) { if (c.ok) throw e; continue; }
    check(c.ok && bytesToHex(result.keypairData) === V.raw && result.confirmedGenesis === c.genesis, c.name);
  }
  return bytesToHex(encryptAccountKeypair(full, V.genesis, kek, V.kid, V.user, s));
}
"""
    harness = r"""
const fs = require('fs'), vm = require('vm'), {webcrypto} = require('crypto');
const c = {Uint8Array, TextEncoder, TextDecoder, DataView, ArrayBuffer, WebAssembly, Promise,
  crypto:webcrypto, console, setTimeout, clearTimeout, atob: v => Buffer.from(v, 'base64').toString('binary')};
c.window=c; c.self=c; c.globalThis=c; vm.createContext(c);
for(const p of process.argv.slice(1,3)) vm.runInContext(fs.readFileSync(p,'utf8'),c);
const input=JSON.parse(fs.readFileSync(0,'utf8')); vm.runInContext(input.source,c);
c.run(input.vectors).then(x=>process.stdout.write(JSON.stringify(x))).catch(e=>{console.error(e);process.exit(1)});
"""
    payload = _input(cases, incoming)
    vendor = ROOT / "web/static/js/vendor"
    result = subprocess.run([node_cmd(), "-e", harness, str(vendor / "libsodium-sumo.min.js"),
                             str(vendor / "libsodium-wrappers.min.js")],
                            input=json.dumps({"source": constants + functions + body, "vectors": payload}),
                            text=True, encoding="utf-8", capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _input(cases, incoming=()):
    envelopes = [{**c, "envelope": aead.encrypt_keypair_wrap(bytes.fromhex(c["payload"]), KEK, KID, UID).hex()}
                 for c in cases]
    blob = aead.encrypt_keypair_wrap(PAYLOAD, KEK, KID, UID)
    envelopes.append({"name": "cross-account", "envelope": blob.hex(), "user": "01JACC0000000000000000000G", "ok": False})
    for field, offset in (("tag", -1), ("kind", 2), ("schema", 1), ("algorithm", 0)):
        changed = bytearray(blob)
        changed[offset] ^= 1
        envelopes.append({"name": field, "envelope": changed.hex(), "ok": False})
    # Unsupported headers with VALID tags must also fail, not just bit flips.
    for alg, schema, kind, kid in ((2, 1, 7, KID), (1, 2, 7, KID), (1, 1, 6, KID), (1, 1, 7, b"x" * 26)):
        nonce = bytes(range(24))
        aad = aead.build_aad(alg, schema, kind, kid, UID, 1)
        ciphertext = aead.nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(b"\x00\x00" + PAYLOAD, aad, nonce, KEK)
        envelope = bytes([alg, schema, kind]) + kid + nonce + ciphertext
        envelopes.append({"name": "authenticated-invalid-header", "envelope": envelope.hex(), "ok": False})
    envelopes.extend({"name": "other-client", "envelope": e, "ok": True, "genesis": GENESIS} for e in incoming)
    return {"raw": RAW.hex(), "full": FULL.hex(), "genesis": GENESIS, "payload": PAYLOAD.hex(),
            "kek": KEK.hex(), "kid": KID.decode(), "user": UID.decode(), "cases": cases, "envelopes": envelopes}


@requires_node
def test_account_bundle_web_desktop_exchange():
    source = (ROOT / "web/static/js/app.js").read_text(encoding="utf-8")
    emitted = _web(source, list(_cases()))
    assert aead.decrypt_account_keypair(bytes.fromhex(emitted), KEK, UID) == (RAW, GENESIS)


@requires_node
def test_account_bundle_three_client_exchange(tmp_path):
    from tests.test_cross_client_password_change import _phone

    source = (ROOT / "web/static/js/app.js").read_text(encoding="utf-8")
    cases = list(_cases())
    web = _web(source, cases)
    python = aead.encrypt_account_keypair(RAW, GENESIS, KEK, KID, UID).hex()
    _phone("", tmp_path, _input(cases, [web, python]), {}, "test/account_anchor_bundle_test.dart")
    mobile = json.loads((tmp_path / "phone/emitted.json").read_text(encoding="utf-8"))
    assert aead.decrypt_account_keypair(bytes.fromhex(mobile), KEK, UID) == (RAW, GENESIS)
    _web(source, cases, [mobile])
