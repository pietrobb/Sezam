"""The phone follows the signed team log (TL5; docs/DESIGN_TEAM_LOG.md §4.3, §6).

Real desktop admin, real server, real phone (flutter test). A lying server
took an item a member the log gives only read pushed into a team folder; the
phone does not store it (first sync, pull, full resync). After the member's
removal the folder is at the log's second generation, and what the phone
writes there is sealed with it: the honest server takes it and the desktop
reads it.
"""

from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.models import new_ulid
from sezam.vault import revocation
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_pull import _entry_payload, _lying_server, _push, shared  # noqa: F401  (fixture)

PHONE_TEST = "test/phone_team_log_test.dart"


@pytest.mark.parametrize("case", ["kek-unconfirmed", "kek-honest", "kek-withdrawn", "kek-cached-withdrawn",
                                  "box-unconfirmed", "box-honest", "box-rotated-honest", "member-rotated-honest", "founder-honest", "founder-rotated-honest", "portable-honest", "portable-foreign", "portable-storage", "portable-conflict", "portable-backup-honest", "portable-backup-crash-honest", "portable-connect-honest", "portable-connect-crash-honest"])
def test_phone_team_key_receipt_requires_confirmed_authority(team, server, tmp_path, case):  # noqa: F811
    from sezam.crypto.aead import encrypt_dek_wrap
    from sezam.models import ulid_to_bytes
    from tests.test_team_log_desktop import _found_with_bob
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "anchor-secret", [{"key": "password", "value": "must-stay-sealed"}])
    assert client.push()["conflicts"] == []
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, client, bob_id, ops, "read")
    key = teamlog.current_key(client.team_state(), ops)
    if case.startswith("kek-"):
        row = next(o for o in db._storage["vault_objects"] if o["id"] == key)
        payload = encrypt_dek_wrap(admin.dek_mgr.unlock_dek(key), bob.dek_mgr._kek,
                                   ulid_to_bytes(bob.dek_mgr.kek_dek_id), ulid_to_bytes(key),
                                   version=row["version"])
        signed = client._make_sync_object(key, "dek", payload, parent_ref=ops, version=row["version"])
        row.update(payload=payload, payload_hash=signed["payload_hash"],
                   client_signature=bytes.fromhex(signed["signature"]))
        envelope = next(o for o in db._storage["vault_objects"]
                        if o["object_type"] == "envelope" and o["parent_ref"] == key)
        envelope["access_level"] = "write"  # The box cannot mask a failed KEK path.

    backup = None
    if case.startswith("portable-backup"):
        from sezam.crypto import aead
        from sezam.crypto.keys import KeyPair, export_sezam_key
        from tests.test_integration_client_server import PARAMS
        user = next(u for u in db._storage["users"] if u["id"] == bob_id)
        keys = KeyPair.from_private_only(aead.encode_account_keypair(
            bob.keypair.serialize_private(), client.team_state().genesis_hash))
        backup_path = tmp_path / "account.sezam-key"
        export_sezam_key(keys, bob.current_kek, backup_path, user["argon2_salt"], PARAMS)
        backup = backup_path.read_bytes().hex()
        keys.zeroize()
    elif case.startswith("portable-") and not case.startswith("portable-connect"):
        from sezam.crypto.aead import encrypt_account_keypair
        user = next(u for u in db._storage["users"] if u["id"] == bob_id)
        user["encrypted_keypair"] = encrypt_account_keypair(
            bob.keypair.serialize_private(), "ab" * 32 if case == "portable-foreign" else client.team_state().genesis_hash,
            bob.current_kek, bob.db.get_meta("kek_dek_id").encode(), bob_id.encode())

    def anchor_account():
        from sezam.crypto.aead import encrypt_account_keypair
        user = next(u for u in db._storage["users"] if u["id"] == bob_id)
        user["encrypted_keypair"] = encrypt_account_keypair(
            bob.keypair.serialize_private(), client.team_state().genesis_hash,
            bob.current_kek, bob.db.get_meta("kek_dek_id").encode(), bob_id.encode())

    def access(level):
        client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": level})])

    if case == "kek-withdrawn":
        access(None)
    if case == "member-rotated-honest":  # goal #369: the admin seals to the member's new key
        from tests.test_integration_client_server import _client
        from tests.test_review9_team_identity import _rotate
        from tests.test_review9_team_log_restore import _pull_confirming
        from tests.test_team_log_desktop import _confirm_founder
        _confirm_founder(admin, bob)
        bob_client = _client(bob, url)
        bob_client.pull()
        _rotate(bob, bob_client, url).push()
        client = _client(admin, url)
        _pull_confirming(client)
        assert client.push()["conflicts"] == []
    if case in ("box-rotated-honest", "founder-rotated-honest"):
        from tests.test_integration_client_server import _client
        client.prepare_key_change()
        admin.db.execute("DELETE FROM access_envelopes WHERE user_id = ?", (bob_id,))
        proof = admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
        proof[:] = bytes(len(proof))
        client = _client(admin, url)
        assert client.push()["conflicts"] == []
    out = _phone(url, tmp_path, {
        "case": case, "user_id": bob_id, "password": PASSWORD, "backup": backup,
        "genesis": client.team_state().genesis_hash,
    }, {"withdraw": lambda: access(None), "regrant": lambda: access("read")}
        if case == "kek-cached-withdrawn" else {"anchor_account": anchor_account}
        if case.startswith("portable-connect") else {}, "test/phone_key_receipt_trust_test.dart")
    assert "All tests passed!" in out, out


@pytest.mark.parametrize("rotation", ["none", "old", "current"])
def test_phone_founder_confirmation_ui_restart(team, server, tmp_path, rotation):  # noqa: F811
    from sezam.crypto.envelope_crypto import compute_fingerprint
    from tests.test_team_log_desktop import _found_with_bob
    from tests.test_team_log_desktop_changes import _ops

    url, _ = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    if rotation != "none":
        from tests.test_review9_team_identity import _rotate
        client = _rotate(admin, client, url)
        if rotation == "current":
            fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    ops = _ops(admin)
    admin.create_entry(ops, "anchor-secret", [{"key": "password", "value": "must-stay-sealed"}])
    assert client.push()["conflicts"] == []
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, client, bob_id, ops, "read")
    out = _phone(url, tmp_path, {
        "user_id": bob_id, "password": PASSWORD, "fingerprint": fingerprint,
        "genesis": client.team_state().genesis_hash,
    }, {}, "test/phone_founder_trust_ui_test.dart")
    assert "All tests passed!" in out, out


@pytest.mark.parametrize("operation", ["entry", "node", "update", "delete", "tier2", "retry"])
def test_phone_unconfirmed_team_writes_preserve_queue(team, server, tmp_path, operation):  # noqa: F811
    from tests.test_team_log_desktop import _found_with_bob
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    from sezam.crypto.aead import encrypt_dek_wrap
    from sezam.models import ulid_to_bytes

    root_key, raw_key = admin.dek_mgr.get_dek_for_node(admin.db.get_meta("root_node_id"))
    root_row = next(o for o in db._storage["vault_objects"] if o["id"] == root_key)
    payload = encrypt_dek_wrap(raw_key, bob.dek_mgr._kek, ulid_to_bytes(bob.dek_mgr.kek_dek_id),
                               ulid_to_bytes(root_key), version=root_row["version"])
    signed = client._make_sync_object(root_key, "dek", payload, version=root_row["version"])
    root_row.update(payload=payload, payload_hash=signed["payload_hash"],
                    client_signature=bytes.fromhex(signed["signature"]))
    revocation.grant_member(admin, client, bob_id, ops, "write")
    before = len(db._storage["vault_objects"])
    out = _phone(url, tmp_path, {
        "operation": operation, "user_id": bob_id, "password": PASSWORD,
        "genesis": client.team_state().genesis_hash, "folder": ops,
    }, {}, "test/phone_team_write_trust_test.dart")
    assert "All tests passed!" in out, out
    assert len(db._storage["vault_objects"]) > before


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("trust,lie", [(trust, lie) for trust in ("fragment", "carrier")
                                      for lie in ("none", "missing", "foreign", "network", "storage")]
                         + [("conflict", "none"), ("pinned-conflict", "none")])
def test_qr_anchor_survives_join_failure_retry_and_restart(team, server, tmp_path, local, trust, lie):  # noqa: F811
    from urllib.parse import urlencode
    from tests.test_team_log_desktop import _found_with_bob
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    assert client.push()["conflicts"] == []
    genesis = client.team_state().genesis_hash

    attempts = 0
    def token():
        nonlocal attempts
        from sezam.crypto.aead import encrypt_account_keypair
        if trust != "fragment":
            user_id = admin.db.get_meta("user_id")
            user = next(u for u in db._storage["users"] if u["id"] == user_id)
            user["encrypted_keypair"] = encrypt_account_keypair(
                admin.keypair.serialize_private(), "ff" * 32 if trust.endswith("conflict") and attempts == 0 else genesis,
                admin.current_kek, admin.db.get_meta("kek_dek_id").encode(), user_id.encode())
        issued = client.create_provisioning_token()
        assert issued["genesis_hash"] == genesis
        qr = "sezam://provision?" + urlencode({
            "token": issued["token"], "server": url, "username": "admin",
        }) + ("" if trust in ("carrier", "pinned-conflict") else "#g=" + issued["genesis_hash"])
        (tmp_path / "phone" / "qr.txt").write_text(qr, encoding="utf-8")
        attempts += 1

    out = _phone(url, tmp_path, {
        "username": "admin", "password": PASSWORD, "user_id": admin.db.get_meta("user_id"),
        "genesis": genesis, "local": local, "lie": lie, "trust": trust,
    }, {"token": token, **({"retry": token} if lie != "none" or trust.endswith("conflict") else {})}, "test/phone_qr_team_anchor_test.dart")
    assert "All tests passed!" in out, out


@pytest.mark.parametrize("lie", [
    "none", "missing", "foreign", "storage", "upload", "conflict", "ui-missing", "ui-foreign", "ui-locked-none",
    "portable-none", "portable-storage", "portable-upload", "portable-conflict", "portable-no-fragment",
    "portable-response-loss", "portable-pending-storage", "portable-expired", "portable-upload-response-loss",
    "portable-after-upload-storage", "portable-pending-carrier", "portable-locked-response-loss",
    "portable-locked-pending-storage", "portable-locked-expired", "portable-locked-upload-response-loss",
    "portable-locked-after-upload-storage", "portable-locked-none", "portable-locked-storage", "portable-locked-upload",
    "portable-locked-login", "pinned-conflict", "pinned-no-fragment",
    "restart-none", "restart-missing", "restart-foreign", "restart-signature", "restart-short", "restart-network",
    "restart-qr-none", "restart-qr-missing", "restart-qr-foreign", "restart-qr-network",
])
def test_invitation_anchor_survives_approval_pull_and_restart(team, server, tmp_path, lie):  # noqa: F811
    from urllib.parse import urlencode
    from tests.test_team_log_desktop import _found_with_bob
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    assert client.push()["conflicts"] == []
    invitation = client.create_invitation()
    genesis = invitation["genesis_hash"]
    link = url + "/?" + urlencode({"invite": invitation["invitation_token"]}) + "#g=" + genesis

    def approve():
        user = next(u for u in db._storage["users"] if u["username"] == "invited-phone")
        user_id = user["id"]
        client.approve_user(user_id)
        client.append_team_log([("member.add", {
            "user_id": user_id, "signing_pk": bytes(user["signing_pk"]).hex(),
            "encryption_pk": bytes(user["encryption_pk"]).hex(), "role": "member",
        })])
        revocation.grant_member(admin, client, user_id, ops, "read")
        (tmp_path / "phone" / "user-id.txt").write_text(user_id, encoding="utf-8")

    def expire():
        from server.app.auth import create_jwt
        from server.app.dependencies import get_jwt_manager
        user = next(u for u in db._storage["users"] if u["username"] == "invited-phone")
        token = create_jwt(get_jwt_manager().signing_key, user["id"], user["username"], False,
                           -1, scope="keypair_upload")
        (tmp_path / "phone" / "expired-token.txt").write_text(token, encoding="utf-8")

    steps = {"refused": lambda: None} if lie in {"conflict", "portable-conflict", "pinned-conflict"} else {"approve": approve}
    if lie in {"portable-expired", "portable-locked-expired"}:
        steps = {"expire": expire, **steps}
    out = _phone(url, tmp_path, {
        "password": PASSWORD, "invitation": link, "genesis": genesis, "lie": lie.removeprefix("ui-"),
    }, steps,
        "test/phone_approval_trust_ui_test.dart" if lie.startswith("ui-") else "test/phone_invitation_team_anchor_test.dart")
    assert "All tests passed!" in out, out
    if lie in {"none", "storage", "upload"} or lie.startswith("portable-") and lie != "portable-conflict":
        from sezam import cli
        from tests.test_integration_client_server import _vault
        fresh = _vault(tmp_path / "fresh", "invited-phone")
        try:
            cli._server_connect_flow(url, fresh, PASSWORD)
            assert fresh.keypair.confirmed_genesis == genesis
            assert fresh.get_field_value(item, "password") == "ops-pw"
            if "-locked-" in lie:
                passwords = {e["name"]: fresh.get_field_value(e["id"], "password")
                             for n in fresh.list_nodes() for e in fresh.list_entries(n["id"])}
                assert passwords["unsent"] == "local-secret"
            fresh.lock()
            fresh.unlock(PASSWORD)
            assert fresh.keypair.confirmed_genesis == genesis
            assert fresh.get_field_value(item, "password") == "ops-pw"
        finally:
            fresh.lock()


@pytest.mark.parametrize("lie", ["level", "withdrawn_access", "none"])
def test_phone_refuses_validly_signed_envelope_outside_log_access(team, server, tmp_path, lie):  # noqa: F811
    from tests.test_team_log_desktop import _found_with_bob
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    assert admin_client.push()["conflicts"] == []
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    key = teamlog.current_key(admin_client.team_state(), ops)
    envelope = next(o for o in db._storage["vault_objects"]
                    if o["object_type"] == "envelope" and o["parent_ref"] == key)
    if lie == "level":
        envelope["access_level"] = "write"  # Not in the signed payload.
    elif lie == "withdrawn_access":
        admin_client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": None})])
    out = _phone(url, tmp_path, {
        "username": "admin", "password": PASSWORD,
        "forged": envelope["id"] if lie != "none" else "absent",
        "accepted_envelope": envelope["id"] if lie == "none" else None,
        "stale_folder": lie == "withdrawn_access",
    }, {}, PHONE_TEST)
    assert "All tests passed!" in out, out


def test_phone_refuses_what_the_log_refuses_and_writes_the_current_generation(
    shared, tmp_path, monkeypatch  # noqa: F811
):
    url, admin, admin_client, bob_id, ops, sk, token = shared
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    first = teamlog.current_key(admin_client.team_state(), ops)

    with monkeypatch.context() as lying:
        _lying_server(lying)
        forged = new_ulid()
        _push(url, token, sk, forged, "entry", ops, _entry_payload(first))

    assert revocation.revoke_member(admin, admin_client, bob_id) == 1
    second = teamlog.current_key(admin_client.team_state(), ops)
    assert second != first

    out = _phone(
        url, tmp_path,
        {"username": "admin", "password": PASSWORD, "forged": forged},
        {}, PHONE_TEST,
    )
    assert "All tests passed!" in out, out

    admin_client.pull()
    [item] = [e for e in admin.list_entries(ops) if e["name"] == "from-phone"]
    row = admin.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (item["id"],))
    assert (row["dek_id"] or admin.dek_mgr.get_dek_for_node(ops)[0]) == second
