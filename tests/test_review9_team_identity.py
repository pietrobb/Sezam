"""Review 1141a20 H1: an identity and its team-log keys must advance together."""
from __future__ import annotations

import pytest

from sezam import teamlog
from sezam.vault import pending_states
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_team_log_desktop import _confirm_founder, _found_with_bob, team  # noqa: F401


def _rotate(vault, client, url):
    client.prepare_key_change()
    proof = vault.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = b"\x00" * len(proof)
    return _client(vault, url)


@pytest.mark.parametrize("who", ["admin", "member"])
def test_rotation_updates_log_and_keeps_founder_trusted(team, server, who):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    vault, client = (admin, admin_client) if who == "admin" else (bob, bob_client)
    uid = vault.db.get_meta("user_id")
    client = _rotate(vault, client, url)
    if who == "admin":
        vault.lock()
        vault.unlock(PASSWORD)
        client = _client(vault, url)
        offline = vault.create_entry(vault.db.get_meta("root_node_id"), "during-rotation", [])
        vault.update_entry(offline, name="still-trusted")
        assert vault.read_entry(offline)["name"] == "still-trusted"
    client.push()  # The fixture's legacy member root can be refused on the follow-up push.
    assert not pending_states.key_change_journal(vault.db)
    state = client.team_state()
    assert state.members[uid].signing_pk == vault.keypair.signing_pk.hex()
    assert state.members[uid].encryption_pk == vault.keypair.encryption_pk.hex()
    records = [{"body": row["body"], "sig": row["sig"]} for row in db._storage["team_log"]]
    assert teamlog.replay(records).to_json() == state.to_json()
    assert teamlog.parse_body(records[-1]["body"])["type"] == "member.keys"
    assert not pending_states.key_change_journal(vault.db)
    if who == "admin":
        assert client.team_log_trusted()
        client.append_team_log([("member.remove", {"user_id": bob.db.get_meta("user_id")})])
        assert not client.team_state().members[bob.db.get_meta("user_id")].active


@pytest.mark.parametrize("fault", ["none", "missing", "signature", "head", "ciphertext", "retired-signature", "withdrawn", "access", "unconfirmed"])
def test_member_reads_received_envelope_after_sender_rotation(team, server, fault):  # noqa: F811
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _ops

    url, _ = server
    _, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "historical-envelope", [{"key": "password", "value": "still-readable"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    _confirm_founder(admin, bob)
    bob_client.pull()
    assert bob.get_field_value(item, "password") == "still-readable"
    old_signer = admin.keypair.to_nacl_signing_key()
    old_sender = bytes(admin.keypair.encryption_sk)
    client = _rotate(admin, client, url)
    client.push()
    bob_client._refresh_team_log()
    assert bob.get_field_value(item, "password") == "still-readable"
    bob.lock()
    bob.unlock(PASSWORD)
    assert bob.get_field_value(item, "password") == "still-readable"
    if fault == "none":
        return
    from nacl.exceptions import CryptoError
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META

    env = bob.db.fetchone("SELECT * FROM access_envelopes WHERE user_id = ?", (bob.db.get_meta("user_id"),))
    receipt_key = "team_envelope_receipt:" + env["id"]
    receipt = bob.db.get_meta_json(receipt_key)
    assert receipt is not None
    if fault == "missing":
        bob.db.execute("DELETE FROM vault_meta WHERE key = ?", (receipt_key,))
    elif fault in ("signature", "head"):
        field = "signature" if fault == "signature" else "hash"
        bob.db.set_meta_json(receipt_key, {**receipt, field: "00" * (64 if fault == "signature" else 32)})
    elif fault == "ciphertext":
        payload = bytearray(env["encrypted_dek"])
        payload[-1] ^= 1
        bob.db.execute("UPDATE access_envelopes SET encrypted_dek = ? WHERE id = ?", (bytes(payload), env["id"]))
    elif fault == "retired-signature":
        import hashlib
        from sezam.crypto.envelope_crypto import create_envelope
        payload = create_envelope(bytes(bob.dek_mgr.unlock_dek(env["dek_id"])), old_sender, bob.keypair.encryption_pk)
        canonical = client._build_signature_payload(env["id"], "envelope", env["dek_id"], env["user_id"],
                                                    0, 1, hashlib.sha256(payload).hexdigest())
        signature = old_signer.sign(canonical).signature.hex()
        bob_client._apply_envelope(env["id"], env["dek_id"], payload, 0, {
            "target_user_id": env["user_id"], "signature_user_id": env["created_by"],
            "access_level": env["access_level"], "signature": signature, "version": 1,
        })
        assert bob.db.get_meta_json(receipt_key) == receipt
    elif fault == "withdrawn":
        bob.db.execute("INSERT INTO withdrawn_envelopes (envelope_id) VALUES (?)", (env["id"],))
    elif fault == "access":
        client.append_team_log([("access.set", {"folder": folder, "user_id": bob.db.get_meta("user_id"), "level": None})])
        bob_client._refresh_team_log()
    else:
        bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {})
    with pytest.raises(CryptoError):
        bob.get_field_value(item, "password")
    bob.lock()
    bob.unlock(PASSWORD)
    with pytest.raises(CryptoError):
        bob.get_field_value(item, "password")
    bob.db.set_meta_json(receipt_key, receipt)
    bob.db.execute("UPDATE access_envelopes SET encrypted_dek = ? WHERE id = ?", (env["encrypted_dek"], env["id"]))
    bob.db.execute("DELETE FROM withdrawn_envelopes WHERE envelope_id = ?", (env["id"],))
    if fault == "access":
        client.append_team_log([("access.set", {"folder": folder, "user_id": bob.db.get_meta("user_id"), "level": "read"})])
        bob_client._refresh_team_log()
    if fault == "unconfirmed":
        _confirm_founder(admin, bob)
    assert bob.get_field_value(item, "password") == "still-readable"


@pytest.mark.parametrize("cache", ["missing-envelope", "missing-key", "wrong-key"])
@pytest.mark.parametrize("failure", ["none", "response-lost"])
def test_rotation_reissues_from_log_for_first_receipt(team, server, tmp_path, monkeypatch, cache, failure):  # noqa: F811
    from sezam.crypto.keys import generate_keypair
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _ops

    url, _ = server
    _, admin, client, bob, bob_client = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "first-receipt", [{"key": "password", "value": "current-sender"}])
    uid = bob.db.get_meta("user_id")
    grant_member(admin, client, uid, folder, "read")
    _confirm_founder(admin, bob)
    client.prepare_key_change()
    if cache == "missing-envelope":
        admin.db.execute("DELETE FROM access_envelopes WHERE user_id = ?", (uid,))
    elif cache == "missing-key":
        admin.db.execute("DELETE FROM known_keys WHERE user_id = ?", (uid,))
    else:
        unrelated = generate_keypair()
        admin.db.execute("UPDATE known_keys SET encryption_pk = ? WHERE user_id = ?", (unrelated.encryption_pk, uid))
        unrelated.zeroize()
    proof = admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    proof[:] = bytes(len(proof))
    admin.lock()
    admin.unlock(PASSWORD)
    client = _client(admin, url)
    if failure == "response-lost":
        real = client._request
        def lose(method, path, data=None, **kwargs):
            result = real(method, path, data, **kwargs)
            if method == "POST" and path == "/api/sync":
                raise RuntimeError("rotation response lost")
            return result
        monkeypatch.setattr(client, "_request", lose)
        with pytest.raises(RuntimeError, match="response lost"):
            client.push()
        assert pending_states.key_change_journal(admin.db)
        admin.lock()
        admin.unlock(PASSWORD)
        client = _client(admin, url)
    client.push()
    assert not pending_states.key_change_journal(admin.db)
    bob_client.pull()  # No envelope or receipt existed on Bob before the rotation.
    assert bob.get_field_value(item, "password") == "current-sender"
    bob.lock()
    bob.unlock(PASSWORD)
    assert bob.get_field_value(item, "password") == "current-sender"


@pytest.mark.parametrize("fault", ["unconfirmed", "removed", "storage"])
def test_log_reissue_failure_preserves_rotation_state(team, server, monkeypatch, fault):  # noqa: F811
    from nacl.exceptions import CryptoError
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _ops

    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    client.prepare_key_change()
    if fault == "unconfirmed":
        admin.db.set_meta("team_log_confirmed_genesis_hash", "ab" * 32)
    elif fault == "removed":
        client.append_team_log([("member.remove", {"user_id": bob.db.get_meta("user_id")})])
    else:
        execute = admin.db.execute
        def failed(sql, *args, **kwargs):
            if sql.startswith("INSERT INTO access_envelopes"):
                raise OSError("reissue storage fault")
            return execute(sql, *args, **kwargs)
        monkeypatch.setattr(admin.db, "execute", failed)
    def snapshot():
        return ([dict(r) for r in admin.db.fetchall("SELECT * FROM deks ORDER BY id")],
                [dict(r) for r in admin.db.fetchall("SELECT * FROM access_envelopes ORDER BY id")],
                admin.db.get_meta("encrypted_keypair"), admin.db.get_meta("key_epoch"))
    before = snapshot()
    with pytest.raises({"unconfirmed": CryptoError, "removed": RuntimeError, "storage": OSError}[fault]):
        admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    assert snapshot() == before
    assert not pending_states.key_change_journal(admin.db)
    assert not pending_states.rekey_batch(admin.db)
    if fault != "removed":
        if fault == "unconfirmed":
            admin.db.execute("DELETE FROM vault_meta WHERE key = 'team_log_confirmed_genesis_hash'")
        else:
            monkeypatch.undo()
        proof = admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
        proof[:] = bytes(len(proof))
        admin.lock()
        admin.unlock(PASSWORD)
        _client(admin, server[0]).push()
        assert not pending_states.key_change_journal(admin.db)


def test_founder_reads_shared_folder_during_offline_identity_rotation(team, server):  # noqa: F811
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _ops

    url, _ = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "offline-founder", [{"key": "password", "value": "keep-readable"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), folder, "read")
    client = _rotate(admin, client, url)
    assert admin.get_field_value(item, "password") == "keep-readable"
    admin.lock()
    admin.unlock(PASSWORD)
    assert admin.get_field_value(item, "password") == "keep-readable"
    _client(admin, url).push()
    assert admin.get_field_value(item, "password") == "keep-readable"


def test_next_rekey_cannot_be_opened_with_members_retired_key(team, server, tmp_path, monkeypatch):  # noqa: F811
    from nacl.exceptions import CryptoError
    from sezam.crypto.envelope_crypto import open_envelope
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _carol, _member, _ops

    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    carol = _carol(url, admin_client, tmp_path, monkeypatch)
    try:
        bob_id, carol_id = bob.db.get_meta("user_id"), carol.db.get_meta("user_id")
        _found_with_bob(admin_client, bob)
        admin_client.append_team_log([("member.add", _member(carol))])
        folder = _ops(admin)
        item = admin.create_entry(folder, "rotated-receipt", [{"key": "password", "value": "next-generation"}])
        grant_member(admin, admin_client, bob_id, folder, "read")
        grant_member(admin, admin_client, carol_id, folder, "read")
        _confirm_founder(admin, bob)
        bob_client.pull()
        old_sk = bytes(bob.keypair.to_nacl_private_key())
        client = _rotate(bob, bob_client, url)
        client.push()
        admin_client._refresh_team_log()
        admin_client.append_team_log([("member.remove", {"user_id": carol_id})])
        assert admin.rekey_after_revocation(carol_id) == 1
        assert not admin_client.push()["conflicts"]
        new_id = teamlog.current_key(admin_client.team_state(), folder)
        envelope = admin.db.fetchone(
            "SELECT encrypted_dek FROM access_envelopes WHERE user_id = ? AND dek_id = ?",
            (bob_id, new_id),
        )
        payload = bytes(envelope["encrypted_dek"])
        new_dek = open_envelope(payload, bytes(bob.keypair.to_nacl_private_key()), admin.keypair.encryption_pk)
        assert bytes(new_dek) == bytes(admin.dek_mgr.get_dek_for_node(folder)[1])
        new_dek[:] = b"\x00" * len(new_dek)
        with pytest.raises(CryptoError):
            open_envelope(payload, old_sk, admin.keypair.encryption_pk)
        client.pull()
        assert bob.get_field_value(item, "password") == "next-generation"
        bob.lock()
        bob.unlock(PASSWORD)
        assert bob.get_field_value(item, "password") == "next-generation"
    finally:
        carol.lock()


@pytest.mark.parametrize("failure", ["head_moved", "response_lost", "restart_after_response_lost"])
def test_rotation_retries_without_losing_the_two_key_proof(team, server, monkeypatch, failure):  # noqa: F811
    from sezam.models import new_ulid

    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    client = _rotate(bob, bob_client, url)
    if failure == "head_moved":
        admin_client.append_team_log([("folder.key", {
            "folder": new_ulid(), "dek_id": new_ulid(), "prev_dek_id": None,
        })])
    else:
        real = client._request
        lost = False

        def lose(method, path, data=None, *args, **kwargs):
            nonlocal lost
            result = real(method, path, data, *args, **kwargs)
            if method == "POST" and path == "/api/sync" and not lost:
                lost = True
                raise RuntimeError("Network error: rotation response lost")
            return result

        monkeypatch.setattr(client, "_request", lose)
        with pytest.raises(RuntimeError, match="response lost"):
            client.push()
        assert pending_states.key_change_journal(bob.db)
        if failure == "restart_after_response_lost":
            bob.lock()
            bob.unlock(PASSWORD)
            client = _client(bob, url)
    client.push()
    uid = bob.db.get_meta("user_id")
    assert client.team_state().members[uid].encryption_pk == bob.keypair.encryption_pk.hex()
    changes = [teamlog.parse_body(row["body"]) for row in db._storage["team_log"]]
    assert len([b for b in changes if b["type"] == "member.keys"]) == 1
    assert not pending_states.key_change_journal(bob.db)


def test_founder_confirmed_after_first_rotation_stays_trusted_after_second(team, server):  # noqa: F811
    from sezam.crypto.keys import compute_fingerprint
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META

    url, _ = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    admin_client = _rotate(admin, admin_client, url)
    admin_client.push()
    bob_client._refresh_team_log()
    bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin.db.get_meta("user_id"): compute_fingerprint(
            admin.keypair.signing_pk, admin.keypair.encryption_pk,
        ),
    })
    assert bob_client.team_log_trusted()
    admin_client = _rotate(admin, admin_client, url)
    admin_client.push()
    bob_client._refresh_team_log()
    assert bob_client.team_log_trusted()
    bob.lock()
    bob.unlock(PASSWORD)
    assert _client(bob, url).team_log_trusted()
    bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin.db.get_meta("user_id"): compute_fingerprint(
            bob.keypair.signing_pk, bob.keypair.encryption_pk,
        ),
    })
    assert not _client(bob, url).team_log_trusted()


def test_browser_reads_and_writes_team_folder_after_founder_rotation(team, server, tmp_path):  # noqa: F811
    from sezam.vault.revocation import grant_member
    from tests.test_team_log_desktop_changes import _ops
    from tests.web_tab import WebTab

    url, _ = server
    _, admin, admin_client, bob, _ = team
    _found_with_bob(admin_client, bob)
    folder = _ops(admin)
    grant_member(admin, admin_client, bob.db.get_meta("user_id"), folder, "read")
    tab = WebTab(url, tmp_path / "rotation-tab.log")
    try:
        before = tab.do("login", username="admin", password=PASSWORD)
        assert before["error"] is None, before
        admin_client = _rotate(admin, admin_client, url)
        admin_client.push()
        tab = WebTab(url, tmp_path / "rotation-tab-reopened.log", tab.close())
        after = tab.do("login", username="admin", password=PASSWORD)
        assert after["error"] is None, after
        assert folder in {node["id"] for node in after["view"]["nodes"]}
        saved = tab.do("save_object", mode="entry", name="after-rotation", parent=folder,
                       fields=[{"key": "password", "value": "rotated-secret"}])
        assert saved["error"] is None, saved
        assert not saved["view"]["dirty"] and not saved["view"]["conflicts"], saved
        admin_client.pull()
        [entry] = [e for e in admin.list_entries(folder) if e["name"] == "after-rotation"]
        assert admin.get_field_value(entry["id"], "password") == "rotated-secret"
    finally:
        tab.kill()


def test_server_refuses_rotation_with_member_keys_stripped(team, server, monkeypatch):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    bob_client.pull()
    uid = bob.db.get_meta("user_id")
    before = next(u for u in db._storage["users"] if u["id"] == uid)["signing_pk"]
    before_records = list(db._storage["team_log"])
    client = _rotate(bob, bob_client, url)
    real = client._request

    def strip(method, path, data=None, **kwargs):
        if method == "POST" and path == "/api/sync":
            data = {k: v for k, v in data.items() if k != "team_log"}
        return real(method, path, data, **kwargs)

    monkeypatch.setattr(client, "_request", strip)
    with pytest.raises(RuntimeError, match="team_log_refused"):
        client.push()
    assert next(u for u in db._storage["users"] if u["id"] == uid)["signing_pk"] == before
    assert db._storage["team_log"] == before_records
    assert pending_states.key_change_journal(bob.db)
