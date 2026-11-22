"""The desktop pull decides team folders by the team log (TL4c; docs/DESIGN_TEAM_LOG.md §4.3.2, §4.3.4).

A lying server takes what the log refuses and serves it. In a folder of the
log the desktop applies a folder or item only when its signer may write there
in the log and it is sealed with the folder's current generation (or the
author's own personal key, with write access), whatever envelopes or
/api/users say; and the folder's key is the log's current generation, not the
latest key id or an archive the server serves.
"""

from __future__ import annotations

import pytest

import server.app.routers.sync as server_sync
from sezam import cli, teamlog
from sezam.models import new_ulid
from sezam.vault import revocation
from sezam.vault.sync_writers import IGNORED_WRITES_META
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review6_web_member_personal_folder import sealed
from tests.test_review7_forged_root_folder_desktop_h4 import _always, _login, _push
from tests.server_admin_lie import users_row_decides
from tests.test_team_log_desktop import _found_with_bob, team  # noqa: F401  (fixture)
from tests.test_team_log_desktop_changes import _ops


async def _no_team_check(*_args, **_kwargs):
    return None


def _lying_server(monkeypatch) -> None:
    """Takes any write: no write_acl, no team log check."""
    monkeypatch.setattr(server_sync, "_has_write_authority", _always)
    monkeypatch.setattr(server_sync, "_team_log_refusal", _no_team_check)


def _entry_payload(dek_id: str) -> bytes:
    meta = sealed(dek_id)
    return len(meta).to_bytes(4, "big") + meta + b"d"


def _applied(vault, entry_id: str) -> bool:
    return vault.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (entry_id,)) is not None


@pytest.fixture
def shared(team, server):  # noqa: F811
    url, _ = server
    db, admin, admin_client, bob, bob_client = team
    bob_id = bob.db.get_meta("user_id")
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    sk = bob.keypair.to_nacl_signing_key()
    return url, admin, admin_client, bob_id, ops, sk, _login(url, sk, "bob")


@pytest.mark.parametrize("operation", [
    "create_entry", "update_entry", "create_node", "rename_node", "delete_entry",
    "delete_node", "move_entry_out", "move_entry_in", "move_node_out", "move_node_in",
    "restore_entry", "restore_node",
])
def test_cached_legacy_data_cannot_be_written_under_unconfirmed_log(team, server, operation):  # noqa: F811
    from tests.test_team_log_desktop import _confirm_founder

    url, _ = server
    _, admin, admin_client, bob, bob_client = team
    ops = bob.create_node("legacy")
    entry = bob.create_entry(ops, "cached", [{"key": "password", "value": "old"}])
    assert bob.read_entry(entry)["name"] == "cached"
    personal = bob.create_personal_folder("private")
    private_entry = bob.create_entry(personal, "private", [])
    private_child = bob.create_node("child", parent_id=personal)
    # A team folder of the log itself does not go into a personal folder
    # (test_review9_move_node_reseal); a folder of it without its own key does.
    ops_child = bob.create_node("sub", parent_id=ops, create_dek=False)
    if operation == "restore_entry":
        bob.delete_entry(entry)
    if operation == "restore_node":
        bob.delete_node(ops)
    _found_with_bob(admin_client, bob)
    admin_client.append_team_log([
        ("folder.key", {"folder": ops, "dek_id": bob.dek_mgr.get_dek_for_node(ops)[0],
                        "gen": 0, "prev_dek_id": None}),
        ("access.set", {"folder": ops, "user_id": bob.db.get_meta("user_id"), "level": "write"}),
    ])
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        bob_client.pull()
    bob.lock()
    bob.unlock(PASSWORD)
    bob_client = _client(bob, url)
    from sezam.vault import trash
    actions = {
        "create_entry": lambda: bob.create_entry(ops, "new-secret", []),
        "update_entry": lambda: bob.update_entry(entry, name="changed"),
        "create_node": lambda: bob.create_node("new-folder", parent_id=ops),
        "rename_node": lambda: bob.rename_node(ops, "changed"),
        "delete_entry": lambda: bob.delete_entry(entry),
        "delete_node": lambda: bob.delete_node(ops),
        "move_entry_out": lambda: bob.move_entry(entry, personal),
        "move_entry_in": lambda: bob.move_entry(private_entry, ops),
        "move_node_out": lambda: bob.move_node(ops_child, personal),
        "move_node_in": lambda: bob.move_node(private_child, ops),
        "restore_entry": lambda: trash.restore_entry(bob, entry),
        "restore_node": lambda: trash.restore_node(bob, ops),
    }
    tables = ("nodes", "entries", "deks", "entry_history")
    before = {t: [dict(r) for r in bob.db.fetchall(f"SELECT * FROM {t}")] for t in tables}
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        actions[operation]()
    assert {t: [dict(r) for r in bob.db.fetchall(f"SELECT * FROM {t}")] for t in tables} == before
    # Own personal data stays usable without trusting the organisation.
    bob.update_entry(private_entry, name="still-private")
    bob.create_node("another-private-child", parent_id=personal)
    _confirm_founder(admin, bob)
    assert bob_client.team_log_trusted()
    actions[operation]()


@pytest.mark.parametrize("full_resync", [False, True])
def test_unconfirmed_log_accepts_no_keys_and_retries_after_confirmation(team, server, full_resync):  # noqa: F811
    from sezam.crypto.keys import compute_fingerprint
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META

    url, _ = server
    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    revocation.grant_member(admin, admin_client, bob.db.get_meta("user_id"), ops, "write")
    key = teamlog.current_key(admin_client.team_state(), ops)
    before_seq = bob.db.get_meta("last_known_commit_seq")
    before_envelopes = [dict(r) for r in bob.db.fetchall("SELECT * FROM access_envelopes")]
    before_nodes = [dict(r) for r in bob.db.fetchall("SELECT * FROM nodes")]
    before_deks = [dict(r) for r in bob.db.fetchall("SELECT * FROM deks")]
    pull = (lambda: bob_client.full_resync(confirmed=True)) if full_resync else bob_client.pull
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        pull()
    assert bob_client.team_state() is not None
    assert not bob_client.team_log_trusted()
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        bob_client.push()
    assert bob.db.get_meta("last_known_commit_seq") == before_seq
    assert [dict(r) for r in bob.db.fetchall("SELECT * FROM access_envelopes")] == before_envelopes
    assert [dict(r) for r in bob.db.fetchall("SELECT * FROM nodes")] == before_nodes
    assert [dict(r) for r in bob.db.fetchall("SELECT * FROM deks")] == before_deks

    # A restart does not promote the observed genesis into a trusted anchor.
    bob.lock()
    bob.unlock(PASSWORD)
    bob_client = _client(bob, url)
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        bob_client.pull()
    bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin.db.get_meta("user_id"): compute_fingerprint(
            admin.keypair.signing_pk, admin.keypair.encryption_pk),
    })
    assert bob_client.team_log_trusted()
    assert bob_client.pull()["pulled"] > 0
    assert bob.db.fetchone("SELECT 1 FROM access_envelopes WHERE dek_id = ?", (key,))
    assert bob.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (ops,))["dek_id"] == key


@pytest.mark.parametrize("case", ["unconfirmed", "withdrawn", "level", "box", "access", "removed",
                                  "kek-unconfirmed", "kek-access", "kek-removed"])
def test_desktop_cached_team_key_requires_live_authority(team, server, case):  # noqa: F811
    from nacl.exceptions import CryptoError
    from tests.test_team_log_desktop import _confirm_founder
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META

    url, _ = server
    _, admin, client, bob, receiver = team
    _found_with_bob(client, bob)
    _confirm_founder(admin, bob)
    folder = _ops(admin)
    item = admin.create_entry(folder, "receipt", [{"key": "password", "value": "actual-secret"}])
    uid = bob.db.get_meta("user_id")
    revocation.grant_member(admin, client, uid, folder, "read")
    client.push()
    receiver.pull()
    if case.startswith("kek-"):
        from sezam.crypto.aead import encrypt_dek_wrap
        key, raw = admin.dek_mgr.get_dek_for_node(folder)
        wrapped = encrypt_dek_wrap(raw, bob.current_kek, bob.db.get_meta("kek_dek_id").encode(), key.encode())
        bob.db.execute("UPDATE deks SET encrypted_dek = ? WHERE id = ?", (wrapped, key))
        case = case.removeprefix("kek-")
    assert bob.get_field_value(item, "password") == "actual-secret"
    key = teamlog.current_key(receiver.team_state(), folder)
    cached = bob.dek_mgr.unlock_dek(key)
    envelope = dict(bob.db.fetchone("SELECT * FROM access_envelopes WHERE dek_id = ? AND user_id = ?", (key, uid)))
    if case == "unconfirmed":
        bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {})
    elif case == "withdrawn":
        bob.db.execute("INSERT INTO withdrawn_envelopes (envelope_id) VALUES (?)", (envelope["id"],))
    elif case == "level":
        bob.db.execute("UPDATE access_envelopes SET access_level = 'write' WHERE id = ?", (envelope["id"],))
    elif case == "box":
        bob.db.execute("UPDATE access_envelopes SET encrypted_dek = ? WHERE id = ?", (bytes(72), envelope["id"]))
    else:
        change = ("member.remove", {"user_id": uid}) if case == "removed" else (
            "access.set", {"folder": folder, "user_id": uid, "level": None})
        client.append_team_log([change])
        if case == "removed":
            # The server denies a removed account HTTP access. Deliver the signed
            # continuation through the admin to exercise offline cached revocation.
            old = receiver.team_state()
            records = client._request("GET", f"/api/team-log?since={old.head_seq}", auth=True)["records"]
            receiver._store_team_log(records, teamlog.replay(records, old))
        else:
            receiver.pull()
    with pytest.raises(CryptoError):
        bob.get_field_value(item, "password")
    assert not any(cached)
    bob.lock()
    bob.unlock(PASSWORD)
    with pytest.raises(CryptoError):
        bob.get_field_value(item, "password")
    # An independently confirmed restoration can open the unchanged ciphertext again.
    if case == "unconfirmed":
        _confirm_founder(admin, bob)
    elif case == "withdrawn":
        bob.db.execute("DELETE FROM withdrawn_envelopes WHERE envelope_id = ?", (envelope["id"],))
    elif case == "level":
        bob.db.execute("UPDATE access_envelopes SET access_level = 'read' WHERE id = ?", (envelope["id"],))
    elif case == "box":
        bob.db.execute("UPDATE access_envelopes SET encrypted_dek = ? WHERE id = ?", (envelope["encrypted_dek"], envelope["id"]))
    else:
        if case == "removed":
            from tests.test_team_log_desktop_changes import _member
            # R9-F: the signed re-add alone brings a removed member back.
            client.append_team_log([("member.add", _member(bob))])
        client.append_team_log([("access.set", {"folder": folder, "user_id": uid, "level": "read"})])
        _client(bob, url).pull()
    assert bob.get_field_value(item, "password") == "actual-secret"


@pytest.mark.parametrize("readd_founder", [False, True])
def test_server_signed_genesis_cannot_replace_confirmed_founder(team, monkeypatch, readd_founder):  # noqa: F811
    from nacl.public import PrivateKey
    from nacl.signing import SigningKey
    from tests.test_team_log_desktop import _confirm_founder

    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    _confirm_founder(admin, bob)
    attacker = SigningKey.generate()
    founder = admin.db.get_meta("user_id")
    record = teamlog.sign_record(teamlog.next_body(teamlog.TeamState(), "genesis", founder, {
        "org": new_ulid(), "user_id": founder,
        "signing_pk": bytes(attacker.verify_key).hex(),
        "encryption_pk": bytes(PrivateKey.generate().public_key).hex(),
    }), attacker)
    records = [record]
    fake = teamlog.replay(records)
    if readd_founder:
        accomplice = SigningKey.generate()
        accomplice_id = new_ulid()
        changes = [
            (founder, attacker, "member.add", {
                "user_id": accomplice_id, "signing_pk": bytes(accomplice.verify_key).hex(),
                "encryption_pk": bytes(PrivateKey.generate().public_key).hex(), "role": "admin",
            }),
            (founder, attacker, "member.role", {"user_id": founder, "role": "member"}),
            (accomplice_id, accomplice, "member.remove", {"user_id": founder}),
            (accomplice_id, accomplice, "member.add", {
                "user_id": founder, "signing_pk": admin.keypair.signing_pk.hex(),
                "encryption_pk": admin.keypair.encryption_pk.hex(), "role": "member",
            }),
        ]
        for author, signer, kind, data in changes:
            records.append(teamlog.sign_record(teamlog.next_body(fake, kind, author, data), signer))
            fake = teamlog.apply_record(fake, records[-1])
    head = {"seq": fake.head_seq, "hash": fake.head_hash, "genesis_hash": fake.genesis_hash}
    request = bob_client._request
    before = bob.db.get_meta("last_known_commit_seq")

    def lying_request(method, path, *args, **kwargs):
        if method == "GET" and path.startswith("/api/team-log"):
            return {"head": head, "records": records}
        result = request(method, path, *args, **kwargs)
        if method == "GET" and path.startswith("/api/sync") and result:
            result["team_log_head"] = head
        return result

    monkeypatch.setattr(bob_client, "_request", lying_request)
    with pytest.raises(RuntimeError, match="founder.*not confirmed"):
        bob_client.pull()
    assert bob_client.team_state().genesis_hash == fake.genesis_hash
    assert not bob_client.team_log_trusted()
    assert bob.db.get_meta("last_known_commit_seq") == before
    assert not bob.db.fetchone("SELECT 1 FROM access_envelopes")
    from click.testing import CliRunner
    from sezam import cli, cli_team_log
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
    from tests.test_team_log_migration import _as

    _as(bob, monkeypatch)
    monkeypatch.setattr(cli_team_log, "_connected", lambda v: bob_client)
    monkeypatch.setattr(bob_client, "_refresh_team_log", lambda: None)
    confirmed = bob.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META)
    out = CliRunner().invoke(cli.main, ["team-log", "confirm-founder", admin.keypair.fingerprint])
    assert out.exit_code != 0 and "Nothing was confirmed" in out.output
    assert bob.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) == confirmed


@pytest.mark.parametrize("lie", ["level", "withdrawn_access"])
def test_trusted_log_rejects_envelopes_without_current_matching_access(team, monkeypatch, lie):  # noqa: F811
    from sezam.crypto.keys import compute_fingerprint
    from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META

    _, admin, admin_client, bob, bob_client = team
    _found_with_bob(admin_client, bob)
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    key = teamlog.current_key(admin_client.team_state(), ops)
    bob.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
        admin.db.get_meta("user_id"): compute_fingerprint(
            admin.keypair.signing_pk, admin.keypair.encryption_pk),
    })
    if lie == "withdrawn_access":
        admin_client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": None})])
    request = bob_client._request
    delivered = []

    def lying_request(method, path, *args, **kwargs):
        result = request(method, path, *args, **kwargs)
        if method == "GET" and path.startswith("/api/sync") and result:
            for obj in result.get("objects", []):
                if obj["object_type"] == "envelope" and obj.get("parent_ref") == key:
                    delivered.append(obj["id"])
                    if lie == "level":
                        obj["access_level"] = "write"  # unsigned; signature stays valid
        return result

    monkeypatch.setattr(bob_client, "_request", lying_request)
    bob_client.pull()
    assert delivered, "The attack must reach the real client's envelope path"
    assert not bob.db.fetchone("SELECT 1 FROM access_envelopes WHERE dek_id = ?", (key,))


def test_an_item_by_a_member_the_log_gives_read_is_not_applied(shared, monkeypatch):
    url, admin, admin_client, bob_id, ops, sk, token = shared
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    key = teamlog.current_key(admin_client.team_state(), ops)
    # An envelope saying 'write' (the old rule's evidence) does not count.
    admin.db.execute(
        "INSERT INTO access_envelopes (id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'write', ?)",
        (new_ulid(), key, bob_id, admin.db.get_meta("user_id"), b"\x00" * 72),
    )
    _lying_server(monkeypatch)
    forged = new_ulid()
    _push(url, token, sk, forged, "entry", ops, _entry_payload(key))

    assert admin_client.pull()["skipped"] == 1
    assert not _applied(admin, forged)
    assert forged in admin.db.get_meta_json(IGNORED_WRITES_META)


def test_a_personal_key_below_a_team_folder_needs_write_access_in_the_log(shared, monkeypatch):
    url, admin, admin_client, bob_id, ops, sk, token = shared
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    _lying_server(monkeypatch)
    personal_dek = new_ulid()
    _push(url, token, sk, personal_dek, "dek", None, b"k" * 72)
    first = new_ulid()
    _push(url, token, sk, first, "entry", ops, _entry_payload(personal_dek))
    assert admin_client.pull()["skipped"] == 1
    assert not _applied(admin, first)


def test_a_personal_key_below_a_team_folder_with_write_access_is_applied(shared):
    url, admin, admin_client, bob_id, ops, sk, token = shared
    revocation.grant_member(admin, admin_client, bob_id, ops, "write")
    personal_dek = new_ulid()
    _push(url, token, sk, personal_dek, "dek", None, b"k" * 72)
    item = new_ulid()
    _push(url, token, sk, item, "entry", ops, _entry_payload(personal_dek))
    assert admin_client.pull()["skipped"] == 0
    assert _applied(admin, item)


def test_moving_an_item_out_of_a_team_folder_needs_write_access_there(shared, team, monkeypatch):  # noqa: F811
    """Capability finding 205: a member the log gives read cannot take an item out of the folder,
    even when the server calls him admin and takes the move."""
    url, admin, admin_client, bob_id, ops, sk, _token = shared
    item = admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    next(u for u in team[0]._storage["users"] if u["id"] == bob_id)["is_admin"] = 1
    users_row_decides(monkeypatch)
    token = _login(url, sk, "bob")
    _lying_server(monkeypatch)
    personal_dek = new_ulid()
    _push(url, token, sk, personal_dek, "dek", None, b"k" * 72)
    version = admin.db.fetchone("SELECT version FROM entries WHERE id = ?", (item,))["version"]
    _push(url, token, sk, item, "entry", None, _entry_payload(personal_dek), version=version + 1)

    assert admin_client.pull()["skipped"] == 1
    assert admin.db.fetchone("SELECT node_id FROM entries WHERE id = ?", (item,))["node_id"] == ops
    assert {e["name"] for e in admin.list_entries(ops)} == {"vpn"}


def test_a_key_the_log_does_not_know_never_becomes_the_folders_key(shared, server, tmp_path, monkeypatch):  # noqa: F811
    url, admin, admin_client, bob_id, ops, _sk, _token = shared
    admin.create_entry(ops, "vpn", [{"key": "password", "value": "ops-pw"}])
    assert admin_client.push()["conflicts"] == []
    revocation.grant_member(admin, admin_client, bob_id, ops, "read")
    logged_key = teamlog.current_key(admin_client.team_state(), ops)

    # Another device of the admin re-keys the folder; the server takes the new
    # key, its archive and the resealed items without a folder.key.
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_client = _client(phone, url)
    phone_client.pull()
    _lying_server(monkeypatch)
    monkeypatch.setattr("sezam.vault.sync_push.rekey_changes", lambda *_a: [])
    assert phone.rekey_after_revocation(bob_id) == 1
    phone_client.push()
    unlogged = phone.dek_mgr.get_dek_for_node(ops)[0]
    assert unlogged != logged_key and unlogged > logged_key
    phone.lock()

    result = admin_client.pull()
    assert admin.dek_mgr.get_dek_for_node(ops)[0] == logged_key
    assert admin.db.fetchone("SELECT scope FROM deks WHERE id = ?", (unlogged,))["scope"] == "tier2"
    # The items resealed with it are not applied: the copies here stay readable.
    assert result["skipped"] >= 1
    assert {e["name"] for e in admin.list_entries(ops)} == {"vpn"}
