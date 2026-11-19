"""Review item T2: real desktop client <-> real server over HTTP.

The unit suites drive the server through an ASGI transport and the client
against fakes, so the two halves were never checked against each other. Here
the FastAPI app runs under uvicorn on a loopback socket (in-memory storage
from test_server_spec.MockDatabase) and the unmodified desktop code — the CLI
connect flow, SyncClient push/pull — talks to it through urllib.
"""

from __future__ import annotations

import asyncio
import io
import threading
import time

import pytest
import uvicorn
from nacl.signing import SigningKey

from sezam.vault import pending_states
from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.crypto.kdf import Argon2Params
from sezam.models import bytes_to_ulid
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.node_support import fetchable_socket
from tests.test_server_spec import MockDatabase

# Lowest cost the server accepts for account KDF params.
PARAMS = Argon2Params(time_cost=2, memory_cost=65_536, parallelism=1)
PASSWORD = "integration-test-pw!"


@pytest.fixture
def server(tmp_path):
    from server.app.config import JWTKeyManager, ServerConfig
    from server.app.dependencies import set_globals
    from server.app.main import app

    db = MockDatabase()
    asyncio.run(db.create_schema())
    key_file = tmp_path / "jwt.key"
    key_file.write_bytes(bytes(SigningKey.generate()))
    config = ServerConfig(
        jwt_expiry_seconds=3600,
        jwt_onboarding_expiry_seconds=900,
        hmac_server_secret="integration-test-server-secret",
        recovery_ip_max_failures_per_hour=50,
        recovery_max_total=20,
    )
    set_globals(config, db, JWTKeyManager(str(key_file)))

    sock = fetchable_socket()  # the web tests reach it with Node's fetch
    port = sock.getsockname()[1]
    uv = uvicorn.Server(uvicorn.Config(app, lifespan="off", ws="none", log_level="warning"))
    thread = threading.Thread(target=uv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not uv.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    yield f"http://127.0.0.1:{port}", db
    uv.should_exit = True
    thread.join(timeout=10)
    sock.close()


def _server_member(db, member_id: str | None = None) -> str:
    """A user the server knows (the envelope's target_user_id is a foreign key)."""
    from sezam.models import new_ulid
    from tests.test_server_spec import _create_regular_user

    member_id = member_id or new_ulid()
    _create_regular_user(db._storage, member_id, f"member-{member_id.lower()}")
    return member_id


def _vault(path, username: str) -> Vault:
    vault = Vault.create(path, PASSWORD, PARAMS)
    vault.db.set_meta("username", username)
    return vault


def _client(vault: Vault, url: str) -> SyncClient:
    client = SyncClient(vault.db, url, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    client.authenticate()
    return client


def _entry_value(vault: Vault, folder: str, title: str, key: str) -> str | None:
    for node in vault.list_nodes():
        if node["name"] != folder:
            continue
        for entry in vault.list_entries(node["id"]):
            if entry["name"] == title:
                return vault.get_field_value(entry["id"], key)
    return None


def test_second_device_recovers_account_and_round_trips_edits(server, tmp_path):
    url, db = server

    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    entry_id = laptop.create_entry(
        folder, "db01", [{"key": "password", "value": "first-secret", "sensitive": True}]
    )
    # Real connect flow: empty server -> bootstrap admin, upload keypair, push.
    cli._server_connect_flow(url, laptop, PASSWORD)
    server_user_id = laptop.db.get_meta("user_id")
    assert any(u["id"] == server_user_id for u in db._storage["users"])
    assert laptop.db.get_meta("server_url") == url
    stored = db._storage.get("vault_objects", [])
    assert stored, "bootstrap push stored nothing"
    # Content-blind: the plaintext never reaches the server.
    assert all(b"first-secret" not in bytes(o.get("payload") or b"") for o in stored)

    # A brand-new vault with the same account recovers the server keypair
    # (Path B) and pulls everything the laptop pushed.
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert phone.db.get_meta("user_id") == server_user_id
    assert phone.keypair.signing_pk == laptop.keypair.signing_pk
    assert _entry_value(phone, "Servers", "db01", "password") == "first-secret"

    # Edit on the second device, push, and pull it back on the first.
    phone_entry = next(
        e for n in phone.list_nodes() if n["name"] == "Servers"
        for e in phone.list_entries(n["id"])
    )
    phone.update_entry(
        phone_entry["id"],
        fields=[{"key": "password", "value": "rotated-secret", "sensitive": True}],
    )
    pushed = _client(phone, url).push()
    assert pushed["accepted"] and not pushed["conflicts"]

    laptop_client = _client(laptop, url)
    result = laptop_client.pull()
    assert result["pulled"] >= 1
    assert laptop.get_field_value(entry_id, "password") == "rotated-secret"

    # Nothing new on the server: the next pull is a no-op.
    assert laptop_client.pull()["pulled"] == 0

    laptop.lock()
    phone.lock()


def test_password_change_reaches_server_as_one_resendable_unit(server, tmp_path):
    """Review 2052248 #1: the keypair upload and the epoch push were separate.

    A failure between them left the server with the new password but every
    DEK under the old KEK. Now one push carries both; if it fails, nothing
    changed on the server and the next sync resends it from the journal.
    """
    url, db = server
    new_password = "integration-new-pw!"
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    def server_user():
        return next(u for u in db._storage["users"] if u["id"] == user_id)

    def server_epoch():
        return next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)["key_epoch"]

    old_server_keypair = server_user()["encrypted_keypair"]
    proof = laptop.change_password(PASSWORD, new_password)
    proof[:] = b"\x00" * len(proof)

    offline = _client(laptop, url)
    real_request = offline._request

    def drop_sync(method, path, *args, **kwargs):
        if path == "/api/sync" and method == "POST":
            raise RuntimeError("network down")
        return real_request(method, path, *args, **kwargs)

    offline._request = drop_sync
    with pytest.raises(RuntimeError, match="network down"):
        offline.push()
    assert server_user()["encrypted_keypair"] == old_server_keypair
    assert server_epoch() == 0
    assert (pending_states.key_change_journal(laptop.db) or None)

    _client(laptop, url).push()  # the next sync
    assert bytes(server_user()["encrypted_keypair"]).hex() == laptop.db.get_meta("encrypted_keypair")
    assert server_epoch() == 1
    assert (pending_states.key_change_journal(laptop.db) or None) is None

    # A new device signs in with the NEW password and reads the data.
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, new_password)
    assert phone.db.get_meta("user_id") == user_id
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    laptop.lock()
    phone.lock()


NEW_PASSWORD = "integration-new-pw!"


def _rotate_on_laptop(url, tmp_path):
    """Laptop and phone share one account; the laptop changes the password."""
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"

    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    _client(laptop, url).push()
    folder = next(n["id"] for n in laptop.list_nodes() if n["name"] == "Servers")
    laptop.create_entry(folder, "web", [{"key": "password", "value": "after", "sensitive": True}])
    assert _client(laptop, url).push()["accepted"]
    return laptop, phone


def test_other_device_adopts_a_password_changed_elsewhere(server, tmp_path):
    """Review 2052248 #1: no path took a newer key_epoch over from the server.

    After a password change on the laptop, the phone (still on the old
    password) failed every pull with "key epoch is stale" and every push with
    409, for good. Now it takes the rotation over with the current password.
    """
    from sezam.vault.sync_client import KeyEpochStale

    url, _db = server
    laptop, phone = _rotate_on_laptop(url, tmp_path)
    phone_folder = next(n["id"] for n in phone.list_nodes() if n["name"] == "Servers")
    phone.create_entry(
        phone_folder, "phone-note", [{"key": "password", "value": "offline", "sensitive": True}]
    )

    client = _client(phone, url)
    with pytest.raises(KeyEpochStale):
        client.pull()
    with pytest.raises(KeyEpochStale):
        client.push()

    with pytest.raises(RuntimeError, match="Wrong current account password"):
        client.adopt_rotated_key_material(phone, "not-the-password")
    assert phone.db.get_meta("key_epoch") == "0"
    assert phone.verify_password(PASSWORD)

    assert client.adopt_rotated_key_material(phone, NEW_PASSWORD) == 1
    assert phone.db.get_meta("key_epoch") == "1"
    client.pull()
    assert _entry_value(phone, "Servers", "web", "password") == "after"
    pushed = client.push()
    assert pushed["accepted"] and not pushed["conflicts"]

    _client(laptop, url).pull()
    assert _entry_value(laptop, "Servers", "phone-note", "password") == "offline"

    # The phone's vault now opens with the account password only.
    phone.lock()
    reopened = Vault(tmp_path / "phone")
    with pytest.raises(ValueError):
        reopened.unlock(PASSWORD)
    reopened.unlock(NEW_PASSWORD)
    assert _entry_value(reopened, "Servers", "db01", "password") == "s3cret"
    reopened.lock()
    laptop.lock()


def test_rival_password_change_from_the_same_epoch_is_taken_over(server, tmp_path):
    """Capability finding (run 10): both devices rotated from epoch 0.

    The laptop's rotation reached the server first (epoch 1). The phone's own
    rotation also targets epoch 1, so neither "server epoch > local" check
    fired: push failed with a generic 409 on every sync and pull applied DEKs
    wrapped under a KEK the phone does not have. It must be a typed
    KeyEpochStale, and adopting the server's password must drop the losing
    rotation and resume syncing.
    """
    from sezam.vault.sync_client import KeyEpochStale

    url, _db = server
    laptop, phone = _rotate_on_laptop(url, tmp_path)
    proof = phone.change_password(PASSWORD, "phone-offline-pw!")
    proof[:] = b"\x00" * len(proof)
    phone.unlock("phone-offline-pw!")
    assert (pending_states.key_change_journal(phone.db) or None)

    client = _client(phone, url)
    with pytest.raises(KeyEpochStale):
        client.push()
    with pytest.raises(KeyEpochStale):
        client.pull()

    assert client.adopt_rotated_key_material(phone, NEW_PASSWORD) == 1
    assert (pending_states.key_change_journal(phone.db) or None) is None
    client.pull()
    assert _entry_value(phone, "Servers", "web", "password") == "after"
    pushed = client.push()
    assert not pushed["conflicts"]
    pulled = client.pull()
    assert not pulled.get("equivocations"), pulled
    assert client.pull()["pulled"] == 0

    # Everything the phone pushed after taking over opens on the laptop too:
    # no DEK on the server is wrapped under the phone's losing KEK.
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert laptop_client.push()["conflicts"] == []
    for row in laptop.db.fetchall("SELECT id, encrypted_dek, version FROM deks"):
        assert laptop.dek_mgr.can_unwrap(row["id"], bytes(row["encrypted_dek"]), row["version"])

    phone.lock()
    reopened = Vault(tmp_path / "phone")
    reopened.unlock(NEW_PASSWORD)
    assert _entry_value(reopened, "Servers", "db01", "password") == "s3cret"
    reopened.lock()
    laptop.lock()


def test_own_rotation_with_a_lost_response_is_not_a_rival(server, tmp_path):
    """Same epoch, same key material: the server applied OUR rotation."""
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)

    lossy = _client(laptop, url)
    real_request = lossy._request

    def lose_response(method, path, *args, **kwargs):
        resp = real_request(method, path, *args, **kwargs)
        if path == "/api/sync" and method == "POST":
            raise RuntimeError("connection reset")
        return resp

    lossy._request = lose_response
    with pytest.raises(RuntimeError, match="connection reset"):
        lossy.push()
    assert (pending_states.key_change_journal(laptop.db) or None)

    client = _client(laptop, url)
    client.pull()  # no KeyEpochStale: the server holds this device's rotation
    client.push()  # idempotent resend clears the journal
    assert (pending_states.key_change_journal(laptop.db) or None) is None
    assert laptop.db.get_meta("last_pushed_key_epoch") == "1"
    laptop.lock()


def test_cli_pull_asks_for_the_account_password_changed_elsewhere(
    server, tmp_path, monkeypatch
):
    from click.testing import CliRunner

    url, _db = server
    laptop, phone = _rotate_on_laptop(url, tmp_path)
    phone.lock()
    laptop.lock()
    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "phone"))
    monkeypatch.setattr(cli, "_load_session", lambda: None)
    monkeypatch.setattr(cli, "_clear_session", lambda: None)

    result = CliRunner().invoke(cli.main, ["pull"], input=f"{PASSWORD}\n{NEW_PASSWORD}\n")
    assert result.exit_code == 0, result.output
    assert "changed on another device" in result.output
    assert "Adopted the new account password (key epoch 1)" in result.output
    assert "Pull failed" not in result.output

    reopened = Vault(tmp_path / "phone")
    reopened.unlock(NEW_PASSWORD)
    assert _entry_value(reopened, "Servers", "web", "password") == "after"
    reopened.lock()


def test_gui_connect_takes_over_a_password_changed_elsewhere(server, tmp_path):
    pytest.importorskip("PySide6")
    from sezam.gui.server_connect_dialog import ServerConnectWorker

    url, _db = server
    laptop, phone = _rotate_on_laptop(url, tmp_path)
    worker = ServerConnectWorker(url, phone, PASSWORD)
    asked, ok, errors = [], [], []
    worker.need_account_password.connect(
        lambda: (asked.append(True), worker.set_account_password(NEW_PASSWORD))
    )
    worker.need_invitation.connect(lambda: worker.request_stop())
    worker.finished_ok.connect(ok.append)
    worker.finished_error.connect(errors.append)
    worker._do_connect()

    assert asked and not errors, errors
    assert ok and "Prevzate nove heslo" in ok[0]
    assert phone.db.get_meta("key_epoch") == "1"
    assert _entry_value(phone, "Servers", "web", "password") == "after"
    phone.lock()
    laptop.lock()


def _fail_first_keypair_upload(monkeypatch, module, name, lost_reply=False):
    """Fail the first PUT /api/me/keypair: before the server sees it, or
    (lost_reply) after the server stored it, as when the reply is lost."""
    real = getattr(module, name)
    failed = []

    def flaky(server_url, method, path, *args, **kwargs):
        if method == "PUT" and path == "/api/me/keypair" and not failed:
            failed.append(True)
            if lost_reply:
                real(server_url, method, path, *args, **kwargs)
            raise RuntimeError("HTTP 503: upstream timeout")
        return real(server_url, method, path, *args, **kwargs)

    monkeypatch.setattr(module, name, flaky)
    return failed


def _assert_bootstrap_finished(url, db, laptop, tmp_path):
    user_id = laptop.db.get_meta("user_id")
    account = next(u for u in db._storage["users"] if u["id"] == user_id)
    assert account.get("encrypted_keypair"), "admin account still has no key material"
    assert not pending_states.bootstrap_upload_flag(laptop.db)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert phone.db.get_meta("user_id") == user_id
    assert _entry_value(phone, "Servers", "db01", "password") == "s1"
    phone.lock()


@pytest.mark.parametrize("lost_reply", [False, True], ids=["not_stored", "reply_lost"])
def test_cli_bootstrap_with_failed_keypair_upload_finishes_on_reconnect(
    server, tmp_path, monkeypatch, lost_reply
):
    """Review 2052248 (desktop medium): a failed upload after POST /api/bootstrap
    left an admin without key material — no setup, recovery or invitation
    could ever complete it. The next connect now finishes the upload."""
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s1", "sensitive": True}])

    failed = _fail_first_keypair_upload(monkeypatch, cli, "_server_request", lost_reply)
    with pytest.raises(RuntimeError, match="503"):
        cli._server_connect_flow(url, laptop, PASSWORD)
    assert failed
    assert pending_states.bootstrap_upload_flag(laptop.db)

    # Capability finding run 13: with the reply lost the server already holds
    # the keypair; the retry must notice instead of a 409 on every connect.
    cli._server_connect_flow(url, laptop, PASSWORD)
    cli._server_connect_flow(url, laptop, PASSWORD)
    _assert_bootstrap_finished(url, db, laptop, tmp_path)
    laptop.lock()


def test_cli_pending_bootstrap_with_foreign_key_material_falls_through_to_recovery(
    server, tmp_path, monkeypatch, capsys
):
    """Capability finding run 13: when the account meanwhile holds key material
    that is not this device's, the pending flag is dropped and the connect
    continues on the existing-account (recovery) path instead of a PUT 409."""
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    _fail_first_keypair_upload(monkeypatch, cli, "_server_request", lost_reply=True)
    with pytest.raises(RuntimeError, match="503"):
        cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")
    account = next(u for u in db._storage["users"] if u["id"] == user_id)
    account["encrypted_keypair"] = b"\x01" * len(account["encrypted_keypair"])
    # Recovery cannot open foreign key material, so the flow ends at the
    # invitation prompt; answer it with nothing.
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    capsys.readouterr()

    cli._server_connect_flow(url, laptop, PASSWORD)
    out = capsys.readouterr()
    assert not pending_states.bootstrap_upload_flag(laptop.db)
    assert "Dokoncenie bootstrapu zlyhalo" not in out.err
    assert "409" not in out.out + out.err
    assert "other key material" in out.out
    assert "Na tomto serveri nemas ucet." in out.out
    laptop.lock()


@pytest.mark.parametrize("lost_reply", [False, True], ids=["not_stored", "reply_lost"])
def test_gui_bootstrap_with_failed_keypair_upload_finishes_on_reconnect(
    server, tmp_path, monkeypatch, lost_reply
):
    pytest.importorskip("PySide6")
    from sezam.gui import server_connect_dialog
    from sezam.gui.server_connect_dialog import ServerConnectWorker

    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s1", "sensitive": True}])

    failed = _fail_first_keypair_upload(
        monkeypatch, server_connect_dialog, "_http_request", lost_reply
    )
    for _attempt in range(3):
        worker = ServerConnectWorker(url, laptop, PASSWORD)
        ok, errors = [], []
        worker.need_invitation.connect(lambda w=worker: w.request_stop())
        worker.finished_ok.connect(ok.append)
        worker.finished_error.connect(errors.append)
        worker.run()
    assert failed
    assert ok and not errors, errors
    _assert_bootstrap_finished(url, db, laptop, tmp_path)
    laptop.lock()


def _gc_tombstones(db) -> None:
    """What server.app.main._cleanup_tombstones does once the GC window passed."""
    objects = db._storage["vault_objects"]
    tombstones = [o for o in objects if o.get("is_deleted")]
    assert tombstones, "nothing to collect"
    counter = db._storage["commit_counter"][0]
    counter["gc_floor_seq"] = max(
        counter.get("gc_floor_seq") or 0, max(o["commit_seq"] for o in tombstones)
    )
    db._storage["vault_objects"] = [o for o in objects if not o.get("is_deleted")]


def test_new_device_and_full_resync_survive_tombstone_gc(server, tmp_path):
    """Review 2052248 item 3: a GC'd folder's DEK still names the folder."""
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    keep = laptop.create_node("Keep")
    laptop.create_entry(keep, "web", [{"key": "password", "value": "kept", "sensitive": True}])
    gone = laptop.create_node("Gone")
    laptop.create_entry(gone, "old", [{"key": "password", "value": "x", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    laptop.delete_node(gone)
    assert _client(laptop, url).push()["accepted"]
    _gc_tombstones(db)

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert _entry_value(phone, "Keep", "web", "password") == "kept"
    assert [n["name"] for n in phone.list_nodes()] == ["Keep"]

    result = _client(laptop, url).full_resync(confirmed=True)
    assert result["full_resync"]
    assert _entry_value(laptop, "Keep", "web", "password") == "kept"
    assert [n["name"] for n in laptop.list_nodes()] == ["Keep"]

    laptop.lock()
    phone.lock()


def test_full_resync_refuses_an_unpushed_password_change(server, tmp_path):
    """Lockout review #1: full resync replaced the new-KEK DEK wraps.

    The server still held every DEK under the old KEK. After the resync the
    vault opened with the new password but no entry could be read, and push
    had nothing left to send. A change whose journal keeps the old KEK re-wraps
    every server wrap into itself (SM40); any other one is still refused.
    """
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    client = _client(laptop, url)
    journal = (pending_states.key_change_journal(laptop.db) or None)
    without_old_kek = {k: v for k, v in journal.items() if k != "old_kek"}
    pending_states.set_key_change_journal(laptop.db, without_old_kek)
    deks_before = laptop.db.fetchall("SELECT id, encrypted_dek, version FROM deks")
    with pytest.raises(RuntimeError, match="password change the server has not received"):
        client.full_resync(confirmed=True)
    assert laptop.db.fetchall("SELECT id, encrypted_dek, version FROM deks") == deks_before
    pending_states.set_key_change_journal(laptop.db, journal)

    assert client.full_resync(confirmed=True)["full_resync"]
    assert (pending_states.key_change_journal(laptop.db) or None)
    assert _entry_value(laptop, "Servers", "db01", "password") == "s3cret"

    # The resync left the rotation intact: the push still sends it.
    client.push()
    assert not client.has_pending_key_change()
    laptop.lock()
    laptop.unlock(NEW_PASSWORD)
    assert _entry_value(laptop, "Servers", "db01", "password") == "s3cret"
    assert _client(laptop, url).full_resync(confirmed=True)["full_resync"]
    assert _entry_value(laptop, "Servers", "db01", "password") == "s3cret"
    laptop.lock()


def test_full_resync_refuses_an_unpushed_member_rekey(server, tmp_path):
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    pending_states.set_rekey_batch(laptop.db, {"object_ids": ["x"]})
    with pytest.raises(RuntimeError, match="re-key the server has not received"):
        _client(laptop, url).full_resync(confirmed=True)
    laptop.lock()


def test_cli_pull_full_resync_is_refused_before_the_prompt(server, tmp_path, monkeypatch):
    from click.testing import CliRunner

    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    # A change that cannot re-wrap the server's DEKs (no old KEK in its journal).
    journal = (pending_states.key_change_journal(laptop.db) or None)
    pending_states.set_key_change_journal(laptop.db, {k: v for k, v in journal.items() if k != "old_kek"})
    monkeypatch.setattr(cli, "_open_vault", lambda: laptop)
    monkeypatch.setattr(cli, "_unlock_vault", lambda vault: None)
    monkeypatch.setattr(laptop, "lock", lambda: None)
    result = CliRunner().invoke(cli.main, ["pull", "--full-resync"], input="y\n")
    assert "Continue with full resync?" not in result.output
    assert "password change the server has not received" in result.output
    assert (pending_states.key_change_journal(laptop.db) or None)


def test_org_recovery_still_works_after_adopting_a_password_changed_elsewhere(
    server, tmp_path
):
    """Lockout review #3: adopt_account_kek left the recovery wrap on the old KEK.

    Org recovery then reconstructed a KEK that opened nothing ("Failed to
    decrypt keypair with recovered KEK"): the rescue path was silently gone.
    """
    url, _db = server
    laptop, phone = _rotate_on_laptop(url, tmp_path)
    shares = phone.setup_org_recovery(threshold=2, shares=3)
    assert _client(phone, url).adopt_rotated_key_material(phone, NEW_PASSWORD) == 1
    assert phone.db.get_meta("org_recovery_stale") == "0"
    phone.lock()

    reopened = Vault(tmp_path / "phone")
    reopened.org_recovery(shares[:2], "recovered-pw!")
    reopened.lock()
    reopened.unlock("recovered-pw!")
    assert _entry_value(reopened, "Servers", "db01", "password") == "s3cret"
    reopened.lock()
    laptop.lock()


def test_cli_org_recovery_sends_the_new_password_to_the_server(server, tmp_path, monkeypatch):
    """Review 2052248 D13: desktop org recovery never synced the server.

    The vault re-keyed locally, but the server kept the old key material and
    epoch, so a new device still had to use the forgotten password.
    """
    from click.testing import CliRunner

    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    shares = laptop.setup_org_recovery(threshold=2, shares=3)
    user_id = laptop.db.get_meta("user_id")
    laptop.lock()

    monkeypatch.setenv("SEZAM_VAULT", str(tmp_path / "laptop"))
    typed = "".join(f"{idx}:{share.hex()}\n" for idx, share in shares[:2])
    result = CliRunner().invoke(
        cli.main, ["org-recovery"], input=f"{typed}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\n"
    )
    assert result.exit_code == 0, result.output
    # Review 688edcb K1: without the old password the server wants another
    # admin's approval ('sezam allow-key-reset'); granted here directly.
    assert f"sezam allow-key-reset {user_id}" in result.output, result.output
    user = next(u for u in db._storage["users"] if u["id"] == user_id)
    user["key_reset_until"] = int(time.time() * 1000) + 60_000
    recovered = Vault(tmp_path / "laptop")
    recovered.unlock(NEW_PASSWORD)
    client = SyncClient(recovered.db, url, recovered.keypair, user_id)
    client.set_dek_manager(recovered.dek_mgr)
    client.push()
    recovered.lock()

    state = next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)
    assert state["key_epoch"] == 1
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    assert phone.db.get_meta("user_id") == user_id
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    phone.lock()


def test_full_resync_on_a_new_device_keeps_dek_roles(server, tmp_path):
    """Review 2052248 (desktop medium): the server never got the DEK scope.

    Every pulled DEK became 'folder', so a full resync on a device whose own
    audit DEK was never pushed pruned it and had no audit DEK left to seal
    the sync checkpoint with: the resync failed.
    """
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    keep = laptop.create_node("Keep")
    laptop.create_entry(keep, "web", [{"key": "password", "value": "kept", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop_audit = laptop.dek_mgr.get_audit_dek()[0]
    laptop_root = laptop.dek_mgr.get_root_dek()[0]
    stored = {o["id"]: o.get("dek_scope") for o in db._storage["vault_objects"]}
    assert stored[laptop_audit] == "audit"
    assert stored[laptop_root] == "root"

    phone = _vault(tmp_path / "phone", "admin")
    phone_audit = phone.dek_mgr.get_audit_dek()[0]
    cli._server_connect_flow(url, phone, PASSWORD)
    assert phone_audit not in {o["id"] for o in db._storage["vault_objects"]}

    result = _client(phone, url).full_resync(confirmed=True)
    assert result["full_resync"]
    scopes = {r["id"]: r["scope"] for r in phone.db.fetchall("SELECT id, scope FROM deks")}
    assert scopes[laptop_audit] == "audit"
    assert scopes[laptop_root] == "root"
    assert _entry_value(phone, "Keep", "web", "password") == "kept"
    laptop.lock()
    phone.lock()


def test_full_resync_against_unlabelled_server_deks_keeps_local_audit_dek(server, tmp_path):
    """A server from before the scope label: the device keeps an audit DEK."""
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    keep = laptop.create_node("Keep")
    laptop.create_entry(keep, "web", [{"key": "password", "value": "kept", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    for obj in db._storage["vault_objects"]:
        obj["dek_scope"] = None

    phone = _vault(tmp_path / "phone", "admin")
    phone_audit = phone.dek_mgr.get_audit_dek()[0]
    cli._server_connect_flow(url, phone, PASSWORD)
    client = _client(phone, url)
    assert client.full_resync(confirmed=True)["full_resync"]
    # SM82: the unlabelled laptop audit DEK is an audit DEK by the signed meta
    # pulled with it (it seals no node's meta), so the server does hold an
    # audit DEK of this account and the phone's own unsent one is not needed.
    laptop_audit = laptop.dek_mgr.get_audit_dek()[0]
    assert phone.db.fetchone("SELECT scope FROM deks WHERE id = ?", (laptop_audit,))["scope"] == "audit"
    assert phone.dek_mgr.get_audit_dek()[0] in {phone_audit, laptop_audit}
    assert client.push()["conflicts"] == []
    assert phone.dek_mgr.get_audit_dek()[0] in {o["id"] for o in db._storage["vault_objects"]}
    assert client.pull() is not None
    laptop.lock()
    phone.lock()


def _entry_dek(vault: Vault, entry_id: str) -> tuple[str | None, str]:
    row = vault.db.fetchone("SELECT dek_id, encrypted_data FROM entries WHERE id = ?", (entry_id,))
    return row["dek_id"], bytes_to_ulid(parse_envelope(bytes(row["encrypted_data"])).dek_id)


def _dek_scopes(vault: Vault) -> dict[str, str]:
    return {r["id"]: r["scope"] for r in vault.db.fetchall("SELECT id, scope FROM deks")}


def test_tier2_entry_and_personal_folder_cross_devices_and_full_resync(server, tmp_path):
    """Review 2052248 (missing tests): tier-2 entries and personal folders
    through a real server - a second device reads both, its move + edit of
    the tier-2 entry keeps the entry's own DEK on the first device, and a full
    resync keeps every DEK role."""
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    ops = laptop.create_node("Ops")
    archive = laptop.create_node("Archive")
    tier2 = laptop.create_entry(
        ops, "root-pw", [{"key": "password", "value": "t2-secret", "sensitive": True}], tier=2
    )
    personal = laptop.create_personal_folder("Moje")
    laptop.create_entry(personal, "bank", [{"key": "password", "value": "pin-1", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    tier2_dek, header = _entry_dek(laptop, tier2)
    assert tier2_dek is not None and header == tier2_dek
    personal_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (personal,))["dek_id"]
    stored = {o["id"]: o.get("dek_scope") for o in db._storage["vault_objects"]}
    assert stored[tier2_dek] == "tier2"
    assert stored[personal_dek] == "personal"

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert _entry_value(phone, "Ops", "root-pw", "password") == "t2-secret"
    assert phone.read_entry(tier2)["tier"] == 2
    assert _entry_value(phone, "Moje", "bank", "password") == "pin-1"
    assert phone.read_node(personal)["name"] == "Moje"

    phone.move_entry(tier2, archive)
    phone.update_entry(tier2, fields=[{"key": "password", "value": "t2-rotated", "sensitive": True}])
    assert _entry_dek(phone, tier2) == (tier2_dek, tier2_dek)
    assert _client(phone, url).push()["conflicts"] == []

    _client(laptop, url).pull()
    assert _entry_value(laptop, "Archive", "root-pw", "password") == "t2-rotated"
    assert _entry_dek(laptop, tier2) == (tier2_dek, tier2_dek)

    assert _client(phone, url).full_resync(confirmed=True)["full_resync"]
    assert _entry_value(phone, "Archive", "root-pw", "password") == "t2-rotated"
    assert _entry_value(phone, "Moje", "bank", "password") == "pin-1"
    scopes = _dek_scopes(phone)
    assert scopes[tier2_dek] == "tier2"
    assert scopes[personal_dek] == "personal"
    laptop.lock()
    phone.lock()


def test_new_device_adopts_its_own_root_among_several_accounts(server, tmp_path, monkeypatch):
    """Review 2052248 (desktop medium): with several users' roots on the server
    a new device took the lowest root id; when that was someone else's root
    it adopted nothing and its own account tree stayed hidden."""
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    admin.create_node("Ops")
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()

    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    bob.create_node("Mine")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    # A second admin (no API for it: the operator sets the flag).
    next(u for u in db._storage["users"] if u["id"] == bob_id)["is_admin"] = 1
    bob_client = _client(bob, url)
    bob_client.pull()
    assert bob_client.push()["conflicts"] == []
    bob_root = bob.db.get_meta("root_node_id")
    assert admin.db.get_meta("root_node_id") < bob_root

    bob_phone = _vault(tmp_path / "bob-phone", "bob")
    cli._server_connect_flow(url, bob_phone, PASSWORD)
    assert bob_phone.db.get_meta("root_node_id") == bob_root
    assert [n["name"] for n in bob_phone.list_nodes()] == ["Mine"]
    admin.lock()
    bob.lock()
    bob_phone.lock()


def test_team_member_completes_the_epoch_push_of_a_password_change(
    server, tmp_path, monkeypatch
):
    """Review 2052248 (desktop medium): a member's password change rode in one
    atomic batch with its unpushable top-level root, so the server refused it
    on every sync and the new epoch never arrived."""
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    admin.create_node("Ops")
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()

    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    _client(bob, url).pull()

    proof = bob.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    bob.unlock(NEW_PASSWORD)
    _client(bob, url).push()

    epoch = next(s for s in db._storage["sync_state"] if s["user_id"] == bob_id)["key_epoch"]
    account = next(u for u in db._storage["users"] if u["id"] == bob_id)
    assert epoch == 1
    assert bytes(account["encrypted_keypair"]).hex() == bob.db.get_meta("encrypted_keypair")
    assert bob.db.get_meta("last_pushed_key_epoch") == "1"
    assert (pending_states.key_change_journal(bob.db) or None) is None
    admin.lock()
    bob.lock()


def test_invited_user_cannot_sync_until_admin_approves(server, tmp_path, monkeypatch):
    url, _db = server
    admin = _vault(tmp_path / "admin", "admin")
    folder = admin.create_node("Ops")
    admin.create_entry(folder, "vpn", [{"key": "password", "value": "ops-pw", "sensitive": True}])
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()

    # The real registration helper, minus its blocking approval poll.
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    pending = SyncClient(bob.db, url, bob.keypair, bob_id)
    with pytest.raises(RuntimeError, match="40[13]"):
        pending.authenticate()

    admin_client.approve_user(bob_id)
    bob_client = _client(bob, url)
    # As _poll_for_approval does: the first pull adopts the account tree's
    # root, so bob never pushes a second top-level root of his own.
    bob_root = bob.db.get_meta("root_node_id")
    result = bob_client.pull()
    assert result["pulled"] > 0
    # Without an access envelope the account tree stays opaque to bob: it is
    # not adopted as his root and nothing of the admin's folder decrypts.
    assert bob.db.get_meta("root_node_id") == bob_root
    assert bob.list_nodes() == []
    assert bob.search("vpn") == []

    admin.lock()
    bob.lock()
