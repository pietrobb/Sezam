"""AI broker R3 (TODO section 10): `sezam server reseed`.

An empty (wiped or new) server takes the bootstrap with the vault's existing
account id, proven by the identity key over a fresh bound challenge, and the
vault pushes everything again. Runs against the real FastAPI server.
"""

from __future__ import annotations

import asyncio
import urllib.error

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey

from sezam import cli
from sezam.vault import reseed as reseed_mod
from sezam.vault.pending_states import reseed_state, set_reseed_state
from sezam.vault.reseed import ReseedError, reseed_message, reseed_server
from sezam.vault.snapshots import list_snapshots
from sezam.vault.sync_client import SyncClient
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)

NEW_PASSWORD = "reseed-new-pw!"


def _wipe(db) -> None:
    """The server lost its database: same URL, empty tables."""
    db._storage.clear()
    asyncio.run(db.create_schema())


def _objects(db) -> dict[str, dict]:
    return {o["id"]: o for o in db._storage.get("vault_objects", [])}


def _seeded_laptop(url, db, tmp_path):
    """Admin with two entries and one password change (key epoch 1)."""
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    _client(laptop, url).push()
    laptop.create_entry(folder, "web", [{"key": "password", "value": "after", "sensitive": True}])
    assert _client(laptop, url).push()["accepted"]
    assert int(laptop.db.get_meta("key_epoch")) == 1
    return laptop


def _bootstrap_body(signing_key: SigningKey, url_challenge: str, user_id: str,
                    username="admin", key_epoch=0, enc_pk=b"\x22" * 32, sign_over=None):
    challenge = bytes.fromhex(url_challenge)
    message = sign_over if sign_over is not None else reseed_message(
        challenge, user_id, username, bytes(signing_key.verify_key), enc_pk, key_epoch
    )
    return {
        "username": username,
        "signing_pk": bytes(signing_key.verify_key).hex(),
        "encryption_pk": enc_pk.hex(),
        "user_id": user_id,
        "key_epoch": key_epoch,
        "challenge": url_challenge,
        "signature": signing_key.sign(message).signature.hex(),
    }


def _post(url, path, body):
    return cli._server_request(url, "POST", path, body)


def _challenge(url, username="admin") -> str:
    return _post(url, "/api/auth/challenge", {"username": username})["challenge"]


USER_ID = "01J0RESEED0000000000000000"


# ── server ──────────────────────────────────────────────────────────────


def test_client_and_server_sign_the_same_reseed_bytes():
    from server.app.auth import reseed_message as server_message

    args = (b"\x01" * 40, USER_ID, "admín", b"\x02" * 32, b"\x03" * 32, 7)
    assert reseed_message(*args) == server_message(*args)


def test_empty_server_bootstraps_the_proposed_account_id_and_key_epoch(server):
    url, db = server
    key = SigningKey.generate()
    resp = _post(url, "/api/bootstrap", _bootstrap_body(key, _challenge(url), USER_ID, key_epoch=3))
    assert resp["user_id"] == USER_ID
    assert [u["id"] for u in db._storage["users"]] == [USER_ID]
    assert db._storage["sync_state"][0]["key_epoch"] == 3


@pytest.mark.parametrize("tamper", [
    "other_key", "key_epoch", "username_of_challenge", "login_signature", "foreign_challenge",
])
def test_reseed_proof_is_bound_to_key_account_epoch_and_a_server_challenge(server, tamper):
    url, db = server
    key = SigningKey.generate()
    challenge = _challenge(url, "someone" if tamper == "username_of_challenge" else "admin")
    body = _bootstrap_body(key, challenge, USER_ID, key_epoch=2)
    if tamper == "other_key":
        body["signature"] = _bootstrap_body(SigningKey.generate(), challenge, USER_ID)["signature"]
    elif tamper == "key_epoch":
        body["key_epoch"] = 5
    elif tamper == "login_signature":
        body["signature"] = key.sign(bytes.fromhex(challenge)).signature.hex()
    elif tamper == "foreign_challenge":
        # Right shape, not issued by this server (HMAC binding fails).
        body = _bootstrap_body(key, "00" * 40 + challenge[80:], USER_ID, key_epoch=2)
    with pytest.raises(RuntimeError, match="401"):
        _post(url, "/api/bootstrap", body)
    assert db._storage["users"] == [] and db._storage["sync_state"] == []


def test_reseed_challenge_is_single_use(server):
    url, db = server
    key = SigningKey.generate()
    body = _bootstrap_body(key, _challenge(url), USER_ID)
    _post(url, "/api/bootstrap", body)
    _wipe_users_only(db)
    with pytest.raises(RuntimeError, match="401"):
        _post(url, "/api/bootstrap", body)
    assert db._storage["users"] == []


def _wipe_users_only(db) -> None:
    db._storage["users"].clear()
    db._storage["sync_state"].clear()


def test_plain_bootstrap_cannot_set_epoch_or_carry_a_proof(server):
    url, db = server
    key = SigningKey.generate()
    body = _bootstrap_body(key, _challenge(url), USER_ID, key_epoch=1)
    del body["user_id"]
    with pytest.raises(RuntimeError, match="400"):
        _post(url, "/api/bootstrap", body)
    assert db._storage["users"] == []


def test_reseed_without_proof_is_refused(server):
    url, db = server
    body = _bootstrap_body(SigningKey.generate(), _challenge(url), USER_ID)
    del body["challenge"], body["signature"]
    with pytest.raises(RuntimeError, match="401"):
        _post(url, "/api/bootstrap", body)
    assert db._storage["users"] == []


# ── client ──────────────────────────────────────────────────────────────


def test_reseed_rebuilds_a_wiped_server_with_the_same_account(server, tmp_path):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    user_id = laptop.db.get_meta("user_id")
    before = _objects(db)
    _wipe(db)

    result = reseed_server(laptop, url, NEW_PASSWORD)

    assert result["conflicts"] == [] and result["pushed"] > 0
    assert [u["id"] for u in db._storage["users"]] == [user_id]
    assert db._storage["sync_state"][0]["key_epoch"] == 1
    after = _objects(db)
    # Every node, entry, DEK, envelope and own audit record is back.
    for obj_id, obj in before.items():
        if obj["object_type"] in ("node", "entry", "dek", "envelope", "dek_archive", "audit"):
            assert obj_id in after, (obj["object_type"], obj_id)
    assert all(b"s3cret" not in bytes(o.get("payload") or b"") for o in after.values())
    assert reseed_state(laptop.db) is None
    assert [s.reason for s in list_snapshots(laptop.db.path.parent)][-1] == "server-reseed"

    # The laptop syncs on as before: no rollback alarm, nothing left to push.
    client = _client(laptop, url)
    assert "rollback_warning" not in client.pull()
    assert client.push()["accepted"] == []

    # A new device recovers the account with the current password and reads it.
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    assert phone.db.get_meta("user_id") == user_id
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    assert _entry_value(phone, "Servers", "web", "password") == "after"
    laptop.lock()
    phone.lock()


def test_reseed_pushes_archived_deks(server, tmp_path):
    """A normal push sends dek_archive rows only inside a re-key batch."""
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    node_id = laptop.create_node("Rekeyed")
    old_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (node_id,))["dek_id"]
    new_dek, raw = laptop.dek_mgr.rekey_folder(old_dek, node_id)
    raw[:] = b"\x00" * len(raw)
    laptop.db.execute("UPDATE nodes SET dek_id = ? WHERE id = ?", (new_dek, node_id))
    archive_id = laptop.db.fetchone("SELECT id FROM dek_archive")["id"]
    _wipe(db)

    assert reseed_server(laptop, url, NEW_PASSWORD)["conflicts"] == []
    assert _objects(db)[archive_id]["object_type"] == "dek_archive"
    assert laptop.db.get_meta_json("reseed_archive_ids") == []
    laptop.lock()


def test_other_device_of_the_account_keeps_syncing_after_reseed(server, tmp_path):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    _wipe(db)
    reseed_server(laptop, url, NEW_PASSWORD)

    folder = next(n["id"] for n in laptop.list_nodes() if n["name"] == "Servers")
    laptop.create_entry(folder, "mail", [{"key": "password", "value": "m4il", "sensitive": True}])
    assert _client(laptop, url).push()["accepted"]
    # Same account id and keys: the phone's login still works. Its checkpoint
    # is ahead of the new server, which it cannot tell from a rollback attack:
    # it warns and keeps its data until an explicit `sezam pull --full-resync`.
    phone_client = _client(phone, url)
    assert phone_client.pull().get("rollback_warning")
    assert _entry_value(phone, "Servers", "mail", "password") is None
    phone_client.full_resync(confirmed=True)
    assert _entry_value(phone, "Servers", "mail", "password") == "m4il"
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    laptop.lock()
    phone.lock()


def test_reseed_refuses_a_server_that_is_not_empty(server, tmp_path):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    dirty = laptop.db.fetchone("SELECT COUNT(*) AS n FROM entries WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")["n"]
    with pytest.raises(ReseedError, match="not empty"):
        reseed_server(laptop, url, NEW_PASSWORD)
    assert laptop.db.fetchone("SELECT COUNT(*) AS n FROM entries WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")["n"] == dirty
    assert reseed_state(laptop.db) is None
    laptop.lock()


def test_reseed_resumes_after_the_bootstrap_reply_is_lost(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    user_id = laptop.db.get_meta("user_id")
    _wipe(db)
    real = SyncClient._request

    def lose_bootstrap_reply(self, method, path, *args, **kwargs):
        resp = real(self, method, path, *args, **kwargs)
        if path == "/api/bootstrap":
            raise urllib.error.URLError("connection reset")
        return resp

    monkeypatch.setattr(SyncClient, "_request", lose_bootstrap_reply)
    with pytest.raises(urllib.error.URLError):
        reseed_server(laptop, url, NEW_PASSWORD)
    monkeypatch.setattr(SyncClient, "_request", real)
    assert [u["id"] for u in db._storage["users"]] == [user_id]

    result = reseed_server(laptop, url, NEW_PASSWORD)
    assert result["resumed"] and result["conflicts"] == []
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    assert _entry_value(phone, "Servers", "web", "password") == "after"
    laptop.lock()
    phone.lock()


def test_reseed_resumes_after_a_failed_push(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    _wipe(db)
    monkeypatch.setattr(SyncClient, "push", lambda self: (_ for _ in ()).throw(OSError("down")))
    with pytest.raises(OSError):
        reseed_server(laptop, url, NEW_PASSWORD)
    monkeypatch.undo()
    assert reseed_state(laptop.db) == f"push {url}"

    assert reseed_server(laptop, url, NEW_PASSWORD)["resumed"]
    assert reseed_state(laptop.db) is None
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    laptop.lock()
    phone.lock()


def test_pending_reseed_does_not_resume_against_another_account(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    _wipe(db)
    # Someone else bootstrapped the empty server first.
    other = _vault(tmp_path / "other", "admin")
    cli._server_connect_flow(url, other, PASSWORD)
    set_reseed_state(laptop.db, f"bootstrap {url}")
    with pytest.raises(Exception):
        reseed_server(laptop, url, NEW_PASSWORD)
    assert reseed_state(laptop.db) == f"bootstrap {url}"
    assert laptop.db.fetchone("SELECT COUNT(*) AS n FROM nodes WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")["n"] == 0
    laptop.lock()
    other.lock()


def test_refused_bootstrap_clears_the_journal(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    _wipe(db)
    monkeypatch.setattr(
        reseed_mod, "reseed_message", lambda *a: b"not what the server checks"
    )
    with pytest.raises(ReseedError, match="401"):
        reseed_server(laptop, url, NEW_PASSWORD)
    assert reseed_state(laptop.db) is None
    assert db._storage["users"] == []
    laptop.lock()


def test_cli_server_reseed(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    vault_dir = laptop.db.path.parent
    laptop.lock()
    _wipe(db)
    _cli_env(vault_dir, monkeypatch)

    result = CliRunner().invoke(cli.main, ["server", "reseed"], input=NEW_PASSWORD + "\n")
    assert result.exit_code == 0, result.output
    assert "Server reseeded" in result.output
    assert NEW_PASSWORD not in result.output
    assert db._storage["users"]

    again = CliRunner().invoke(cli.main, ["server", "reseed"], input=NEW_PASSWORD + "\n")
    assert again.exit_code != 0 and "not empty" in again.output
