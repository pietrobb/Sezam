"""Capability review of #284 (K1/K2): a grant could stay on this device for good.

An access envelope had no pushed state of its own: it went out only while
its folder node was dirty. Since the push is split (K1) the folder could be
marked clean when its chunk landed, before the chunk with its envelope; a
failure of that later chunk left the envelope out of every later push. A
grant made while its folder was being sent (K2 checks only the version,
and a grant does not raise it) was marked pushed with the folder. Either
way the member never got the folder and nothing showed it as pending.
"""

from __future__ import annotations

from nacl.public import PrivateKey

from sezam import cli
from sezam.models import new_ulid
from sezam.vault import sync_push
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _server_member,
    _vault,
    server,
)


def _server_ids(db, object_type: str) -> set[str]:
    return {
        o["id"] for o in db._storage.get("vault_objects", [])
        if o["object_type"] == object_type and not o.get("is_deleted")
    }


def _member_pk() -> bytes:
    return bytes(PrivateKey.generate().public_key)


def _connected_laptop(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    return laptop


def test_a_grant_is_sent_after_the_chunk_with_it_failed(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _connected_laptop(url, tmp_path)
    folder = laptop.create_node("Ops")
    laptop.create_entry(folder, "vpn", [{"key": "password", "value": "v1"}])
    envelope_id = laptop.grant_folder_access(folder, _server_member(db), _member_pk())

    # Folder and entry go in the first chunk, the folder's DEK and the
    # envelope in the second, which fails.
    monkeypatch.setattr(sync_push, "split_for_push", lambda objs: [objs[i:i + 2] for i in range(0, len(objs), 2)])
    client = _client(laptop, url)
    real_request = client._request
    posts = []

    def failing_second_post(method, path, *args, **kwargs):
        if method == "POST" and path == "/api/sync":
            posts.append(path)
            if len(posts) == 2:
                raise RuntimeError("connection reset")
        return real_request(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", failing_second_post)
    try:
        client.push()
    except RuntimeError:
        pass
    monkeypatch.undo()
    assert envelope_id not in _server_ids(db, "envelope")

    _client(laptop, url).push()
    assert envelope_id in _server_ids(db, "envelope")
    assert not [
        o for o in _client(laptop, url)._collect_dirty_objects()
        if o["object_type"] == "envelope"
    ]
    laptop.lock()


def test_a_grant_made_while_its_folder_is_being_sent_is_sent(server, tmp_path, monkeypatch):
    url, db = server
    laptop = _connected_laptop(url, tmp_path)
    folder = laptop.create_node("Ops")
    client = _client(laptop, url)
    real_request = client._request
    granted = []

    def grant_during_post(method, path, *args, **kwargs):
        if method == "POST" and path == "/api/sync" and not granted:
            granted.append(laptop.grant_folder_access(folder, _server_member(db), _member_pk()))
        return real_request(method, path, *args, **kwargs)

    monkeypatch.setattr(client, "_request", grant_during_post)
    client.push()
    monkeypatch.undo()

    _client(laptop, url).push()
    assert granted[0] in _server_ids(db, "envelope")
    laptop.lock()


def test_a_grant_an_older_version_lost_is_sent_after_the_update(server, tmp_path):
    url, db = server
    laptop = _connected_laptop(url, tmp_path)
    folder = laptop.create_node("Ops")
    assert _client(laptop, url).push()["conflicts"] == []
    envelope_id = laptop.grant_folder_access(folder, _server_member(db), _member_pk())
    dek_id = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
    foreign_envelope = new_ulid()
    laptop.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (foreign_envelope, dek_id, _server_member(db), _server_member(db), b"\x00" * 72),
    )
    # The state an older version left: folder marked clean, grant never sent,
    # no envelope push state at all (it is moved into the outbox on open).
    laptop.db.execute(
        "DELETE FROM outbox WHERE kind = 'write' AND object_id IN (SELECT id FROM nodes)"
    )
    laptop.db.execute("DELETE FROM outbox WHERE kind = 'envelope'")
    laptop.db.execute("CREATE TABLE envelope_sync_state (envelope_id TEXT PRIMARY KEY)")
    laptop.db.close()
    laptop.db.open()
    assert not laptop.db.fetchone(
        "SELECT 1 FROM sqlite_master WHERE name = 'envelope_sync_state'"
    )

    sent = [
        o["id"] for o in _client(laptop, url)._collect_dirty_objects()
        if o["object_type"] == "envelope"
    ]
    assert sent == [envelope_id]  # another admin's envelope came from the server
    assert _client(laptop, url).push()["conflicts"] == []
    assert envelope_id in _server_ids(db, "envelope")
    laptop.lock()


def test_envelopes_from_the_server_are_not_sent_back(server, tmp_path):
    url, db = server
    laptop = _connected_laptop(url, tmp_path)
    folder = laptop.create_node("Ops")
    envelope_id = laptop.grant_folder_access(folder, _server_member(db), _member_pk())
    assert _client(laptop, url).push()["conflicts"] == []
    assert envelope_id in _server_ids(db, "envelope")

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    assert phone.db.fetchone("SELECT 1 FROM access_envelopes WHERE id = ?", (envelope_id,))
    assert not [
        o for o in _client(phone, url)._collect_dirty_objects()
        if o["object_type"] == "envelope"
    ]
    laptop.lock()
    phone.lock()
