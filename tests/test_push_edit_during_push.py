"""Review 526419e #2: an edit made while a push was out was marked pushed and lost.

After the server accepted an object the client ran
``UPDATE … SET is_dirty = 0 WHERE id = ?`` without checking which version it
had sent. The GUI saving v3 while 'sezam push' (or a background sync) sent
v2 left v3 locally marked sent, v2 on the server, and the next change
from another device overwrote v3 for good.
"""

from __future__ import annotations

from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from sezam import cli
from sezam.vault import outbox


def _edit_while_push_is_out(client, edit):
    real_request = client._request
    done = []

    def request(method, path, *args, **kwargs):
        if method == "POST" and path == "/api/sync" and not done:
            done.append(True)
            edit()
        return real_request(method, path, *args, **kwargs)

    client._request = request


def _server_version(db, obj_id: str) -> int:
    return next(o for o in db._storage["vault_objects"] if o["id"] == obj_id)["version"]


def test_an_entry_edited_during_the_push_stays_dirty_and_goes_out_next(server, tmp_path):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    entry_id = laptop.create_entry(folder, "db01", [{"key": "password", "value": "v1"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.update_entry(entry_id, fields=[{"key": "password", "value": "v2"}])

    client = _client(laptop, url)
    _edit_while_push_is_out(
        client,
        lambda: laptop.update_entry(entry_id, fields=[{"key": "password", "value": "v3"}]),
    )
    client.push()
    assert _server_version(db, entry_id) == 2
    row = laptop.db.fetchone("SELECT version FROM entries WHERE id = ?", (entry_id,))
    assert (row["version"], outbox.has_write(laptop.db, entry_id)) == (3, True)

    _client(laptop, url).push()
    assert _server_version(db, entry_id) == 3
    assert not laptop.db.fetchone("SELECT id FROM entries WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')")
    laptop.lock()


def test_a_folder_renamed_during_the_push_stays_dirty(server, tmp_path):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Old")
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.rename_node(folder, "Middle")

    client = _client(laptop, url)
    _edit_while_push_is_out(client, lambda: laptop.rename_node(folder, "New"))
    client.push()
    row = laptop.db.fetchone("SELECT version FROM nodes WHERE id = ?", (folder,))
    assert outbox.has_write(laptop.db, folder)
    assert _server_version(db, folder) == row["version"] - 1

    _client(laptop, url).push()
    assert _server_version(db, folder) == row["version"]
    laptop.lock()
