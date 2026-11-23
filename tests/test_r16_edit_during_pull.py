"""Review 18c300f R16-M1 (= R12-H1): an edit racing a pull got stuck silently.

update_entry read the entry (its content and version) and wrote the new
version later, in a separate transaction. A pull of the desktop app that
applied the other device's version in between was overwritten by an edit
built on the version before it, numbered like the server's: no conflict was
shown and the edit never reached the server.

The read and the write are one transaction under the vault lock now: a pull
waits for the edit (and then meets a queued write: a conflict the user sees),
or ran before it (and the edit is built on what it brought).
"""

from __future__ import annotations

import threading

from sezam import cli
from sezam.vault.crud import Vault
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)


def test_an_edit_racing_a_pull_reaches_the_server_or_shows_a_conflict(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    entry = laptop.create_entry(folder, "db", [{"key": "password", "value": "v1"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    phone.update_entry(entry, fields=[{"key": "password", "value": "v2"}])
    assert _client(phone, url).push()["conflicts"] == []

    app = Vault(tmp_path / "laptop")  # the desktop app on the same vault file
    app.unlock(PASSWORD)
    app_client = _client(app, url)
    snapshot = laptop._create_history_snapshot
    pulls: list[threading.Thread] = []

    def the_app_pulls_meanwhile(entry_id):
        snapshot(entry_id)
        if not pulls:
            pulls.append(threading.Thread(target=app_client.pull))
            pulls[0].start()
            pulls[0].join(3)  # it runs now, or waits for the edit

    laptop._create_history_snapshot = the_app_pulls_meanwhile
    laptop.update_entry(entry, name="db-renamed")
    pulls[0].join(60)
    assert not pulls[0].is_alive()

    # the laptop syncs as usual: push, pull, push
    _client(laptop, url).push()
    _client(laptop, url).pull()
    _client(laptop, url).push()
    shown = laptop._db.fetchall("SELECT 1 FROM sync_conflicts WHERE object_id = ?", (entry,))
    _client(phone, url).pull()
    on_server = phone.read_entry(entry)["name"] == "db-renamed"
    assert on_server or shown, "the edit neither reached the server nor showed a conflict"
    app.lock()
    laptop.lock()
    phone.lock()
