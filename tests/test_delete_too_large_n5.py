"""Review d150605 N5: deleting an entry over the server's 1 MiB limit never synced.

The desktop keeps such an entry local (the server refuses it). Its tombstone
carried the same content, so the delete was refused the same way on every push:
the copy other devices still held from before the entry grew never went away.
The tombstone now goes with the name only; the content stays on this device.
"""

from __future__ import annotations

import os

from sezam.vault import crud, outbox, trash
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from sezam import cli


def test_deleting_an_entry_over_the_limit_reaches_other_devices(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Notes")
    entry = laptop.create_entry(folder, "big", [{"key": "note", "value": "small"}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert _entry_value(tablet, "Notes", "big", "note") == "small"

    # The note grew past the limit before saving checked it (review 526419e
    # #1); the vault was upgraded since. It stays on the laptop.
    big = os.urandom(700 * 1024).hex()
    with monkeypatch.context() as m:
        m.setattr(crud, "require_syncable_entry", lambda *_: None)
        laptop.update_entry(entry, fields=[{"key": "note", "value": big}])
    result = _client(laptop, url).push()
    assert [c["id"] for c in result["conflicts"]] == [entry]

    laptop.delete_entry(entry)
    assert _client(laptop, url).push()["conflicts"] == []
    assert not outbox.has_write(laptop._db, entry)

    _client(tablet, url).pull()
    assert _entry_value(tablet, "Notes", "big", "note") is None

    # Restored on the laptop, the content is all there.
    trash.restore_entry(laptop, entry)
    assert _entry_value(laptop, "Notes", "big", "note") == big
    laptop.lock()
    tablet.lock()
