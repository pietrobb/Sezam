"""Review main@d615826 (desktop): a full resync deleted every item's history.

Earlier versions of an entry live only on this device (entry_history is
never synced). 'sezam pull --full-resync' emptied the whole table, so one
resync after a server restore took every earlier password with it. Only the
history of an entry that is gone, or whose key is gone, goes now.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import trash
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)


def _password(fields) -> str:
    return next(f["value"] for f in fields if f["key"] == "password")


def test_full_resync_keeps_the_history_of_entries_it_keeps(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Ops")
    entry = laptop.create_entry(folder, "vpn", [{"key": "password", "value": "v1", "sensitive": True}])
    laptop.update_entry(entry, fields=[{"key": "password", "value": "v2", "sensitive": True}])
    laptop.update_entry(entry, fields=[{"key": "password", "value": "v3", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    before = trash.list_history(laptop, entry)
    assert len(before) == 2

    assert _client(laptop, url).full_resync(confirmed=True)["full_resync"]

    assert trash.list_history(laptop, entry) == before
    assert [_password(trash.read_history(laptop, entry, h["id"])) for h in before] == ["v2", "v1"]
    laptop.lock()
