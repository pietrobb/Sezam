"""Review d150605 N8: two pulls of one vault at once reported a server rollback.

The desktop app and a CLI command (or the MCP server) pull the same vault.
One fetched a delta, the other pulled further and saved its checkpoint, and the
first then checked its older batch against that newer checkpoint: "Sync
rollback detected", and its batch was thrown away. The server never went back.
"""

from __future__ import annotations

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)


def test_a_pull_racing_another_pull_is_no_rollback(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("F")
    entry = laptop.create_entry(folder, "db", [{"key": "password", "value": "v1"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    phone_folder = next(n["id"] for n in phone.list_nodes() if n["name"] == "F")
    phone_entry = next(e["id"] for e in phone.list_entries(phone_folder))
    assert phone_entry == entry
    phone.update_entry(entry, fields=[{"key": "password", "value": "v2"}])
    assert _client(phone, url).push()["conflicts"] == []

    command = _client(laptop, url)
    fetch = command._fetch_pull_pages
    raced = []

    def fetch_then_the_app_pulls(*args, **kwargs):
        resp = fetch(*args, **kwargs)
        if not raced:
            raced.append(True)
            phone.update_entry(entry, fields=[{"key": "password", "value": "v3"}])
            assert _client(phone, url).push()["conflicts"] == []
            _client(laptop, url).pull()  # the desktop app, meanwhile
        return resp

    command._fetch_pull_pages = fetch_then_the_app_pulls
    result = command.pull()
    assert raced
    assert "rollback_warning" not in result
    assert _entry_value(laptop, "F", "db", "password") == "v3"
    laptop.lock()
    phone.lock()
