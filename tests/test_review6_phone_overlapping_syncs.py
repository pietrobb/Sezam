"""Review main@d615826 (mobile): SyncService had no lock.

Overlapping syncs of the phone (after unlock, pull-to-refresh, after a change)
ran their pushes and pulls interleaved on one checkpoint. They now run one
after the other and end without conflicts; desktop A then reads every change
of the phone.
"""

from __future__ import annotations

from sezam import cli
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)

PHONE_TEST = "test/phone_overlapping_syncs_test.dart"


def test_overlapping_phone_syncs_end_without_conflicts(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {}, PHONE_TEST)

    _client(laptop, url).pull()
    passwords = {
        e["name"]: laptop.get_field_value(e["id"], "password")
        for n in laptop.list_nodes() for e in laptop.list_entries(n["id"])
    }
    assert passwords == {"db01": "r1", "phone": "p1"}
    laptop.lock()
