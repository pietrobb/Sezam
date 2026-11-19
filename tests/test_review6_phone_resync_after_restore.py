"""Review main@d615826 H6: the phone's full resync after a server restore.

The phone wrote a folder and two entries; the server was then restored from a
backup taken before them. The phone's full resync stopped on its own rollback
check ("ROLLBACK DETECTED"), and without that it deleted what the server had
lost. It now finishes, keeps the phone's lost objects and sends them again,
so desktop A sees them too.
"""

from __future__ import annotations

import copy

from sezam import cli
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_rollback_commit_token_sm7 import _restore

PHONE_TEST = "test/phone_full_resync_after_restore_test.dart"


def test_phone_full_resync_after_a_restore_keeps_and_resends_what_was_lost(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    backup: dict = {}

    def take_backup():
        backup.update(copy.deepcopy(db._storage))

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {
        "backup": take_backup,
        "restored": lambda: _restore(db, backup),
    }, PHONE_TEST)

    _client(laptop, url).pull()
    names = {e["name"] for n in laptop.list_nodes() for e in laptop.list_entries(n["id"])}
    assert {"db01", "kept", "deep"} <= names
    laptop.lock()
