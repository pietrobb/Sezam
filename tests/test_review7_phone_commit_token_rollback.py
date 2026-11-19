"""Review 7c10379 (mobile, medium): rollback detection by commit token.

The phone synced an entry; the server was then restored from a backup taken
before it, and desktop A pushed more than the phone had seen. The restored
server's head was not behind the phone's checkpoint, so the phone's delta pull
went on from it: it skipped A's commits that got the sequence numbers it had
passed, and its own entry was gone from the server for good. The phone now
sends the token of the commit at its checkpoint (as desktop SM7 and web
SM71); a server that handed that commit_seq out again asks for a full resync,
which keeps and resends the lost entry and reads all of A's.
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

PHONE_TEST = "test/phone_commit_token_rollback_test.dart"


def test_phone_detects_a_restored_server_pushed_past_its_checkpoint(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    backup: dict = {}

    def restored():
        _restore(db, backup)
        for i in range(6):  # one push each: past the phone's checkpoint
            laptop.create_entry(folder, f"a{i}", [{"key": "password", "value": f"v{i}", "sensitive": True}])
            _client(laptop, url).push()

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {
        "backup": lambda: backup.update(copy.deepcopy(db._storage)),
        "restored": restored,
    }, PHONE_TEST)

    _client(laptop, url).pull()
    names = {e["name"] for n in laptop.list_nodes() for e in laptop.list_entries(n["id"])}
    assert names == {"db01", "phone"} | {f"a{i}" for i in range(6)}
    laptop.lock()
