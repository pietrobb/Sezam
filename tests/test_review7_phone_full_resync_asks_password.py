"""Review 7c10379 (mobile, medium): UI dead end at a lowered key_epoch.

The phone took desktop A's password change over; the server was then restored
from a backup taken before it. The app's full resync stopped on the restored
server's older key_epoch ("Full resync failed") and the next sync asked for
the full resync again, for good. It now asks for the password the server has,
takes it over and finishes; a new desktop joining with that password reads
the vault.
"""

from __future__ import annotations

import copy

from sezam import cli
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_rollback_commit_token_sm7 import _restore

PHONE_TEST = "test/phone_full_resync_asks_password_test.dart"


def test_phone_full_resync_asks_for_the_restored_servers_password(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    backup: dict = {}

    def changed():
        backup.update(copy.deepcopy(db._storage))
        proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(NEW_PASSWORD)
        _client(laptop, url).push()

    _phone(url, tmp_path, {
        "username": "admin", "old_password": PASSWORD, "new_password": NEW_PASSWORD,
    }, {"changed": changed, "restored": lambda: _restore(db, backup)}, PHONE_TEST)

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    passwords = {
        e["name"]: tablet.get_field_value(e["id"], "password")
        for n in tablet.list_nodes() for e in tablet.list_entries(n["id"])
    }
    assert passwords == {"db01": "s3cret"}
    tablet.lock()
    laptop.lock()
