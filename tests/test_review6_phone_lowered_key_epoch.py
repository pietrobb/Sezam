"""Review main@d615826 (mobile): a key_epoch lowered by a server restore.

Desktop A changed the password (key_epoch 1) and the phone took the change
over. The server was then restored from a backup taken before it: key_epoch 0
and the old password's key material. Every pull of the phone stopped on
"Invalid or rolled-back key_epoch", for good. It now asks for the password the
server has (as for a change made elsewhere), takes the older epoch over and
sends the edit it made offline; a new desktop joining with that password
reads it.
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

PHONE_TEST = "test/phone_lowered_key_epoch_test.dart"


def test_phone_takes_over_the_older_key_epoch_of_a_restored_server(server, tmp_path):  # noqa: F811
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
    assert passwords == {"db01": "s3cret", "offline": "o1"}
    tablet.lock()
    laptop.lock()
