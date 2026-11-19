"""Review 7c10379 H9 (mobile): a full resync after a restore kept a folder without its key.

The phone took desktop A's password change over and made a personal folder
with its own key; the server confirmed both. The server was then restored from
a backup taken before the change. Taking the older password over re-wrapped
the key but left its old signature, so the full resync no longer counted the
key as the phone's own and dropped it, while it kept the folder and sent it
back: nobody could read it. The key is kept now, the phone reads the folder,
and a new desktop joining with that password opens its key.
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

PHONE_TEST = "test/phone_resync_keeps_rekeyed_key_test.dart"


def test_phone_resync_after_restore_keeps_the_key_of_a_kept_folder(server, tmp_path):  # noqa: F811
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
    # The folder's key went back to the server and opens with the password.
    # (The desktop does not list a phone's personal folder yet: idea #28.)
    personal = [r["id"] for r in tablet._db.fetchall("SELECT id FROM deks WHERE scope = 'personal'")]
    assert len(personal) == 1, personal
    tablet.dek_mgr.unlock_dek(personal[0])
    tablet.lock()
    laptop.lock()
