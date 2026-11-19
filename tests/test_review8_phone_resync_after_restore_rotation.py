"""Review a159e97 (mobile, medium): full resync after a restore and a rotation.

The phone wrote an entry; the server was restored from a backup taken before
it, and desktop A then rotated the account's identity keys. The phone took the
rotation over and ran a full resync. It kept only rows signed with the current
key (DEKs also by their wrap), so the entry, signed with the previous key,
was deleted. It is now kept, sent again, and desktop A reads it.
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

PHONE_TEST = "test/phone_resync_after_restore_rotation_test.dart"


def test_phone_resync_after_a_restore_and_a_rotation_keeps_its_entry(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    old_pk = laptop.keypair.signing_pk
    backup: dict = {}

    def take_backup():
        backup.update(copy.deepcopy(db._storage))

    def restored_and_rotated():
        _restore(db, backup)
        _client(laptop, url).prepare_key_change()
        proof = laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(PASSWORD)
        _client(laptop, url).push()
        assert laptop.keypair.signing_pk != old_pk

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {
        "backup": take_backup,
        "restored_and_rotated": restored_and_rotated,
    }, PHONE_TEST)

    _client(laptop, url).pull()
    names = {e["name"] for n in laptop.list_nodes() for e in laptop.list_entries(n["id"])}
    assert {"db01", "kept"} <= names
    laptop.lock()
