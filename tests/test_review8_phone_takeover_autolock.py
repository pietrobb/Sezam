"""Review a159e97 (mobile): an auto-lock during a password take-over was undone.

The phone's take-over of a password change made on desktop A waits on the
network and then unlocks the vault with the new KEK; lock() did not stop it,
so a vault the app had just auto-locked stood open again. Runs
mobile/test/phone_takeover_autolock_test.dart against a real server.
"""

from __future__ import annotations

from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _vault,
    server,
)
from sezam import cli

PHONE_TEST = "test/phone_takeover_autolock_test.dart"


def test_an_auto_lock_during_a_take_over_keeps_the_phone_locked(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)

    def changed():
        proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(NEW_PASSWORD)
        _client(laptop, url).push()

    _phone(url, tmp_path, {
        "username": "admin", "old_password": PASSWORD, "new_password": NEW_PASSWORD,
    }, {"changed": changed}, PHONE_TEST)
    laptop.lock()
