"""Review main@d615826 (mobile): the re-key and the keypair were not saved together.

Taking over a password change made on desktop A moved the phone's DEKs to the
new KEK and only then wrote the new keypair and salt to the Keychain. The
phone killed in between held keys no stored salt derives, and neither
password opened its records again. Now the next unlock finishes the change
and the new password opens everything.
"""

from __future__ import annotations

from sezam import cli
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _vault,
    server,
)

PHONE_TEST = "test/phone_adopt_killed_test.dart"


def test_take_over_killed_before_the_keychain_write_is_finished_on_unlock(server, tmp_path):  # noqa: F811
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
        laptop.create_entry(folder, "desk", [{"key": "password", "value": "after", "sensitive": True}])
        assert _client(laptop, url).push()["accepted"]

    _phone(url, tmp_path, {
        "username": "admin", "old_password": PASSWORD, "new_password": NEW_PASSWORD,
    }, {"changed": changed}, PHONE_TEST)
    laptop.lock()
