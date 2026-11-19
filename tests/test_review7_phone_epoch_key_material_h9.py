"""Review 7c10379 H9 (mobile): a newer key_epoch taken over without its key material.

The phone signed in with the password, stayed unlocked, and desktop A changed
the password. The sign-in again on the 401 took the new epoch over with the
old KEK, and the phone pushed the key of a new personal folder wrapped under
it: no other device of the account could open it. The phone now asks for the
password the server has first, and A opens the key the phone pushed.
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

PHONE_TEST = "test/phone_epoch_needs_key_material_test.dart"


def test_phone_takes_a_newer_epoch_over_only_with_its_key_material(server, tmp_path):  # noqa: F811
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

    _client(laptop, url).pull()
    # The phone's new personal key opens with the account's KEK here.
    personal = [r["id"] for r in laptop._db.fetchall("SELECT id FROM deks WHERE scope = 'personal'")]
    assert len(personal) == 1, personal
    laptop.dek_mgr.unlock_dek(personal[0])
    laptop.lock()
