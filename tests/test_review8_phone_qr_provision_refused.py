"""Review a159e97 (mobile, medium): a refused QR provisioning kept the session.

The phone signed in to the scanned account before it checked its own vault;
a refusal after that (here: the phone's own vault is locked) left the phone
signed in to that account. The previous session now comes back.
"""

from __future__ import annotations

from sezam.vault.sync_client import SyncClient
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)
from sezam import cli

PHONE_TEST = "test/phone_qr_provision_refused_test.dart"


def test_refused_qr_provisioning_signs_the_phone_out(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    def token():
        client = SyncClient(laptop.db, url, laptop.keypair, user_id)
        client.authenticate()
        issued = client.create_provisioning_token()
        (tmp_path / "phone" / "token.txt").write_text(issued["token"], encoding="utf-8")

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD},
           {"token": token}, PHONE_TEST)
    laptop.lock()
