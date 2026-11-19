"""Review 1141a20 (R9-G), phone: a failed QR provisioning and the scanned server.

The phone, signed in to its own server, scans a QR of another server. The
provisioning fails before the sign-in (the scanned server refuses the token
or answers garbage). The phone stayed pointed at the scanned server with the
session of its own one, so its next sync sent that JWT there. Now nothing
but the provisioning request reaches the scanned server, and the phone keeps
syncing with its own.
"""

from __future__ import annotations

from sezam import cli
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)

PHONE_TEST = "test/phone_qr_foreign_server_test.dart"


def test_a_failed_qr_provisioning_sends_no_session_to_the_scanned_server(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.lock()
    out = _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {}, PHONE_TEST)
    assert "All tests passed!" in out, out
