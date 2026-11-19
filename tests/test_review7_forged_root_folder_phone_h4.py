"""Review 7c10379 H4, phone: folders a read-only member wrote below the root.

The member's folder sealed with the root's shared key and the item in it
(planted as the server before b8c3cb8 took them) are left out by the phone
after its first sync, a pull and a full resync; the admin's own item shows.
"""

from __future__ import annotations

from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    server,
)
from tests.test_review7_forged_root_folder_desktop_h4 import forged  # noqa: F401  (fixture)

PHONE_TEST = "test/phone_forged_root_folder_test.dart"


def test_phone_leaves_out_a_members_folder_sealed_with_the_shared_key(forged, tmp_path):  # noqa: F811
    url, laptop, _root, _folder, _items, _personal, _alice = forged
    servers = laptop.create_node("Servers")
    laptop.create_entry(servers, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    _client(laptop, url).push()
    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD}, {}, PHONE_TEST)
