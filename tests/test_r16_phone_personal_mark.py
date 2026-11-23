"""Review 18c300f R16-H2, phone: a member's top-level folder sealed with a key
this account shares, whose sealed meta says ``personal``, is no personal
folder of this account.

Alice (a member) pushes a top-level folder sealed with the admin's shared
root key that says ``personal: true``. On 18c300f the admin's phone took the
mark as it came and listed the folder as its own personal folder; what the
admin saved there was sealed with a key every member holds.
"""

from __future__ import annotations

from sezam import cli
from sezam.crypto.aead import BlobKind, encrypt
from sezam.models import NodeMeta, new_ulid, ulid_to_bytes
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)
import server.app.routers.sync as server_sync
from tests.test_review7_forged_root_folder_desktop_h4 import _always, _login, _push
from tests.test_server_spec import _create_regular_user

PHONE_TEST = "test/r16_phone_personal_mark_test.dart"


def test_phone_takes_no_members_folder_for_its_personal_folder(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    root = laptop.db.get_meta("root_node_id")
    root_key = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (root,))["dek_id"]
    forged = new_ulid()
    payload = encrypt(
        plaintext=NodeMeta(name="Osobne", personal=True).to_json(),
        dek=laptop.dek_mgr.unlock_dek(root_key),
        dek_id=ulid_to_bytes(root_key),
        object_id=ulid_to_bytes(forged),
        version=1,
        blob_kind=BlobKind.NODE_META,
    )
    laptop.lock()

    alice = new_ulid()
    sk, _ = _create_regular_user(db._storage, alice, "alice")
    # A lying server takes it (the server takes a top-level folder only sealed with its author's own key).
    monkeypatch.setattr(server_sync, "_sealed_with_own_dek", _always)
    _push(url, _login(url, sk, "alice"), sk, forged, "node", None, payload)
    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD, "forged": forged}, {}, PHONE_TEST)
