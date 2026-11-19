"""Review 7c10379 (mobile, medium): QR provisioning onto a local vault.

A phone that kept entries offline in its own vault was provisioned by QR into
an existing account. It re-wrapped its DEKs in place and kept its own root, so
its push gave the account a second root. It now joins like a password connect:
the account keeps one root and desktop A reads the phone's entry in it.
"""

from __future__ import annotations

from sezam.vault.sync_client import SyncClient
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from sezam import cli

PHONE_TEST = "test/phone_qr_provision_local_vault_test.dart"


def _entry_values(vault) -> dict:
    return {
        e["name"]: vault.get_field_value(e["id"], "password")
        for n in vault.list_nodes() for e in vault.list_entries(n["id"])
    }


def test_qr_provisioning_moves_a_local_vault_into_the_account(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    def token():
        client = SyncClient(laptop.db, url, laptop.keypair, user_id)
        client.authenticate()
        issued = client.create_provisioning_token()
        (tmp_path / "phone" / "token.txt").write_text(issued["token"], encoding="utf-8")

    _phone(url, tmp_path, {"username": "admin", "password": PASSWORD},
           {"token": token}, PHONE_TEST)

    assert [u["id"] for u in db._storage["users"]] == [user_id]
    roots = [
        o["id"] for o in db._storage["vault_objects"]
        if o["object_type"] == "node" and o.get("parent_ref") is None and not o.get("is_deleted")
    ]
    assert len(roots) == 1, roots
    _client(laptop, url).pull()
    assert _entry_values(laptop) == {"db01": "s3cret", "offline": "o1"}
    laptop.lock()
