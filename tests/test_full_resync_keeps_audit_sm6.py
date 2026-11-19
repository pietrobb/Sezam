"""Stateful test finding SM6: a full resync dropped audit records the server lost.

The server was restored from a backup that did not hold an audit record the
phone had already sent. The full resync the phone was told to run kept only
the server's audit records: the lost one was gone for good, and a newer
record naming it as a parent (sent before the phone noticed the restore,
as the stateful test found) failed 'Audit DAG record ... references missing
parent(s)' on every later full resync and every new device. Audit records
are append-only: those the server lacks stay and the lost ones go out again.
"""

from __future__ import annotations

import copy

from sezam import cli
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_rollback_commit_token_sm7 import sees_rollback


def _folder(vault) -> str:
    return next(n["id"] for n in vault.list_nodes() if n["name"] == "F")


def test_full_resync_after_a_restore_keeps_audit_records_the_server_lost(server, tmp_path):  # noqa: F811
    url, db = server
    phone = _vault(tmp_path / "phone", "admin")
    phone.create_node("F")
    cli._server_connect_flow(url, phone, PASSWORD)
    client = _client(phone, url)
    backup = copy.deepcopy(db._storage)

    phone.create_entry(_folder(phone), "lost", [{"key": "password", "value": "1", "sensitive": True}])
    assert client.push()["accepted"]
    assert client.pull().get("rollback_warning") is None

    audit_before_restore = {row["id"] for row in phone.db.fetchall("SELECT id FROM audit_log")}
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    # Written and pushed before the phone pulled: its audit record names the
    # one the server lost as a parent.
    phone.create_entry(_folder(phone), "after", [{"key": "password", "value": "2", "sensitive": True}])
    try:
        client.push()
    except RuntimeError:
        pass  # the push itself may already see the restore
    assert sees_rollback(client)

    assert client.full_resync(confirmed=True)["full_resync"]
    client.push()

    laptop = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    assert laptop.db.get_meta("server_url") == url
    names = {e["name"] for e in laptop.list_entries(_folder(laptop))}
    assert names == {"lost", "after"}
    server_audit = {o["id"] for o in db._storage["vault_objects"] if o["object_type"] == "audit"}
    local_audit = {row["id"] for row in phone.db.fetchall("SELECT id FROM audit_log")}
    assert local_audit <= server_audit
    assert audit_before_restore <= local_audit, "audit records the server lost were dropped"
    phone.lock()
    laptop.lock()
