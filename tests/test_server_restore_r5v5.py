"""Review d150605 #5: the server database restored from a nightly backup.

The rollback was reported once; after another device pushed the server head
past the old checkpoint, delta pulls skipped what the server committed again
under sequence numbers the laptop had already passed (pull failed on "Audit
DAG ... missing parent(s)" with no hint), and the full resync kept nothing:
an entry the server lost lived on only in a snapshot. The laptop now keeps
asking for a full resync after a rollback, and a full resync keeps (and sends
again) what the server confirmed above its GC floor and no longer has.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)


def _restore(db, backup) -> None:
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))


def _setup(url, db, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "old", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    backup = copy.deepcopy(db._storage)

    laptop.create_entry(folder, "db02", [{"key": "password", "value": "new", "sensitive": True}])
    client = _client(laptop, url)
    assert client.push()["conflicts"] == []
    client.pull()
    return laptop, folder, backup


def _phone_moves_the_head_on(url, tmp_path, laptop) -> None:
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_folder = next(n["id"] for n in phone.list_nodes() if n["name"] == "Servers")
    last = int(laptop.db.get_meta("last_known_commit_seq"))
    client = _client(phone, url)
    for i in range(last):
        phone.create_entry(phone_folder, f"p{i}", [{"key": "k", "value": "v"}])
        client.push()
        if client.pull()["max_commit_seq"] > last:
            break
    phone.lock()


def test_after_a_rollback_the_pull_keeps_asking_for_a_full_resync(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, _folder, backup = _setup(url, db, tmp_path)
    _restore(db, backup)

    client = _client(laptop, url)
    warning = client.pull().get("rollback_warning")
    assert warning and "--full-resync" in warning

    _phone_moves_the_head_on(url, tmp_path, laptop)
    with pytest.raises(RuntimeError, match="--full-resync"):
        client.pull()

    result = client.full_resync(confirmed=True)
    assert result["kept_local"] >= 1
    assert client.push()["conflicts"] == []
    assert client.pull().get("rollback_warning") is None
    laptop.lock()


def test_full_resync_keeps_what_the_restored_server_lost(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, _folder, backup = _setup(url, db, tmp_path)
    _restore(db, backup)
    # The laptop was off while the phone pushed past its checkpoint.
    _phone_moves_the_head_on(url, tmp_path, laptop)

    client = _client(laptop, url)
    result = client.full_resync(confirmed=True)
    assert result["kept_local"] == 1
    assert _entry_value(laptop, "Servers", "db02", "password") == "new"
    assert client.push()["conflicts"] == []
    laptop.lock()

    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    assert _entry_value(tablet, "Servers", "db02", "password") == "new"
    assert _entry_value(tablet, "Servers", "db01", "password") == "old"
    tablet.lock()
