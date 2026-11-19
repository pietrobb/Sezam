"""Stateful test finding SM7: a server restore went unnoticed once pushes moved on.

A device noticed a server restored from a backup only when the server head
was below its checkpoint. When another device (or the device itself) pushed
first, the restored server handed the lost commit_seq numbers out again and
the head reached the checkpoint: the pull answered 304 or skipped what was
committed under the reused numbers, and what the server lost was never sent
again. Every push transaction now has a server token. The device keeps the
token of its checkpoint, and a different token is a rollback.
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


def _folder(vault) -> str:
    return next(n["id"] for n in vault.list_nodes() if n["name"] == "F")


def _add(vault, name: str) -> None:
    vault.create_entry(_folder(vault), name, [{"key": "password", "value": name, "sensitive": True}])


def _names(vault) -> set[str]:
    return {e["name"] for e in vault.list_entries(_folder(vault))}


def _restore(db, backup) -> None:
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))


def sees_rollback(client) -> bool:
    """The device asks for a full resync: now, or remembered from its push."""
    try:
        return bool(client.pull().get("rollback_warning"))
    except RuntimeError as exc:
        return "--full-resync" in str(exc)


def _two_devices(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    return laptop, phone


def test_restore_is_seen_after_another_device_pushed_past_the_checkpoint(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    tablet = _vault(tmp_path / "tablet", "admin")
    cli._server_connect_flow(url, tablet, PASSWORD)
    backup = copy.deepcopy(db._storage)
    _add(laptop, "lost")
    laptop_client = _client(laptop, url)
    assert laptop_client.push()["accepted"]
    phone_client = _client(phone, url)
    phone_client.pull()
    assert "lost" in _names(phone)

    _restore(db, backup)
    # The tablet saw nothing the restore took: its pushes land.
    for name in ("a", "b", "c", "d", "e", "f"):
        _add(tablet, name)
        assert _client(tablet, url).push()["accepted"]

    assert sees_rollback(phone_client)
    assert phone_client.full_resync(confirmed=True)["full_resync"]
    phone_client.push()
    # The laptop's own push was lost: it may not build on it.
    _add(laptop, "x")
    refused = laptop_client.push()
    assert refused.get("rollback_warning") and not refused["accepted"]
    assert laptop_client.full_resync(confirmed=True)["full_resync"]
    laptop_client.push()

    newcomer = _vault(tmp_path / "newcomer", "admin")
    cli._server_connect_flow(url, newcomer, PASSWORD)
    assert _names(newcomer) == {"lost", "x", "a", "b", "c", "d", "e", "f"}
    for vault in (laptop, phone, tablet, newcomer):
        vault.lock()


def test_restore_is_seen_when_the_head_comes_back_to_the_checkpoint(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    client = _client(phone, url)
    backup = copy.deepcopy(db._storage)
    _add(phone, "lost")
    assert client.push()["accepted"]
    client.pull()

    checkpoint = int(phone.db.get_meta("last_known_commit_seq"))

    _restore(db, backup)
    count = 0
    while db._storage["commit_counter"][0]["next_seq"] - 1 < checkpoint:
        count += 1
        _add(laptop, f"after{count}")
        assert _client(laptop, url).push()["accepted"]

    assert sees_rollback(client)
    laptop.lock()
    phone.lock()


def test_a_push_the_restore_dropped_is_seen_and_sent_again(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client = _client(laptop, url)
    backup = copy.deepcopy(db._storage)
    _add(laptop, "lost")
    assert laptop_client.push()["accepted"]  # never pulled after this

    _restore(db, backup)
    phone_client = _client(phone, url)
    for name in ("a", "b", "c", "d", "e", "f"):
        _add(phone, name)
        phone_client.push()
    _add(laptop, "x")
    laptop_client.push()

    assert sees_rollback(laptop_client)
    assert laptop_client.full_resync(confirmed=True)["full_resync"]
    laptop_client.push()
    newcomer = _vault(tmp_path / "newcomer", "admin")
    cli._server_connect_flow(url, newcomer, PASSWORD)
    assert _names(newcomer) == {"lost", "x", "a", "b", "c", "d", "e", "f"}
    for vault in (laptop, phone, newcomer):
        vault.lock()


def test_a_healthy_server_never_reads_as_a_rollback(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, phone = _two_devices(url, tmp_path)
    phone_client = _client(phone, url)
    for name in ("a", "b", "c"):
        _add(laptop, name)
        _client(laptop, url).push()
        assert phone_client.pull().get("rollback_warning") is None
        assert phone_client.pull().get("rollback_warning") is None
    assert _names(phone) == {"a", "b", "c"}
    laptop.lock()
    phone.lock()
