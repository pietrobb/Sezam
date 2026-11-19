"""Lockout review M6: a reseed from an out-of-date device must not erase newer data.

After the server lost its database, `sezam server reseed` from a laptop that
had missed the phone's later changes rebuilt the server with the laptop's
older state. The phone's documented way back, `sezam pull --full-resync`,
replaced its local vault with that state: its newer edit, a new entry, a new
folder and a delete were gone. A full resync against a server that is behind
the device (lower commit_seq, or an older version of an object the device had
synced) now keeps what the device has newer and pushes it.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault.reseed import reseed_server
from tests.test_ai_r3_reseed import NEW_PASSWORD, _seeded_laptop, _wipe
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    _client,
    _entry_value,
    _vault,
    server,
)

PW = [{"key": "password", "value": "", "sensitive": True}]


def _pw(value: str) -> list[dict]:
    return [{**PW[0], "value": value}]


def _entry_id(vault, folder: str, title: str) -> str:
    node = next(n for n in vault.list_nodes() if n["name"] == folder)
    return next(e["id"] for e in vault.list_entries(node["id"]) if e["name"] == title)


def _phone_ahead_of_reseeded_server(url, db, tmp_path):
    laptop = _seeded_laptop(url, db, tmp_path)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    servers = next(n["id"] for n in phone.list_nodes() if n["name"] == "Servers")
    phone.update_entry(_entry_id(phone, "Servers", "db01"), fields=_pw("rotated-on-phone"))
    phone.create_entry(servers, "phone-only", _pw("p1"))
    phone.delete_entry(_entry_id(phone, "Servers", "web"))
    vpn = phone.create_node("VPN")
    phone.create_entry(vpn, "office", _pw("v1"))
    assert _client(phone, url).push()["conflicts"] == []

    # The laptop never pulled those changes; the server is lost and the
    # laptop rebuilds it from its own, older copy.
    _wipe(db)
    assert reseed_server(laptop, url, NEW_PASSWORD)["conflicts"] == []
    return laptop, phone


def test_full_resync_keeps_and_pushes_what_the_device_has_newer(server, tmp_path):
    url, db = server
    laptop, phone = _phone_ahead_of_reseeded_server(url, db, tmp_path)

    phone_client = _client(phone, url)
    assert phone_client.pull().get("rollback_warning")
    result = phone_client.full_resync(confirmed=True)

    assert _entry_value(phone, "Servers", "db01", "password") == "rotated-on-phone"
    assert _entry_value(phone, "Servers", "phone-only", "password") == "p1"
    assert _entry_value(phone, "VPN", "office", "password") == "v1"
    assert _entry_value(phone, "Servers", "web", "password") is None
    assert result["kept_local"] >= 4

    assert _client(phone, url).push()["conflicts"] == []
    laptop_client = _client(laptop, url)
    laptop_client.pull()
    assert _entry_value(laptop, "Servers", "db01", "password") == "rotated-on-phone"
    assert _entry_value(laptop, "Servers", "phone-only", "password") == "p1"
    assert _entry_value(laptop, "VPN", "office", "password") == "v1"
    assert _entry_value(laptop, "Servers", "web", "password") is None
    laptop.lock()
    phone.lock()


def test_full_resync_against_a_server_ahead_still_follows_the_server(server, tmp_path):
    """Tombstone GC: an object the server dropped was deleted elsewhere."""
    from tests.test_integration_client_server import _gc_tombstones

    url, db = server
    laptop = _seeded_laptop(url, db, tmp_path)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW_PASSWORD)
    web = _entry_id(laptop, "Servers", "web")
    laptop.delete_entry(web)
    assert _client(laptop, url).push()["conflicts"] == []
    _gc_tombstones(db)

    result = _client(phone, url).full_resync(confirmed=True)

    assert _entry_value(phone, "Servers", "web", "password") is None
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    assert result["kept_local"] == 0
    pushed = _client(phone, url).push()["accepted"]
    assert web not in {obj["id"] for obj in pushed}
    laptop.lock()
    phone.lock()
