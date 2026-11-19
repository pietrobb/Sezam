"""Review d150605 #3: a key epoch advance over 1000 DEKs.

Every tier-2 entry has its own DEK, each re-key adds one and none is ever
deleted. A password change, an identity rotation and a Shamir recovery must
send every DEK in one all-or-nothing push, and the server takes 1000 objects
per request: past that, change_password and rotate_identity were refused up
front, and org_recovery went through locally and then failed every push for
good (the way back needed the forgotten password). The batch is now staged
in parts and the last part applies all of it at once.
"""

from __future__ import annotations

import pytest

from sezam.vault import pending_states
from sezam import cli
from sezam.vault import sync_limits
from sezam.vault.crud import Vault
from sezam.vault.sync_limits import SyncUnitTooLarge
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)

NEW = "a-new-password-1!"
DEKS = 1010


def _laptop_with_many_deks(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    for _ in range(DEKS):
        laptop.dek_mgr.create_dek("tier2", folder)
    cli._server_connect_flow(url, laptop, PASSWORD)
    assert len(laptop.db.fetchall("SELECT id FROM deks")) > 1000
    return laptop


def _assert_epoch_landed(db, vault) -> None:
    assert vault.db.get_meta("last_pushed_key_epoch") == vault.db.get_meta("key_epoch")
    assert not db._storage.get("sync_staged_objects")


def test_password_change_with_over_1000_deks(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _laptop_with_many_deks(url, tmp_path)
    laptop.change_password(PASSWORD, NEW)
    laptop.unlock(NEW)
    assert _client(laptop, url).push()["conflicts"] == []
    _assert_epoch_landed(db, laptop)
    laptop.lock()

    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, NEW)
    assert _entry_value(phone, "Servers", "db01", "password") == "s3cret"
    phone.lock()


def test_shamir_recovery_with_over_1000_deks(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _laptop_with_many_deks(url, tmp_path)
    shares = laptop.setup_org_recovery(threshold=2, shares=3)
    _client(laptop, url).store_org_recovery(
        pending_states.org_recovery_registration(laptop.db), laptop.current_auth_proof(PASSWORD)
    )
    laptop.lock()

    recovered = Vault(tmp_path / "laptop")
    recovered.org_recovery(shares[:2], NEW)
    recovered.lock()
    recovered.unlock(NEW)
    try:
        assert _client(recovered, url).push()["conflicts"] == []
        _assert_epoch_landed(db, recovered)
        assert _entry_value(recovered, "Servers", "db01", "password") == "s3cret"
    finally:
        recovered.lock()


def test_shamir_recovery_over_the_unit_limit_is_refused_up_front(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("A")
    cli._server_connect_flow(url, laptop, PASSWORD)
    shares = laptop.setup_org_recovery(threshold=2, shares=3)
    laptop.lock()

    monkeypatch.setattr(sync_limits, "MAX_STAGED_OBJECTS", 1)
    recovered = Vault(tmp_path / "laptop")
    with pytest.raises(SyncUnitTooLarge, match="Shamir recovery"):
        recovered.org_recovery(shares[:2], NEW)
    recovered.lock()
    recovered.unlock(PASSWORD)  # nothing changed: the old password still opens it
    recovered.lock()
