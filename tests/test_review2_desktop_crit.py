"""Regressions for follow-up review main@2052248, desktop critical items 2-4."""

from __future__ import annotations

import os
import sys

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.crypto.keys import generate_keypair
from sezam.models import new_ulid
from sezam.vault.db import VaultDB
from sezam.vault.dek import DEKManager
from sezam.vault.sync_client import SyncClient
from sezam.vault.crud import Vault

FAST = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
PASSWORD = "TestHeslo123!"


def _db(tmp_path, name="r2.db"):
    db = VaultDB(tmp_path / name)
    db.open()
    db.create_schema()
    return db


def _wrap(db, dek_id):
    row = db.fetchone("SELECT encrypted_dek, version FROM deks WHERE id = ?", (dek_id,))
    return bytes(row["encrypted_dek"]), row["version"]


# ── 2: own DEKs must never be marked foreign by a stale server wrap ──


def test_stale_server_wrap_after_local_password_change_keeps_dek_owned(tmp_path):
    db = _db(tmp_path)
    try:
        manager = DEKManager(db, bytearray(os.urandom(32)))
        dek_id, _ = manager.create_dek("root")
        stale_payload, stale_version = _wrap(db, dek_id)

        # Local password change, not pushed yet: v2 under the new KEK.
        manager.rewrap_all_deks(bytearray(os.urandom(32)))
        client = SyncClient(db, "https://example.invalid", generate_keypair(), new_ulid())
        client.set_dek_manager(manager)

        # Pull still returns the server's v1 wrap under the old KEK.
        client._apply_dek(dek_id, None, stale_payload, stale_version, {})

        assert dek_id not in (db.get_meta_json("foreign_dek_ids") or [])
        assert _wrap(db, dek_id)[1] == 2

        # The next password change must still re-wrap it.
        newest = bytearray(os.urandom(32))
        manager.rewrap_all_deks(newest)
        assert _wrap(db, dek_id)[1] == 3
        DEKManager(db, bytearray(newest)).unlock_dek(dek_id)
    finally:
        db.close()


def test_rewrap_decides_ownership_by_unwrapping_not_by_the_list(tmp_path):
    db = _db(tmp_path)
    try:
        manager = DEKManager(db, bytearray(os.urandom(32)))
        own_id, _ = manager.create_dek("folder", None)
        other_kek = bytearray(os.urandom(32))
        foreign_id, _ = DEKManager(db, other_kek).create_dek("folder", None)
        # Corrupted metadata from an older client: our DEK listed as foreign.
        db.set_meta_json("foreign_dek_ids", sorted([own_id, foreign_id]))
        foreign_wrap = _wrap(db, foreign_id)

        new_kek = bytearray(os.urandom(32))
        manager.rewrap_all_deks(new_kek)

        fresh = DEKManager(db, bytearray(new_kek))
        fresh.unlock_dek(own_id)
        assert _wrap(db, foreign_id) == foreign_wrap
        assert db.get_meta_json("foreign_dek_ids") == [foreign_id]
    finally:
        db.close()


# ── 4: the GUI connect flow checks the typed password before the server ──


@pytest.fixture
def qapp():
    QApplication = pytest.importorskip("PySide6.QtWidgets").QApplication
    return QApplication.instance() or QApplication(sys.argv)


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path, PASSWORD, FAST)
    yield v
    if v.is_unlocked:
        v.lock()


def test_verify_password_is_side_effect_free(vault):
    assert vault.verify_password(PASSWORD)
    assert not vault.verify_password(PASSWORD + "x")
    assert vault.is_unlocked
    assert vault.list_nodes() == []


def test_gui_connect_with_mistyped_password_never_reaches_the_server(qapp, vault, monkeypatch):
    from sezam.gui import server_connect_dialog as scd

    requests = []
    monkeypatch.setattr(scd, "_http_request", lambda *a, **k: requests.append(a) or {})
    worker = scd.ServerConnectWorker("https://sezam.invalid", vault, PASSWORD + "typo")
    errors, done = [], []
    worker.finished_error.connect(errors.append)
    worker.finished_ok.connect(done.append)

    worker.run()

    assert requests == []
    assert done == []
    assert errors and "heslo" in errors[0].lower()
    assert vault.db.get_meta("server_url") in (None, "")
