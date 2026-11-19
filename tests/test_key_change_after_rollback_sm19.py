"""Stateful test finding SM19: a key change built on a server that went back.

The phone took the laptop's password change over and pushed; then the server
was restored from a backup made before that push. The pull that
'sezam change-password' runs first saw the rollback but only warned, so the
change was built on folder-key versions the server had lost: the server
refused it with 409 'Atomic batch conflict' on every push, and the full
resync that would have helped is not allowed while a change is pending. The
key-change commands now stop at a rollback and name the full resync.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)

FIRST = "first-new-pw!"
SECOND = "second-new-pw!"


def test_key_change_after_a_server_restore_waits_for_the_full_resync(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)

    laptop.change_password(PASSWORD, FIRST)
    assert not _client(laptop, url).push()["conflicts"]
    backup = copy.deepcopy(db._storage)
    phone_client = _client(phone, url)
    with pytest.raises(KeyEpochStale):
        phone_client.pull()
    phone_client.adopt_rotated_key_material(phone, FIRST)
    phone.create_node("G")
    assert not phone_client.push()["conflicts"]
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))

    with pytest.raises(RuntimeError, match="full-resync"):
        phone_client.prepare_key_change()
    assert not phone_client.has_pending_key_change()

    # The way out it names: the full resync, then the change goes through.
    phone_client.full_resync(confirmed=True)
    phone_client.prepare_key_change()
    phone.change_password(FIRST, SECOND)
    phone_client = _client(phone, url)
    assert not phone_client.push()["conflicts"]
    assert not phone_client.has_pending_key_change()
    phone.lock()
    phone.unlock(SECOND)
    phone.lock()
    laptop.lock()
