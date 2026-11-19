"""Stateful test finding SM9: a password change the restored server can never take.

The laptop changed the password and the server took it; then the server was
restored from a backup made before. The laptop's next password change proves
the password it last sent, which the server no longer has, so the push was
refused with 403 'Wrong current account password' on every sync, and the
refusal named no way out. It now names 'sezam abandon-pending-change', which
takes over the server's key material with the password it has now.
"""

from __future__ import annotations

import copy

import pytest

from sezam import cli
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)

FIRST = "first-new-pw!"
SECOND = "second-new-pw!"


def _change(vault, url, old: str, new: str) -> dict:
    vault.change_password(old, new)
    return _client(vault, url).push()


def test_change_refused_by_restored_server_names_the_way_out(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    backup = copy.deepcopy(db._storage)
    _change(laptop, url, PASSWORD, FIRST)
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))

    laptop.change_password(FIRST, SECOND)
    client = _client(laptop, url)
    with pytest.raises(RuntimeError, match="403.*abandon-pending-change"):
        client.push()

    # The way out works with the password the server has now.
    client.abandon_pending_change(laptop, PASSWORD)
    assert not client.has_pending_key_change()
    client.pull()
    laptop.lock()
    laptop.unlock(PASSWORD)
    # And a new change goes out normally.
    assert not _change(laptop, url, PASSWORD, SECOND)["conflicts"]
    assert not _client(laptop, url).has_pending_key_change()
    laptop.lock()
