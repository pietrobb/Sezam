"""Stateful test finding SM65: an org recovery on a restored server names the full resync.

The server was restored from a backup that predates the laptop's last push,
and the phone then added a folder (a folder key the laptop never saw). The
laptop's password was reset with an org recovery; its change misses that
folder key, and the pull meant to bring it saw the restore and applied
nothing. The refusal then named 'sezam abandon-pending-change', which needs
the password the user forgot, so the laptop had no way out. It now asks for
the full resync, which brings the folder key into the change.
"""

from __future__ import annotations

import copy

import pytest

from sezam.vault import org_recovery_server
from tests.test_integration_client_server import PASSWORD, _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _add, _restore, _two_devices

RECOVERED = "laptop-rec-sm65!"


def test_org_recovery_on_a_restored_server_asks_for_the_full_resync(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    laptop_client, phone_client = _client(laptop, url), _client(phone, url)
    shares = org_recovery_server.setup_and_register(laptop, PASSWORD, 2, 3).shares
    laptop_client.push()
    phone_client.pull()
    backup = copy.deepcopy(db._storage)
    _add(laptop, "lost")
    laptop_client.push()

    _restore(db, backup)
    phone.create_node("G")
    assert phone_client.push()["accepted"]

    laptop.lock()
    laptop.org_recovery(shares[:2], RECOVERED)
    laptop_client = _client(laptop, url)
    with pytest.raises(RuntimeError) as refused:
        laptop_client.push()
    assert "--full-resync" in str(refused.value)
    assert "abandon-pending-change" not in str(refused.value)

    assert laptop_client.full_resync(confirmed=True)["full_resync"]
    laptop_client.push()
    assert not laptop_client.has_pending_key_change()
    phone_client.adopt_rotated_key_material(phone, RECOVERED)
    phone_client.pull()
    assert {"lost"} <= {e["name"] for n in phone.list_nodes() for e in phone.list_entries(n["id"])}
    assert "G" in {n["name"] for n in laptop.list_nodes()}
    laptop.lock()
    phone.lock()
