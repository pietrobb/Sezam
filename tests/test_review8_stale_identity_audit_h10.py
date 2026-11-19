"""Review a159e97 H10: a process unlocked before a rebind signed audit under the dead id.

The GUI or 'mcp-serve' stays unlocked with the account id and keypair it read
at unlock. 'connect' (or a recovery) in another process rebinds the vault to
the server's id and re-attributes the unpushed audit records to it. The old
process then appended its own records under the id that no longer exists;
the server refused them ('Invalid audit signature') and every push of the
vault stuck. A process whose identity is no longer the vault's signs nothing.
"""

from __future__ import annotations

import pytest

from sezam.vault.crud import Vault
from sezam.vault.db import VaultChangedElsewhere
from sezam.crypto.keys import generate_keypair
from tests.test_ai_p3_session_limits import FAST_PARAMS

PASSWORD = "stale-identity-password"
SERVER_ID = "01SRV00000000000000000000A"


def _actors(vault) -> set:
    return {r["actor_id"] for r in vault.db.fetchall("SELECT actor_id FROM audit_log")}


@pytest.fixture
def stale_gui(tmp_path):
    Vault.create(tmp_path, PASSWORD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(PASSWORD)
    cli.unlock(PASSWORD)
    gui.create_node("before")
    yield gui, cli
    gui.lock()


def test_a_rebind_elsewhere_stops_the_stale_process_signing_audit(stale_gui):
    gui, cli = stale_gui
    old_id = gui.db.get_meta("user_id")
    cli.rebind_server_identity(SERVER_ID)
    cli.lock()
    assert old_id not in _actors(gui)

    # the vault generation (TL6) refuses it already at the new folder's key
    with pytest.raises(VaultChangedElsewhere, match="unlock it again"):
        gui.create_node("after")  # before: an audit record under the dead id
    assert old_id not in _actors(gui)

    gui.lock()
    gui.unlock(PASSWORD)
    gui.create_node("after unlock")
    assert _actors(gui) == {SERVER_ID}


def test_a_new_keypair_elsewhere_stops_it_too(stale_gui):
    gui, cli = stale_gui
    cli.rebind_server_identity(SERVER_ID, generate_keypair())
    cli.lock()
    with pytest.raises(VaultChangedElsewhere):
        gui.create_node("after")
