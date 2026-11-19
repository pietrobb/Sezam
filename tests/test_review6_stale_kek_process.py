"""Review main@d615826 H4: a second process with the old KEK locked the vault.

The GUI or 'mcp-serve' stays unlocked with the KEK it derived at unlock. A
password change in another process re-wraps every DEK under the new KEK; the
old process then made a new folder and wrapped its DEK under the old KEK, so
neither the new nor the old password opened everything any more. A stale
process changing the password again re-wrapped only the DEKs it had cached
and took the rest for foreign. Every KEK wrap now checks that the vault's
kek_dek_id is still the one this process unlocked with.
"""

from __future__ import annotations

import pytest

from sezam.vault.crud import Vault
from sezam.vault.dek import KeyChangedElsewhere
from tests.test_ai_p3_session_limits import FAST_PARAMS

OLD = "stale-kek-old-password"
NEW = "stale-kek-new-password"


@pytest.fixture
def two_processes(tmp_path):
    Vault.create(tmp_path, OLD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(OLD)
    cli.unlock(OLD)
    folder = gui.create_node("before")
    cli.change_password(OLD, NEW)
    cli.lock()
    yield tmp_path, gui, folder
    gui.lock()


def test_stale_process_cannot_wrap_a_new_dek_under_the_old_kek(two_processes):
    path, gui, _folder = two_processes
    with pytest.raises(KeyChangedElsewhere):
        gui.create_node("after")

    fresh = Vault(path)
    fresh.unlock(NEW)
    names = {n["name"] for n in fresh.list_nodes(fresh.db.get_meta("root_node_id"))}
    assert names == {"before"}
    for row in fresh.db.fetchall("SELECT id FROM deks"):
        fresh.dek_mgr.unlock_dek(row["id"])  # every DEK opens with the new password
    fresh.lock()


def test_stale_process_is_told_to_unlock_again_for_a_key_made_elsewhere(tmp_path):
    """Stateful test SM79: the folder came after the password change, from the
    process that made it; its key is under the new KEK. Opening it in the old
    process failed with a bare 'Decryption failed'."""
    Vault.create(tmp_path, OLD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(OLD)
    cli.unlock(OLD)
    cli.change_password(OLD, NEW)
    folder = cli.create_node("made after the change")
    cli.lock()
    try:
        with pytest.raises(KeyChangedElsewhere, match="unlock it again"):
            gui.create_node("inside", folder)
    finally:
        gui.lock()


def test_stale_process_cannot_change_the_password_again(two_processes):
    path, gui, _folder = two_processes
    with pytest.raises(KeyChangedElsewhere):
        gui.change_password(OLD, "third-password-x")
    fresh = Vault(path)
    fresh.unlock(NEW)
    for row in fresh.db.fetchall("SELECT id FROM deks"):
        fresh.dek_mgr.unlock_dek(row["id"])
    fresh.lock()
