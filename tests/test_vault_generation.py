"""Vault generation between processes (TL6, review a159e97 H10; docs/DESIGN_TEAM_LOG.md §8).

The GUI or 'mcp-serve' stays unlocked with what it loaded at unlock: the KEK,
the keypair, the account id, the key epoch and the server. The KEK and the
account id/signing key were checked one by one; the key epoch, the encryption
key and the server were not, so a process that missed a change of those still
synced with the old ones. Each change of any of them now gives the vault a new
generation; a process that loaded an older one writes no DEK, no audit record
and does not sync until it is locked and unlocked again.
"""

from __future__ import annotations

import pytest

from sezam.vault.crud import Vault
from sezam.vault.db import GENERATION_META, VaultChangedElsewhere
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import PASSWORD, _vault

URL = "http://127.0.0.1:9"


@pytest.fixture
def two(tmp_path):
    """The same vault unlocked in two processes: 'gui' stays open, 'cli' changes it."""
    path = tmp_path / "vault"
    cli = _vault(path, "admin")
    cli.db.set_meta("server_url", URL)
    gui = Vault(path)
    gui.unlock(PASSWORD)
    yield path, gui, cli
    gui.lock()
    cli.lock()


def _sync_client(vault: Vault) -> SyncClient:
    client = SyncClient(vault.db, URL, vault.keypair, vault.db.get_meta("user_id"))
    client.set_dek_manager(vault.dek_mgr)
    return client


def _refused_everywhere(gui: Vault) -> None:
    entries = gui.db.fetchone("SELECT COUNT(*) FROM entries")[0]
    with pytest.raises(VaultChangedElsewhere):
        gui.create_node("New folder")  # wraps a new DEK under its KEK
    with pytest.raises(VaultChangedElsewhere):
        gui._audit_log("vault.unlock", strict=True)
    for sync in ("pull", "push"):
        with pytest.raises(VaultChangedElsewhere):
            getattr(_sync_client(gui), sync)()
    with pytest.raises(VaultChangedElsewhere):
        _sync_client(gui).full_resync(confirmed=True)
    assert gui.db.fetchone("SELECT COUNT(*) FROM entries")[0] == entries


@pytest.mark.parametrize("key, value", [
    ("server_url", "https://other.example"),
    ("key_epoch", "7"),
    ("encryption_pk", "11" * 32),
])
def test_a_process_that_missed_a_change_writes_and_syncs_nothing(two, key, value):
    path, gui, cli = two
    cli.db.set_meta(key, value)
    _refused_everywhere(gui)
    gui.lock()
    if key == "encryption_pk":
        with pytest.raises(ValueError, match="Invalid keypair public keys"):
            gui.unlock(PASSWORD)
        assert not gui.is_unlocked and gui._keypair is None
        assert cli.db.get_meta(key) == value
        cli.db.set_meta(key, cli.keypair.encryption_pk.hex())
    gui.unlock(PASSWORD)  # only a consistent identity can be loaded
    gui.create_node("After unlock")


def test_own_changes_and_unchanged_values_keep_the_generation(two):
    _path, gui, cli = two
    before = cli.db.get_meta(GENERATION_META)
    cli.db.set_meta("server_url", URL)  # the same value: nothing changed
    assert cli.db.get_meta(GENERATION_META) == before
    gui.db.set_meta("server_url", "https://moved.example")  # its own change
    gui.create_node("Still current")
    with pytest.raises(VaultChangedElsewhere):
        cli.create_node("Missed the move")


def test_a_stale_process_cannot_change_them_either(two):
    _path, gui, cli = two
    cli.db.set_meta("key_epoch", "3")
    with pytest.raises(VaultChangedElsewhere):
        gui.db.set_meta("server_url", "https://stale.example")
    assert gui.db.get_meta("server_url") == URL
    assert gui.db.get_meta("key_epoch") == "3"


def test_a_rolled_back_change_is_no_change(two):
    """The generation written and rolled back is not one the other process
    can hit later: each generation is new, not a counter."""
    _path, gui, cli = two
    with pytest.raises(RuntimeError, match="abort"):
        with gui.db.transaction():
            gui.db.set_meta("server_url", "https://rolled.back")
            raise RuntimeError("abort")
    assert gui.db.get_meta("server_url") == URL
    gui.create_node("After rollback")
    cli.create_node("Other process too")
    cli.db.set_meta("server_url", "https://real.change")
    with pytest.raises(VaultChangedElsewhere):
        gui.create_node("Missed it")


def test_a_password_change_elsewhere_is_one_too(two):
    _path, gui, cli = two
    proof = cli.change_password(PASSWORD, "another long password 2")
    proof[:] = b"\x00" * len(proof)
    with pytest.raises(RuntimeError, match="(?i)another sezam program|password was changed"):
        gui.create_node("Under the dead KEK")
    with pytest.raises(RuntimeError, match="(?i)another sezam program|password was changed"):
        _sync_client(gui).pull()
