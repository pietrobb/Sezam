"""Review 7c10379 (desktop sync, medium): a process with an outdated KEK syncs.

The GUI stays unlocked with the KEK it derived at unlock while 'sezam
change-password' in another process moves the vault to a new one. Another
device of the account then makes a folder under the new account KEK. A pull
of the stale process judged that DEK by its old KEK, could not open it and
put it into 'foreign_dek_ids' for good: the next unlock with the new password
skipped it and the folder stayed unreadable. A full resync did the same to
every DEK. Pull, push, full resync and taking a server epoch over now refuse
such a process (KeyChangedElsewhere) before they touch the vault or the network.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault
from sezam.vault.dek import KeyChangedElsewhere
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)


@pytest.fixture
def stale_gui(server, tmp_path):  # noqa: F811
    url, _db = server
    path = tmp_path / "laptop"
    laptop = _vault(path, "admin")
    cli._server_connect_flow(url, laptop, PASSWORD)
    gui = Vault(path)
    gui.unlock(PASSWORD)

    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    assert not _client(laptop, url).push()["conflicts"]
    laptop.lock()

    desk = _vault(tmp_path / "desk", "admin")
    cli._server_connect_flow(url, desk, NEW_PASSWORD)
    folder = desk.create_node("Made elsewhere")
    desk.create_entry(folder, "web", [{"key": "password", "value": "after", "sensitive": True}])
    assert _client(desk, url).push()["accepted"]
    desk.lock()
    yield url, path, gui
    gui.lock()


def _reads_the_new_folder(url, path) -> None:
    fresh = Vault(path)
    fresh.unlock(NEW_PASSWORD)
    _client(fresh, url).pull()
    assert _entry_value(fresh, "Made elsewhere", "web", "password") == "after"
    # Ours is what our KEK opens: none of it is left on the foreign list,
    # which every later key change and re-key skips.
    foreign = set(fresh.db.get_meta_json("foreign_dek_ids") or [])
    ours = {
        row["id"] for row in fresh.db.fetchall("SELECT id, encrypted_dek, version FROM deks")
        if fresh.dek_mgr.can_unwrap(row["id"], row["encrypted_dek"], row["version"])
    }
    assert ours and not ours & foreign
    fresh.lock()


def _attempt(action) -> Exception | None:
    """Run it, keep what it raised: the harm is checked before the refusal
    (review run 182), so the test fails on the old code because of the harm."""
    try:
        action()
    except Exception as exc:  # noqa: BLE001
        return exc
    return None


def test_stale_process_cannot_pull_and_mark_own_deks_foreign(stale_gui):
    url, path, gui = stale_gui
    seq = gui.db.get_meta("last_known_commit_seq")
    raised = _attempt(lambda: _client(gui, url).pull())
    pulled_seq = gui.db.get_meta("last_known_commit_seq")
    _reads_the_new_folder(url, path)
    assert isinstance(raised, KeyChangedElsewhere), raised
    assert pulled_seq == seq


def test_stale_process_cannot_full_resync(stale_gui):
    url, path, gui = stale_gui
    raised = _attempt(lambda: _client(gui, url).full_resync(confirmed=True))
    _reads_the_new_folder(url, path)
    assert isinstance(raised, KeyChangedElsewhere), raised


def test_stale_process_cannot_push(stale_gui):
    url, _path, gui = stale_gui
    with pytest.raises(KeyChangedElsewhere):
        _client(gui, url).push()


def test_stale_process_cannot_take_a_server_epoch_over(stale_gui):
    """Its own (old) KEK as the 'account' one: only the epoch would change."""
    _url, _path, gui = stale_gui
    epoch = gui.db.get_meta("key_epoch")
    salt = bytes.fromhex(gui.db.get_meta("argon2_salt"))
    params = Argon2Params.from_dict(gui.db.get_meta_json("argon2_params"))
    with pytest.raises(KeyChangedElsewhere):
        gui.adopt_account_kek(bytes(gui.dek_mgr._kek), salt, params, key_epoch=int(epoch) + 5)
    assert gui.db.get_meta("key_epoch") == epoch
