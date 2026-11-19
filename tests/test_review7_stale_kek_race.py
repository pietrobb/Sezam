"""Review main@7c10379 (R7-H, desktop Z-table): the stale-KEK check of d615826 H4
raced the password change it guards against.

``create_dek`` read ``kek_dek_id`` and inserted the new wrap as two autocommit
statements. A ``sezam change-password`` committed in another process between
them re-wrapped every DEK it saw, not this one: a tier-2 entry made in the GUI
at that moment had a DEK under the old KEK, and the new password, the only one
the vault then had, did not open it. The test runs the password change from a
second Vault (another process' connection) exactly in that gap.
"""

from __future__ import annotations

import threading

import pytest

import sezam.vault.dek as dek_mod
from sezam.vault.crud import Vault
from sezam.vault.dek import KeyChangedElsewhere
from tests.test_ai_p3_session_limits import FAST_PARAMS

OLD = "stale-kek-old-password"
NEW = "stale-kek-new-password"


def _password_of(path) -> str:
    for password in (NEW, OLD):
        probe = Vault(path)
        try:
            probe.unlock(password)
        except ValueError:
            continue
        probe.lock()
        return password
    raise AssertionError("neither password opens the vault")


@pytest.mark.parametrize("what", ["tier2 entry", "folder", "personal folder"])
def test_a_password_change_between_the_check_and_the_wrap_misses_no_dek(
    tmp_path, monkeypatch, what
):
    Vault.create(tmp_path, OLD, FAST_PARAMS).lock()
    gui, cli = Vault(tmp_path), Vault(tmp_path)
    gui.unlock(OLD)
    cli.unlock(OLD)
    folder = gui.create_node("f")
    real_wrap = dek_mod.encrypt_dek_wrap
    main = threading.get_ident()
    other: list[threading.Thread] = []
    refused: list[Exception] = []  # refused while the GUI writes: also fine

    def change_password_elsewhere():
        try:
            cli.change_password(OLD, NEW)
        except Exception as exc:  # noqa: BLE001
            refused.append(exc)

    def wrap_in_the_gap(**kwargs):
        if not other and threading.get_ident() == main and kwargs["wrapping_key"] is gui.dek_mgr._kek:
            other.append(threading.Thread(target=change_password_elsewhere))
            other[0].start()
            other[0].join(timeout=3)  # old code: the change commits right here
        return real_wrap(**kwargs)

    monkeypatch.setattr(dek_mod, "encrypt_dek_wrap", wrap_in_the_gap)
    try:
        if what == "tier2 entry":
            gui.create_entry(folder, "e", [{"key": "password", "value": "x"}], tier=2)
        elif what == "folder":
            gui.create_node("g")
        else:
            gui.create_personal_folder("p")
    except KeyChangedElsewhere:
        pass
    finally:
        assert other, "the wrap under the GUI's KEK never ran"
        other[0].join(timeout=30)
        monkeypatch.undo()
        gui.lock()
        cli.lock()

    fresh = Vault(tmp_path)
    fresh.unlock(_password_of(tmp_path))
    try:
        for row in fresh.db.fetchall("SELECT id FROM deks"):
            fresh.dek_mgr.unlock_dek(row["id"])  # old code: CryptoError on the tier-2 DEK
    finally:
        fresh.lock()
