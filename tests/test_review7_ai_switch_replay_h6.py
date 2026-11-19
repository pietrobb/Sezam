"""Review 7c10379 H6: the AI kill switch came back on by replaying an old 'on'.

disable() left the MAC of the 'on' state in vault_meta, so an agent with a
shell wrote back ('1', old epoch) and AI was on at the next unlock. A running
broker's in-memory brake was released by any 'on' read while the vault was
locked (its MAC cannot be checked then), so a replay worked under a running
broker too. Now disable() deletes the MAC, the brake is released only by a
verified 'on' at its epoch or later, and a broker refuses an 'on' below the
highest epoch it has seen off (also an 'ai off' from another process).
"""

from __future__ import annotations

import pytest

from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from sezam.vault.db import VaultDB
from tests.test_ai_p3_session_limits import FAST_PARAMS
from tests.test_ai_s1b_control import _code, _FakeSSH

PASSWORD = "r7-ai-replay-master"
ROWS = (ai_access.ENABLED_KEY, ai_access.EPOCH_KEY, ai_access.STATE_MAC_KEY)


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def _broker(vault) -> MCPBroker:
    return MCPBroker(vault, ApprovalManager(), _FakeSSH())


def _copy_rows(vault) -> dict:
    return {key: vault.db.get_meta(key) for key in ROWS}


def _write_rows(vault, rows: dict) -> None:
    """What the agent does with a shell: plain SQLite, vault open or locked."""
    db = VaultDB(vault.db.path)
    db.open()
    try:
        for key, value in rows.items():
            db.set_meta(key, value)
    finally:
        db.close()


def _allowed(broker) -> bool:
    return _code(lambda: broker.vault_list("")) != "ai_disabled"


def test_writing_back_the_old_on_after_ai_off_does_not_turn_ai_on(vault):
    ai_access.disable(vault, "cli")  # ('0', 1)

    _write_rows(vault, {ai_access.ENABLED_KEY: "1", ai_access.EPOCH_KEY: "0"})
    vault.lock()
    vault.unlock(PASSWORD)

    assert not ai_access.read_state(vault).enabled
    assert not _allowed(_broker(vault))


def test_a_locked_vault_claiming_on_does_not_release_a_running_brake(vault):
    broker = _broker(vault)
    saved = _copy_rows(vault)  # copied while AI was on
    broker.disable_ai("cli")
    vault.lock()

    _write_rows(vault, {ai_access.ENABLED_KEY: "1", ai_access.EPOCH_KEY: "1"})
    broker.enforce_kill_switch()  # locked: the 'on' cannot be checked
    _write_rows(vault, saved)  # the old, validly sealed ('1', 0)
    vault.unlock(PASSWORD)

    assert ai_access.read_state(vault).enabled  # on disk: the replayed copy
    assert broker.enforce_kill_switch()
    assert not _allowed(broker)


def test_ai_off_from_another_process_holds_against_a_replay(vault):
    broker = _broker(vault)
    saved = _copy_rows(vault)
    assert _allowed(broker)

    ai_access.disable(vault, "cli")  # 'sezam ai off' in another process
    assert broker.enforce_kill_switch()
    _write_rows(vault, saved)

    assert not _allowed(broker)


def test_ai_on_with_the_password_still_releases_the_brake(vault):
    broker = _broker(vault)
    broker.disable_ai("cli")
    assert not _allowed(broker)

    ai_access.enable(vault, "cli")

    assert ai_access.read_state(vault) == ai_access.AIAccessState(True, 1)
    assert _allowed(broker)
    assert not broker.enforce_kill_switch()
