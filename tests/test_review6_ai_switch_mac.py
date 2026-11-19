"""Review main@d615826 (AI broker, medium): the kill switch state was not protected.

vault_meta is plain SQLite and a missing ``ai_access_enabled`` meant ON, so an
agent with a shell turned AI access on again with
``DELETE FROM vault_meta WHERE key='ai_access_enabled'``; raising
``ai_remote_policy_epoch`` to the maximum made every brake from the phone look
already applied. Now 'on' and the applied remote epoch count only with an
HMAC under a key from the KEK, a missing value is off, and an unsealed applied
epoch is 0 (the phone's brake applies again).
"""

from __future__ import annotations

import pytest

from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.remote_policy import MAX_EPOCH, applied_epoch
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_p3_session_limits import FAST_PARAMS
from tests.test_ai_s1b_control import _code, _FakeSSH
from tests.test_ai_s1e_remote_policy import _policy, _poller

PASSWORD = "r6-ai-mac-master"


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def _broker(vault) -> MCPBroker:
    return MCPBroker(vault, ApprovalManager(), _FakeSSH())


def test_a_new_vault_is_on_and_sealed(vault):
    assert ai_access.read_state(vault) == ai_access.AIAccessState(True, 0)
    _broker(vault).vault_list("")


def test_deleting_the_switch_row_does_not_turn_ai_on(vault):
    ai_access.disable(vault, "cli")

    vault.db.execute("DELETE FROM vault_meta WHERE key = ?", (ai_access.ENABLED_KEY,))

    assert not ai_access.read_state(vault).enabled
    assert _code(lambda: _broker(vault).vault_list("")) == "ai_disabled"


def test_writing_on_without_the_kek_does_not_turn_ai_on(vault):
    ai_access.disable(vault, "cli")

    vault.db.set_meta(ai_access.ENABLED_KEY, "1")
    vault.db.execute("DELETE FROM vault_meta WHERE key = ?", (ai_access.STATE_MAC_KEY,))

    assert not ai_access.read_state(vault).enabled
    vault.db.set_meta(ai_access.STATE_MAC_KEY, "00" * 32)
    assert not ai_access.read_state(vault).enabled
    assert _code(lambda: _broker(vault).vault_list("")) == "ai_disabled"


def test_a_sealed_on_with_another_epoch_does_not_verify(vault):
    ai_access.disable(vault, "cli")
    ai_access.enable(vault, "cli")  # epoch 1, sealed
    assert ai_access.read_state(vault) == ai_access.AIAccessState(True, 1)

    vault.db.set_meta(ai_access.EPOCH_KEY, "0")

    assert not ai_access.read_state(vault).enabled


def test_ai_on_survives_a_password_change(vault):
    vault.change_password(PASSWORD, PASSWORD + "-new")

    assert ai_access.read_state(vault).enabled
    vault.lock()
    vault.unlock(PASSWORD + "-new")
    assert ai_access.read_state(vault).enabled


def test_raising_the_applied_remote_epoch_does_not_blind_the_phone_brake(vault):
    broker = _broker(vault)
    poller, box = _poller(vault, broker, _policy(vault, 5))
    assert poller.poll_once() == "applied"
    ai_access.enable(vault, "cli")
    assert applied_epoch(vault) == 5

    vault.db.set_meta(ai_access.REMOTE_APPLIED_KEY, str(MAX_EPOCH))
    box["policy"] = _policy(vault, 6)  # a new brake from the phone

    assert applied_epoch(vault) == 0
    assert poller.poll_once() == "applied"
    assert not ai_access.read_state(vault).enabled
    assert applied_epoch(vault) == 6


def test_the_applied_remote_epoch_stays_sealed_across_a_password_change(vault):
    broker = _broker(vault)
    poller, _ = _poller(vault, broker, _policy(vault, 9))
    assert poller.poll_once() == "applied"
    ai_access.enable(vault, "cli")

    vault.change_password(PASSWORD, PASSWORD + "-new")

    assert applied_epoch(vault) == 9
    assert poller.poll_once() == "unchanged"  # 'sezam ai on' after the brake sticks
    assert ai_access.read_state(vault).enabled
