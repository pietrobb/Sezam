"""Review 8595ec1 (R10, medium): 'sezam ai on' lost a brake applied meanwhile.

enable() read the epoch, wrote the audit record and only then wrote
('1', epoch) with a fresh MAC, outside any write lock. An 'ai off' from another
process (a broker, the phone's remote policy) committed in between bumped the
epoch and was overwritten: AI was on again, at an epoch below the brake, and
a new broker allowed calls. Now the epoch is read again under the write lock
and an 'on' whose epoch moved is refused.
"""

from __future__ import annotations

import pytest

from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_review7_ai_switch_replay_h6 import _allowed, _broker
from tests.test_ai_p3_session_limits import FAST_PARAMS

PASSWORD = "r10-ai-enable-race"


@pytest.fixture
def vault(tmp_path):
    vault = Vault.create(tmp_path, PASSWORD, FAST_PARAMS)
    yield vault
    vault.lock()


def _brake_during_audit(vault, monkeypatch) -> list:
    """Another process's 'ai off' commits while enable() writes its audit."""
    real = vault._audit_log
    braked = []

    def audit(action, *args, **kwargs):
        result = real(action, *args, **kwargs)
        if action == "ai_on" and not braked:
            braked.append(ai_access.disable(vault, "remote-policy"))
        return result

    monkeypatch.setattr(vault, "_audit_log", audit)
    return braked


def test_a_brake_between_the_read_and_the_write_of_ai_on_holds(vault, monkeypatch):
    ai_access.disable(vault, "cli")  # ('0', 1)
    braked = _brake_during_audit(vault, monkeypatch)

    with pytest.raises(RuntimeError, match="switched off"):
        ai_access.enable(vault, "cli")

    assert braked and braked[0].epoch == 2
    state = ai_access.read_state(vault)
    assert (state.enabled, state.epoch) == (False, 2)
    assert not _allowed(_broker(vault))


def test_ai_on_without_a_brake_meanwhile_still_turns_it_on(vault):
    ai_access.disable(vault, "cli")

    state = ai_access.enable(vault, "cli")

    assert (state.enabled, state.epoch) == (True, 1)
    assert ai_access.read_state(vault) == state
    assert _allowed(_broker(vault))
