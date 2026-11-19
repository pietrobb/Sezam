"""AI broker TODO P2: tier-2 ceiling and validated policy types.

Encrypted metadata can be written by any synced client, so the broker must
treat malformed ``tier`` / ``allowed_actions`` values fail-closed instead of
raising, under-protecting (negative tier skipping approval) or substring
matching an action name inside a string.
"""

from __future__ import annotations

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.vault.crud import Vault

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost=8192, parallelism=1)
SEED = "JBSWY3DPEHPK3PXP"


class _DenyingApprovals(ApprovalManager):
    def __init__(self):
        super().__init__()
        self.requests: list[str] = []

    def request_approval(self, request_id, path, action, agent_name, details=None, **kwargs):
        self.requests.append(action)
        return super().request_approval(
            request_id=request_id, path=path, action=action, agent_name=agent_name,
            details=details, **kwargs,
        )

    def check_and_consume(self, request_id):
        return "denied"


@pytest.fixture
def env(tmp_path):
    vault = Vault.create(tmp_path, "p2-master", FAST_PARAMS)
    approvals = _DenyingApprovals()
    broker = MCPBroker(vault, approvals)
    yield vault, broker, approvals
    vault.lock()


def _totp_entry(vault, folder, name, **policy):
    return vault.create_entry(
        folder,
        name,
        [{"key": "totp", "value": SEED, "sensitive": True, "field_type": "totp"}],
        ai_read_secret=True,
        **policy,
    )


def test_lower_tier_entry_under_tier2_folder_stays_hidden_in_search_read_list(env):
    vault, broker, _ = env
    secret = vault.create_node("Secret", tier=2)
    inner = vault.create_node("Inner", parent_id=secret, tier=0)
    _totp_entry(vault, inner, "leaky", tier=0, allowed_actions=["totp_code"])

    assert broker.vault_search("leaky") == {"results": []}
    assert broker.vault_read("Secret/Inner/leaky")["status"] == "not_found"
    assert broker.vault_read("Secret/Inner/leaky", field="totp")["status"] == "not_found"
    assert broker.vault_use("Secret/Inner/leaky", "totp_code")["status"] == "not_found"
    assert broker.vault_list("Secret/Inner") == {"nodes": [], "entries": []}


def test_string_allowed_actions_never_substring_match(env):
    vault, broker, approvals = env
    folder = vault.create_node("Ops")
    _totp_entry(vault, folder, "otp", tier=0, allowed_actions="xtotp_code,ssh_execute")

    result = broker.vault_use("Ops/otp", "totp_code")

    assert result["status"] == "denied", result
    assert "output" not in result
    assert approvals.requests == []


def test_non_string_items_in_allowed_actions_allow_nothing(env):
    vault, broker, _ = env
    folder = vault.create_node("Ops")
    _totp_entry(vault, folder, "otp", tier=0, allowed_actions=["totp_code", 1])

    assert broker.vault_use("Ops/otp", "totp_code")["status"] == "denied"


@pytest.mark.parametrize("bad_tier", [-1, "0", "2", 1.0, True, 3, [0]])
def test_malformed_entry_tier_hides_the_entry(env, bad_tier):
    vault, broker, approvals = env
    folder = vault.create_node("Ops")
    _totp_entry(vault, folder, "otp", tier=bad_tier, allowed_actions=["totp_code"])

    assert broker.vault_use("Ops/otp", "totp_code")["status"] == "not_found"
    assert broker.vault_read("Ops/otp", field="totp")["status"] == "not_found"
    assert broker.vault_search("otp") == {"results": []}
    assert broker.vault_list("Ops")["entries"] == []
    assert approvals.requests == []


@pytest.mark.parametrize("bad_tier", ["2", -5, 2.5])
def test_malformed_folder_tier_is_a_ceiling(env, bad_tier):
    vault, broker, _ = env
    folder = vault.create_node("Odd", tier=bad_tier)
    _totp_entry(vault, folder, "otp", tier=0, allowed_actions=["totp_code"])

    assert broker.vault_list("") == {"nodes": [], "entries": []}
    assert broker.vault_read("Odd/otp")["status"] == "not_found"
    assert broker.vault_use("Odd/otp", "totp_code")["status"] == "not_found"


def test_valid_policy_still_works(env):
    vault, broker, approvals = env
    folder = vault.create_node("Ops")
    _totp_entry(vault, folder, "auto", tier=0, allowed_actions=["totp_code"])
    _totp_entry(vault, folder, "asks", tier=1, allowed_actions=["totp_code"])

    auto = broker.vault_use("Ops/auto", "totp_code")
    assert auto["status"] == "ok" and len(auto["output"]) == 6
    assert broker.vault_use("Ops/asks", "totp_code")["status"] == "denied"
    assert approvals.requests == ["use_secret:totp_code"]
