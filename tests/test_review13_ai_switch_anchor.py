"""Review c78fd19 R13-11: an L1 agent saved the AI switch and wrote it back.

An agent under the owner's OS user copied the vault_meta rows of a sealed
'on' while AI access was on. After 'sezam ai off' it wrote them back. The
running broker refused them (its off floor), but a restarted broker had no
floor and took the old, validly sealed 'on'. The broker now anchors the
highest 'off' it saw on the sync server (keyed by the KEK, so the agent can
neither lower it nor make a new one), and after an unlock the first call
waits for one check of it.
"""

from __future__ import annotations

import time

import pytest

from sezam import cli
from sezam.mcp.approval import ApprovalManager
from sezam.mcp.broker import MCPBroker
from sezam.mcp.remote_policy import RemotePolicyPoller
from sezam.vault import ai_access
from sezam.vault.crud import Vault
from tests.test_ai_s1b_control import _FakeSSH, _code
from tests.test_integration_client_server import PASSWORD, _client, _vault
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_ai_switch_replay_h6 import _copy_rows, _write_rows


def _broker(vault) -> MCPBroker:
    """A freshly started mcp-serve: broker plus its (real) poller thread."""
    broker = MCPBroker(vault, ApprovalManager(), _FakeSSH())
    poller = RemotePolicyPoller(vault, broker, interval=3600)
    broker.remote_policy = poller
    poller.start()
    return broker


def _allowed(broker) -> bool:
    return _code(lambda: broker.vault_list("")) != "ai_disabled"


def _stop(*brokers) -> None:
    for broker in brokers:
        broker.remote_policy.stop()


@pytest.fixture
def laptop(server, tmp_path):  # noqa: F811
    url, _ = server
    vault = _vault(tmp_path / "laptop", "admin")
    cli._server_connect_flow(url, vault, PASSWORD)
    yield vault
    vault.lock()


def _ai_off_elsewhere(vault) -> None:
    """'sezam ai off' in its own process: no password, vault locked there."""
    ai_access.disable(Vault(vault.path), "cli")


def test_a_saved_on_written_back_does_not_turn_ai_on_after_a_restart(laptop):
    first = _broker(laptop)
    assert _allowed(first)
    saved = _copy_rows(laptop)  # the agent's copy, AI on

    _ai_off_elsewhere(laptop)
    assert not _allowed(first)
    first.remote_policy.poll_once()  # what the poller does on the new 'off'
    _write_rows(laptop, saved)
    assert ai_access.read_state(laptop).enabled  # on disk: the replayed copy
    assert not _allowed(first)  # the running broker refused it before too

    second = _broker(laptop)  # mcp-serve restarted (before: AI was on)
    assert not _allowed(second)
    assert second.status()["ai_access"] == "off"

    # The owner's 'sezam ai on' turns it on again, at an epoch the broker takes.
    ai_access.enable(laptop, "cli")
    assert _allowed(second)
    _stop(first, second)


def test_the_new_off_is_anchored_without_waiting_for_the_poll_interval(laptop):
    broker = _broker(laptop)
    saved = _copy_rows(laptop)
    _ai_off_elsewhere(laptop)
    broker.enforce_kill_switch()  # the backstop tick sees it and wakes the poller
    _write_rows(laptop, saved)

    held = ai_access.read_state(laptop).epoch + 1
    client = _client(laptop, laptop.db.get_meta("server_url"))
    anchor = ai_access.anchor_id(laptop)
    for _ in range(200):
        found = client._request("GET", f"/api/ai-anchor/{anchor}", auth=True)["anchor"]
        if found and found["epoch"] == held:
            break
        time.sleep(0.05)
    else:
        pytest.fail("the 'off' was not anchored")
    assert not _allowed(_broker(laptop))
    _stop(broker)


def test_server_never_lowers_an_anchor_and_keeps_it_per_account(laptop, server, tmp_path):  # noqa: F811
    url, _ = server
    client = _client(laptop, url)
    anchor = "ab" * 32
    body = {"anchor": anchor, "epoch": 5, "mac": "cd" * 32}
    assert client._request("PUT", "/api/ai-anchor", body, auth=True)["anchor"]["epoch"] == 5
    with pytest.raises(RuntimeError, match="409"):
        client._request("PUT", "/api/ai-anchor", {**body, "epoch": 4}, auth=True)
    assert client._request("PUT", "/api/ai-anchor", body, auth=True)["anchor"]["epoch"] == 5
    stored = client._request("GET", f"/api/ai-anchor/{anchor}", auth=True)["anchor"]
    assert stored == {"anchor": anchor, "epoch": 5, "mac": "cd" * 32}


def test_a_forged_anchor_is_ignored(laptop):
    """The server cannot raise it: an anchor without the KEK's MAC counts as none."""
    client = _client(laptop, laptop.db.get_meta("server_url"))
    anchor = ai_access.anchor_id(laptop)
    client._request(
        "PUT", "/api/ai-anchor", {"anchor": anchor, "epoch": 99, "mac": "00" * 32}, auth=True
    )
    broker = _broker(laptop)
    assert _allowed(broker)
    _stop(broker)
