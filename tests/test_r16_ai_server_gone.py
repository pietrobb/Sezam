"""Review 18c300f R16-L6: a sync server that is gone kept AI access off for good.

A vault that syncs with a server expects the AI switch's anchor there
(R14-M3), and nothing removes server_url. Once the server was gone, every
AI tool call was refused ('ai_anchor_unverified') however often the owner
ran 'sezam ai on', and neither 'sezam ai on' nor 'sezam ai status' said
why. The owner can now say the server is gone ('sezam ai on --server-gone',
master password): the switch is anchored nowhere until the vault connects
to a server. 'sezam ai on' and 'sezam ai status' say what AI tools wait for.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.mcp import broker as broker_mod
from sezam.mcp import control
from sezam.vault import ai_access
from sezam.vault.sync_client import SyncClient
from tests.test_ai_s1b_control import _code, _run
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_ai_switch_replay_h6 import _copy_rows, _write_rows
from tests.test_review13_ai_switch_anchor import _ai_off_elsewhere, _broker, _stop
from tests.test_review13_ai_switch_anchor import laptop  # noqa: F401  (fixture)
from tests.test_review14_ai_anchor_fail_closed import _delete_meta

REFUSED = ("ai_disabled", "ai_anchor_unverified", "vault_locked")


@pytest.fixture(autouse=True)
def _short_wait(monkeypatch):
    monkeypatch.setattr(broker_mod, "ANCHOR_WAIT_SECONDS", 2)


@pytest.fixture
def gone(monkeypatch):
    """The sync server is gone: nothing answers any more."""

    def nothing(self, method, path, *args, **kwargs):
        raise ConnectionError("the sync server is gone")

    monkeypatch.setattr(SyncClient, "_request", nothing)


def _refused(broker) -> str:
    try:
        return _code(lambda: broker.vault_list(""))
    except broker_mod.MCPError as exc:
        return exc.code


def _message(broker) -> str:
    try:
        broker.vault_list("")
    except broker_mod.MCPError as exc:
        return exc.message
    return ""


def test_the_owner_turns_ai_on_without_a_server_that_is_gone(laptop, gone):  # noqa: F811
    broker = _broker(laptop)
    ai_access.enable(laptop, "cli")  # what the owner tried before: no help
    assert _refused(broker) == "ai_anchor_unverified"
    assert "--server-gone" in _message(broker)
    assert broker.status()["anchor"] == "unconfirmed"

    ai_access.enable(laptop, "cli", server_gone=True)
    assert _refused(broker) not in REFUSED
    assert broker.status()["anchor"] == "confirmed"
    assert ai_access.anchor_home(laptop) is None
    _stop(broker)


def test_ai_off_still_holds_without_the_server(laptop, gone):  # noqa: F811
    ai_access.enable(laptop, "cli", server_gone=True)
    broker = _broker(laptop)
    assert _refused(broker) not in REFUSED
    _ai_off_elsewhere(laptop)
    assert _refused(broker) == "ai_disabled"
    _stop(broker)


def test_an_agent_cannot_bring_back_a_home_the_owner_let_go(laptop):  # noqa: F811
    """The rows of the anchored 'on' (home included), written back after
    the owner let the server go and turned AI off: the old server is asked,
    and it is gone."""
    homed = _copy_rows(laptop) | {
        key: laptop.db.get_meta(key)
        for key in (ai_access.ANCHOR_HOME_KEY, ai_access.ANCHOR_HOME_MAC_KEY)
    }
    real = SyncClient._request
    try:
        def nothing(self, method, path, *args, **kwargs):
            raise ConnectionError("the sync server is gone")

        SyncClient._request = nothing
        ai_access.enable(laptop, "cli", server_gone=True)
        _ai_off_elsewhere(laptop)
        _write_rows(laptop, homed)
        broker = _broker(laptop)
        assert _refused(broker) in REFUSED
        _stop(broker)
    finally:
        SyncClient._request = real


def test_deleting_the_let_go_home_turns_ai_off(laptop, gone):  # noqa: F811
    ai_access.enable(laptop, "cli", server_gone=True)
    _delete_meta(laptop, ai_access.ANCHOR_HOME_KEY)
    _delete_meta(laptop, ai_access.ANCHOR_HOME_MAC_KEY)
    broker = _broker(laptop)
    assert _refused(broker) in REFUSED
    _stop(broker)


def test_a_new_server_anchors_the_switch_there_again(laptop, gone):  # noqa: F811
    ai_access.enable(laptop, "cli", server_gone=True)
    ai_access.name_server(laptop, "http://127.0.0.1:9")
    home = ai_access.anchor_home(laptop)
    assert home is not None and home.server_url == "http://127.0.0.1:9"
    assert ai_access.read_state(laptop).enabled  # the 'on' moved with it


def test_ai_on_without_the_flag_anchors_on_the_server_again(laptop, gone):  # noqa: F811
    ai_access.enable(laptop, "cli", server_gone=True)
    ai_access.enable(laptop, "cli")
    home = ai_access.anchor_home(laptop)
    assert home is not None and home.server_url == laptop.db.get_meta("server_url")


def test_ai_status_says_what_ai_tools_wait_for(monkeypatch):
    monkeypatch.setattr(cli, "_has_local_vault", lambda: False)
    monkeypatch.setattr(control, "send_all", lambda command: [(None, {
        "status": "ok", "pid": 7, "ai_access": "on", "vault_unlocked": True,
        "ssh_sessions": 0, "sessions": [], "remote_policy": "error", "anchor": "unconfirmed",
    })])
    result = _run("ai", "status")
    assert result.exit_code == 0, result.output
    assert "switch anchor: unconfirmed" in result.output
    assert "sezam ai on --server-gone" in result.output
