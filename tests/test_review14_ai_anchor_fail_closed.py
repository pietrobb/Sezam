"""Review 8bc70f7 R14-M3: the AI switch anchor could be bypassed.

R13-11 anchored the highest 'off' on the sync server, so an 'on' an agent
under the owner's OS user saved and wrote back after 'sezam ai off' stayed
off after a restart. But a check that failed counted as done
(remote_policy.py: "Unreachable counts as checked"), and a vault with no
server_url was not checked at all (broker.py _await_anchor): the agent only
had to block the server, or drop or redirect the server_url row, and the
restarted broker took the written-back 'on'. The anchor's home (random id,
server, account) is now sealed under the KEK, and a vault that expects it
keeps AI access off until a check succeeds.
"""

from __future__ import annotations

import pytest

from sezam.mcp import broker as broker_mod
from sezam.vault import ai_access
from sezam.vault.db import VaultDB
from sezam.vault.sync_client import SyncClient
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_ai_switch_replay_h6 import _copy_rows, _write_rows
from tests.test_review13_ai_switch_anchor import (
    _ai_off_elsewhere,
    _allowed,
    _broker,
    _code,
    _stop,
    laptop,  # noqa: F401  (fixture)
    signed_anchor,
)


@pytest.fixture(autouse=True)
def _short_wait(monkeypatch):
    monkeypatch.setattr(broker_mod, "ANCHOR_WAIT_SECONDS", 2)


def _off_anchored_then_replayed(vault) -> None:
    """AI on and anchored, the agent's copy of 'on', 'sezam ai off' (anchored
    by the running broker), the copy written back; the broker stops."""
    first = _broker(vault)
    assert _allowed(first)
    saved = _copy_rows(vault)
    _ai_off_elsewhere(vault)
    first.remote_policy.poll_once()
    _write_rows(vault, saved)
    assert ai_access.read_state(vault).enabled  # on disk: the replayed copy
    _stop(first)


def _delete_meta(vault, key: str) -> None:
    db = VaultDB(vault.db.path)
    db.open()
    try:
        db.execute("DELETE FROM vault_meta WHERE key = ?", (key,))
    finally:
        db.close()


def _reopen(vault) -> None:
    vault.lock()
    vault.unlock(PASSWORD)


def _refused(broker) -> str:
    return _code(lambda: broker.vault_list(""))


def test_a_server_that_cannot_be_reached_keeps_ai_off(laptop, monkeypatch):  # noqa: F811
    _off_anchored_then_replayed(laptop)
    real = SyncClient._request

    def blocked(self, method, path, *args, **kwargs):
        if path.startswith("/api/ai-anchor"):
            raise ConnectionError("blocked by the agent")
        return real(self, method, path, *args, **kwargs)

    monkeypatch.setattr(SyncClient, "_request", blocked)
    second = _broker(laptop)  # restarted
    assert _refused(second) == "ai_anchor_unverified"
    # The server answers again: the anchor holds the 'off'.
    monkeypatch.setattr(SyncClient, "_request", real)
    assert _refused(second) == "ai_disabled"
    _stop(second)


def test_a_dropped_server_url_does_not_skip_the_check(laptop):  # noqa: F811
    _off_anchored_then_replayed(laptop)
    url = laptop.db.get_meta("server_url")
    _delete_meta(laptop, "server_url")
    second = _broker(laptop)
    # Checked on the sealed home's server, not on what vault_meta names.
    assert _refused(second) == "ai_disabled"
    _stop(second)
    _write_rows(laptop, {"server_url": url})


def test_a_redirected_server_url_does_not_move_the_check(laptop, monkeypatch):  # noqa: F811
    # The policy poll on the dead URL comes first (a refused connect takes
    # about 2 s on Windows); the anchor check follows it.
    monkeypatch.setattr(broker_mod, "ANCHOR_WAIT_SECONDS", 15)
    _off_anchored_then_replayed(laptop)
    url = laptop.db.get_meta("server_url")
    _write_rows(laptop, {"server_url": "http://127.0.0.1:9"})
    _reopen(laptop)  # a new server is a new generation: the restarted process
    second = _broker(laptop)
    assert _refused(second) == "ai_disabled"
    _stop(second)
    _write_rows(laptop, {"server_url": url})
    _reopen(laptop)


def test_a_home_that_does_not_verify_keeps_ai_off(laptop):  # noqa: F811
    _off_anchored_then_replayed(laptop)
    _write_rows(laptop, {ai_access.ANCHOR_HOME_KEY: '{"anchor":"' + "ab" * 32
                         + '","server_url":"http://127.0.0.1:9","user_id":"x"}'})
    second = _broker(laptop)
    # R16-H3: the replayed 'on' names the home it was sealed next to; with
    # another home it does not verify at all.
    assert _refused(second) == "ai_disabled"
    _stop(second)


def test_a_home_without_its_seal_and_server_url_keeps_ai_off(laptop):  # noqa: F811
    """The MAC row and server_url gone: the home row says one is expected."""
    _off_anchored_then_replayed(laptop)
    _delete_meta(laptop, ai_access.ANCHOR_HOME_MAC_KEY)
    _delete_meta(laptop, "server_url")
    second = _broker(laptop)
    assert _refused(second) == "ai_anchor_unverified"
    _stop(second)


def test_the_anchor_id_is_sealed_not_made_of_host_and_path(laptop):  # noqa: F811
    broker = _broker(laptop)
    assert _allowed(broker)
    home = ai_access.anchor_home(laptop)
    assert home is not None and home.anchor == ai_access.anchor_home(laptop).anchor
    assert home.anchor != ai_access.legacy_anchor_id(laptop)
    assert home.server_url == laptop.db.get_meta("server_url")
    _stop(broker)


def test_an_anchor_kept_under_the_old_id_still_counts(laptop):  # noqa: F811
    """A vault anchored before R14-M3 (hostname + path id) keeps its floor."""
    from tests.test_integration_client_server import _client

    saved = _copy_rows(laptop)
    epoch = ai_access.read_state(laptop).epoch + 3
    legacy = ai_access.legacy_anchor_id(laptop)
    client = _client(laptop, laptop.db.get_meta("server_url"))
    client._request("PUT", "/api/ai-anchor", signed_anchor(
        laptop, legacy, epoch, ai_access.anchor_mac(laptop, legacy, epoch)
    ), auth=True)
    _write_rows(laptop, saved)
    broker = _broker(laptop)
    assert _refused(broker) == "ai_disabled"
    _stop(broker)


def test_ai_on_moves_the_anchor_to_the_new_server(laptop):  # noqa: F811
    """A server move is the owner's: connected with the password, 'sezam ai
    on' re-homes it. Review c02cc47 R17-L: under a new id, so the old
    server's anchor records verify for it no more."""
    home = ai_access.anchor_home(laptop)
    ai_access.name_server(laptop, "http://127.0.0.1:9")
    ai_access.enable(laptop, "cli")
    moved = ai_access.anchor_home(laptop)
    assert moved.server_url == "http://127.0.0.1:9" and moved.anchor != home.anchor


def test_ai_on_does_not_move_the_anchor_to_a_server_written_into_the_file(laptop):  # noqa: F811
    """Review c02cc47 R17-L: an agent under the owner's OS user wrote its own
    server_url; 'sezam ai on' anchored the switch there."""
    home = ai_access.anchor_home(laptop)
    _write_rows(laptop, {"server_url": "http://127.0.0.1:9"})
    _reopen(laptop)
    with pytest.raises(ai_access.UnsealedServer):
        ai_access.enable(laptop, "cli")
    assert ai_access.anchor_home(laptop) == home
    ai_access.enable(laptop, "cli", confirmed_server="http://127.0.0.1:9")  # the owner says so
    assert ai_access.anchor_home(laptop).server_url == "http://127.0.0.1:9"


def test_an_account_token_alone_cannot_push_the_anchor_out(laptop):  # noqa: F811
    """An agent with the account's JWT (not its signing key): new anchors
    until the oldest is deleted, or a higher epoch with a MAC no broker takes."""
    from server.app.routers.ai_policy import MAX_ANCHORS_PER_USER
    from tests.test_integration_client_server import _client

    broker = _broker(laptop)
    assert _allowed(broker)  # the vault's anchor home is made
    _ai_off_elsewhere(laptop)
    broker.remote_policy.poll_once()  # its 'off' anchored
    _stop(broker)
    anchor = ai_access.anchor_home(laptop).anchor
    client = _client(laptop, laptop.db.get_meta("server_url"))
    held = client._request("GET", f"/api/ai-anchor/{anchor}", auth=True)["anchor"]
    for i in range(MAX_ANCHORS_PER_USER + 1):
        with pytest.raises(RuntimeError, match="422"):
            client._request("PUT", "/api/ai-anchor", {
                "anchor": f"{i:064x}", "epoch": 1, "mac": "00" * 32,
            }, auth=True)
    bad = {**signed_anchor(laptop, anchor, held["epoch"] + 50, "00" * 32), "signature": "11" * 64}
    with pytest.raises(RuntimeError, match="400"):
        client._request("PUT", "/api/ai-anchor", bad, auth=True)
    assert client._request("GET", f"/api/ai-anchor/{anchor}", auth=True)["anchor"] == held
