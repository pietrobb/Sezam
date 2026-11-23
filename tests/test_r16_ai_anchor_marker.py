"""Review 18c300f R16-H3: the AI switch anchor could still be bypassed.

R14-M3 sealed the anchor's home under the KEK and kept AI access off while a
vault that expects its anchor could not check it. But whether a vault
expects one was read from three plain vault_meta rows (ai_anchor_home, its
MAC, server_url): an agent under the owner's OS user wrote back a saved
'on', deleted the three rows (and the local floor) and the restarted broker
checked nothing and took the 'on'.

The sealed 'on' now names the anchor home it was sealed next to: without
that home it does not verify, so deleting the rows turns AI access off. An
'on' sealed before R16-H3 counts only next to a home that verifies.
"""

from __future__ import annotations

import pytest

from sezam.mcp import broker as broker_mod
from sezam.vault import ai_access
from tests.test_integration_client_server import PASSWORD
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_review7_ai_switch_replay_h6 import _copy_rows, _write_rows
from tests.test_review13_ai_switch_anchor import (
    _ai_off_elsewhere,
    _allowed,
    _broker,
    _stop,
    laptop,  # noqa: F401  (fixture)
)
from tests.test_review14_ai_anchor_fail_closed import (
    _delete_meta,
    _off_anchored_then_replayed,
    _refused,
    _reopen,
)

DROPPED = (ai_access.ANCHOR_HOME_KEY, ai_access.ANCHOR_HOME_MAC_KEY, "server_url", ai_access.FLOOR_KEY)


@pytest.fixture(autouse=True)
def _short_wait(monkeypatch):
    monkeypatch.setattr(broker_mod, "ANCHOR_WAIT_SECONDS", 2)


def test_dropping_every_anchor_row_does_not_skip_the_check(laptop):  # noqa: F811
    _off_anchored_then_replayed(laptop)
    for key in DROPPED:
        _delete_meta(laptop, key)
    _reopen(laptop)
    assert not ai_access.anchor_expected(laptop)  # nothing on disk says so ...
    assert not ai_access.read_state(laptop).enabled  # ... and the 'on' is off
    second = _broker(laptop)
    assert _refused(second) == "ai_disabled"
    _stop(second)


def test_an_on_copied_before_the_home_existed_does_not_come_back(laptop):  # noqa: F811
    """Capability review 501: the first broker made the anchor home, so the
    'on' rows of a vault already on a server named no home until then, and
    a copy of them came back once the home rows were deleted. Connecting
    seals the home now: the earliest copy on a server names it."""
    assert laptop.db.get_meta(ai_access.ANCHOR_HOME_KEY) is not None
    early = _copy_rows(laptop)
    first = _broker(laptop)
    assert _allowed(first)
    _ai_off_elsewhere(laptop)
    first.remote_policy.poll_once()
    _stop(first)
    _write_rows(laptop, early)
    for key in DROPPED:
        _delete_meta(laptop, key)
    _reopen(laptop)
    assert not ai_access.read_state(laptop).enabled
    second = _broker(laptop)
    assert _refused(second) in ("ai_disabled", "ai_anchor_unverified")
    _stop(second)


def test_an_on_sealed_before_the_fix_counts_only_next_to_its_home(laptop):  # noqa: F811
    """A vault upgraded with AI on keeps it while its home verifies."""
    first = _broker(laptop)
    assert _allowed(first)  # the anchor home is made
    _stop(first)
    kek = ai_access._vault_kek(laptop)
    db = laptop.db
    legacy = ai_access._mac(kek, ai_access.STATE_MAC_KEY, db.get_meta(ai_access.ENABLED_KEY),
                            db.get_meta(ai_access.EPOCH_KEY))
    _write_rows(laptop, {ai_access.STATE_MAC_KEY: legacy})
    assert ai_access.read_state(laptop).enabled
    second = _broker(laptop)
    assert _allowed(second)
    _stop(second)

    saved = _copy_rows(laptop)
    for key in DROPPED:
        _delete_meta(laptop, key)
    _write_rows(laptop, saved)
    assert not ai_access.read_state(laptop).enabled


def test_a_kek_change_carries_an_on_sealed_before_the_fix_over(laptop):  # noqa: F811
    first = _broker(laptop)
    assert _allowed(first)
    _stop(first)
    old = ai_access._vault_kek(laptop)
    db = laptop.db
    _write_rows(laptop, {ai_access.STATE_MAC_KEY: ai_access._mac(
        old, ai_access.STATE_MAC_KEY, db.get_meta(ai_access.ENABLED_KEY), db.get_meta(ai_access.EPOCH_KEY))})
    new = bytes(range(32))
    ai_access.rewrap_macs(db, old, new)
    assert ai_access._state_verified(new, db)
    assert db.get_meta(ai_access.STATE_MAC_KEY) == ai_access._state_mac(new, db)


def test_ai_on_without_a_server_drops_the_anchor(laptop):  # noqa: F811
    """L6: the owner whose server is gone turns AI on with the password."""
    first = _broker(laptop)
    assert _allowed(first)
    _stop(first)
    ai_access.disable(laptop, "cli")
    _delete_meta(laptop, "server_url")
    _reopen(laptop)
    ai_access.enable(laptop, "cli")
    assert not ai_access.anchor_expected(laptop)
    assert ai_access.read_state(laptop).enabled
    second = _broker(laptop)
    assert _allowed(second)
    _stop(second)


def test_the_unverified_anchor_message_says_the_way_out():
    import inspect

    source = inspect.getsource(broker_mod.MCPBroker._await_anchor)
    assert "sezam ai on" in source
