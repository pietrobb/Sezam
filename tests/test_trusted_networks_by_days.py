"""Review e4cd15a (low): the owner's trusted networks were the 8 most recent.

A phone on mobile data gets a new /64 every few hours, so a day of it pushed
the home and office networks off the list, and the owner's correct password
from home waited behind the locked name's ration again. Networks now count
the days they were seen: a full list drops the one seen on the fewest days.
"""

from __future__ import annotations

import time

import pytest

from tests.test_recover_lockout_dos import (
    _client_from,
    _locked_by_attacker,
    _recover,
    _three_networks_fill_the_ration,
)
from tests.test_server_spec import (  # noqa: F401  (fixtures)
    _create_admin_user,
    _do_challenge_verify,
    app_client,
    mock_db,
)


@pytest.mark.asyncio
async def test_home_network_outlives_a_day_of_mobile_networks(app_client, mock_db, monkeypatch):
    sk, _ = _create_admin_user(mock_db._storage)
    real_time = time.time
    for days_ago in (3, 2, 1):  # the laptop at home, three days in a row
        monkeypatch.setattr(time, "time", lambda d=days_ago: real_time() - d * 86_400)
        async with _client_from("198.51.100.10") as home:
            await _do_challenge_verify(home, mock_db._storage, sk, "admin")
    monkeypatch.setattr(time, "time", real_time)
    for i in range(20):  # then a day of the phone on mobile data
        async with _client_from(f"2001:db8:{i:x}::1") as phone:
            await _do_challenge_verify(phone, mock_db._storage, sk, "admin")

    row, proof = await _locked_by_attacker(mock_db)
    await _three_networks_fill_the_ration(mock_db)
    async with _client_from("198.51.100.10") as home:
        assert await _recover(home, proof) == 200
