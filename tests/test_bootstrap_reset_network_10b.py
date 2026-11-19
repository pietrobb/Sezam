"""Review 688edcb #10: an unfinished first-admin setup was open to anyone.

Lockout review #10 let a new bootstrap replace a lone keyless admin an hour
after its setup, so a server whose first key upload failed did not refuse
setup forever. But the replacement was open to every client on the internet:
an hour after an unfinished setup a stranger became the admin of a server its
operator believed set up. Now only a bootstrap from the network the first one
came from replaces it; from elsewhere the operator allows it explicitly
(SEZAM_BOOTSTRAP_RESET_ANY_NETWORK), and the refusal is logged with that hint.
"""

from __future__ import annotations

import pytest

from tests.test_onboarding_atomic_review10 import HOUR_MS, _age, _keys
from tests.test_recover_lockout_dos import _client_from
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)

OPERATOR = "198.51.100.20"
STRANGER = "203.0.113.9"


async def _bootstrap(client, username: str):
    return await client.post("/api/bootstrap", json={"username": username, **_keys()})


async def _needs_setup(client) -> bool:
    return (await client.get("/api/bootstrap-status")).json()["needs_setup"]


def _usernames(mock_db) -> list[str]:
    return [u["username"] for u in mock_db._storage["users"]]


@pytest.mark.asyncio
async def test_only_the_first_setups_network_may_redo_it(app_client, mock_db, caplog):
    async with _client_from(OPERATOR) as operator, _client_from(STRANGER) as stranger:
        first = await _bootstrap(operator, "lost-admin")
        assert first.status_code == 200, first.text
        _age(mock_db, first.json()["user_id"], HOUR_MS + 1000)

        assert not await _needs_setup(stranger)
        with caplog.at_level("WARNING"):
            assert (await _bootstrap(stranger, "intruder")).status_code == 403
        assert "SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1" in caplog.text
        assert _usernames(mock_db) == ["lost-admin"]

        assert await _needs_setup(operator)
        again = await _bootstrap(operator, "admin")
        assert again.status_code == 200, again.text
        assert _usernames(mock_db) == ["admin"]


@pytest.mark.asyncio
async def test_operator_can_allow_any_network(app_client, mock_db):
    from server.app.dependencies import get_config

    async with _client_from(OPERATOR) as operator, _client_from(STRANGER) as elsewhere:
        first = await _bootstrap(operator, "lost-admin")
        _age(mock_db, first.json()["user_id"], HOUR_MS + 1000)
        # A setup from before this fix recorded no network.
        mock_db._storage["users"][0]["recovery_trusted_nets"] = None
        assert (await _bootstrap(operator, "admin")).status_code == 403

        get_config().bootstrap_reset_any_network = True
        assert await _needs_setup(elsewhere)
        assert (await _bootstrap(elsewhere, "admin")).status_code == 200
        assert _usernames(mock_db) == ["admin"]
