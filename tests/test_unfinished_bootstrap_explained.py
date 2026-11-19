"""Review e4cd15a (low): an unfinished bootstrap was explained only in the log.

A first-admin setup whose key upload never happened can be redone only from
the network it came from (688edcb #10). From another network the web showed a
login nobody could pass and the server answered a plain "Server already has
users"; the reason and the way out (SEZAM_BOOTSTRAP_RESET_ANY_NETWORK) were in
the server log alone. bootstrap-status and the refused bootstrap now carry it,
and the web shows it on the login screen.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_bootstrap_reset_network_10b import OPERATOR, STRANGER, _bootstrap
from tests.test_onboarding_atomic_review10 import HOUR_MS, _age
from tests.test_recover_lockout_dos import _client_from
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)

WEB = Path(__file__).resolve().parent.parent / "web" / "static" / "js"


@pytest.mark.asyncio
async def test_other_network_is_told_why_and_how(app_client, mock_db):
    async with _client_from(OPERATOR) as operator, _client_from(STRANGER) as stranger:
        first = await _bootstrap(operator, "lost-admin")
        assert first.status_code == 200, first.text

        status = (await stranger.get("/api/bootstrap-status")).json()
        assert status.get("unfinished_setup") is None  # still within the upload window

        _age(mock_db, first.json()["user_id"], HOUR_MS + 1000)
        status = (await stranger.get("/api/bootstrap-status")).json()
        assert status["needs_setup"] is False
        assert "SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1" in status["unfinished_setup"]

        refused = await _bootstrap(stranger, "intruder")
        assert refused.status_code == 403
        assert "SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1" in refused.json()["detail"]

        status = (await operator.get("/api/bootstrap-status")).json()
        assert status["needs_setup"] is True and status.get("unfinished_setup") is None


@pytest.mark.asyncio
async def test_finished_server_says_nothing_of_it(app_client, mock_db):
    async with _client_from(OPERATOR) as operator:
        await _bootstrap(operator, "admin")
        mock_db._storage["users"][0]["encrypted_keypair"] = b"\x01" * 64
        _age(mock_db, mock_db._storage["users"][0]["id"], HOUR_MS + 1000)
    async with _client_from(STRANGER) as stranger:
        status = (await stranger.get("/api/bootstrap-status")).json()
        assert status["needs_setup"] is False and status.get("unfinished_setup") is None


def test_web_shows_the_explanation_on_the_login_screen():
    app = (WEB / "app.js").read_text(encoding="utf-8")
    i18n = (WEB / "i18n.js").read_text(encoding="utf-8")
    assert "data.unfinished_setup" in app
    assert "t('bootstrap.unfinished_elsewhere')" in app
    assert i18n.count("'bootstrap.unfinished_elsewhere':") == 2  # sk + en
