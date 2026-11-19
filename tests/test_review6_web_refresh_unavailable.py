"""Review main@d615826 (web): any failed token refresh ended the session.

A request that met a 401 tried to refresh the token, and every failure of that
refresh (network down, a busy server, a rate limit) signed the user out and
dropped the keys from the page. Only the server refusing the refresh (401/403)
ends the session now; otherwise the page stays signed in and tries again on
the next request.
"""

from __future__ import annotations

from sezam import cli
from tests.test_cross_client_password_change import NEW_PASSWORD
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab

REFRESH_DOWN = {"method": "POST", "path": "/api/auth/refresh", "mode": "before"}


def test_refresh_lost_on_the_network_keeps_the_session(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        # The password change revokes the page's token: the next pull meets a 401.
        proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(NEW_PASSWORD)
        _client(laptop, url).push()

        down = tab.do("refresh", fail=REFRESH_DOWN)
        assert down["failure"]["fired"], down
        assert "error.session_refresh_unavailable" in (down["error"] or ""), down
        assert down["view"]["unlocked"] and down["view"]["token"], down

        refused = tab.do("refresh")
        assert "error.session_ended" in (refused["error"] or ""), refused
        assert not refused["view"]["unlocked"] and not refused["view"]["token"], refused
    finally:
        tab.kill()
        laptop.lock()
