"""Review 7c10379 (web, medium): a lost refresh response ended the session.

The server revokes the old token in the same transaction that issues the new
one. When the response never reached the page, it was left with a revoked
token; the next request met a 401, the refresh with that token was refused,
and the page signed the user out and dropped the keys. A refused refresh now
signs in again with the session's keypair. A password change elsewhere (the
account's key material changed) still ends the session
(tests/test_review6_web_refresh_unavailable.py).
"""

from __future__ import annotations

from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab
from sezam import cli

REFRESH_LOST = {"method": "POST", "path": "/api/auth/refresh", "mode": "after"}


def test_a_refresh_whose_response_was_lost_keeps_the_session(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        lost = tab.do("refresh_token", fail=REFRESH_LOST)
        assert lost["failure"]["fired"] and lost["failure"]["reply"].get("token"), lost
        assert lost["view"]["unlocked"] and lost["view"]["token"], lost

        # The page still holds the token the server revoked with that refresh.
        pulled = tab.do("refresh")
        assert pulled["error"] is None, pulled
        assert pulled["view"]["unlocked"] and pulled["view"]["token"], pulled
        assert any(n["name"] == "Servers" for n in pulled["view"]["nodes"]), pulled

        assert tab.do("refresh_token")["error"] is None
    finally:
        tab.kill()
        laptop.lock()


def test_two_tokens_in_one_second_differ():
    """Else signing in again in the second of the lost refresh returned the
    very token that refresh revoked (Ed25519 signatures are deterministic)."""
    from nacl.signing import SigningKey

    from server.app.auth import create_jwt

    key = SigningKey.generate()
    tokens = {create_jwt(key, "01U0000000000000000000000A", "admin", True) for _ in range(3)}
    assert len(tokens) == 3
