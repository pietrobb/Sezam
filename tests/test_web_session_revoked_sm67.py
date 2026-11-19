"""Stateful test finding SM67: the web page outlived a revoked session.

The browser had an unsent save queued when the desktop changed the account
password; the server revokes every token of the account on that change. The
page could not refresh its token, but stayed unlocked: Retry and every save
failed on "Token revoked" and nothing told the user to sign in again. It now
ends the session with that message. Signing in with the new password sets the
queued change aside; Restore with the previous password sends it.
"""

from __future__ import annotations

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_cross_client_password_change import NEW_PASSWORD
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab


def test_revoked_session_ends_the_page_and_the_queued_change_survives(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        queued = tab.do("save_object", mode="entry", name="web1", parent=folder,
                        fields=[{"key": "password", "value": "w1"}],
                        fail={"method": "POST", "path": "/api/sync", "mode": "before"})
        assert queued["view"]["dirty"], queued

        proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(NEW_PASSWORD)
        _client(laptop, url).push()

        retry = tab.do("retry")
        assert "error.session_ended" in (retry["error"] or ""), retry
        assert not retry["view"]["unlocked"] and not retry["view"]["token"], retry
        assert not retry["rejections"], retry
        idb = tab.close()
    finally:
        tab.kill()

    again = WebTab(url, tmp_path / "tab2.log", idb)
    try:
        login = again.do("login", username="admin", password=NEW_PASSWORD)
        assert login["error"] is None, login
        assert login["view"]["set_aside"], login
        restored = again.do("restore_set_aside", password=PASSWORD)
        assert restored["error"] is None, restored
        assert not restored["view"]["dirty"] and not restored["view"]["set_aside"], restored
    finally:
        again.kill()
    _client(laptop, url).pull()
    assert _entry_value(laptop, "Servers", "web1", "password") == "w1"
    laptop.lock()
