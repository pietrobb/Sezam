"""Review a159e97 (web, medium): a lock during a login's full pull lost the queue.

handleLock does not wait for the sync lock. The pull of a login still waiting
for the server went on after the lock reset the page: it reconciled the
emptied in-memory queue and, once the same user had signed in again, saved
that empty queue over the offline changes in IndexedDB. The next login's
pull then loaded nothing. A sync step of an ended session now stops before
it writes, and the queue is never saved by a session that has not loaded it.
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
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab


def test_a_lock_and_login_during_the_full_pull_keeps_the_offline_queue(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        queued = tab.do("save_object", mode="entry", name="offline1", parent=folder,
                        fields=[{"key": "password", "value": "o1"}],
                        fail={"method": "POST", "path": "/api/sync", "mode": "before"})
        assert queued["view"]["dirty"], queued
        entry = queued["view"]["dirty"][0]

        again = tab.do("lock_and_login_during_pull", username="admin", password=PASSWORD)
        assert again["error"] is None, again
        assert again["view"]["unlocked"], again
        assert entry in again["view"]["dirty"], again  # before: [] (the queue was gone)
        assert not again["rejections"], again

        retry = tab.do("retry")
        assert retry["error"] is None and not retry["view"]["dirty"], retry
    finally:
        tab.kill()
    _client(laptop, url).pull()
    assert _entry_value(laptop, "Servers", "offline1", "password") == "o1"
    laptop.lock()
