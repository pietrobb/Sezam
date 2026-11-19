"""Stateful test finding SM71 (web device): after a server restore the web
page could never sign in again.

The page saved an item, and the server was then restored from a backup taken
before it. The page's checkpoint is ahead of the restored server, so every
pull - and with it every sign-in in this browser - failed with ROLLBACK
DETECTED and nothing offered a way out. As with 'sezam pull --full-resync' on
the desktop, the page now asks whether the server was restored; yes takes the
server's state as it is now (the full pull is verified as usual), no changes
nothing.

The open page did not even notice: an empty delta echoes since_commit_seq as
max_commit_seq and the check took the larger of that and the server head.
Once the restored server took new commits past the page's seq, only the
commit token of the page's last commit shows it (the desktop's SM7); the
checkpoint keeps that token and the delta pull sends it.
"""

from __future__ import annotations

import copy

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab


def _names(view: dict) -> set[str]:
    return {e["name"] for e in view["entries"]}


def _restore(db, backup) -> None:
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))


def _reload(tab: WebTab, url: str, log) -> WebTab:
    return WebTab(url, log, tab.close())


def test_web_accepts_a_restored_server_only_when_asked(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    log = tmp_path / "tab.log"

    tab = WebTab(url, log)
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        backup = copy.deepcopy(db._storage)
        saved = tab.do("save_object", mode="entry", name="web01", parent=folder,
                       fields=[{"key": "password", "value": "w"}])
        assert saved["error"] is None, saved
        _restore(db, backup)

        # Declined in the open page: nothing changes.
        declined = tab.do("refresh", confirm=False)
        assert "ROLLBACK DETECTED" in (declined["error"] or ""), declined
        assert any("rollback_confirm" in c for c in declined["confirms"]), declined
        assert declined["view"]["unlocked"] and "web01" in _names(declined["view"])

        # A new tab on this browser: before the fix every sign-in failed here.
        tab = _reload(tab, url, log)
        refused = tab.do("login", username="admin", password=PASSWORD, confirm=False)
        assert "ROLLBACK DETECTED" in (refused["error"] or ""), refused
        tab = _reload(tab, url, log)
        accepted = tab.do("login", username="admin", password=PASSWORD, confirm=True)
        assert accepted["error"] is None, accepted
        assert not accepted["rejections"], accepted
        assert any("rollback_confirm" in c for c in accepted["confirms"]), accepted
        assert accepted["view"]["unlocked"] and _names(accepted["view"]) == {"db01"}

        # Accepted in the open page (a delta pull): without a reload. The page
        # still holds what it sent and the restored server lost (sync redesign
        # S4a): it is queued again, as the desktop's full resync keeps it.
        backup = copy.deepcopy(db._storage)
        saved = tab.do("save_object", mode="entry", name="web02", parent=folder,
                       fields=[{"key": "password", "value": "w"}])
        assert saved["error"] is None, saved
        _restore(db, backup)
        pulled = tab.do("refresh", confirm=True)
        assert pulled["error"] is None, pulled
        assert _names(pulled["view"]) == {"db01", "web02"}
        web02 = next(e["id"] for e in pulled["view"]["entries"] if e["name"] == "web02")
        assert web02 in pulled["view"]["dirty"], pulled["view"]["dirty"]

        # The page now trusts the restored server: the next sign-in asks nothing.
        tab = _reload(tab, url, log)
        again = tab.do("login", username="admin", password=PASSWORD)
        assert again["error"] is None and not again["confirms"], again
        assert _names(again["view"]) == {"db01", "web02"}
        assert tab.do("retry")["error"] is None
        assert not tab.do("refresh")["view"]["dirty"]

        # The restored server took new commits past the page's seq: only the
        # commit token shows that the page's last commit is not the server's.
        backup = copy.deepcopy(db._storage)
        saved = tab.do("save_object", mode="entry", name="web03", parent=folder,
                       fields=[{"key": "password", "value": "w"}])
        assert saved["error"] is None, saved
        _restore(db, backup)
        added = {f"lap{i}" for i in range(8)}
        for name in sorted(added):
            laptop.create_entry(folder, name, [{"key": "password", "value": name, "sensitive": True}])
        assert _client(laptop, url).push()["accepted"]
        declined = tab.do("refresh", confirm=False)
        assert "no longer holds commit" in (declined["error"] or ""), declined
        assert "web03" in _names(declined["view"])
        pulled = tab.do("refresh", confirm=True)
        assert pulled["error"] is None, pulled
        assert _names(pulled["view"]) == {"db01", "web02", "web03"} | added
        assert tab.do("retry")["error"] is None
        assert not tab.do("refresh")["view"]["dirty"]
    finally:
        tab.kill()
    # What the page sent again reached the server: the laptop has it.
    _client(laptop, url).pull()
    assert {e["name"] for e in laptop.list_entries(folder)} == {"db01", "web02", "web03"} | added
    laptop.lock()
