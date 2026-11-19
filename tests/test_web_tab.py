"""The long-lived web tab (tests/web_tab.py) against the real server.

Groundwork for the web device in the stateful sync test: what the tab writes
reaches the desktop and the other way round, a lost reply and a failed send
are what the page queues and later settles, and a new tab on the same browser
profile opens the same vault.
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


def _names(result: dict) -> dict:
    return {e["name"]: e["parent_ref"] for e in result["view"]["entries"]}


def _ok(result: dict) -> dict:
    assert result["error"] is None, result
    assert not result["rejections"], result
    return result


def test_web_tab_writes_both_ways_and_settles_lost_requests(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        login = _ok(tab.do("login", username="admin", password=PASSWORD))
        assert _names(login) == {"db01": folder}
        assert {n["id"]: n["name"] for n in login["view"]["nodes"]}[folder] == "Servers"

        # The web saves a new entry and edits the desktop's; the desktop pulls both.
        _ok(tab.do("save_object", mode="entry", name="web1", parent=folder,
                   fields=[{"key": "password", "value": "w1"}]))
        db01 = next(e["id"] for e in login["view"]["entries"] if e["name"] == "db01")
        _ok(tab.do("save_object", mode="entry", id=db01, name="db01b",
                   fields=[{"key": "password", "value": "s4"}]))
        desk.pull()
        assert _entry_value(laptop, "Servers", "web1", "password") == "w1"
        assert _entry_value(laptop, "Servers", "db01b", "password") == "s4"

        # The desktop renames the folder; the page shows it after its pull.
        laptop.rename_node(folder, "Hosts")
        assert desk.push()["accepted"]
        seen = _ok(tab.do("refresh"))
        assert {n["id"]: n["name"] for n in seen["view"]["nodes"]}[folder] == "Hosts"

        # The reply of a save is lost: the change stays queued until the
        # next pull finds the server holds that very version.
        lost = tab.do("save_object", mode="entry", name="web2", parent=folder,
                      fields=[{"key": "password", "value": "w2"}],
                      fail={"method": "POST", "path": "/api/sync", "mode": "after"})
        assert lost["failure"]["fired"] and lost["error"], lost
        assert lost["view"]["dirty"], lost
        assert not _ok(tab.do("refresh"))["view"]["dirty"]

        # A save that never reached the server goes out on Retry.
        down = tab.do("save_object", mode="entry", name="web3", parent=folder,
                      fields=[{"key": "password", "value": "w3"}],
                      fail={"method": "POST", "path": "/api/sync", "mode": "before"})
        assert down["failure"]["fired"] and down["view"]["dirty"], down
        assert not _ok(tab.do("retry"))["view"]["dirty"]

        web1 = next(e["id"] for e in seen["view"]["entries"] if e["name"] == "web1")
        _ok(tab.do("delete_entry", id=web1))
        desk.pull()
        assert _entry_value(laptop, "Hosts", "web1", "password") is None
        assert _entry_value(laptop, "Hosts", "web2", "password") == "w2"
        assert _entry_value(laptop, "Hosts", "web3", "password") == "w3"
        before = _names(_ok(tab.do("view")))
        idb = tab.close()
    finally:
        tab.kill()

    # A reload: a new tab on the same profile signs in and shows the same vault.
    again = WebTab(url, tmp_path / "tab2.log", idb)
    try:
        assert _names(_ok(again.do("login", username="admin", password=PASSWORD))) == before
    finally:
        again.kill()
    laptop.lock()
