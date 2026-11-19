"""Stateful test finding SM75 (web device): a full pull took a restored
server's history without asking.

The page saved items, and the server was then restored from a backup taken
before them; another device pushed new commits past the page's seq. SM71 made
the delta pull send the commit token of the page's last commit, but a full
pull - "Use the server's version" of a conflict, or a sign-in in a new tab -
sent nothing, saw the server's seq ahead of the checkpoint and took the
restored state: what only this browser had sent was gone without the
question. The full pull now sends the token as well.
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


def _restore_and_move_on(db, backup, laptop, folder, url, prefix) -> set[str]:
    """Restore the server, then another device commits past the page's seq."""
    db._storage.clear()
    db._storage.update(copy.deepcopy(backup))
    added = {f"{prefix}{i}" for i in range(8)}
    for name in sorted(added):
        laptop.create_entry(folder, name, [{"key": "password", "value": name, "sensitive": True}])
    assert _client(laptop, url).push()["accepted"]
    return added


def _save(tab: WebTab, folder: str, name: str) -> None:
    saved = tab.do("save_object", mode="entry", name=name, parent=folder,
                   fields=[{"key": "password", "value": "w"}])
    assert saved["error"] is None, saved


def test_web_full_pull_notices_a_restored_server(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    log = tmp_path / "tab.log"

    tab = WebTab(url, log)
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None

        # The full pull of "Use the server's version" in the open page.
        backup = copy.deepcopy(db._storage)
        _save(tab, folder, "web01")
        _save(tab, folder, "web02")
        added = _restore_and_move_on(db, backup, laptop, folder, url, "lap")
        declined = tab.do("use_server", confirm=False)
        assert "no longer holds commit" in (declined["error"] or ""), declined
        assert any("rollback_confirm" in c for c in declined["confirms"]), declined
        assert {"web01", "web02"} <= _names(declined["view"])
        accepted = tab.do("use_server", confirm=True)
        assert accepted["error"] is None and not accepted["rejections"], accepted
        assert _names(accepted["view"]) == {"db01"} | added

        # The full pull of a sign-in in a new tab of this browser.
        backup = copy.deepcopy(db._storage)
        _save(tab, folder, "web03")
        more = _restore_and_move_on(db, backup, laptop, folder, url, "pc")
        tab = WebTab(url, log, tab.close())
        refused = tab.do("login", username="admin", password=PASSWORD, confirm=False)
        assert "no longer holds commit" in (refused["error"] or ""), refused
        tab = WebTab(url, log, tab.close())
        signed_in = tab.do("login", username="admin", password=PASSWORD, confirm=True)
        assert signed_in["error"] is None and not signed_in["rejections"], signed_in
        assert any("rollback_confirm" in c for c in signed_in["confirms"]), signed_in
        assert _names(signed_in["view"]) == {"db01"} | added | more
    finally:
        tab.kill()
    laptop.lock()
