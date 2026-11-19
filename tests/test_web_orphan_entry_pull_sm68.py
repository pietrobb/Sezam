"""Stateful test finding SM68 (web device): an entry left in a deleted folder
stopped every pull of the web page.

The web edited an entry; the desktop, not having pulled that, deleted its
folder. The folder's delete landed, the entry's conflicted and the desktop
kept the server's version: the server holds a live entry under a deleted
folder. The page's pull runs the legacy personal-folder migration over every
object, which walks the entry's parents, found the folder missing and threw
"Parent folder is unavailable." - on this and every later pull. An object
whose folder the page does not hold has nothing to migrate; the pull goes on.
"""

from __future__ import annotations

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab


def test_web_pull_survives_an_entry_whose_folder_was_deleted(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    entry = laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        edited = tab.do("save_object", mode="entry", id=entry, name="db01-web", parent=folder,
                        fields=[{"key": "password", "value": "web"}])
        assert edited["error"] is None, edited

        laptop.delete_node(folder)
        pushed = desk.push()
        assert [c["id"] for c in pushed["conflicts"]] == [entry]
        desk.pull()
        desk.resolve_conflict(entry, "server")
        on_server = {o["id"]: o["is_deleted"] for o in db._storage["vault_objects"]}
        assert on_server[folder] and not on_server[entry]

        pulled = tab.do("refresh")
        assert pulled["error"] is None, pulled
        assert not pulled["rejections"], pulled
        assert pulled["view"]["unlocked"]
        assert folder not in {n["id"] for n in pulled["view"]["nodes"]}
    finally:
        tab.kill()
    laptop.lock()
