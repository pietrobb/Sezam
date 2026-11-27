"""Stateful test finding SM72 (web device): nothing could be saved in a folder
whose parent another device had deleted meanwhile.

The web created a folder in a folder; the laptop, not having pulled that,
deleted the parent. Its delete landed, so the server holds a live folder
below a deleted one, and the page shows it at the top. Saving a folder or an
entry in it walked up for a personal folder, met the deleted parent and threw
'Parent folder is unavailable.'. The walk now goes on through the deleted
folder's tombstone, which the page still holds.

R16-N29 (manual CI 45931201600 stateful-deep on bb255e2): the walk opened the
tombstone's blob only at the row version or one below. A delete kept over a
conflict ("keep mine") goes out a version above the server's, so its blob is
sealed two versions below the row, and the walk threw the same error. It now
reads the tombstone at every version below it, as sealed.py does.
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
from tests.test_sync_state_machine import snapshot
from tests.web_tab import WebTab


def test_web_saves_in_a_live_folder_below_a_deleted_one(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    parent = laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        made = tab.do("save_object", mode="folder", name="web", parent=parent)
        assert made["error"] is None, made
        child = next(n["id"] for n in made["view"]["nodes"] if n["name"] == "web")

        laptop.delete_node(parent)
        desk.push()
        on_server = {o["id"]: o["is_deleted"] for o in db._storage["vault_objects"]}
        assert on_server[parent] and not on_server[child]

        assert tab.do("refresh")["error"] is None
        folder = tab.do("save_object", mode="folder", name="inner", parent=child)
        assert folder["error"] is None, folder
        entry = tab.do("save_object", mode="entry", name="db01", parent=child,
                       fields=[{"key": "password", "value": "s3cret"}])
        assert entry["error"] is None, entry
        assert not entry["view"]["dirty"] and not entry["rejections"], entry
    finally:
        tab.kill()

    desk.pull()
    below = {state[1] for state in snapshot(laptop).values() if state[0] and state[2] == child}
    assert below == {"inner", "db01"}, below
    laptop.lock()


def test_web_saves_below_a_delete_kept_over_a_conflict(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    parent = laptop.create_node("Servers")
    child = laptop.create_node("Web", parent_id=parent)
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        for folder, name, under in ((parent, "Servers2", None), (child, "Web2", parent)):
            renamed = tab.do("save_object", mode="folder", id=folder, name=name, parent=under)
            assert renamed["error"] is None, renamed

        # The laptop deletes both on the versions it holds; the page's renames
        # make both conflicts. It keeps its delete of the parent (sent a
        # version above the server's, its blob sealed two below that) and the
        # page's rename of the child.
        laptop.delete_node(parent)
        desk.push()
        desk.pull()
        desk.resolve_conflict(parent, "local")
        desk.resolve_conflict(child, "server")
        desk.push()
        rows = {o["id"]: o for o in db._storage["vault_objects"]}
        assert rows[parent]["is_deleted"] and rows[parent]["version"] == 3, rows[parent]
        assert not rows[child]["is_deleted"] and rows[child]["parent_ref"] == parent

        assert tab.do("refresh")["error"] is None
        folder = tab.do("save_object", mode="folder", name="inner", parent=child)
        assert folder["error"] is None, folder
        assert not folder["view"]["dirty"] and not folder["rejections"], folder
    finally:
        tab.kill()

    desk.pull()
    below = {state[1] for state in snapshot(laptop).values() if state[0] and state[2] == child}
    assert below == {"inner"}, below
    laptop.lock()
