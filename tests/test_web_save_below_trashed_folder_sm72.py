"""Stateful test finding SM72 (web device): nothing could be saved in a folder
whose parent another device had deleted meanwhile.

The web created a folder in a folder; the laptop, not having pulled that,
deleted the parent. Its delete landed, so the server holds a live folder
below a deleted one, and the page shows it at the top. Saving a folder or an
entry in it walked up for a personal folder, met the deleted parent and threw
'Parent folder is unavailable.'. The walk now goes on through the deleted
folder's tombstone, which the page still holds.
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
