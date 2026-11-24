"""R16-Z SM22 on the web device: a folder move another device's move crossed.

The laptop moved X below Y and pushed; the web page, not having pulled that,
moved Y below X. The server took both and every device held a parent cycle.
The server now refuses the page's move (tests/test_crossed_moves_sm22.py);
the page shows it as a conflict that says why, and 'Use the server's
version' leaves both devices on the server's tree with nothing waiting.
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


def test_web_crossed_move_is_a_conflict_that_says_why(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    top = laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        # Folders the page makes share their parent's key, so the page moves them.
        for name in ("X", "Y"):
            assert tab.do("save_object", mode="folder", name=name, parent=top)["error"] is None
        made = {n["name"]: n["id"] for n in tab.do("refresh")["view"]["nodes"]}
        x, y = made["X"], made["Y"]
        desk.pull()
        laptop.move_node(x, y)
        desk.push()

        moved = tab.do("save_object", mode="folder", id=y, parent=x)
        assert moved["error"] and "inside this folder" in moved["error"], moved
        assert moved["view"]["conflicts"] == [y], moved
        on_server = {o["id"]: o["parent_ref"] for o in db._storage["vault_objects"]}
        assert on_server[x] == y and on_server[y] == top

        assert tab.do("use_server")["error"] is None
        settled = tab.do("refresh")
        assert settled["error"] is None, settled
        parents = {n["id"]: n["parent_ref"] for n in settled["view"]["nodes"]}
        assert parents[x] == y and parents[y] == top, parents
        assert not settled["view"]["dirty"] and not settled["view"]["conflicts"], settled
    finally:
        tab.kill()

    desk.pull()
    rows = {r["id"]: r["parent_id"] for r in laptop.db.fetchall("SELECT id, parent_id FROM nodes")}
    assert rows[x] == y and rows[y] == top
    laptop.lock()
