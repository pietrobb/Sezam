"""Review 7c10379 H4, web: folders a read-only member wrote below the root.

The same objects as tests/test_review7_forged_root_folder_desktop_h4.py: a
folder the member sealed with the root's shared key and an item in it
(stored by a server before b8c3cb8, or served by a lying one), and in her
personal folder one item under her own key and one under the shared key.
The page showed the shared-key ones as the company's own; now it shows her
personal folder and the item under her key only.
"""

from __future__ import annotations

from tests.test_integration_client_server import PASSWORD, server  # noqa: F401  (fixture)
from tests.test_review7_forged_root_folder_desktop_h4 import forged  # noqa: F401  (fixture)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.web_tab import WebTab


def test_web_does_not_show_a_members_folder_sealed_with_the_shared_key(forged, tmp_path):  # noqa: F811
    url, _laptop, _root, folder, (entry, own_item, shared_key_item), personal, _alice = forged
    tab = WebTab(url, tmp_path / "tab.log")
    try:
        login = tab.do("login", username="admin", password=PASSWORD)
        assert login["error"] is None, login
        view = tab.do("refresh")
        assert view["error"] is None, view
        nodes = {n["id"] for n in view["view"]["nodes"]}
        entries = {e["id"] for e in view["view"]["entries"]}
        assert folder not in nodes
        assert entry not in entries and shared_key_item not in entries
        assert personal in nodes and own_item in entries
    finally:
        tab.kill()
