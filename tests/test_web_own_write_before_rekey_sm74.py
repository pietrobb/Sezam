"""Stateful test finding SM74 (web device): the web's own write that reached the
server just before another device's re-key stayed under the old folder key.

The admin shared a folder with a member. The web saved an entry in it and the
server took it. The laptop, which had not pulled that, removed the member: its
re-key sealed the folder's items it knew under a new key, the web's entry not
among them, and the server took the re-key as well. The entry stayed sealed
with the old key the removed member holds. The desktop reseals its own such
write after a pull (SM28); the page now does too.
"""

from __future__ import annotations

from sezam import cli
from sezam.vault import revocation
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_web_queued_change_after_rekey_sm70 import _entry_dek, _member
from tests.web_tab import WebTab


def test_own_web_write_is_sealed_again_after_a_rekey_that_missed_it(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Team")
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)
    member = _member(url, tmp_path, laptop, desk)
    revocation.grant_member(laptop, desk, member, folder, "read", confirm_fingerprint=lambda _fp: True)
    old_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        saved = tab.do("save_object", mode="entry", name="db01", parent=folder,
                       fields=[{"key": "password", "value": "web-secret"}])
        assert saved["error"] is None and not saved["view"]["dirty"], saved
        entry = next(o["id"] for o in db._storage["vault_objects"]
                     if o["object_type"] == "entry" and o.get("parent_ref") == folder)
        assert _entry_dek(db, entry) == old_dek

        assert revocation.revoke_member(laptop, desk, member) == 1  # without pulling the entry
        new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]
        assert new_dek != old_dek
        assert _entry_dek(db, entry) == old_dek

        refreshed = tab.do("refresh")
        assert refreshed["error"] is None, refreshed
        assert not refreshed["view"]["dirty"], refreshed
        assert _entry_dek(db, entry) == new_dek  # not the key the removed member holds
    finally:
        tab.kill()
    desk.pull()
    assert _entry_value(laptop, "Team", "db01", "password") == "web-secret"
    laptop.lock()
