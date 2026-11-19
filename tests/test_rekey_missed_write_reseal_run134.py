"""Capability review run 134: a write a re-key missed is resealed even when its
writer lost its record of it.

SM74 had the web reseal its own entry that reached the server just before
another device's re-key (a member removed), from a list of its accepted writes
sealed under the KEK. After a password change elsewhere the page signed in
again without that list (and a new tab never had it); the desktop reseals only
its own writes, so the entry stayed under the old key the removed member
holds. The folder's owner now finishes the re-key for any writer's live item.
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

NEW_PASSWORD = "new-pw-run134!"


def _setup(url, db, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Team")
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)
    member = _member(url, tmp_path, laptop, desk)
    revocation.grant_member(laptop, desk, member, folder, "read", confirm_fingerprint=lambda _fp: True)
    old_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]
    tab = WebTab(url, tmp_path / "tab.log")
    assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
    saved = tab.do("save_object", mode="entry", name="db01", parent=folder,
                   fields=[{"key": "password", "value": "web-secret"}])
    assert saved["error"] is None and not saved["view"]["dirty"], saved
    entry = next(o["id"] for o in db._storage["vault_objects"]
                 if o["object_type"] == "entry" and o.get("parent_ref") == folder)
    assert revocation.revoke_member(laptop, desk, member) == 1  # without pulling the entry
    new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]
    assert new_dek != old_dek and _entry_dek(db, entry) == old_dek
    return laptop, desk, tab, entry, new_dek


def test_web_reseals_after_signing_in_again_after_a_password_change_elsewhere(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, desk, tab, entry, new_dek = _setup(url, db, tmp_path)
    try:
        proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
        proof[:] = b"\x00" * len(proof)
        laptop.unlock(NEW_PASSWORD)
        assert _client(laptop, url).push()["accepted"]  # re-sends the retired DEK unbound
        assert tab.do("refresh")["error"] == "error.session_ended"
        assert tab.do("login", username="admin", password=NEW_PASSWORD)["error"] is None
        refreshed = tab.do("refresh")
        assert refreshed["error"] is None and not refreshed["view"]["dirty"], refreshed
        assert not refreshed["view"]["conflicts"], refreshed
        assert _entry_dek(db, entry) == new_dek  # not the key the removed member holds
    finally:
        tab.kill()
    desk.pull()
    assert _entry_value(laptop, "Team", "db01", "password") == "web-secret"
    laptop.lock()


def test_folder_owner_desktop_reseals_a_web_write_the_rekey_missed(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, desk, tab, entry, new_dek = _setup(url, db, tmp_path)
    tab.kill()  # the page that wrote it never comes back
    desk.pull()
    assert desk.push()["accepted"]
    assert _entry_dek(db, entry) == new_dek
    assert not desk.get_pull_conflicts()
    assert _entry_value(laptop, "Team", "db01", "password") == "web-secret"
    laptop.lock()
