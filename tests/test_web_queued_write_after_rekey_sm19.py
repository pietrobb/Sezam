"""Stateful test finding R16-Z SM19a (web device): a queued write the page can
no longer open after its folder was re-keyed.

The team has a log. The page saved an entry in a shared folder while the
network failed, so the encrypted entry stayed queued (in the failing run the
reply was lost: the server took it and the page queued it as unsent). The
admin's desktop then removed the member and re-keyed the folder. The page
pulled the re-key: the log refuses the folder's old key for reading, and the
page keeps it apart only to seal the queued write again when Retry sends it.
Until then (and for good while the write is in conflict, which Retry does not
send) the page showed its own entry as an encrypted item it cannot open.

Invariant (INV-7, docs/SYNC_SINGLE_SOURCE.md point 1, as the desktop's
_reseal_under_successors and the phone's resealUnsentOnCurrentKeys): a write
queued under a folder key a re-key replaced is sealed again under the folder's
current key as soon as the page pulls the re-key, conflict or not.
"""

from __future__ import annotations

import pytest

from sezam import cli
from sezam.vault import revocation
from sezam.vault.team_migration import found_team_log
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_web_queued_change_after_rekey_sm70 import _entry_dek, _member
from tests.web_tab import WebTab


@pytest.mark.parametrize("mode", ["before", "after"])
def test_a_queued_web_write_opens_after_its_folder_is_rekeyed(server, tmp_path, mode):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Team")
    cli._server_connect_flow(url, laptop, PASSWORD)
    desk = _client(laptop, url)
    member = _member(url, tmp_path, laptop, desk)
    revocation.grant_member(laptop, desk, member, folder, "read", confirm_fingerprint=lambda _fp: True)
    found_team_log(laptop, desk, lambda _uid, _fp: True)
    old_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]

    tab = WebTab(url, tmp_path / "tab.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        saved = tab.do("save_object", mode="entry", name="db01", parent=folder,
                       fields=[{"key": "password", "value": "web-secret"}],
                       fail={"method": "POST", "path": "/api/sync", "mode": mode})
        assert saved["view"]["dirty"], saved
        entry = saved["view"]["dirty"][0]

        desk.pull()
        assert revocation.revoke_member(laptop, desk, member) == 1
        new_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))[0]
        assert new_dek != old_dek

        pulled = tab.do("refresh")
        assert pulled["error"] is None, pulled
        shown = {e["id"]: e for e in pulled["view"]["entries"]}
        assert not shown[entry]["undecryptable"], (pulled["view"]["dirty"], pulled["view"]["conflicts"])
        assert shown[entry]["name"] == "db01"

        retried = tab.do("retry")
        if retried["view"]["conflicts"]:
            retried = tab.do("use_server", confirm=True)
        assert not retried["view"]["dirty"], retried
        assert not [e for e in retried["view"]["entries"] if e["undecryptable"]], retried["view"]
        assert _entry_dek(db, entry) == new_dek  # not the key the removed member holds
    finally:
        tab.kill()
    laptop.lock()
