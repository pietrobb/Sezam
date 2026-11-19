"""Review main@7c10379 (R7-H, web; d615826 H7 / c476b20 bypassed).

A login that finds the browser's keypair cache under another KEK sets the
records sealed under the old KEK aside before the pull reads them, and only
then replaces the cache (c476b20). A login with a .sezam-key backup skipped
both: after the password was changed on the desktop, the backup exported
there replaced the cache at once and the unsent queue sealed under the old
password failed the pull ("Invalid encrypted dirty state"). The cache now
opened with the new password, so this and every later login of the browser
failed the same way, and the queued edit was out of reach.
"""

from __future__ import annotations

import pytest

import tests.web_tab as wt
from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.crypto.keys import export_sezam_key
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401

# The login screen's "import .sezam-key" file input, chosen by the user.
CHOOSE_BACKUP = r"""
  async choose_backup(step) {
    const bytes = Uint8Array.from(Buffer.from(step.hex, 'hex'));
    importFile = { files: [{ arrayBuffer: async () => bytes.buffer }] };
    return null;
  },
  async view() { return null; },"""


@pytest.fixture
def backup_tab(monkeypatch):
    tab = (
        wt.TAB.replace("id === 'sezam-key-import' ? null", "id === 'sezam-key-import' ? importFile", 1)
        .replace("let shares = [];", "let shares = [];\nlet importFile = null;", 1)
        .replace("  async view() { return null; },", CHOOSE_BACKUP, 1)
    )
    assert tab.count("importFile") == 3
    monkeypatch.setattr(wt, "TAB", tab)


def _login(url, log, idb, **step):
    tab = wt.WebTab(url, log, idb=idb)
    try:
        if "backup" in step:
            assert tab.do("choose_backup", hex=step.pop("backup"))["error"] is None
        result = tab.do("login", username="admin", password=NEW_PASSWORD)
        return result, tab.close()
    finally:
        tab.kill()


def test_a_backup_login_after_a_password_change_sets_the_old_queue_aside(
    server, tmp_path, backup_tab  # noqa: F811
):
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    node = laptop.create_node("Servers")
    cli._server_connect_flow(url, laptop, PASSWORD)

    # The browser queues an edit while offline, under the old password.
    tab = wt.WebTab(url, tmp_path / "before.log")
    try:
        assert tab.do("login", username="admin", password=PASSWORD)["error"] is None
        queued = tab.do("save_object", mode="entry", name="offline-web", parent=node,
                        fields=[{"key": "password", "value": "w1"}],
                        fail={"method": "POST", "path": "/api/sync", "mode": "before"})
        assert queued["view"]["dirty"], queued
        idb = tab.close()
    finally:
        tab.kill()

    # The desktop changes the password and exports a backup under the new one.
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    _client(laptop, url).push()
    backup = tmp_path / "admin.sezam-key"
    export_sezam_key(
        laptop.keypair, laptop.current_kek, backup,
        bytes.fromhex(laptop.db.get_meta("argon2_salt")),
        Argon2Params.from_dict(laptop.db.get_meta_json("argon2_params")),
    )

    first, idb = _login(url, tmp_path / "backup.log", idb, backup=backup.read_bytes().hex())
    assert first["error"] is None, first
    assert first["view"]["unlocked"], first
    assert first["alerts"] == ["sync.old_kek_records_set_aside"], first
    assert len(first["view"]["set_aside"]) == 1, first

    # Later logins from the cache the backup left work as well.
    again, idb = _login(url, tmp_path / "again.log", idb)
    assert again["error"] is None, again
    assert again["view"]["unlocked"], again

    # The edit queued under the old password is restored with it and sent.
    tab = wt.WebTab(url, tmp_path / "restore.log", idb=idb)
    try:
        assert tab.do("login", username="admin", password=NEW_PASSWORD)["error"] is None
        restored = tab.do("restore_set_aside", password=PASSWORD)
        assert restored["view"]["set_aside"] == [], restored
        assert restored["view"]["dirty"] == [], restored
    finally:
        tab.kill()
    _client(laptop, url).pull()
    assert {e["name"] for e in laptop.list_entries(node)} == {"offline-web"}
    laptop.lock()
