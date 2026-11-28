"""Review 8bc70f7 M7 (goal #420), web: the unmodified page against the real server.

* An edit saved after a push of the same item whose reply was lost (or while
  that push was out) got the pushed version's number again: the tree had not
  moved on. The pull then took the landed push as the edit's base
  (adopt_as_base), but the edit kept its number, so the server refused it as
  not newer on every Retry, and it never went out.
* A full pull (Use the server's version, a 410, the team log served again)
  started from nothing, so it took an older version of an item this browser
  held, as a delta pull never does (webPulledIsStale).
* Two saves in one tab: the queue record written by the first was put back
  over the tab's queue once IndexedDB finished, and a change the second
  queued meanwhile left the queue (in memory and in the next write); offline,
  it was gone.
"""

from __future__ import annotations

import copy

from sezam import cli
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_review_web import WEB_DIRTY_SAVE, pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB
from tests.test_web_push_limits import _run
from tests.web_tab import WebTab

LOST = {"method": "POST", "path": "/api/sync", "mode": "after"}
DOWN = {"method": "POST", "path": "/api/sync", "mode": "before"}


def _ok(result: dict) -> dict:
    assert result["error"] is None, result
    assert not result["rejections"], result
    return result


def _password(result: dict, entry: str):
    return next(e["password"] for e in result["view"]["entries"] if e["id"] == entry)


def _setup(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    entry = laptop.create_entry(folder, "db01", [{"key": "password", "value": "v1", "sensitive": True}])
    other = laptop.create_entry(folder, "db02", [{"key": "password", "value": "o1", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    return laptop, folder, entry, other


def test_an_edit_after_a_landed_push_whose_reply_was_lost_goes_out(server, tmp_path):  # noqa: F811
    url, _db = server
    laptop, _folder, entry, _other = _setup(url, tmp_path)
    tab = WebTab(url, tmp_path / "tab.log")
    try:
        _ok(tab.do("login", username="admin", password=PASSWORD))
        lost = tab.do("save_object", mode="entry", id=entry, fields=[{"key": "password", "value": "a"}], fail=LOST)
        assert lost["failure"]["fired"] and lost["view"]["dirty"], lost
        # The user saves again before any pull: the same version number.
        tab.do("save_object", mode="entry", id=entry, fields=[{"key": "password", "value": "b"}])
        for _ in range(3):  # the banner's Retry, then the periodic pull
            tab.do("retry")
            seen = tab.do("refresh")
        assert seen["view"]["dirty"] == [] and seen["view"]["conflicts"] == [], seen["view"]
        assert _password(seen, entry) == "b"
    finally:
        tab.kill()
    _client(laptop, url).pull()
    assert _entry_value(laptop, "Servers", "db01", "password") == "b"
    laptop.lock()


def test_a_full_pull_keeps_a_newer_version_than_the_server_serves(server, tmp_path):  # noqa: F811
    url, db = server
    laptop, _folder, entry, other = _setup(url, tmp_path)
    desk = _client(laptop, url)
    rows = db._storage["vault_objects"]
    old = copy.deepcopy(next(o for o in rows if o["id"] == other))
    tab = WebTab(url, tmp_path / "tab.log")
    try:
        _ok(tab.do("login", username="admin", password=PASSWORD))
        _ok(tab.do("save_object", mode="entry", id=other, fields=[{"key": "password", "value": "o2"}]))
        # A conflict on another item: the desktop and the page (offline) both edit it.
        laptop.update_entry(entry, fields=[{"key": "password", "value": "desk", "sensitive": True}])
        assert desk.push()["accepted"]
        tab.do("save_object", mode="entry", id=entry, fields=[{"key": "password", "value": "web"}], fail=DOWN)
        tab.do("retry")
        held = _ok(tab.do("refresh"))
        assert held["view"]["conflicts"] == [entry] and _password(held, other) == "o2", held["view"]
        # The server serves the item's first version again (validly signed),
        # as a new commit.
        row = next(o for o in rows if o["id"] == other)
        row.update({**copy.deepcopy(old), "commit_seq": max(o["commit_seq"] for o in rows) + 1})
        # "Use the server's version": a full pull.
        after = _ok(tab.do("use_server"))
        assert after["view"]["conflicts"] == [], after["view"]
        assert _password(after, entry) == "desk"
        assert _password(after, other) == "o2", "a full pull took an older version back"
    finally:
        tab.kill()
    laptop.lock()


PUSH = [
    "assertNotStackedOnConflict", "assertTeamLogAllowsWrite", "webWriteState", "syncPayloadBytes", "assertSyncObjectFits",
    "pushEncryptedVaultObject", "pushEncryptedVaultObjectLocked", "renumberedAboveBase", "webBase",
    "withWebBase", "isSameSyncVersion", "webDirtyStateRecordId", "webDirtyStateAAD", "loadWebDirtyState",
    "saveWebDirtyState", "validWebOutboxOps", "idbKeysRequest", "hexToBytes", "bytesToHex",
] + WEB_DIRTY_SAVE


def test_a_change_queued_while_the_tab_writes_its_queue_stays_queued():
    result = _run(PUSH, FAKE_IDB + """
        state.kek = newKek;
        t = key => key;
        ensureSodium = async () => sodium;
        renderWebSyncConflicts = () => {};
        apiFetch = async () => { throw new Error('offline'); };
        // One save of the queue record at a time, as navigator.locks gives a page.
        const tails = {};
        navigator = { locks: { request(name, op) {
            const run = (tails[name] || Promise.resolve()).then(() => op());
            tails[name] = run.then(() => {}, () => {});
            return run;
        } } };
        // The first write's transaction stays open until released.
        let reached, release;
        const atWrite = new Promise(resolve => { reached = resolve; });
        const released = new Promise(resolve => { release = resolve; });
        let hold = true;
        const plainTransaction = fakeDb.transaction;
        fakeDb.transaction = (name, mode) => {
            const tx = plainTransaction.call(fakeDb, name, mode);
            if (mode !== 'readwrite' || !hold) return tx;
            hold = false;
            let done = null;
            Object.defineProperty(tx, 'oncomplete', {
                set(fn) { done = fn; },
                get() { return done && (() => { reached(); released.then(done); }); },
            });
            return tx;
        };
        const entry = id => ({ id, object_type: 'entry', version: 2, is_deleted: false,
                               payload: Buffer.from(id).toString('base64') });
        const outcome = push => push.then(() => null, err => err.message);
        const x = outcome(pushEncryptedVaultObject(entry('X')));
        await atWrite;
        const y = outcome(pushEncryptedVaultObject(entry('Y')));
        await new Promise(resolve => setTimeout(resolve, 20));  // Y queued; its write waits
        release();
        const errors = [await x, await y];
        const stored = await loadWebDirtyState(sodium);
        return { errors, memory: Object.keys(state.outbox).sort(), stored: Object.keys(stored.objects).sort() };
    """)
    assert result["errors"] == ["offline", "offline"]
    assert result["memory"] == ["X", "Y"], "the tab's queue lost the change saved during the write"
    assert result["stored"] == ["X", "Y"], "the stored queue lost the change saved during the write"
