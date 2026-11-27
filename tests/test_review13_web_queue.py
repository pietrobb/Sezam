"""Review c78fd19 (R13-5), web medium findings.

* Two tabs over one IndexedDB each saved their own copy of the queue whole:
  one tab's save dropped what the other had queued, a member's pending
  removal too. A save now runs under navigator.locks and merges what this
  tab changed into the stored queue.
* The queue went out in the order it was made, not folders first.
* An edit after a push whose reply was lost was a conflict with itself:
  the browser now remembers what it sent (own_earlier_push).
* A change an older version queued without its base was never sent.
* A delta pull took an object back to an older version (app.js:2925).
* An old teamlog.js from the browser's cache broke the login: the server
  now versions every asset URL by its content.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path

from tests.test_review_web import APP, _function, _run, pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB, FUNCTIONS as OLD_KEK_FUNCTIONS

ROOT = Path(__file__).resolve().parents[1]

NEW = ["openWebDirtyState", "withWebDirtyStateLock", "mergeWebKeyed", "mergeWebDirtyState", "replaceWebKeyed"]
FUNCTIONS = list(dict.fromkeys(OLD_KEK_FUNCTIONS + ["loadFromIndexedDB"] + [
    name for name in NEW if f"function {name}(" in APP
]))

TABS = FAKE_IDB + """
  decryptLoginKeypair = () => ({ keypairBytes: new Uint8Array(96) });
  state.kek = newKek;
  // A tab: its own queue in memory, as loaded by its first pull.
  const QUEUE = ['outbox', 'syncConflicts', 'outboxOps', 'outboxSent', 'outboxBaseline'];
  const openTab = async () => {
    const pending = await loadWebDirtyState(sodium);
    return { outbox: pending.objects, syncConflicts: pending.conflicts, outboxOps: pending.ops,
             outboxSent: pending.sent || {}, outboxBaseline: JSON.parse(JSON.stringify(pending)) };
  };
  const inTab = async (tab, fn) => {
    for (const k of QUEUE) state[k] = tab[k];
    try { return await fn(); } finally { for (const k of QUEUE) tab[k] = state[k]; }
  };
  const removal = { kind: 'rekey', revoked_user_id: 'BOB', phase: 'prepared', objects: [] };
"""


def test_a_second_tab_keeps_what_the_first_one_queued():
    script = TABS + """
      const a = await openTab();
      const b = await openTab();
      // Tab A queues Bob's removal; tab B, which loaded the queue before, an edit.
      await inTab(a, () => saveWebDirtyState(state.outbox, state.syncConflicts, sodium, [removal]));
      await inTab(b, async () => {
        state.outbox.X = { id: 'X', object_type: 'entry', version: 2 };
        await saveWebDirtyState(state.outbox, state.syncConflicts, sodium);
      });
      const afterB = await loadWebDirtyState(sodium);
      // Tab A finishes the removal; B's edit stays.
      await inTab(a, () => saveWebDirtyState(state.outbox, state.syncConflicts, sodium, []));
      const afterA = await loadWebDirtyState(sodium);
      return {
        afterB: [Object.keys(afterB.objects), afterB.ops.map(op => op.revoked_user_id)],
        tabB: [Object.keys(b.outbox), (b.outboxOps || []).map(op => op.revoked_user_id)],
        afterA: [Object.keys(afterA.objects), afterA.ops.length],
      };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    # c78fd19: tab B's save put [X], [] over the stored removal.
    assert result["afterB"] == [["X"], ["BOB"]]
    assert result["tabB"] == [["X"], ["BOB"]]  # the other tab's work joins this one
    assert result["afterA"] == [["X"], 0]


def test_a_write_one_tab_sent_stays_when_the_other_changed_it_again():
    script = TABS + """
      state.outboxBaseline = null;
      const a = await openTab();
      await inTab(a, async () => {
        state.outbox.X = { id: 'X', object_type: 'entry', version: 2, payload: 'p2' };
        await saveWebDirtyState(state.outbox, state.syncConflicts, sodium);
      });
      const b = await openTab();
      await inTab(b, async () => {
        state.outbox.X = { id: 'X', object_type: 'entry', version: 2, payload: 'p2-again' };
        await saveWebDirtyState(state.outbox, state.syncConflicts, sodium);
      });
      // Tab A's push of p2 was accepted: it takes X out.
      await inTab(a, async () => {
        delete state.outbox.X;
        await saveWebDirtyState(state.outbox, state.syncConflicts, sodium);
      });
      return (await loadWebDirtyState(sodium)).objects.X?.payload || null;
    """
    assert _run(FUNCTIONS, f"(async () => {{ {script} }})()") == "p2-again"


def test_saves_take_a_lock_all_tabs_share():
    script = TABS + """
      const names = [];
      let held = 0, overlap = false, tail = Promise.resolve();
      navigator = { locks: { request: (name, fn) => {
        names.push(name);
        const run = tail.then(async () => { if (held++) overlap = true; try { return await fn(); } finally { held--; } });
        tail = run.catch(() => {});
        return run;
      } } };
      state.outboxBaseline = null;
      await Promise.all([1, 2, 3].map(n => {
        state.outbox['X' + n] = { id: 'X' + n, object_type: 'entry', version: 1 };
        return saveWebDirtyState(state.outbox, state.syncConflicts, sodium);
      }));
      return { names: [...new Set(names)], overlap, stored: Object.keys((await loadWebDirtyState(sodium)).objects).sort() };
    """
    result = _run(FUNCTIONS, f"(async () => {{ {script} }})()")
    assert result == {"names": ["sezam:dirty_state:ME"], "overlap": False, "stored": ["X1", "X2", "X3"]}


def test_what_was_sent_is_kept_with_its_write_only():
    script = TABS + """
      state.outboxBaseline = null;
      state.outbox = { X: { id: 'X', object_type: 'entry', version: 5 } };
      state.outboxSent = { X: [[5, 'h5']], GONE: [[2, 'h2']] };
      await saveWebDirtyState(state.outbox, state.syncConflicts, sodium);
      return (await loadWebDirtyState(sodium)).sent;
    """
    assert _run(FUNCTIONS, f"(async () => {{ {script} }})()") == {"X": [[5, "h5"]]}


RECONCILE = [name for name in (
    "syncCoreVersion", "withLegacyWebBase", "webOwnEarlierPush", "reconcileWebDirtyState",
) if f"function {name}(" in APP]


def _reconcile(outbox: dict, server: list, sent: dict | None = None):
    script = f"""
      const r = reconcileWebDirtyState({server!r}, {outbox!r}, {{}}, {sent or {}!r});
      return {{ outbox: r.outbox, conflicts: Object.keys(r.conflicts) }};
    """
    return _run(RECONCILE, f"(async () => {{ {script} }})()")


def test_an_edit_after_a_push_whose_reply_was_lost_is_no_conflict():
    # v5 (h5) landed, its reply was lost; the user edited again (v6, base v4).
    outbox = {"X": {"id": "X", "object_type": "entry", "version": 6, "payload_hash": "h6",
                    "parent_ref": "F", "is_deleted": 0, "base_version": 4, "base_payload_hash": "h4"}}
    server = [{"id": "X", "object_type": "entry", "version": 5, "payload_hash": "h5",
               "parent_ref": "F", "is_deleted": 0}]
    result = _reconcile(outbox, server, {"X": [[5, "h5"], [6, "h6"]]})
    assert result["conflicts"] == []  # c78fd19: a conflict with its own push
    assert result["outbox"]["X"]["base_version"] == 5 and result["outbox"]["X"]["base_payload_hash"] == "h5"
    # Another device's v5 is still a conflict.
    assert _reconcile(outbox, server, {"X": [[6, "h6"]]})["conflicts"] == ["X"]


def test_a_change_queued_before_the_upgrade_gets_its_base():
    outbox = {"X": {"id": "X", "object_type": "node", "version": 5, "payload_hash": "h5",
                    "parent_ref": "F", "is_deleted": 0}}
    on_base = [{"id": "X", "object_type": "node", "version": 4, "payload_hash": "h4",
                "parent_ref": "F", "is_deleted": 0}]
    result = _reconcile(outbox, on_base)
    assert result["conflicts"] == []  # c78fd19: refused as a new object for good
    assert result["outbox"]["X"]["base_version"] == 4 and result["outbox"]["X"]["base_payload_hash"] == "h4"
    # The server moved on past it: a conflict, as before.
    ahead = [{**on_base[0], "version": 5, "payload_hash": "other"}]
    assert _reconcile(outbox, ahead)["conflicts"] == ["X"]


def test_a_delta_pull_never_takes_an_object_back():
    script = """
      const held = { id: 'X', object_type: 'entry', version: 5, payload_hash: 'h5', is_deleted: 0, commit_seq: 40 };
      const pulled = (version, hash) => ({ id: 'X', object_type: 'entry', version, payload_hash: hash });
      const tomb = { ...held, is_deleted: 1 };
      return [
        webPulledIsStale(held, pulled(4, 'h4'), 10),  // an older version
        webPulledIsStale(held, pulled(5, 'other'), 10),  // another copy of v5
        webPulledIsStale(held, pulled(5, 'h5'), 10),
        webPulledIsStale(held, pulled(6, 'h6'), 10),
        webPulledIsStale(undefined, pulled(1, 'h1'), 10),
        webPulledIsStale(tomb, pulled(5, 'other'), 50),  // its tombstone was collected (SM8)
        webPulledIsStale(tomb, pulled(5, 'other'), 10),
        webPulledIsStale(tomb, pulled(3, 'h3'), 50),  // INV-3: older, whatever the floor
        // R17-N1: the version held with other signed fields is another copy.
        webPulledIsStale(held, { ...pulled(5, 'h5'), parent_ref: 'P' }, 10),
        webPulledIsStale(held, { ...pulled(5, 'h5'), is_deleted: 1 }, 10),
        webPulledIsStale(held, { ...pulled(5, 'h5'), object_type: 'node' }, 10),
      ];
    """
    assert _run(["webPulledIsStale"], f"(async () => {{ {script} }})()") == [
        True, True, False, False, False, False, True, True, True, True, True,
    ]
    pull = _function("pullAndBuildTreeLocked")
    guard = pull.index("webPulledIsStale(held, obj, gcFloorSeq)")
    assert pull.rindex("if (heldCopies) {", 0, guard) > pull.index("verifiedObjects.push(obj);")
    assert guard < pull.index("reconcileWebDirtyState(")


def test_retry_sends_keys_and_folders_first():
    script = """
      const order = webPushOrder([
        { id: 'E', object_type: 'entry', parent_ref: 'F' },
        { id: 'F', object_type: 'node', parent_ref: 'G' },
        { id: 'G', object_type: 'node', parent_ref: null },
        { id: 'K', object_type: 'dek', parent_ref: 'G' },
      ]);
      return order.map(o => o.id);
    """
    assert _run(["webPushOrder"], f"(async () => {{ {script} }})()") == ["K", "G", "F", "E"]
    assert "const pending = webPushOrder(Object.values(state.outbox));" in _function("retryAllWebDirtyObjects")


def test_a_push_remembers_what_it_sends_before_it_goes():
    push = _function("pushEncryptedVaultObjectLocked")
    assert push.index("state.outboxSent = rememberWebSent(") < push.index("apiFetch('/api/sync'")
    script = """
      let sent = rememberWebSent({}, { id: 'X', object_type: 'entry', version: 5, payload_hash: 'h5' });
      sent = rememberWebSent(sent, { id: 'X', object_type: 'entry', version: 6, payload_hash: 'h6' });
      sent = rememberWebSent(sent, { id: 'K', object_type: 'dek', version: 1, payload_hash: 'k' });
      for (let v = 7; v < 20; v++) sent = rememberWebSent(sent, { id: 'Y', object_type: 'node', version: v, payload_hash: 'y' + v });
      return { x: sent.X, k: sent.K || null, y: sent.Y.length };
    """
    result = _run(["rememberWebSent"], f"(async () => {{ {script} }})()")
    assert result == {"x": [[5, "h5"], [6, "h6"]], "k": None, "y": 8}


def test_every_asset_url_carries_its_content_hash():
    from server.app import main

    main._web_shell.cache_clear()
    for route, page in ((main.web_vault, "index.html"), (lambda: main.share_page("x"), "share.html")):
        response = asyncio.run(route())
        body = response.body.decode("utf-8")
        assert response.headers["cache-control"] == "no-cache"
        refs = re.findall(r'(?:src|href)="(/static/[^"]+)"', body)
        template = (ROOT / "web" / "templates" / page).read_text(encoding="utf-8")
        assert len(refs) == len(re.findall(r'(?:src|href)="/static/', template))
        for ref in refs:
            path, _, version = ref.partition("?v=")
            digest = hashlib.sha256((ROOT / "web" / path.lstrip("/")).read_bytes()).hexdigest()[:16]
            assert version == digest, ref  # c78fd19: teamlog.js?v=20261113-1 by hand
        if page == "index.html":
            assert re.search(r'src="/static/js/teamlog\.js\?v=[0-9a-f]{16}"', body)
