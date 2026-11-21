"""One browser tab of the unmodified web client, kept open across many steps.

The page (web/static/js/app.js in node, see tests/web_browser.py) stays loaded
while Python sends it what the user does, one JSON line per step, and reads
back what the page then shows. Closing the tab keeps its IndexedDB, so a new
tab on it is the same browser after a reload.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

from tests.test_review_web import ROOT, VENDOR
from tests.web_browser import BROWSER_ACTIONS, BROWSER_PRELUDE
from tests.node_support import node_cmd

APP_JS = ROOT / "web" / "static" / "js" / "app.js"
MARK = "@@TAB@@"
PAUSED = "@@PAUSED@@"

TAB = BROWSER_PRELUDE + BROWSER_ACTIONS + r"""
const rejections = [];
process.on('unhandledRejection', err => rejections.push(String(err && err.message || err)));
const page = name => vm.runInContext(name, context);
const PAUSED = '@@PAUSED@@';
let releasePaused = null;

// What the state machine's web device does, on top of the actions above.
const tabActions = {
  async login_anchor_write_failure(step) {
    const original = page('idbKeysRequest');
    context.idbKeysRequest = (mode, operation) => original(mode, store => operation(new Proxy(store, {
      get(target, prop) {
        if (prop === 'put') return value => {
          if (value.id.startsWith('confirmed_team_genesis:')) throw new Error('injected anchor disk full');
          return target.put(value);
        };
        return target[prop];
      },
    })));
    try { return await actions.login(step); }
    finally { context.idbKeysRequest = original; }
  },
  async login_backup(step) {
    const bytes = Uint8Array.from(Buffer.from(step.backup, 'hex'));
    const original = document.getElementById;
    const fileInput = { files: [{ arrayBuffer: async () => bytes.buffer }] };
    document.getElementById = id => id === 'sezam-key-import' ? fileInput : original(id);
    try { return await actions.login(step); }
    finally { document.getElementById = original; }
  },
  // A new tab opens on the browser profile of the last one.
  async load_idb(step) {
    for (const [name, rows] of Object.entries(step.idb || {})) {
      for (const row of rows) stores[name].set(row[keyPaths[name]], unpack(row.__json));
    }
    return null;
  },
  // The entry/folder modal opened the way the UI opens it (new, or on an
  // existing object), the user's changes, then Save. `parent` is a folder
  // id or 'ROOT'; leaving it out keeps the object where it is.
  async save_object(step) {
    const state = page('state');
    const existing = step.id
      ? (step.mode === 'folder' ? state.nodes[step.id] : state.entries[step.id]) : null;
    if (step.id && !existing) return `no ${step.mode} ${step.id} in the page`;
    page(step.mode === 'folder' ? 'openFolderModal' : 'openEntryModal')(existing || undefined);
    document.getElementById('modal-name').value = step.name ?? existing.name;
    if (step.parent !== undefined) {
      document.getElementById('modal-parent').value = step.parent === 'ROOT' ? state.rootNodeId : step.parent;
    }
    const fields = step.fields || (existing && existing.fields) || [];
    fieldRows = fields.map(f => ({
      querySelector: cls => ({
        '.field-key-input': { value: f.key },
        '.field-value-input': { value: f.value },
        '.field-sensitive-input': { checked: f.sensitive !== false },
      })[cls],
    }));
    try {
      await page('handleModalSave')({ preventDefault() {} });
    } finally {
      fieldRows = [];
    }
    return document.getElementById('modal-error');
  },
  async delete_entry(step) {
    const entry = page('state').entries[step.id];
    if (!entry) return `no entry ${step.id} in the page`;
    page('openDeleteModal')(entry);
    const before = alerts.length;
    await page('handleDeleteConfirm')();
    return alerts.length > before ? alerts.slice(before).join('; ') : null;
  },
  // What the page does on its own (the periodic pull, a reload of the tree).
  async refresh() {
    try { await page('pullAndBuildTree')(); return null; } catch (err) { return err.message || String(err); }
  },
  // The periodic pull in pages: before its first continuation page it
  // waits until Python sends {action: 'release'} (WebTab.refresh_between_pages).
  async refresh_between_pages() {
    const inner = context.fetch;
    let armed = true;
    context.fetch = async (url, options = {}) => {
      if (armed && url.includes('/api/sync?') && url.includes('cursor=')) {
        armed = false;
        await new Promise(resolve => { releasePaused = resolve; process.stdout.write(PAUSED + '\n'); });
      }
      return inner(url, options);
    };
    try {
      const error = await tabActions.refresh();
      return armed ? 'the pull had a single page' : error;
    } finally {
      context.fetch = inner;
    }
  },
  // The periodic token refresh (startJwtRefreshTimer).
  async refresh_token() {
    const outcome = await page('refreshJWT')();
    return outcome === true ? null : `refresh: ${outcome}`;
  },
  // The conflict banner: Retry, and Use the server's version.
  async retry() {
    try { await page('retryAllWebDirtyObjects')(); return null; } catch (err) { return err.message || String(err); }
  },
  async use_server() {
    const ids = Object.keys(page('state').syncConflicts || {});
    try { await page('discardWebConflictedChanges')(ids); return null; } catch (err) { return err.message || String(err); }
  },
  // The set-aside banner after a password change elsewhere: the previous
  // password, then Restore (it also retries the queue).
  async restore_set_aside(step) {
    const before = alerts.length;
    try {
      const _sodium = await page('ensureSodium')();
      await page('restoreAllSetAsideWebChanges')(step.password, _sodium);
      await page('renderSetAsideWebChanges')();
      await page('retryAllWebDirtyObjects')();
    } catch (err) {
      return err.message || String(err);
    }
    return alerts.length > before ? alerts.slice(before).join('; ') : null;
  },
  async founder(step) {
    if (step.open) await page('openTeamTrustModal')();
    if (step.cancel) page('closeTeamTrustModal')();
    if (step.fingerprint !== undefined) {
      document.getElementById('team-founder-fingerprint').value = step.fingerprint;
      for (const [id, value] of [['team-publish-password', step.password],
          ['team-publish-new-password', step.new_password],
          ['team-publish-confirm-password', step.confirm_password ?? step.new_password]]) {
        const input = document.getElementById(id);
        if (input) input.value = value || '';
      }
      await page('handleConfirmTeamFounder')({ preventDefault() {} });
    }
    return document.getElementById('team-trust-error');
  },
  // Team trust's "Forget the pinned team log": the typed genesis, then the
  // risk confirmation answered with step.confirm.
  async forget_pin(step) {
    document.getElementById('team-forget-genesis').value = step.typed;
    await page('handleForgetTeamPin')({ preventDefault() {} });
    return document.getElementById('team-trust-error');
  },
  // The admin list's Revoke, confirmed: the member is revoked and their
  // folders re-keyed (confirmRevokeUser).
  async revoke(step) {
    const before = alerts.length;
    await page('confirmRevokeUser')(step.user_id);
    return alerts.length > before ? alerts.slice(before).join('; ') : null;
  },
  // The key-change dialog of a periodic pull, answered "accept" (the user
  // checked the member's new fingerprint with them).
  async accept_key_change() {
    const shown = [];
    const dialog = context.showMITMWarning;
    context.showMITMWarning = (...args) => { shown.push(args); };
    try { await page('pullAndBuildTree')(); } catch (err) { /* the dialog's error */ } finally {
      context.showMITMWarning = dialog;
    }
    for (const [, userId, signingPk, encryptionPk] of shown) {
      await page('acceptChangedKey')(userId, signingPk, encryptionPk);
    }
    return shown.length ? null : 'no key change to accept';
  },
  async view() { return null; },
  async select_entry(step) {
    page('renderEntry')(page('state').entries[step.id]);
    return null;
  },
  // Sign in, lock while that login's first (full) pull waits for the
  // server, and sign in again before the answer comes.
  async lock_and_login_during_pull(step) {
    const inner = context.fetch;
    let release, held;
    const gate = new Promise(resolve => { release = resolve; });
    const reached = new Promise(resolve => { held = resolve; });
    let armed = true;
    context.fetch = async (url, options = {}) => {
      if (armed && (options.method || 'GET') === 'GET' && url.includes('/api/sync?')) {
        armed = false;
        held();
        await gate;
      }
      return inner(url, options);
    };
    try {
      page('handleLock')();
      const first = actions.login(step);
      await reached;
      page('handleLock')();
      const second = actions.login(step);
      release();
      await first;
      return await second;
    } finally {
      context.fetch = inner;
    }
  },
};

async function setAside() {
  const state = page('state');
  if (!state.userId || !state.kek) return [];
  return (await page('listSetAsideRecords')()).changes;
}

function pageView() {
  return vm.runInContext(`({
    token: !!state.token, userId: state.userId, keyEpoch: state.keyEpoch,
    unlocked: !!state.kek, rootNodeId: state.rootNodeId || null,
    nodes: (state.allNodes || []).map(n => ({
      id: n.id, name: n.name, parent_ref: n.parent_ref || null,
      personal: !!n.personal, undecryptable: !!n._undecryptable, owner_id: n.owner_id || null,
    })),
    entries: (state.allEntries || []).map(e => ({
      id: e.id, name: e.name, parent_ref: e.parent_ref || null, undecryptable: !!e._undecryptable,
      password: ((e.fields || []).find(f => f.key === 'password') || {}).value ?? null,
    })),
    dirty: Object.keys(state.outbox || {}),
    conflicts: Object.keys(state.syncConflicts || {}),
    selectedPassword: ((state.selectedEntry?.fields || []).find(f => f.key === 'password') || {}).value ?? null,
    detailFields: document.getElementById('entry-fields').innerHTML,
  })`, context);
}

const reply = obj => process.stdout.write('@@TAB@@' + JSON.stringify(obj) + '\n');
const idbDump = () => Object.fromEntries(Object.entries(stores).map(([name, rows]) => [
  name, [...rows.entries()].map(([key, value]) => ({ [keyPaths[name]]: key, __json: pack(value) })),
]));

async function runCommand(step) {
  await context.sodium.ready;
  if (step.action === 'close') {
    reply({ idb: idbDump() });
    process.exit(0);
  }
  const alertsAt = alerts.length;
  const callsAt = calls.length;
  const confirmsAt = confirms.length;
  const failure = step.fail ? { ...step.fail } : null;
  failNext = failure;
  confirmAnswer = !!step.confirm;
  let error;
  let timer;
  try {
    const action = actions[step.action] || tabActions[step.action];
    const out = await Promise.race([
      action(step),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('step never settled')), 60000); }),
    ]);
    error = out && out.classList ? (out.classList.contains('hidden') ? null : out.textContent) : (out || null);
  } catch (err) {
    error = `threw: ${err && err.stack || err}`;
  } finally {
    clearTimeout(timer);
  }
  failNext = null;
  confirmAnswer = false;
  const view = pageView();
  view.set_aside = await setAside();
  reply({
    error, view, alerts: alerts.slice(alertsAt), calls: calls.slice(callsAt),
    confirms: confirms.slice(confirmsAt), shares,
    failure: failure ? { fired: !!failure.fired, reply: failure.reply ?? null } : null,
    rejections: rejections.splice(0),
  });
}

let queue = Promise.resolve();
require('readline').createInterface({ input: process.stdin })
  .on('line', line => {
    const step = JSON.parse(line);
    // Not queued: the step in progress waits for it.
    if (step.action === 'release') { releasePaused(); return; }
    queue = queue.then(() => runCommand(step));
  })
  .on('close', () => queue.then(() => process.exit(0)));
"""


class WebTab:
    """A browser tab on ``origin``; ``idb`` is the profile a previous tab left."""

    def __init__(self, origin: str, log: Path, idb: dict | None = None):
        self._log_path = log
        self._log = open(log, "a", encoding="utf-8")
        payload = base64.b64encode(json.dumps({"origin": origin}).encode()).decode()
        self.proc = subprocess.Popen(
            [node_cmd(), "-e", TAB, str(VENDOR / "libsodium-sumo.min.js"),
             str(VENDOR / "libsodium-wrappers.min.js"), str(APP_JS), payload],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._log,
            text=True, encoding="utf-8",
        )
        if idb:
            self.do("load_idb", idb=idb)

    def do(self, action: str, **step) -> dict:
        """One user step; returns {error, view, alerts, calls, failure, rejections}."""
        self._send({"action": action, **step})
        return self._reply(action)

    def refresh_between_pages(self, between) -> dict:
        """The periodic pull; ``between()`` runs before its first continuation page."""
        self._send({"action": "refresh_between_pages"})
        out = self._reply("refresh_between_pages", paused=True)
        if out is not None:  # one page only: nothing waited
            return out
        between()
        self._send({"action": "release"})
        return self._reply("refresh_between_pages")

    def _send(self, step: dict) -> None:
        self.proc.stdin.write(json.dumps(step) + "\n")
        self.proc.stdin.flush()

    def _reply(self, action: str, paused: bool = False) -> dict | None:
        while True:
            line = self.proc.stdout.readline()
            if not line:
                self.proc.wait(timeout=10)
                self._log.flush()
                tail = self._log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
                raise RuntimeError(f"the web tab exited ({self.proc.returncode}) during {action}:\n{tail}")
            if paused and line.startswith(PAUSED):
                return None
            if line.startswith(MARK):
                return json.loads(line[len(MARK):])

    def close(self) -> dict:
        """Close the tab; returns its IndexedDB for the next one."""
        try:
            return self.do("close")["idb"]
        finally:
            self.kill()

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)
        self._log.close()
