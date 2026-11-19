"""The browser around the unmodified web client, for tests that run app.js in node.

BROWSER_PRELUDE loads libsodium and web/static/js/app.js into a vm context with
webcrypto, an IndexedDB that outlives one node run as JSON (a browser profile),
a DOM of plain elements and the Argon2 Web Worker (node Argon2id, same
parameters). BROWSER_ACTIONS are what the user does in the page, each
returning its error element. node gets: libsodium-sumo, libsodium-wrappers,
app.js, base64 JSON {origin, idb}.
"""

BROWSER_PRELUDE = r"""
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const input = JSON.parse(Buffer.from(process.argv[4], 'base64').toString('utf8'));

// IndexedDB of one browser profile; it outlives a single node run as JSON.
const isBytes = v => Object.prototype.toString.call(v) === '[object Uint8Array]';
const pack = v => JSON.stringify(v, (k, x) => isBytes(x) ? { __u8: Buffer.from(x).toString('hex') } : x);
const unpack = s => JSON.parse(s, (k, x) => x && typeof x === 'object' && typeof x.__u8 === 'string'
  ? Uint8Array.from(Buffer.from(x.__u8, 'hex')) : x);
const stores = { keys: new Map(), known_keys: new Map() };
const keyPaths = { keys: 'id', known_keys: 'user_id' };
for (const [name, rows] of Object.entries(input.idb || {})) {
  for (const row of rows) stores[name].set(row[keyPaths[name]], unpack(row.__json));
}
const later = fn => setTimeout(fn, 0);
const indexedDB = {
  open() {
    const req = {};
    const db = {
      objectStoreNames: { contains: name => name in stores },
      createObjectStore() {},
      transaction(names, mode) {
        const tx = { error: null };
        tx.objectStore = name => {
          const store = stores[name];
          const op = run => {
            const req = { result: undefined, error: null };
            req.result = run();
            later(() => req.onsuccess && req.onsuccess());
            return req;
          };
          const writable = () => { if (mode !== 'readwrite') throw new Error('readonly transaction'); };
          return {
            get: key => op(() => store.has(key) ? unpack(pack(store.get(key))) : undefined),
            getAllKeys: () => op(() => [...store.keys()]),
            count: () => op(() => store.size),
            put: value => op(() => { writable(); store.set(value[keyPaths[name]], unpack(pack(value))); }),
            delete: key => op(() => { writable(); store.delete(key); }),
          };
        };
        later(() => later(() => tx.oncomplete && tx.oncomplete()));
        return tx;
      },
    };
    req.result = db;
    later(() => req.onsuccess && req.onsuccess());
    return req;
  },
};

function makeElement(id) {
  const classes = new Set();
  // Any other element method (reset, showModal, ...) is a no-op.
  const noop = () => undefined;
  return new Proxy({
    id, value: '', textContent: '', innerHTML: '', hidden: false, disabled: false,
    style: {}, dataset: {}, children: [], childNodes: [], files: undefined,
    classList: {
      add: (...c) => c.forEach(x => classes.add(x)),
      remove: (...c) => c.forEach(x => classes.delete(x)),
      contains: c => classes.has(c),
      toggle: (c, force) => {
        const on = force === undefined ? !classes.has(c) : !!force;
        if (on) classes.add(c); else classes.delete(c);
        return on;
      },
    },
    addEventListener() {}, removeEventListener() {}, appendChild: c => c, append() {},
    prepend() {}, replaceChildren() {}, remove() {}, setAttribute() {}, removeAttribute() {},
    getAttribute: () => null, querySelector: () => makeElement('query'), querySelectorAll: () => [],
    focus() {}, blur() {}, click() {}, insertBefore: c => c, removeChild: c => c,
    closest: () => null, contains: () => false, scrollIntoView() {},
    getBoundingClientRect: () => ({ width: 0, height: 0, top: 0, left: 0 }),
  }, {
    // Not a thenable: an element returned from an async function stays an element.
    get: (el, key) => key in el || typeof key === 'symbol' || key === 'then' ? el[key] : noop,
  });
}
const elements = {};
const created = [];
// Field rows of the entry modal while a `save` step fills it.
let fieldRows = [];
const document = {
  getElementById: id => id === 'sezam-key-import' ? null : (elements[id] ||= makeElement(id)),
  createElement: tag => { const el = makeElement(tag); created.push(el); return el; },
  createTextNode: text => ({ textContent: text }),
  createDocumentFragment: () => makeElement('fragment'),
  querySelector: () => makeElement('query'),
  querySelectorAll: sel => sel === '#modal-fields-list .modal-field-row' ? fieldRows : [],
  addEventListener() {}, removeEventListener() {},
  body: makeElement('body'), documentElement: makeElement('html'), hidden: false,
};

const alerts = [];
const calls = [];
let dropKeyRotation = false;
// The next request matching {method, path} fails: 'before' it is sent, or
// 'after' the server processed it (the reply is lost).
let failNext = null;
// What the user answers to window.confirm.
let confirmAnswer = false;
const confirms = [];
const context = {
  console, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt, Promise, AbortSignal,
  WebAssembly, URL, URLSearchParams, Buffer, crypto: webcrypto, clearTimeout,
  // A full resync saves unsent changes as a download (Blob + object URL).
  Blob,
  // Session timers (inactivity lock, ...) must not keep node alive.
  setTimeout: (fn, ms, ...args) => {
    const timer = setTimeout(fn, ms, ...args);
    if (ms > 1000) timer.unref();
    return timer;
  },
  setInterval: () => 0, clearInterval() {},
  atob: v => Buffer.from(v, 'base64').toString('binary'),
  btoa: v => Buffer.from(v, 'binary').toString('base64'),
  location: { origin: input.origin, search: '', href: input.origin + '/' },
  navigator: { userAgent: 'node', clipboard: { writeText: async () => {} } },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  indexedDB, document,
  alert: message => { alerts.push(message); },
  confirm: message => { confirms.push(String(message)); return confirmAnswer; },
  addEventListener() {}, removeEventListener() {},
  fetch: async (url, options = {}) => {
    // A step with drop_key_rotation loses the connection on the rotation push.
    if (dropKeyRotation && options.method === 'POST' && url.endsWith('/api/sync') &&
        String(options.body).includes('"key_rotation"')) {
      throw new Error('network down');
    }
    const call = { method: options.method || 'GET', path: url.slice(input.origin.length).split('?')[0] };
    if (call.method === 'POST' && call.path === '/api/sync') {
      try { call.objects = JSON.parse(options.body).objects.map(o => o.id); } catch (_) { /* not JSON */ }
    }
    const failure = failNext && call.method === failNext.method && call.path === failNext.path ? failNext : null;
    if (failure) {
      failNext = null;
      failure.fired = true;
      call.status = `injected ${failure.mode}`;
      calls.push(call);
      if (failure.mode === 'before') throw new Error('network down (injected)');
      failure.reply = await (await fetch(url, options)).json().catch(() => null);
      throw new Error('reply lost (injected)');
    }
    let resp;
    try {
      resp = await fetch(url, options);
    } catch (err) {
      throw new Error(`fetch ${url} failed: ${err.cause ? err.cause.message || err.cause.code : err.message}`);
    }
    call.status = resp.status;
    calls.push(call);
    return resp;
  },
};
context.window = context; context.self = context; context.globalThis = context;
// Messages are their i18n keys, followed by any values (e.g. the error behind "recovery.failed").
context.SezamI18n = {
  defaultLanguage: 'sk', languages: { sk: {} }, applyDocument: () => 'sk',
  listLanguages: () => [], resolveLanguage: () => 'sk',
  translate: (_language, key, values = {}) => Object.keys(values).length
    ? `${key} ${JSON.stringify(values)}` : key,
};
vm.createContext(context);
for (const path of process.argv.slice(1, 4)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
// The page loads teamlog.js (SezamTeamLog) next to app.js (TL5).
vm.runInContext(fs.readFileSync(require('path').join(require('path').dirname(process.argv[3]), 'teamlog.js'), 'utf8'), context);
// ... and the shared sync core (vendor/sezam-sync-core.js, built from core/).
vm.runInContext(fs.readFileSync(require('path').join(require('path').dirname(process.argv[1]), 'sezam-sync-core.js'), 'utf8'), context);

// The Argon2 Web Worker, with node's Argon2id and the same parameters.
context.Worker = class {
  postMessage({ password, salt, params }) {
    later(() => {
      const kek = new Uint8Array(require('crypto').argon2Sync('argon2id', {
        message: password, nonce: salt, parallelism: params.parallelism,
        tagLength: 64, memory: params.mem, passes: params.time,
      }));
      this.onmessage({ data: { kek } });
    });
  }
  terminate() {}
};

"""

BROWSER_ACTIONS = r"""
// What the user does in the browser, step by step; each returns its error element.
let shares = [];
const actions = {
  async login(step) {
    document.getElementById('username').value = step.username;
    document.getElementById('password').value = step.password;
    await vm.runInContext('handleLogin', context)({ preventDefault() {} });
    return document.getElementById('login-error');
  },
  // Admin menu → org recovery setup; the shares are read off the modal.
  async org_recovery_setup(step) {
    document.getElementById('shamir-threshold').value = String(step.threshold);
    document.getElementById('shamir-total').value = String(step.total_shares);
    document.getElementById('shamir-password').value = step.password;
    await vm.runInContext('handleShamirGenerate', context)();
    const modal = created.find(el => el.id === 'shamir-shares-modal');
    shares = modal ? [...modal.innerHTML.matchAll(/<code>(\d+:[0-9a-f]+)<\/code>/g)].map(m => m[1]) : [];
    return document.getElementById('shamir-setup-error');
  },
  // Login screen → org recovery: shares and a new account password.
  async org_recovery(step) {
    step.shares.forEach((share, i) => { document.getElementById(`recovery-share-${i}`).value = share; });
    document.getElementById('recovery-new-password').value = step.password;
    document.getElementById('recovery-confirm-password').value = step.password;
    await vm.runInContext('handleOrgRecovery', context)(step.shares.length, step.total_shares);
    return document.getElementById('org-recovery-error');
  },
  // The new-folder / new-personal-folder / new-entry modal, filled and saved.
  // `parent` names a folder ('ROOT' = the account root).
  async save(step) {
    const nodes = vm.runInContext('state', context).allNodes;
    const parent = step.parent === 'ROOT'
      ? vm.runInContext('state', context).rootNodeId
      : (nodes.find(n => n.name === step.parent) || {}).id;
    document.getElementById('modal-mode').value = step.mode;
    document.getElementById('modal-entry-id').value = '';
    document.getElementById('modal-name').value = step.name;
    document.getElementById('modal-parent').value = step.parent ? parent || 'missing' : '';
    document.getElementById('modal-tags').value = '';
    document.getElementById('modal-shared').checked = false;
    fieldRows = (step.fields || []).map(f => ({
      querySelector: cls => ({
        '.field-key-input': { value: f.key },
        '.field-value-input': { value: f.value },
        '.field-sensitive-input': { checked: true },
      })[cls],
    }));
    await vm.runInContext('handleModalSave', context)({ preventDefault() {} });
    fieldRows = [];
    return document.getElementById('modal-error');
  },
};

"""
