"""Review 18c300f R16-L2: the page reads every blob as the kind it expects.

An entry's meta and data blobs share its id, version and key, so both decrypt
wherever they stand; only the authenticated kind in the header tells them
apart. On 18c300f a server that swapped them got the entry shown empty on the
page (its name read as fields, its fields as name). The desktop checks the kind
(aead.decrypt expected_blob_kind); the phone: mobile/test/r16_blob_kind_test.dart.
"""

import subprocess
from pathlib import Path

from tests.node_support import node_cmd

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, Promise,
  WebAssembly, Blob, URL, crypto: webcrypto,
  location: { origin: 'https://sezam.invalid', search: '' },
  addEventListener() {},
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
  document: { addEventListener() {} },
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 4)) {
  vm.runInContext(fs.readFileSync(path, 'utf8'), context);
}
(async () => {
  await context.sodium.ready;
  const s = context.sodium;
  const K = vm.runInContext('BLOB_KIND', context);
  const dek = context.Uint8Array.from({ length: 32 }, (_, i) => i);
  const dekId = '01JD0000000000000000000001';
  const id = '01JE0000000000000000000001';
  const keys = { [dekId]: dek };
  const payload = context.encryptEntryPayload(
    { name: 'bank', tags: [], fields: [{ key: 'password', value: 's3cret', sensitive: true }] },
    dekId, id, 1, dek, s);
  const back = context.decryptEntryPayload(payload, id, 1, keys, s);
  assert.strictEqual(back.name, 'bank');
  assert.strictEqual(back.fields[0].value, 's3cret');

  const metaLen = new DataView(payload.buffer, payload.byteOffset).getUint32(0, false);
  const meta = payload.slice(4, 4 + metaLen);
  const data = payload.slice(4 + metaLen);
  const swapped = new context.Uint8Array(4 + data.length + meta.length);
  new DataView(swapped.buffer).setUint32(0, data.length, false);
  swapped.set(data, 4);
  swapped.set(meta, 4 + data.length);
  const outcome = {};
  try {
    const shown = context.decryptEntryPayload(swapped, id, 1, keys, s);
    outcome.swapped = 'shown: ' + JSON.stringify(shown);
  } catch (e) { outcome.swapped = 'refused: ' + e.message; }
  // A meta blob served as a whole (legacy single-envelope) entry.
  try {
    const shown = context.decryptEnvelope(meta, id, 1, keys, s, K.ENTRY_DATA);
    outcome.single = 'shown: ' + JSON.stringify(shown);
  } catch (e) { outcome.single = 'refused: ' + e.message; }
  // A node blob read as anything but node meta.
  const node = context.encryptEnvelope({ name: 'F' }, K.NODE_META, dekId, id, 1, dek, s);
  try {
    context.decryptEnvelope(node, id, 1, keys, s, K.ENTRY_DATA);
    outcome.node = 'shown';
  } catch (e) { outcome.node = 'refused: ' + e.message; }
  assert.strictEqual(context.decryptEnvelope(node, id, 1, keys, s, K.NODE_META).name, 'F');
  process.stdout.write(JSON.stringify(outcome));
})().catch((error) => { console.error(error); process.exit(1); });
"""


def test_the_page_refuses_a_blob_of_another_kind():
    import json

    vendor = ROOT / "web" / "static" / "js" / "vendor"
    out = subprocess.run(
        [
            node_cmd(), "-e", HARNESS,
            str(vendor / "libsodium-sumo.min.js"),
            str(vendor / "libsodium-wrappers.min.js"),
            str(ROOT / "web" / "static" / "js" / "app.js"),
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    outcome = json.loads(out.stdout)
    for case, result in outcome.items():
        assert result.startswith("refused: Unexpected blob kind"), (case, result)
