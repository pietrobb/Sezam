"""Capability review run 60 (goal #252, Idea #5): the web repair of personal branches.

migrateLegacyPersonalDescendants runs on every web pull. It re-encrypted every
object under a personal root whose DEK differed from the personal DEK, with a
payload of only the web form fields: a desktop tier-2 entry lost its own DEK
and its tier / AI-broker settings, a desktop subfolder lost tier and
ai_read_secret. The web also dropped those meta keys whenever it decrypted a
canonical entry, so they could not be carried over.
"""

from __future__ import annotations

import json
import subprocess

from tests.test_review_web import ROOT, VENDOR, pytestmark  # noqa: F401
from tests.node_support import node_cmd

APP_JS = ROOT / "web" / "static" / "js" / "app.js"

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
context.window = context; context.self = context; context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 4)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
(async () => {
  await context.sodium.ready;
  const result = await vm.runInContext(process.argv[4], context);
  process.stdout.write(JSON.stringify(result));
})().catch((error) => { console.error(error); process.exit(1); });
"""

ME = "01ME000000000000000000000A"
P = "01P0000000000000000000000A"          # web personal root
SUB = "01S0000000000000000000000A"        # desktop subfolder under P, legacy root DEK
OLD = "01L0000000000000000000000A"        # legacy web entry under P, root DEK
T2 = "01T0000000000000000000000A"         # desktop tier-2 entry under P
ROOT_DEK = "01R0000000000000000000000A"
PDEK = "01Q0000000000000000000000A"
TIER2_DEK = "01Z0000000000000000000000A"

AI_META = {
    "tier": 2, "allowed_actions": ["read"], "ai_read_secret": True,
    "local_root": "C:/w", "remote_root": "/srv", "max_session_minutes": 15,
    "created_at": 1700000000000, "modified_at": 1700000000001,
}

SCRIPT = f"""
(async () => {{
  const dek = n => Uint8Array.from({{ length: 32 }}, () => n);
  const own = {{ owner_id: '{ME}', signer: '{ME}', write_policy: 'owner_only' }};
  const nodes = [
    {{ id: '{P}', name: 'Private', personal: true, dekId: '{PDEK}', parent_ref: null,
       version: 1, ...own }},
    {{ id: '{SUB}', name: 'Desk sub', personal: false, dekId: '{ROOT_DEK}', parent_ref: '{P}',
       version: 3, tier: 1, ai_read_secret: true, created_at: 1700000000000, ...own }},
  ];
  const entries = [
    {{ id: '{OLD}', name: 'legacy', tags: ['x'], fields: [{{ key: 'password', value: 'pw' }}],
       dekId: '{ROOT_DEK}', parent_ref: '{P}', version: 2, owner_id: '{ME}', signer: '{ME}',
       write_policy: 'any_member', allowed_actions: ['read', 'ssh'], tier: 1 }},
    {{ id: '{T2}', name: 'ssh key', tags: [], fields: [{{ key: 'key', value: 'k' }}],
       dekId: '{TIER2_DEK}', parent_ref: '{P}', version: 1, ...own, ...{json.dumps(AI_META)} }},
  ];
  state.userId = '{ME}';
  state.rootDekId = '{ROOT_DEK}';
  state.deks = {{ '{ROOT_DEK}': dek(1), '{PDEK}': dek(2), '{TIER2_DEK}': dek(3) }};
  state.allNodes = nodes; state.allEntries = entries;
  state.nodes = Object.fromEntries(nodes.map(n => [n.id, n]));
  state.entries = Object.fromEntries(entries.map(e => [e.id, e]));
  state.syncObjects = {{
    '{ROOT_DEK}': {{ id: '{ROOT_DEK}', object_type: 'dek', scope: 'root', parent_ref: null }},
    '{PDEK}': {{ id: '{PDEK}', object_type: 'dek', scope: 'personal', parent_ref: '{P}' }},
    '{TIER2_DEK}': {{ id: '{TIER2_DEK}', object_type: 'dek', scope: 'tier2', parent_ref: '{P}' }},
  }};
  const pushed = [];
  pushVaultObjectLocked = async obj => {{ pushed.push(obj); }};
  const migrated = await migrateLegacyPersonalDescendants();
  // What each rewrite really puts on the wire, read back as the web reads it.
  const readBack = {{}};
  for (const obj of pushed) {{
    if (obj.object_type === 'entry') {{
      const bytes = encryptEntryPayload(obj.payloadData, obj.dekId, obj.id, obj.version,
                                        state.deks[obj.dekId], sodium);
      readBack[obj.id] = decryptEntryPayload(bytes, obj.id, obj.version, state.deks, sodium);
    }} else {{
      const bytes = encryptEnvelope(obj.payloadData, BLOB_KIND.NODE_META, obj.dekId, obj.id,
                                    obj.version, state.deks[obj.dekId], sodium);
      readBack[obj.id] = decryptEnvelope(bytes, obj.id, obj.version, state.deks, sodium,
                                         BLOB_KIND.NODE_META);
    }}
  }}
  return {{ migrated, pushed: pushed.map(o => ({{ id: o.id, dekId: o.dekId,
    write_policy: o.write_policy, version: o.version }})), readBack }};
}})()
"""


def _migrate() -> dict:
    out = subprocess.run(
        [node_cmd(), "-e", HARNESS, str(VENDOR / "libsodium-sumo.min.js"),
         str(VENDOR / "libsodium-wrappers.min.js"), str(APP_JS), SCRIPT],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_web_repair_leaves_a_tier2_entry_on_its_own_dek():
    result = _migrate()
    assert T2 not in {p["id"] for p in result["pushed"]}


def test_web_repair_keeps_every_desktop_meta_key_and_the_write_policy():
    result = _migrate()
    assert result["migrated"] is True
    pushed = {p["id"]: p for p in result["pushed"]}
    assert set(pushed) == {SUB, OLD}
    assert {p["dekId"] for p in pushed.values()} == {PDEK}
    assert pushed[OLD]["write_policy"] == "any_member"
    assert pushed[OLD]["version"] == 3

    entry = result["readBack"][OLD]
    assert entry["name"] == "legacy" and entry["tags"] == ["x"]
    assert entry["fields"] == [{"key": "password", "value": "pw"}]
    assert entry["tier"] == 1 and entry["allowed_actions"] == ["read", "ssh"]
    node = result["readBack"][SUB]
    assert node == {"name": "Desk sub", "tier": 1, "ai_read_secret": True,
                    "created_at": 1700000000000}
