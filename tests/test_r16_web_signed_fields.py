"""Review 18c300f R16-H2: what a sealed copy says never replaces the signed
fields of the object that carries it (web, pullAndBuildTreeLocked).

The page built each pulled node and entry as ``{id: obj.id, ...meta}``: the
content came after the object's id, so a member with write access in a team
folder pushed a validly signed node sealed with the team key whose content
said ``{"id": <the victim's personal root>, "personal": true}``. It took the
root's place in the victim's tree, and what the victim saved there next was
sealed with the team key the member holds. An entry's content could name
another entry's id the same way.

The test runs the page's own decrypt step (the source between the
``decryptedNodes`` declaration and the merge into the candidate maps) on real
sealed copies.
"""

from __future__ import annotations

import json
import subprocess

from tests.node_support import node_cmd
from tests.test_web_personal_migration import APP_JS, HARNESS, VENDOR, pytestmark  # noqa: F401

ME = "01ME000000000000000000000A"
MEMBER = "01MB000000000000000000000A"
P = "01P0000000000000000000000A"          # this account's personal root
X = "01X0000000000000000000000A"          # the member's node in the team folder
OWN_X = "01Y0000000000000000000000A"      # this account's node sealed with the team key
E = "01E0000000000000000000000A"          # this account's entry in the personal root
EVIL = "01V0000000000000000000000A"       # the member's entry naming E
TEAM = "01T0000000000000000000000A"       # the team folder
PDEK = "01Q0000000000000000000000A"       # personal key: this account's KEK opens it
TDEK = "01D0000000000000000000000A"       # team key: an envelope gave it

SCRIPT = f"""
(async () => {{
  const key = n => Uint8Array.from({{ length: 32 }}, () => n);
  const deks = {{ '{PDEK}': key(1), '{TDEK}': key(2) }};
  const b64 = bytes => btoa(Array.from(bytes, c => String.fromCharCode(c)).join(''));
  const node = (id, meta, dekId, signer, parent) => ({{
    id, object_type: 'node', version: 1, parent_ref: parent, owner_id: signer, signer,
    write_policy: 'owner_only',
    payload: b64(encryptEnvelope(meta, BLOB_KIND.NODE_META, dekId, id, 1, deks[dekId], sodium)),
  }});
  const entry = (id, meta, dekId, signer, parent) => ({{
    id, object_type: 'entry', version: 1, parent_ref: parent, owner_id: signer, signer,
    write_policy: 'owner_only',
    payload: b64(encryptEntryPayload(meta, dekId, id, 1, deks[dekId], sodium)),
  }});
  state.userId = '{ME}';
  const nodeObjs = [
    node('{P}', {{ name: 'Private', personal: true }}, '{PDEK}', '{ME}', null),
    node('{X}', {{ name: 'evil', id: '{P}', personal: true, dekId: '{PDEK}', parent_ref: null,
                   signer: '{ME}', owner_id: '{ME}', version: 9 }}, '{TDEK}', '{MEMBER}', '{TEAM}'),
    node('{OWN_X}', {{ name: 'mine, team key', personal: true }}, '{TDEK}', '{ME}', null),
  ];
  const entryObjs = [
    entry('{E}', {{ name: 'bank', fields: [{{ key: 'password', value: 'pw' }}] }}, '{PDEK}', '{ME}', '{P}'),
    entry('{EVIL}', {{ name: 'bank', id: '{E}', parent_ref: '{P}', dekId: '{PDEK}', signer: '{ME}',
                      fields: [{{ key: 'password', value: 'attacker' }}] }}, '{TDEK}', '{MEMBER}', '{TEAM}'),
  ];
  const candidateDeks = deks;
  const kekDekIds = new Set(['{PDEK}']);
  const _sodium = sodium;
  const verifiedSigner = obj => obj.signer;
  const src = pullAndBuildTreeLocked.toString();
  const step = src.slice(src.indexOf('const decryptedNodes = [];'), src.indexOf('// Merge into candidate maps.'));
  const built = eval(step + '\\n;({{ decryptedNodes, decryptedEntries }})');
  // The page merges them by id (candidateNodes[n.id] = n).
  const nodes = {{}}; for (const n of built.decryptedNodes) nodes[n.id] = n;
  const entries = {{}}; for (const e of built.decryptedEntries) entries[e.id] = e;
  const pick = o => o && ({{ id: o.id, personal: !!o.personal, dekId: o.dekId, parent_ref: o.parent_ref,
                             signer: o.signer, version: o.version, name: o.name }});
  return {{
    nodes: Object.fromEntries(Object.entries(nodes).map(([k, v]) => [k, pick(v)])),
    entries: Object.fromEntries(Object.entries(entries).map(([k, v]) => [k, {{ ...pick(v),
      password: v.fields?.[0]?.value }}])),
  }};
}})()
"""


def _pull() -> dict:
    out = subprocess.run(
        [node_cmd(), "-e", HARNESS, str(VENDOR / "libsodium-sumo.min.js"),
         str(VENDOR / "libsodium-wrappers.min.js"), str(APP_JS), SCRIPT],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_a_members_node_naming_my_personal_root_does_not_take_its_place():
    nodes = _pull()["nodes"]
    assert nodes[P] == {"id": P, "personal": True, "dekId": PDEK, "parent_ref": None,
                        "signer": ME, "version": 1, "name": "Private"}
    assert nodes[X]["id"] == X
    assert nodes[X]["dekId"] == TDEK
    assert nodes[X]["parent_ref"] == TEAM
    assert nodes[X]["signer"] == MEMBER
    assert nodes[X]["version"] == 1


def test_only_my_own_node_on_my_own_key_is_a_personal_folder():
    nodes = _pull()["nodes"]
    assert nodes[X]["personal"] is False        # signed by the member
    assert nodes[OWN_X]["personal"] is False    # sealed with a key an envelope gave


def test_a_members_entry_naming_my_entry_does_not_replace_it():
    entries = _pull()["entries"]
    assert entries[E]["password"] == "pw"
    assert entries[E]["dekId"] == PDEK
    assert entries[EVIL]["id"] == EVIL
    assert entries[EVIL]["parent_ref"] == TEAM
    assert entries[EVIL]["signer"] == MEMBER
