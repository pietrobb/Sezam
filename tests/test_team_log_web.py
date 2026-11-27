"""Web team log (web/static/js/teamlog.js) against the shared decision vectors (TL2).

The browser code runs in node with the vendored libsodium; every scenario must
give the Python reference's state, answers and error (code and record).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.node_support import node_cmd, requires_node
from tests.team_log_vectors import VECTORS_PATH

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "web" / "static" / "js"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def web_scripts() -> list[str]:
    """libsodium, the core (vendor/sezam-sync-core.js) and teamlog.js, as the page loads them."""
    vendor = JS / "vendor"
    return [str(vendor / "libsodium-sumo.min.js"), str(vendor / "libsodium-wrappers.min.js"),
            str(vendor / "sezam-sync-core.js"), str(JS / "teamlog.js")]

JS_NAMES = {
    "may_write": "mayWrite", "key_recipients": "keyRecipients", "current_key": "currentKey",
    "key_generation": "keyGeneration", "is_team_folder": "isTeamFolder", "is_stale": "isStale",
    "may_seal": "maySeal", "is_admin": "isAdmin", "may_hold_key": "mayHoldKey",
    "envelope_valid": "envelopeValid", "item_refusal": "itemRefusal",
    "tombstone_refusal": "tombstoneRefusal", "move_refusal": "moveRefusal",
    "admin_policy_refusal": "adminPolicyRefusal",
}

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = { console, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, BigInt,
  Promise, WebAssembly, crypto: webcrypto, setTimeout, clearTimeout,
  atob: (v) => Buffer.from(v, 'base64').toString('binary') };
context.window = context; context.self = context; context.globalThis = context;
vm.createContext(context);
for (const path of process.argv.slice(1, 5)) vm.runInContext(fs.readFileSync(path, 'utf8'), context);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
vm.runInContext(`(async () => {
  await sodium.ready;
  await SezamSyncCore.ready;
  const T = SezamTeamLog;
  const out = [];
  for (const s of __input.vectors.scenarios) {
    try {
      const state = T.replay(s.records, sodium);
      const answers = (s.questions || []).map((q) => T[__input.names[q.fn]](state, ...q.args));
      out.push({ state: T.stateToJson(state), answers });
    } catch (e) {
      out.push(e instanceof T.TeamLogError ? { error: { seq: e.seq, code: e.code } } : { crash: String(e && e.stack) });
    }
  }
  return JSON.stringify(out);
})()`, Object.assign(context, { __input: input }))
  .then((r) => process.stdout.write(r))
  .catch((e) => { console.error(e && e.stack); process.exit(1); });
"""


@pytest.fixture(scope="module")
def web_results():
    result = subprocess.run(
        [node_cmd(), "-e", HARNESS, *web_scripts()],
        input=json.dumps({"vectors": VECTORS, "names": JS_NAMES}),
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@requires_node
@pytest.mark.parametrize(
    "index", range(len(VECTORS["scenarios"])), ids=[s["name"] for s in VECTORS["scenarios"]],
)
def test_web_team_log_matches_the_vectors(web_results, index):
    scenario = VECTORS["scenarios"][index]
    got = web_results[index]
    assert "crash" not in got, got["crash"]
    if "error" in scenario:
        assert got == {"error": scenario["error"]}
        return
    assert got["state"] == scenario["state"]
    assert got["answers"] == [q["answer"] for q in scenario["questions"]]


@requires_node
def test_web_signs_records_the_python_reference_accepts():
    """The other direction: a record the browser signs replays in Python."""
    from nacl.signing import SigningKey

    from sezam import teamlog as tl
    from tests.team_log_vectors import ORG, A

    script = HARNESS.replace("const input = JSON.parse(fs.readFileSync(0, 'utf8'));", """
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
vm.runInContext(`(async () => {
  await sodium.ready;
  await SezamSyncCore.ready;
  const T = SezamTeamLog;
  const kp = sodium.crypto_sign_seed_keypair(Uint8Array.from(__input.seed.match(/../g), (b) => parseInt(b, 16)));
  const body = T.nextBody(T.emptyState(), 'genesis', __input.uid, {
    org: __input.org, user_id: __input.uid, signing_pk: __input.spk, encryption_pk: __input.epk });
  return JSON.stringify(T.signRecord(body, kp.privateKey, sodium));
})()`, Object.assign(context, { __input: input }))
  .then((r) => { process.stdout.write(r); process.exit(0); });
return;
""")
    seed = A.sk.encode().hex()
    assert SigningKey(bytes.fromhex(seed)).verify_key.encode().hex() == A.spk
    result = subprocess.run(
        [node_cmd(), "-e", "(function(){" + script + "})()", *web_scripts()],
        input=json.dumps({"seed": seed, "uid": A.uid, "org": ORG, "spk": A.spk, "epk": A.epk}),
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    state = tl.replay([record])
    assert state.members[A.uid].role == "admin"
    assert record == tl.sign_record(tl.next_body(tl.TeamState(), "genesis", A.uid, {
        "org": ORG, "user_id": A.uid, "signing_pk": A.spk, "encryption_pk": A.epk}), A.sk)
