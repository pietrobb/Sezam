"""Capability run 269: the pre-anchor password states are one format in Python, JS and Dart.

The anchored account bundle (SZACCT02) records each password state that
opened bundles without the team anchor. Every client must parse the same
bytes, refuse the same malformed states, recognise every recorded password
(in any of its KDF forms) and nothing else, and emit bundles the others read.
"""

import json
import subprocess
import unicodedata

from sezam.crypto import aead
from sezam.crypto.kdf import Argon2Params, derive_kek, derive_kek_and_proof, password_forms
from tests.node_support import node_cmd, requires_node
from tests.test_account_anchor_bundle import FULL, GENESIS, KEK, KID, RAW, ROOT, UID
from tests.test_cross_client_vectors import _web_constant, _web_function

PARAMS = Argon2Params(time_cost=2, memory_cost=65_536, parallelism=1)  # the browser's floor
S0, S1 = bytes(range(16)), bytes(range(16, 32))
P0 = unicodedata.normalize("NFC", "pre-anchor-žltý-kôň")
P1 = "second-pre-anchor-state"
CHECKS = [(P0, True), (unicodedata.normalize("NFD", P0), True), (P1, True), ("never-used-password", False)]


def _vectors() -> dict:
    kek0 = derive_kek(P0, S0, PARAMS)
    kek1 = derive_kek(P1, S1, PARAMS)
    first = aead.add_pre_anchor(b"", S0, 2, 65_536, 1, kek0)
    states = aead.add_pre_anchor(first, S1, 2, 65_536, 1, kek1)
    material = {}
    for password, _ in CHECKS:
        for form in password_forms(password):
            for salt in (S0, S1):
                kek, proof = derive_kek_and_proof(form, salt, PARAMS, exact=True)
                material[f"{form}|{salt.hex()}"] = (bytes(kek) + bytes(proof)).hex()
    entry = first[1:]
    bad = [
        b"\x00",  # no states
        bytes([9]) + entry * 9,  # above the cap
        first[:-1],  # truncated
        first + b"\x00",  # trailing byte
        b"\x01" + entry[:16] + (0).to_bytes(4, "big") + entry[20:],  # time cost 0
        b"\x01" + entry[:20] + (4096).to_bytes(4, "big") + entry[24:],  # memory below range
        b"\x01" + entry[:24] + (17).to_bytes(4, "big") + entry[28:],  # lanes above range
    ]
    return {
        "states": states.hex(), "first": first.hex(), "kek0": bytes(kek0).hex(), "s0": S0.hex(),
        "params": {"time_cost": 2, "memory_cost": 65_536, "parallelism": 1, "hash_len": 64},
        "checks": [{"password": p, "reopens": r} for p, r in CHECKS],
        "material": material, "bad": [b.hex() for b in bad],
        "bad_bundle": (b"SZACCT02" + bytes(RAW) + bytes.fromhex(GENESIS)).hex(),
        "envelope": aead.encrypt_account_keypair(RAW, GENESIS, KEK, KID, UID, states).hex(),
        "full": FULL.hex(), "raw": RAW.hex(), "genesis": GENESIS, "kek": KEK.hex(),
        "kid": KID.decode(), "user": UID.decode(),
    }


def _assert_emitted(vectors: dict, emitted: dict) -> None:
    assert emitted["first"] == vectors["first"]
    assert emitted["merged"] == vectors["states"]
    keys, genesis, states = aead.decrypt_account_bundle(bytes.fromhex(emitted["envelope"]), KEK, UID)
    assert (keys, genesis, states.hex()) == (RAW, GENESIS, vectors["states"])


def test_python_pre_anchor_vectors():
    v = _vectors()
    states = bytes.fromhex(v["states"])
    for password, reopens in CHECKS:
        assert aead.password_reopens_pre_anchor(password, states) is reopens, password
    for blob in v["bad"]:
        try:
            aead.parse_pre_anchor(bytes.fromhex(blob))
        except ValueError:
            continue
        raise AssertionError(blob)
    try:
        aead.decode_account_bundle(bytes.fromhex(v["bad_bundle"]))
        raise AssertionError("SZACCT02 without states opened")
    except ValueError:
        pass
    assert aead.merge_pre_anchor(states, bytes.fromhex(v["first"])) == states
    assert aead.decrypt_account_bundle(bytes.fromhex(v["envelope"]), KEK, UID)[2] == states


WEB_BODY = r"""
async function run(V) {
  await sodium.ready; const s = sodium;
  const check = (ok, what) => { if (!ok) throw new Error('mismatch: ' + what); };
  const states = hexToBytes(V.states);
  for (const c of V.checks) {
    check(await passwordReopensPreAnchor(c.password, states, s) === c.reopens, 'reopens ' + c.password);
  }
  for (const b of V.bad) {
    let refused = false;
    try { parsePreAnchor(hexToBytes(b)); } catch { refused = true; }
    check(refused, 'bad states ' + b.slice(0, 8));
  }
  let refused = false;
  try { decodeAccountKeypair(hexToBytes(V.bad_bundle), s); } catch { refused = true; }
  check(refused, 'SZACCT02 without states');
  const opened = decryptAccountKeypair(hexToBytes(V.envelope), hexToBytes(V.kek), V.user, s);
  check(bytesToHex(opened.keypairData) === V.raw && opened.confirmedGenesis === V.genesis &&
    bytesToHex(opened.preAnchor) === V.states, 'open python bundle');
  const first = addPreAnchor(null, hexToBytes(V.s0), V.params, hexToBytes(V.kek0), s);
  return {
    first: bytesToHex(first),
    merged: bytesToHex(mergePreAnchor(states, first)),
    envelope: bytesToHex(encryptAccountKeypair(hexToBytes(V.full), V.genesis, hexToBytes(V.kek),
      V.kid, V.user, s, states)),
  };
}
"""

WEB_HARNESS = r"""
const fs = require('fs'), vm = require('vm'), {webcrypto} = require('crypto');
const c = {Uint8Array, TextEncoder, TextDecoder, DataView, ArrayBuffer, WebAssembly, Promise, BigInt,
  crypto:webcrypto, console, setTimeout, clearTimeout, atob: v => Buffer.from(v, 'base64').toString('binary')};
c.window=c; c.self=c; c.globalThis=c; vm.createContext(c);
for(const p of process.argv.slice(1,4)) vm.runInContext(fs.readFileSync(p,'utf8'),c);
const input=JSON.parse(fs.readFileSync(0,'utf8')); vm.runInContext(input.source,c);
c.run(input.vectors).then(x=>process.stdout.write(JSON.stringify(x))).catch(e=>{console.error(e);process.exit(1)});
"""


def _web(vectors: dict) -> dict:
    source = (ROOT / "web/static/js/app.js").read_text(encoding="utf-8")
    functions = "\n".join(_web_function(source, name) for name in (
        "preAnchorCheck", "parsePreAnchor", "mergePreAnchor", "addPreAnchor", "passwordReopensPreAnchor",
        "canonicalPassword", "passwordForms", "normalizeKdfParams", "deriveKEK", "deriveKEKViaWorker",
        "encodeAccountKeypair", "decodeAccountKeypair", "encryptAccountKeypair", "decryptAccountKeypair",
        "encryptKeypairWrap", "decryptKeypairWrap", "expandDesktopKeypair", "buildAAD", "idBytes26",
        "padPlaintext", "paddedSize", "unpadPlaintext", "bytesToHex", "hexToBytes",
    ))
    constants = "\n".join(_web_constant(source, n) for n in (
        "ENVELOPE_ALG", "SCHEMA_VERSION", "BLOB_KIND", "ARGON2_HARD_FLOOR", "ARGON2_ACCOUNT_MAX",
        "PRE_ANCHOR_ENTRY_LEN", "PRE_ANCHOR_MAX", "ACCOUNT_BUNDLE_LENGTHS",
    ))
    vendor = ROOT / "web/static/js/vendor"
    result = subprocess.run(
        [node_cmd(), "-e", WEB_HARNESS, str(vendor / "libsodium-sumo.min.js"),
         str(vendor / "libsodium-wrappers.min.js"), str(vendor / "argon2-bundled.min.js")],
        input=json.dumps({"source": "var state = null;\n" + constants + functions + WEB_BODY,
                          "vectors": vectors}),
        text=True, encoding="utf-8", capture_output=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@requires_node
def test_web_pre_anchor_vectors():
    vectors = _vectors()
    _assert_emitted(vectors, _web(vectors))


def test_phone_pre_anchor_vectors(tmp_path):
    from tests.test_cross_client_password_change import _phone

    vectors = _vectors()
    _phone("", tmp_path, vectors, {}, "test/pre_anchor_vectors_test.dart")
    _assert_emitted(vectors, json.loads((tmp_path / "phone/emitted.json").read_text(encoding="utf-8")))
