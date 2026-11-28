"""tests/vectors/account_bundle.json on the desktop and the web: pre-anchor
password states and the SZACCT account bundle are the core's
(docs/CORE_UNIFICATION.md U6e). core/tests/account_bundle_vectors.rs checks the
core itself, mobile/test/account_bundle_vectors_test.dart the phone."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sezam.crypto import aead

V = json.loads((Path(__file__).parent / "vectors" / "account_bundle.json").read_text(encoding="utf-8"))


def _outcome(fn, *args):
    try:
        return {"ok": fn(*args)}
    except ValueError:
        return {"error": True}


@pytest.mark.parametrize("case", V["pre_anchor_parse"])
def test_parse(case):
    out = _outcome(aead.parse_pre_anchor, bytes.fromhex(case["blob"]))
    if "error" in case:
        assert "error" in out
    else:
        assert [(s.hex(), t, m, p, c.hex()) for s, t, m, p, c in out["ok"]] == [
            (e["salt"], e["time_cost"], e["memory_cost"], e["parallelism"], e["check"]) for e in case["ok"]
        ]


@pytest.mark.parametrize("case", V["pre_anchor_merge"])
def test_merge(case):
    out = _outcome(aead.merge_pre_anchor, bytes.fromhex(case["kept"]), bytes.fromhex(case["other"]))
    if "error" in case:
        assert "error" in out
    else:
        assert (out["ok"].hex() or None) == case["ok"]


def test_a_state_the_other_side_records_twice_takes_one_place():
    """aead.py appended every state ``other`` had that ``kept`` lacked, a
    repeated one twice; the copy pushed a real state out of the 8 kept."""
    case = next(c for c in V["pre_anchor_merge"] if c["kept"].startswith("07") and "desktop_before" in c)
    merged = aead.merge_pre_anchor(bytes.fromhex(case["kept"]), bytes.fromhex(case["other"]))
    assert merged.hex() == case["ok"]
    assert merged[0] == 8 and len({merged[1 + i * 60:61 + i * 60] for i in range(8)}) == 8


@pytest.mark.parametrize("case", V["pre_anchor_add"])
def test_add(case):
    out = _outcome(aead.add_pre_anchor, bytes.fromhex(case["blob"]), bytes.fromhex(case["salt"]),
                   case["time_cost"], case["memory_cost"], case["parallelism"], bytes.fromhex(case["kek"]))
    if "error" in case:
        assert "error" in out
    else:
        assert (out["ok"].hex() or None) == case["ok"]


def test_check():
    c = V["pre_anchor_check"]
    assert aead.pre_anchor_check(bytes.fromhex(c["kek"])).hex() == c["check"]


@pytest.mark.parametrize("case", V["bundle_decode"])
def test_bundle_decode(case):
    out = _outcome(aead.decode_account_bundle, bytes.fromhex(case["payload"]))
    if "error" in case:
        assert "error" in out
    else:
        keys, genesis, states = out["ok"]
        assert {"keys": bytes(keys).hex(), "confirmed_genesis": genesis,
                "pre_anchor": states.hex() or None} == case["ok"]


@pytest.mark.parametrize("case", V["bundle_encode"])
def test_bundle_encode(case):
    out = _outcome(aead.encode_account_keypair, bytes.fromhex(case["keys"]), case["confirmed_genesis"],
                   bytes.fromhex(case["pre_anchor"] or ""))
    if "error" in case:
        assert "error" in out
    else:
        assert bytes(out["ok"]).hex() == case["ok"]


def test_the_web_through_the_core():
    from tests.test_review_web import _run

    script = """(() => {
      const V = %s;
      const h = v => v ? hexToBytes(v) : null;
      const hex = v => v ? bytesToHex(v) : null;
      const tryit = f => { try { return { ok: f() }; } catch (e) { return { error: true }; } };
      const entry = e => [bytesToHex(e.salt), e.time_cost, e.memory_cost, e.parallelism, bytesToHex(e.check)];
      return {
        parse: V.pre_anchor_parse.map(c => tryit(() => parsePreAnchor(h(c.blob)).map(entry))),
        merge: V.pre_anchor_merge.map(c => tryit(() => hex(mergePreAnchor(h(c.kept), h(c.other))))),
        add: V.pre_anchor_add.map(c => tryit(() => hex(addPreAnchor(h(c.blob), hexToBytes(c.salt),
          { time_cost: c.time_cost, memory_cost: c.memory_cost, parallelism: c.parallelism },
          hexToBytes(c.kek), sodium)))),
        decode: V.bundle_decode.map(c => tryit(() => {
          const d = decodeAccountKeypair(hexToBytes(c.payload), sodium);
          return { keys: bytesToHex(d.keypairData), confirmed_genesis: d.confirmedGenesis, pre_anchor: hex(d.preAnchor) };
        })),
        encode: V.bundle_encode.map(c => tryit(() =>
          bytesToHex(encodeAccountKeypair(hexToBytes(c.keys), c.confirmed_genesis, sodium, h(c.pre_anchor))))),
      };
    })()""" % json.dumps(V)
    out = _run(["parsePreAnchor", "mergePreAnchor", "preAnchorCheck", "addPreAnchor", "decodeAccountKeypair",
                "encodeAccountKeypair"], script)

    def want(cases, shape=lambda ok: ok):
        return [{"error": True} if "error" in c else {"ok": shape(c["ok"])} for c in cases]

    assert out["parse"] == want(V["pre_anchor_parse"], lambda ok: [
        [e["salt"], e["time_cost"], e["memory_cost"], e["parallelism"], e["check"]] for e in ok])
    assert out["merge"] == want(V["pre_anchor_merge"])
    assert out["add"] == want(V["pre_anchor_add"])
    assert out["decode"] == want(V["bundle_decode"])
    assert out["encode"] == want(V["bundle_encode"])
