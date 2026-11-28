"""tests/vectors/password_forms.json and shamir.json on the desktop and the web.

Both take secrets (the master password, recovery shares), so they stay with
each platform instead of moving into the core (docs/CORE_UNIFICATION.md U6j,
rule 3); these shared vectors keep the copies the same. The phone checks
password_forms.json in mobile/test/password_forms_vectors_test.dart and has
no org recovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sezam.crypto import kdf, shamir
from tests.test_review_web import _run, _run_source, pytestmark  # noqa: F401

VECTORS = Path(__file__).parent / "vectors"
PF = json.loads((VECTORS / "password_forms.json").read_text(encoding="utf-8"))
SH = json.loads((VECTORS / "shamir.json").read_text(encoding="utf-8"))
APP_JS = (Path(__file__).parents[1] / "web" / "static" / "js" / "app.js").read_text(
    encoding="utf-8"
)


def _web_shamir() -> str:
    start = APP_JS.index("const GF_EXP = new Uint8Array(512);")
    end = APP_JS.rindex(
        "\n// ", start, APP_JS.index("async function openShamirSetupModal")
    )
    return APP_JS[start:end]


@pytest.mark.parametrize("case", PF["cases"], ids=lambda c: c["name"])
def test_the_desktop_password_forms(case):
    assert kdf.canonical_password(case["password"]) == case["canonical"]
    assert kdf.password_forms(case["password"]) == case["forms"]


def test_the_web_password_forms():
    # Code points, not text: the harness reads node's stdout in the locale's code page.
    script = """(() => {
      const cp = s => [...s].map(c => c.codePointAt(0));
      return %s.map(p => [cp(canonicalPassword(p)), passwordForms(p).map(cp)]);
    })()""" % json.dumps([c["password"] for c in PF["cases"]])

    def cp(s):
        return [ord(c) for c in s]

    expected = [[cp(c["canonical"]), [cp(f) for f in c["forms"]]] for c in PF["cases"]]
    assert _run(["canonicalPassword", "passwordForms"], script) == expected


def _shares(raw):
    return [(i, bytes.fromhex(h)) for i, h in raw]


@pytest.mark.parametrize("case", SH["split"], ids=lambda c: c["name"])
def test_the_desktop_split(case, monkeypatch):
    rnd = bytearray.fromhex(case["random"])

    def urandom(n):
        chunk = bytes(rnd[:n])
        del rnd[:n]
        return chunk

    monkeypatch.setattr(shamir.os, "urandom", urandom)
    got = shamir.split_secret(
        bytes.fromhex(case["secret"]), case["threshold"], case["shares"]
    )
    assert [[i, s.hex()] for i, s in got] == case["expected"]
    assert not rnd


def test_the_desktop_reconstruct_and_refusals():
    for case in SH["reconstruct"]:
        assert (
            shamir.reconstruct_secret(_shares(case["shares"])).hex() == case["secret"]
        ), case["name"]
    for r in SH["refused_split"]:
        with pytest.raises(ValueError):
            shamir.split_secret(bytes.fromhex(r["secret"]), r["threshold"], r["shares"])
    for r in SH["refused_reconstruct"]:
        with pytest.raises(ValueError):
            shamir.reconstruct_secret(_shares(r["shares"]))


WEB_SCRIPT = """(() => {
  const V = %s;
  const hx = b => Buffer.from(b).toString('hex');
  const un = h => Uint8Array.from(Buffer.from(h, 'hex'));
  const refused = f => { try { f(); return 'accepted'; } catch (e) { return 'refused'; } };
  const real = globalThis.crypto;
  const split = V.split.map(c => {
    const rnd = un(c.random);
    let pos = 0;
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { getRandomValues: a => {
      a.set(rnd.subarray(pos, pos + a.length)); pos += a.length; return a; } } });
    try {
      const out = shamirSplit(un(c.secret), c.threshold, c.shares).map(([i, s]) => [i, hx(s)]);
      return [out, pos === rnd.length];
    } finally {
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: real });
    }
  });
  return {
    split,
    reconstruct: V.reconstruct.map(c => hx(shamirReconstruct(c.shares.map(([i, h]) => [i, un(h)])))),
    refused_split: V.refused_split.map(r => refused(() => shamirSplit(un(r.secret), r.threshold, r.shares))),
    refused_reconstruct: V.refused_reconstruct.map(r => refused(() => shamirReconstruct(r.shares.map(([i, h]) => [i, un(h)])))),
  };
})()"""


def test_the_web_shamir_is_the_desktop_one():
    out = _run_source(_web_shamir(), WEB_SCRIPT % json.dumps(SH))
    assert out["split"] == [[c["expected"], True] for c in SH["split"]]
    assert out["reconstruct"] == [c["secret"] for c in SH["reconstruct"]]
    assert out["refused_split"] == ["refused"] * len(SH["refused_split"])


def test_the_web_refuses_bad_shares_as_the_desktop():
    """shamirReconstruct took a short share as zeros (NaN ^ value) and a
    duplicate index as a division by zero; the desktop refuses both up front."""
    out = _run_source(_web_shamir(), WEB_SCRIPT % json.dumps(SH))
    assert dict(
        zip((r["name"] for r in SH["refused_reconstruct"]), out["refused_reconstruct"])
    ) == {r["name"]: "refused" for r in SH["refused_reconstruct"]}
