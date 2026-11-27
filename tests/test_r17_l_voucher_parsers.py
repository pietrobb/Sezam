"""Review c02cc47 R17-L: the three voucher parsers differed.

Desktop (src/sezam/key_vouchers.py, which the server runs too), web
(web/static/js/app.js) and phone (mobile/lib/services/key_vouchers.dart) gave
different answers for the same served list: JSON.parse reads a version 3.0 as
3, Python and Dart refused it; bytes.fromhex took spaces in the key and the
signature; a version above 2^53 - 1 counted in Python and Dart, not on the web;
only Python capped the entries (after removing duplicates, while the server's
KeyVoucherList caps them as posted). Only a refusal, never a forgery, but the
clients must decide alike (INV-9).

The lists are signed here with the tree's own key_vouchers, so the same cases
run on every tree; each client must give the answers below.
"""

from __future__ import annotations

import hashlib
import json

from nacl.signing import SigningKey

from sezam import key_vouchers as kv
from tests.test_cross_client_password_change import _phone
from tests.test_review_web import _run, pytestmark  # noqa: F401

USER = "01JACC0000000000000000000F"
OBJ = "01JOBJ00000000000000000001"
DIGEST = hashlib.sha256(b"a").hexdigest()
KEY = SigningKey(hashlib.sha256(b"r17-l-voucher-parse").digest())
PK = bytes(KEY.verify_key)
BIG = 2 ** 53


def _signed(items: list) -> dict:
    """A list over ``items`` signed by the message layout of the tree's core,
    without its entry checks (a version it refuses can still be served)."""
    message = kv.DOMAIN + USER.encode() + PK + len(items).to_bytes(4, "big") + b"".join(
        obj.encode() + version.to_bytes(8, "big") + bytes.fromhex(digest) for obj, version, digest in items)
    return {"signing_pk": PK.hex(), "entries": [list(i) for i in items],
            "signature": KEY.sign(message).signature.hex()}


def _cases() -> list[dict]:
    plain = _signed([(OBJ, 3, DIGEST)])
    sig = plain["signature"]
    return [
        {"name": "a plain list", "list": plain, "entry": [OBJ, 3, DIGEST], "vouched": True},
        {"name": "a version written 3.0", "list": {**plain, "entries": [[OBJ, 3.0, DIGEST]]},
         "entry": [OBJ, 3, DIGEST], "vouched": True},
        {"name": "uppercase hex", "list": {**plain, "signing_pk": PK.hex().upper(), "signature": sig.upper()},
         "entry": [OBJ, 3, DIGEST], "vouched": True},
        {"name": "a space in the signature", "list": {**plain, "signature": sig[:2] + " " + sig[2:]},
         "entry": [OBJ, 3, DIGEST], "vouched": False},
        {"name": "a space in the key", "list": {**plain, "signing_pk": PK.hex()[:2] + " " + PK.hex()[2:]},
         "entry": [OBJ, 3, DIGEST], "vouched": False},
        {"name": "a version of 2^53", "list": _signed([(OBJ, BIG, DIGEST)]),
         "entry": [OBJ, BIG, DIGEST], "vouched": False},
        {"name": "more entries than the server takes", "list": plain, "repeat": 200_001,
         "entry": [OBJ, 3, DIGEST], "vouched": False},
    ]


def _expanded(case: dict) -> dict:
    voucher_list = case["list"]
    return {**voucher_list, "entries": voucher_list["entries"] * case.get("repeat", 1)}


def test_desktop_and_server_parse_the_voucher_cases():
    answers = {c["name"]: tuple(c["entry"]) in kv.vouched(USER, PK, [_expanded(c)]) for c in _cases()}
    assert answers == {c["name"]: c["vouched"] for c in _cases()}


def test_web_parses_the_voucher_cases():
    result = _run(["keyVoucherKey", "canonicalKeyVoucherEntries", "keyVoucherMessage", "idBytes26",
                   "vouchedEntries", "hexToBytes"], f"""(() => {{
        const cases = {json.dumps(_cases())};
        const out = {{}};
        for (const c of cases) {{
            const entries = [];
            for (let i = 0; i < (c.repeat || 1); i++) entries.push(...c.list.entries);
            out[c.name] = vouchedEntries({json.dumps(USER)}, hex({json.dumps(PK.hex())}),
                [{{ ...c.list, entries }}], globalThis.sodium).has(keyVoucherKey(...c.entry));
        }}
        return out;
    }})()""")
    assert result == {c["name"]: c["vouched"] for c in _cases()}


def test_phone_parses_the_voucher_cases(tmp_path):
    _phone("", tmp_path, {"user_id": USER, "signing_pk": PK.hex(), "cases": _cases()}, {},
           test_file="test/r17_l_voucher_parse_test.dart")
